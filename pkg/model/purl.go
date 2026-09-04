package model

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// PURL is a parsed Package URL: the canonical identity of a package.
//
// Scanners name the same package differently — one reports "openssl", another
// "libssl1.1" — so package names cannot be compared directly. PURL gives a
// structured identity that can.
//
// The general form is:
//
//	pkg:type/namespace/name@version?qualifiers
//
// Real examples from testdata/fixtures:
//
//	pkg:deb/debian/apt@2.2.4?arch=amd64&distro=debian-11.11
//	pkg:deb/debian/libdb5.3@5.3.28%2Bdfsg1-0.8?arch=amd64&distro=debian-11.11&upstream=db5.3
//
// Note the second: Grype percent-encodes '+' as %2B where Trivy writes it
// literally, and adds an "upstream" qualifier Trivy omits. Both refer to the
// same package. Comparing the raw strings would say otherwise.
type PURL struct {
	Type       string            // deb, apk, npm, pypi, golang, maven
	Namespace  string            // debian, alpine — may be empty
	Name       string            // decoded package name
	Version    string            // decoded version
	Qualifiers map[string]string // decoded, lower-cased keys
}

// identityQualifiers are the qualifiers that distinguish one package from
// another. Everything else is metadata: informative, but two PURLs that differ
// only in a non-identity qualifier refer to the same package.
//
// "upstream" is deliberately excluded. Grype emits it to record which source
// package a binary package was built from; it describes provenance, not
// identity, and including it would prevent Trivy and Grype findings from
// correlating.
var identityQualifiers = map[string]bool{
	"arch":   true, // amd64 and arm64 builds are genuinely different packages
	"distro": true, // the same version in debian-11 and debian-12 is not the same package
	"epoch":  true, // part of the version in RPM ecosystems
}

// ParsePURL parses a Package URL string.
//
// Percent-encoding is decoded, qualifier keys are lower-cased, and the type
// and namespace are normalised to lowercase as the specification requires.
// Values are left as-is beyond decoding: package names and versions are
// case-sensitive in some ecosystems.
func ParsePURL(raw string) (PURL, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return PURL{}, fmt.Errorf("empty package URL")
	}
	rest, ok := strings.CutPrefix(s, "pkg:")
	if !ok {
		return PURL{}, fmt.Errorf("package URL must start with %q: %s", "pkg:", raw)
	}

	// Split off the qualifiers, then the subpath, which we do not use but must
	// not treat as part of the version.
	var qualifierPart string
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest, qualifierPart = rest[:i], rest[i+1:]
	}
	if i := strings.IndexByte(qualifierPart, '#'); i >= 0 {
		qualifierPart = qualifierPart[:i]
	}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}

	// Version is everything after the last '@'. Using the last one matters:
	// Maven coordinates can contain '@' earlier in the string.
	var version string
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		rest, version = rest[:i], rest[i+1:]
	}

	segments := strings.Split(rest, "/")
	if len(segments) < 2 {
		return PURL{}, fmt.Errorf("package URL needs a type and a name: %s", raw)
	}

	p := PURL{
		Type:       strings.ToLower(segments[0]),
		Qualifiers: map[string]string{},
	}
	if p.Type == "" {
		return PURL{}, fmt.Errorf("package URL has an empty type: %s", raw)
	}

	name, err := url.PathUnescape(segments[len(segments)-1])
	if err != nil {
		return PURL{}, fmt.Errorf("package URL has an undecodable name: %s", raw)
	}
	p.Name = name
	if p.Name == "" {
		return PURL{}, fmt.Errorf("package URL has an empty name: %s", raw)
	}

	// Anything between the type and the name is the namespace. It can have
	// several segments — a Maven group ID, for instance.
	if len(segments) > 2 {
		ns, err := url.PathUnescape(strings.Join(segments[1:len(segments)-1], "/"))
		if err != nil {
			return PURL{}, fmt.Errorf("package URL has an undecodable namespace: %s", raw)
		}
		p.Namespace = strings.ToLower(ns)
	}

	if version != "" {
		v, err := url.PathUnescape(version)
		if err != nil {
			return PURL{}, fmt.Errorf("package URL has an undecodable version: %s", raw)
		}
		p.Version = v
	}

	for _, kv := range strings.Split(qualifierPart, "&") {
		if kv == "" {
			continue
		}
		key, value, found := strings.Cut(kv, "=")
		if !found || key == "" {
			continue // a malformed qualifier is metadata we can do without
		}
		decoded, err := url.QueryUnescape(value)
		if err != nil {
			continue
		}
		p.Qualifiers[strings.ToLower(key)] = decoded
	}

	return p, nil
}

// Canonical returns the identity form of the PURL: decoded, with only
// identity-bearing qualifiers, sorted by key.
//
// This is the correlation key. Two PURLs written differently by two scanners
// produce the same canonical form when they refer to the same package.
func (p PURL) Canonical() string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(p.Type)
	if p.Namespace != "" {
		b.WriteByte('/')
		b.WriteString(p.Namespace)
	}
	b.WriteByte('/')
	b.WriteString(p.Name)
	if p.Version != "" {
		b.WriteByte('@')
		b.WriteString(p.Version)
	}

	keys := make([]string, 0, len(p.Qualifiers))
	for k := range p.Qualifiers {
		if identityQualifiers[k] && p.Qualifiers[k] != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	for i, k := range keys {
		if i == 0 {
			b.WriteByte('?')
		} else {
			b.WriteByte('&')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(p.Qualifiers[k])
	}
	return b.String()
}

// String returns the canonical form.
func (p PURL) String() string { return p.Canonical() }

// Equal reports whether two PURLs identify the same package, ignoring encoding
// differences, qualifier order, and qualifiers that do not bear on identity.
func (p PURL) Equal(other PURL) bool {
	return p.Canonical() == other.Canonical()
}

// SameArtifact reports whether two PURLs name the same package ignoring
// version — the same package at two different versions.
//
// The correlator needs this when scanners agree on the package but report
// different installed versions, which happens when one reads the package
// database and another reads file metadata.
func (p PURL) SameArtifact(other PURL) bool {
	a, b := p, other
	a.Version, b.Version = "", ""
	return a.Canonical() == b.Canonical()
}

// Ecosystem returns the package type, which is what trust weighting is scoped
// by.
//
// On node:12-alpine, Grype reported 90 apk findings against Trivy's 23, while
// the two agreed almost exactly on npm — 45 against 44. A single trust weight
// per scanner cannot express that; the weight has to be per ecosystem.
func (p PURL) Ecosystem() string { return p.Type }

// IsZero reports whether this is the zero value, meaning no PURL was available.
//
// Not every scanner emits a PURL for every finding. A finding without one can
// still be reported, but cannot be correlated on exact identity — it falls to
// approximate matching, and to the uncorrelated category if that fails too.
func (p PURL) IsZero() bool { return p.Type == "" && p.Name == "" }
