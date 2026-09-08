package correlate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

// Resolution decides which value to present where sources disagree, and records
// what it rejected.
//
// Disagreement is the normal case, not an edge case: on the debian:11 fixtures,
// 145 of 222 findings carry severity ratings from more than one source that do
// not agree. Silently taking the highest, or whichever the scanner happened to
// promote, is a decision made on the reader's behalf with no way to check it.
//
// Every resolution here records the values it did not choose and the reason it
// did not choose them.
type Resolution struct {
	Severity  model.Severity
	FixState  model.FixState
	Versions  []string
	Conflicts []model.Conflict
}

// distroForEcosystem maps a package ecosystem to the severity source that is
// authoritative for it.
//
// A distribution is authoritative about its own packages because it decides
// what a vulnerability means there. Debian and Red Hat backport security fixes
// without changing upstream version numbers, so NVD — which describes the
// upstream software — can call a package affected that the distribution has
// already patched.
var distroForEcosystem = map[string]string{
	"deb": "debian",
	"apk": "alpine",
	"rpm": "redhat",
}

// genericSources describe the upstream software rather than any particular
// package build. They are used as a fallback, never as an authority over a
// distribution's own assessment.
var genericSources = map[string]bool{
	"nvd":  true,
	"ghsa": true,
}

// ResolveSeverity picks the severity to present for a consolidated finding.
//
// The strategies are tried in order, and the first that applies wins. Each
// records why it applied.
func ResolveSeverity(findings []model.Finding, ecosystem string) (model.Severity, *model.Conflict) {
	ratings := collectRatings(findings)
	if len(ratings) == 0 {
		return model.SeverityUnknown, nil
	}

	values := map[string]string{}
	distinct := map[model.Severity]bool{}
	for source, sev := range ratings {
		values[source] = string(sev)
		distinct[sev] = true
	}

	// No disagreement: nothing to resolve.
	if len(distinct) == 1 {
		for _, sev := range ratings {
			return sev, nil
		}
	}

	severity, reason := resolveBySource(ratings, ecosystem)
	return severity, &model.Conflict{
		Kind:     model.ConflictSeverity,
		Values:   values,
		Resolved: string(severity),
		Reason:   reason,
	}
}

// resolveBySource applies the resolution strategies in order of authority.
func resolveBySource(ratings map[string]model.Severity, ecosystem string) (model.Severity, string) {
	// 1. The distribution that owns the package decides. It knows what it
	//    backported; nobody else does.
	if distro, ok := distroForEcosystem[ecosystem]; ok {
		if sev, present := ratings[distro]; present {
			return sev, fmt.Sprintf("%s is authoritative for %s packages", distro, ecosystem)
		}
	}

	// 2. Where distributions agree with each other and only a generic source
	//    dissents, the distributions win. On debian:11, CVE-2022-3715 in bash
	//    is rated MEDIUM by six independent distributions and HIGH by NVD
	//    alone. Six assessments of the same bug converging is stronger evidence
	//    than one that describes the upstream software rather than the package.
	if sev, count, ok := distroConsensus(ratings); ok {
		return sev, fmt.Sprintf("%d distribution sources agree; generic sources dissent", count)
	}

	// 3. No consensus among distributions either. Take the most severe of them,
	//    which errs toward surfacing rather than hiding.
	if sev, ok := mostSevereDistro(ratings); ok {
		return sev, "distributions disagree; taking the most severe distribution rating"
	}

	// 4. Only generic sources rated this. They describe the upstream software,
	//    which may or may not match the package as built here.
	sev := mostSevere(ratings)
	return sev, "no distribution rating available; using the most severe generic rating"
}

// distroConsensus reports the severity every distribution source agrees on,
// when there are at least two of them and they do agree.
func distroConsensus(ratings map[string]model.Severity) (model.Severity, int, bool) {
	var agreed model.Severity
	count := 0
	for source, sev := range ratings {
		if genericSources[source] {
			continue
		}
		if count == 0 {
			agreed = sev
		} else if sev != agreed {
			return "", 0, false
		}
		count++
	}
	if count < 2 {
		return "", 0, false
	}
	return agreed, count, true
}

// mostSevereDistro returns the highest rating among non-generic sources.
func mostSevereDistro(ratings map[string]model.Severity) (model.Severity, bool) {
	worst := model.SeverityUnknown
	found := false
	for source, sev := range ratings {
		if genericSources[source] {
			continue
		}
		found = true
		if sev.MoreSevereThan(worst) {
			worst = sev
		}
	}
	return worst, found
}

func mostSevere(ratings map[string]model.Severity) model.Severity {
	worst := model.SeverityUnknown
	for _, sev := range ratings {
		if sev.MoreSevereThan(worst) {
			worst = sev
		}
	}
	return worst
}

// collectRatings gathers every source's severity across all the scanners that
// reported this finding.
//
// Where two scanners quote the same source differently — which happens, since
// they snapshot vendor feeds at different times — the more severe reading is
// kept, so a disagreement is never resolved by silently discarding the worse
// half of it.
func collectRatings(findings []model.Finding) map[string]model.Severity {
	out := map[string]model.Severity{}
	for _, f := range findings {
		for _, r := range f.Severities {
			if r.Severity == model.SeverityUnknown {
				continue
			}
			if existing, seen := out[r.Source]; !seen || r.Severity.MoreSevereThan(existing) {
				out[r.Source] = r.Severity
			}
		}
	}
	return out
}

// ResolveFixState picks the fix state to present.
//
// A concrete fix outranks everything: if any source names a version that fixes
// this, that is actionable and the others are not. Below that, the states are
// ordered by how much they constrain what the reader can do.
func ResolveFixState(findings []model.Finding) (model.FixState, []string, *model.Conflict) {
	states := map[string]model.FixState{}
	var versions []string

	for _, f := range findings {
		if f.FixState == model.FixUnknown {
			continue
		}
		states[f.Scanner] = f.FixState
		if f.HasFix() && len(versions) == 0 {
			versions = append(versions, f.FixedVersions...)
		}
	}

	if len(states) == 0 {
		return model.FixUnknown, nil, nil
	}

	distinct := map[model.FixState]bool{}
	values := map[string]string{}
	for scanner, state := range states {
		distinct[state] = true
		values[scanner] = string(state)
	}

	resolved, reason := pickFixState(states)
	if len(distinct) == 1 {
		return resolved, versions, nil
	}
	return resolved, versions, &model.Conflict{
		Kind:     model.ConflictFixState,
		Values:   values,
		Resolved: string(resolved),
		Reason:   reason,
	}
}

// fixStatePriority orders fix states by how actionable they are. A named fix
// is the most useful thing a report can say; "not affected" is the next, since
// it closes the finding; the rest describe degrees of being stuck.
var fixStatePriority = map[model.FixState]int{
	model.FixAvailable:   5,
	model.FixNotAffected: 4,
	model.FixWontFix:     3,
	model.FixUnavailable: 2,
	model.FixUnknown:     1,
}

func pickFixState(states map[string]model.FixState) (model.FixState, string) {
	best := model.FixUnknown
	for _, state := range states {
		if fixStatePriority[state] > fixStatePriority[best] {
			best = state
		}
	}

	switch best {
	case model.FixAvailable:
		return best, "a fixed version was reported; a named fix outranks states that offer no action"
	case model.FixNotAffected:
		return best, "a source reports this package is not affected, which closes the finding"
	default:
		return best, "no source reported an available fix"
	}
}

// ConflictSummary renders the conflicts on a finding as a single line, for
// terminal output and log lines.
func ConflictSummary(conflicts []model.Conflict) string {
	if len(conflicts) == 0 {
		return ""
	}
	parts := make([]string, 0, len(conflicts))
	for _, c := range conflicts {
		sources := make([]string, 0, len(c.Values))
		for s := range c.Values {
			sources = append(sources, s)
		}
		sort.Strings(sources)

		pairs := make([]string, 0, len(sources))
		for _, s := range sources {
			pairs = append(pairs, s+"="+c.Values[s])
		}
		parts = append(parts, fmt.Sprintf("%s: %s -> %s (%s)",
			c.Kind, strings.Join(pairs, ", "), c.Resolved, c.Reason))
	}
	return strings.Join(parts, "; ")
}
