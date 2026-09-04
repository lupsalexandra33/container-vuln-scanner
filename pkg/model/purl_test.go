package model

import "testing"

func TestParsePURL(t *testing.T) {
	tests := []struct {
		name          string
		raw           string
		wantType      string
		wantNamespace string
		wantName      string
		wantVersion   string
		wantErr       bool
	}{
		// Both of these are copied verbatim from testdata/fixtures.
		{
			name:          "trivy debian package",
			raw:           "pkg:deb/debian/apt@2.2.4?arch=amd64&distro=debian-11.11",
			wantType:      "deb",
			wantNamespace: "debian",
			wantName:      "apt",
			wantVersion:   "2.2.4",
		},
		{
			name:          "grype debian package with encoded plus and upstream qualifier",
			raw:           "pkg:deb/debian/libdb5.3@5.3.28%2Bdfsg1-0.8?arch=amd64&distro=debian-11.11&upstream=db5.3",
			wantType:      "deb",
			wantNamespace: "debian",
			wantName:      "libdb5.3",
			wantVersion:   "5.3.28+dfsg1-0.8", // %2B decoded back to '+'
		},

		{
			name:        "no namespace",
			raw:         "pkg:npm/lodash@4.17.21",
			wantType:    "npm",
			wantName:    "lodash",
			wantVersion: "4.17.21",
		},
		{
			name:          "multi-segment namespace",
			raw:           "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
			wantType:      "maven",
			wantNamespace: "org.apache.commons",
			wantName:      "commons-lang3",
			wantVersion:   "3.12.0",
		},
		{
			name:          "no version",
			raw:           "pkg:apk/alpine/musl",
			wantType:      "apk",
			wantNamespace: "alpine",
			wantName:      "musl",
			wantVersion:   "",
		},
		{
			name:          "type and namespace are lower-cased",
			raw:           "pkg:DEB/Debian/apt@2.2.4",
			wantType:      "deb",
			wantNamespace: "debian",
			wantName:      "apt",
			wantVersion:   "2.2.4",
		},
		{
			name:          "subpath is not part of the version",
			raw:           "pkg:golang/github.com/gin-gonic/gin@v1.9.0#internal/render",
			wantType:      "golang",
			wantNamespace: "github.com/gin-gonic",
			wantName:      "gin",
			wantVersion:   "v1.9.0",
		},

		{name: "empty", raw: "", wantErr: true},
		{name: "missing pkg prefix", raw: "deb/debian/apt@2.2.4", wantErr: true},
		{name: "no name segment", raw: "pkg:deb", wantErr: true},
		{name: "empty type", raw: "pkg:/debian/apt", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePURL(tt.raw)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParsePURL(%q) = %+v, want error", tt.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePURL(%q) returned unexpected error: %v", tt.raw, err)
			}
			if got.Type != tt.wantType {
				t.Errorf("type = %q, want %q", got.Type, tt.wantType)
			}
			if got.Namespace != tt.wantNamespace {
				t.Errorf("namespace = %q, want %q", got.Namespace, tt.wantNamespace)
			}
			if got.Name != tt.wantName {
				t.Errorf("name = %q, want %q", got.Name, tt.wantName)
			}
			if got.Version != tt.wantVersion {
				t.Errorf("version = %q, want %q", got.Version, tt.wantVersion)
			}
		})
	}
}

// TestPURLEqualAcrossScanners covers the case the correlator exists for: the
// same package reported by two scanners that write it differently.
func TestPURLEqualAcrossScanners(t *testing.T) {
	tests := []struct {
		name      string
		a, b      string
		wantEqual bool
	}{
		{
			name:      "encoded and literal plus are the same package",
			a:         "pkg:deb/debian/libdb5.3@5.3.28%2Bdfsg1-0.8?arch=amd64&distro=debian-11.11",
			b:         "pkg:deb/debian/libdb5.3@5.3.28+dfsg1-0.8?arch=amd64&distro=debian-11.11",
			wantEqual: true,
		},
		{
			name:      "upstream qualifier does not affect identity",
			a:         "pkg:deb/debian/libdb5.3@5.3.28-1?arch=amd64&distro=debian-11.11&upstream=db5.3",
			b:         "pkg:deb/debian/libdb5.3@5.3.28-1?arch=amd64&distro=debian-11.11",
			wantEqual: true,
		},
		{
			name:      "qualifier order does not affect identity",
			a:         "pkg:deb/debian/apt@2.2.4?arch=amd64&distro=debian-11.11",
			b:         "pkg:deb/debian/apt@2.2.4?distro=debian-11.11&arch=amd64",
			wantEqual: true,
		},
		{
			name:      "different architectures are different packages",
			a:         "pkg:deb/debian/apt@2.2.4?arch=amd64",
			b:         "pkg:deb/debian/apt@2.2.4?arch=arm64",
			wantEqual: false,
		},
		{
			name:      "same version in different distributions is not the same package",
			a:         "pkg:deb/debian/apt@2.2.4?distro=debian-11",
			b:         "pkg:deb/debian/apt@2.2.4?distro=debian-12",
			wantEqual: false,
		},
		{
			name:      "different versions are different",
			a:         "pkg:deb/debian/apt@2.2.4",
			b:         "pkg:deb/debian/apt@2.2.5",
			wantEqual: false,
		},
		{
			name:      "same name in different ecosystems is not the same package",
			a:         "pkg:deb/debian/openssl@1.1.1n",
			b:         "pkg:apk/alpine/openssl@1.1.1n",
			wantEqual: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := ParsePURL(tt.a)
			if err != nil {
				t.Fatalf("parsing a: %v", err)
			}
			b, err := ParsePURL(tt.b)
			if err != nil {
				t.Fatalf("parsing b: %v", err)
			}

			if got := a.Equal(b); got != tt.wantEqual {
				t.Errorf("Equal() = %v, want %v\n  a canonical: %s\n  b canonical: %s",
					got, tt.wantEqual, a.Canonical(), b.Canonical())
			}
		})
	}
}

func TestPURLCanonicalIsStable(t *testing.T) {
	// The canonical form is the correlation key, so it must be deterministic.
	// Go randomises map iteration order, which is exactly what sorting the
	// qualifier keys defends against.
	p, err := ParsePURL("pkg:deb/debian/apt@2.2.4?distro=debian-11&arch=amd64&upstream=apt")
	if err != nil {
		t.Fatal(err)
	}

	want := "pkg:deb/debian/apt@2.2.4?arch=amd64&distro=debian-11"
	for i := 0; i < 20; i++ {
		if got := p.Canonical(); got != want {
			t.Fatalf("Canonical() = %q on iteration %d, want %q", got, i, want)
		}
	}
}

func TestPURLSameArtifact(t *testing.T) {
	a, _ := ParsePURL("pkg:deb/debian/openssl@1.1.1n-0+deb11u5?arch=amd64")
	b, _ := ParsePURL("pkg:deb/debian/openssl@1.1.1t-0+deb11u1?arch=amd64")
	c, _ := ParsePURL("pkg:deb/debian/curl@7.74.0?arch=amd64")

	if !a.SameArtifact(b) {
		t.Error("same package at two versions should be the same artifact")
	}
	if a.Equal(b) {
		t.Error("same package at two versions should not be equal")
	}
	if a.SameArtifact(c) {
		t.Error("different packages should not be the same artifact")
	}
}

func TestPURLIsZero(t *testing.T) {
	var empty PURL
	if !empty.IsZero() {
		t.Error("the zero value should report IsZero")
	}

	p, _ := ParsePURL("pkg:deb/debian/apt@2.2.4")
	if p.IsZero() {
		t.Error("a parsed PURL should not report IsZero")
	}
}
