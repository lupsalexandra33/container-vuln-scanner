package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLINormalizeFixtures(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		scanner string
		format  string
	}{
		{
			name:    "trivy debian_11",
			fixture: filepath.Join("..", "..", "testdata", "fixtures", "debian_11", "trivy.json"),
			scanner: "trivy",
			format:  "trivy-json",
		},
		{
			name:    "grype debian_11",
			fixture: filepath.Join("..", "..", "testdata", "fixtures", "debian_11", "grype.json"),
			scanner: "grype",
			format:  "grype-json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := os.Stat(tt.fixture); os.IsNotExist(err) {
				t.Skipf("fixture %s not found", tt.fixture)
			}

			var stdout, stderr bytes.Buffer
			args := []string{
				"-file", tt.fixture,
				"-scanner", tt.scanner,
				"-format", tt.format,
				"-out", "table",
				"-min-severity", "HIGH",
			}

			code := runNormalize(args, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("expected exit code 0, got %d: stderr=%s", code, stderr.String())
			}

			out := stdout.String()
			if !strings.Contains(out, "SEVERITY") || !strings.Contains(out, "Total:") {
				t.Errorf("expected table headers and total summary row, got:\n%s", out)
			}
		})
	}
}

// TestCLINormalizeStdin checks that reading from stdin works when -scanner
// and -format are given explicitly, since stdin has no filename to infer
// them from.
func TestCLINormalizeStdin(t *testing.T) {
	fixture := filepath.Join("..", "..", "testdata", "fixtures", "debian_11", "trivy.json")
	payload, err := os.ReadFile(fixture)
	if os.IsNotExist(err) {
		t.Skip("fixture not found")
	} else if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	var stdout, stderr bytes.Buffer
	args := []string{
		"-file", "-",
		"-scanner", "trivy",
		"-format", "trivy-json",
		"-out", "json",
	}

	stdin := bytes.NewReader(payload)
	code := runNormalize(args, stdin, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0 on stdin run, got %d: stderr=%s", code, stderr.String())
	}

	if !strings.Contains(stdout.String(), `"Vulnerability":`) {
		t.Errorf("expected JSON payload output, got:\n%s", stdout.String())
	}
}

// TestCLINormalizeStdinRequiresExplicitScannerAndFormat covers the case the
// PR's own first example got wrong: piping into "-file -" without -scanner
// and -format cannot be inferred, since there is no filename, and must fail
// with a clear error rather than the generic "cannot infer" message.
func TestCLINormalizeStdinRequiresExplicitScannerAndFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{
		"-file", "-",
	}

	stdin := strings.NewReader(`{}`)
	code := runNormalize(args, stdin, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2 when scanner/format are omitted for stdin, got %d", code)
	}

	if !strings.Contains(stderr.String(), "required when reading from stdin") {
		t.Errorf("expected an error message explaining stdin needs explicit -scanner/-format, got:\n%s", stderr.String())
	}
}

// TestCLINormalizeFilenameInference checks that -scanner and -format are
// correctly inferred from a real file path, without being told explicitly.
func TestCLINormalizeFilenameInference(t *testing.T) {
	fixture := filepath.Join("..", "..", "testdata", "fixtures", "debian_11", "trivy.json")
	if _, err := os.Stat(fixture); os.IsNotExist(err) {
		t.Skip("fixture not found")
	}

	var stdout, stderr bytes.Buffer
	args := []string{
		"-file", fixture,
		"-out", "table",
	}

	code := runNormalize(args, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0 with inferred scanner/format, got %d: stderr=%s", code, stderr.String())
	}

	if !strings.Contains(stdout.String(), "Normalized") {
		t.Errorf("expected normalized output using inferred trivy/trivy-json, got:\n%s", stdout.String())
	}
}

// TestCLINormalizeUninferrableFilename checks that a filename giving no clue
// about its scanner still requires -scanner/-format explicitly, with a
// message distinct from the stdin case.
func TestCLINormalizeUninferrableFilename(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{
		"-file", "dummy.json",
	}

	code := runNormalize(args, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2 for an uninferrable filename, got %d", code)
	}
	if strings.Contains(stderr.String(), "required when reading from stdin") {
		t.Errorf("a plain file path should not produce the stdin-specific error, got:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "cannot be inferred from the filename") {
		t.Errorf("expected the filename-specific error message, got:\n%s", stderr.String())
	}
}

func TestCLINormalizeFailOnThreshold(t *testing.T) {
	fixture := filepath.Join("..", "..", "testdata", "fixtures", "debian_11", "trivy.json")
	if _, err := os.Stat(fixture); os.IsNotExist(err) {
		t.Skip("fixture not found")
	}

	var stdout, stderr bytes.Buffer
	args := []string{
		"-file", fixture,
		"-fail-on", "CRITICAL",
	}

	code := runNormalize(args, nil, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected CI failure exit code 1, got %d", code)
	}

	if !strings.Contains(stderr.String(), "[FAIL]") {
		t.Errorf("expected failure message in stderr, got:\n%s", stderr.String())
	}
}

// TestCLINormalizeInvalidSeverity passes -scanner and -format explicitly so
// that this test actually exercises severity validation, rather than
// tripping the earlier "scanner/format required" check for an unrelated
// reason and passing on it by coincidence.
func TestCLINormalizeInvalidSeverity(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{
		"-file", "dummy.json",
		"-scanner", "trivy",
		"-format", "trivy-json",
		"-min-severity", "CRITIAL",
	}

	code := runNormalize(args, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected CLI syntax error code 2 for invalid severity, got %d", code)
	}
	if !strings.Contains(stderr.String(), "-min-severity") {
		t.Errorf("expected the error to name -min-severity specifically, got:\n%s", stderr.String())
	}
}
