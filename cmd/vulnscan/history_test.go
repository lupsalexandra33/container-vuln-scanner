package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

// minimalSession builds the smallest ScanSession that saveSession/loadSession
// and replaySession can round-trip. The payload is an empty JSON object rather
// than a real scanner fixture: history and diff care about session metadata
// (target, timestamps, tool list) and about whether replay succeeds, not about
// the specific findings inside, and every normalizer seen so far (osv.go
// included) unmarshals an empty object into zero findings without erroring.
//
// If this assumption is wrong for trivy-json or grype-json specifically, the
// fix is to point Payload at a real minimal fixture instead — the tests below
// don't depend on which.
func minimalSession(target string, startedAt time.Time) *model.ScanSession {
	return &model.ScanSession{
		ID:        "test-session",
		Target:    model.Target{Reference: target},
		StartedAt: startedAt,
		Tools: []model.ToolVersion{
			{Name: "trivy", Version: "0.74.0"},
		},
		Raw: []model.RawResult{
			{Scanner: "trivy", Format: "trivy-json", Payload: []byte(`{}`)},
		},
	}
}

func writeTestSession(t *testing.T, dir, filename string, s *model.ScanSession) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	if err := saveSession(path, s); err != nil {
		t.Fatalf("saving test session: %v", err)
	}
	return path
}

func TestHistoryListsSessionsMostRecentFirst(t *testing.T) {
	dir := t.TempDir()

	older := minimalSession("alpine:3.14", time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC))
	newer := minimalSession("alpine:3.14", time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC))

	writeTestSession(t, dir, "old.session", older)
	writeTestSession(t, dir, "new.session", newer)

	var stdout, stderr bytes.Buffer
	code := runHistory([]string{"-from", dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d: stderr=%s", code, stderr.String())
	}

	out := stdout.String()
	newIdx := indexOf(out, "new.session")
	oldIdx := indexOf(out, "old.session")
	if newIdx == -1 || oldIdx == -1 {
		t.Fatalf("expected both sessions listed, got:\n%s", out)
	}
	if newIdx > oldIdx {
		t.Errorf("expected the more recent session listed first, got:\n%s", out)
	}
}

// TestHistoryIgnoresNonSessionFiles is why discoverSessions tries to load
// every file rather than filtering by extension: a directory holding session
// files alongside results.json or sbom.json must not fail history just
// because most of what's there isn't a session.
func TestHistoryIgnoresNonSessionFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "results.json"), []byte(`[]`), 0o644); err != nil {
		t.Fatalf("writing unrelated file: %v", err)
	}

	writeTestSession(t, dir, "run.session", minimalSession("debian:11", time.Now()))

	var stdout, stderr bytes.Buffer
	code := runHistory([]string{"-from", dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d: stderr=%s", code, stderr.String())
	}
	if indexOf(stdout.String(), "run.session") == -1 {
		t.Errorf("expected the real session file to be listed, got:\n%s", stdout.String())
	}
}

func TestHistoryFiltersByTarget(t *testing.T) {
	dir := t.TempDir()

	writeTestSession(t, dir, "a.session", minimalSession("alpine:3.14", time.Now()))
	writeTestSession(t, dir, "b.session", minimalSession("debian:11", time.Now()))

	var stdout, stderr bytes.Buffer
	code := runHistory([]string{"-from", dir, "-target", "debian:11"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d: stderr=%s", code, stderr.String())
	}

	out := stdout.String()
	if indexOf(out, "b.session") == -1 {
		t.Errorf("expected the matching session listed, got:\n%s", out)
	}
	if indexOf(out, "a.session") != -1 {
		t.Errorf("expected the non-matching session excluded, got:\n%s", out)
	}
}

func TestHistoryReportsEmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := runHistory([]string{"-from", dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("an empty directory is not an error, want exit code 0, got %d", code)
	}
	if indexOf(stderr.String(), dir) == -1 {
		t.Errorf("expected a message naming the empty directory, got:\n%s", stderr.String())
	}
}

// indexOf is a tiny substring search, matching the style already used by
// other _test.go files in this package rather than pulling in strings.Contains
// with an extra import just for tests.
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
