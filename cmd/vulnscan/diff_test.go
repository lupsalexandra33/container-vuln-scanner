package main

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"
)

func TestDiffReportsNoDifferenceForIdenticalSessions(t *testing.T) {
	dir := t.TempDir()

	session := minimalSession("alpine:3.14", time.Now())
	oldPath := writeTestSession(t, dir, "a.session", session)
	newPath := writeTestSession(t, dir, "b.session", session)

	var stdout, stderr bytes.Buffer
	code := runDiff([]string{oldPath, newPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d: stderr=%s", code, stderr.String())
	}
	if indexOf(stdout.String(), "No differences") == -1 {
		t.Errorf("expected a no-differences message, got:\n%s", stdout.String())
	}
}

// TestDiffRejectsDifferentTargets is the case diff must refuse outright: two
// scans of different images would make every finding look "resolved" and
// "new" purely because the packages differ, not because anything actually
// changed between two scans of the same image over time.
func TestDiffRejectsDifferentTargets(t *testing.T) {
	dir := t.TempDir()

	oldPath := writeTestSession(t, dir, "a.session", minimalSession("alpine:3.14", time.Now()))
	newPath := writeTestSession(t, dir, "b.session", minimalSession("debian:11", time.Now()))

	var stdout, stderr bytes.Buffer
	code := runDiff([]string{oldPath, newPath}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2 for mismatched targets, got %d", code)
	}
	if indexOf(stderr.String(), "different targets") == -1 {
		t.Errorf("expected an error naming the mismatch, got:\n%s", stderr.String())
	}
}

func TestDiffRequiresTwoArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runDiff([]string{"only-one.session"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2 with one argument, got %d", code)
	}
}

func TestDiffErrorsOnMissingFile(t *testing.T) {
	dir := t.TempDir()
	validPath := writeTestSession(t, dir, "a.session", minimalSession("alpine:3.14", time.Now()))

	var stdout, stderr bytes.Buffer
	code := runDiff([]string{validPath, filepath.Join(dir, "does-not-exist.session")}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2 for a missing file, got %d", code)
	}
}
