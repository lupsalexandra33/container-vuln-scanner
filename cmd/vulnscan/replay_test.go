package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/trust"
)

// storedSession builds a session from the recorded fixtures, which is all
// replaySession needs — it never invokes a scanner, only re-reads what one
// produced. That is the whole point of the command, and it is what makes this
// testable without any tool installed.
func storedSession(t *testing.T, image string) *model.ScanSession {
	t.Helper()

	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures", image, name))
		if err != nil {
			t.Fatalf("reading fixture: %v", err)
		}
		return b
	}

	return &model.ScanSession{
		ID:     "test-session",
		Target: model.Target{Reference: image},
		Raw: []model.RawResult{
			{Scanner: "trivy", Format: "trivy-json", Payload: read("trivy.json")},
			{Scanner: "grype", Format: "grype-json", Payload: read("grype.json")},
		},
	}
}

// TestReplayIsDeterministic is the property the command exists to demonstrate:
// the same stored output, replayed twice, produces the same findings. Without
// it, `replay --verify` could report a difference that came from our own
// nondeterminism rather than from a change in the logic.
func TestReplayIsDeterministic(t *testing.T) {
	session := storedSession(t, "debian_11")
	weights := trust.DefaultWeights()

	first, _, _, err := replaySession(session, weights, io.Discard)
	if err != nil {
		t.Fatalf("first replay: %v", err)
	}
	second, _, _, err := replaySession(session, weights, io.Discard)
	if err != nil {
		t.Fatalf("second replay: %v", err)
	}

	if len(first) == 0 {
		t.Fatal("replay produced no findings")
	}
	if diffs := compareFindings(first, second); len(diffs) != 0 {
		t.Fatalf("two replays of the same session diverged:\n  %v", diffs)
	}
	t.Logf("%d findings reproduced identically", len(first))
}

// TestCompareFindingsDetectsDrift checks that the comparison would actually
// catch a regression. A verifier that reports "identical" regardless is worse
// than none, because it produces a green check for a property nobody measured.
func TestCompareFindingsDetectsDrift(t *testing.T) {
	session := storedSession(t, "debian_11")
	findings, _, _, err := replaySession(session, trust.DefaultWeights(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) < 2 {
		t.Fatal("need at least two findings for this test")
	}

	t.Run("severity change is reported", func(t *testing.T) {
		altered := append([]model.ConsolidatedFinding(nil), findings...)
		altered[0].Severity = model.SeverityCritical
		if findings[0].Severity == model.SeverityCritical {
			altered[0].Severity = model.SeverityLow
		}

		if diffs := compareFindings(findings, altered); len(diffs) == 0 {
			t.Error("a changed severity should be reported as a difference")
		}
	})

	t.Run("confidence change is reported", func(t *testing.T) {
		altered := append([]model.ConsolidatedFinding(nil), findings...)
		altered[0].Confidence = findings[0].Confidence / 2

		if diffs := compareFindings(findings, altered); len(diffs) == 0 {
			t.Error("a changed confidence should be reported as a difference")
		}
	})

	t.Run("a dropped finding is reported", func(t *testing.T) {
		if diffs := compareFindings(findings, findings[1:]); len(diffs) == 0 {
			t.Error("a missing finding should be reported as a difference")
		}
	})

	t.Run("an added finding is reported", func(t *testing.T) {
		if diffs := compareFindings(findings[1:], findings); len(diffs) == 0 {
			t.Error("an extra finding should be reported as a difference")
		}
	})
}

// TestCompareFindingsIsStable guards the report itself. A verifier whose output
// reorders between runs cannot be diffed, which is most of what it is for.
func TestCompareFindingsIsStable(t *testing.T) {
	session := storedSession(t, "debian_11")
	findings, _, _, err := replaySession(session, trust.DefaultWeights(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	altered := append([]model.ConsolidatedFinding(nil), findings[2:]...)
	first := compareFindings(findings, altered)

	for i := 0; i < 10; i++ {
		got := compareFindings(findings, altered)
		if len(got) != len(first) {
			t.Fatalf("run %d produced %d diffs, first produced %d", i, len(got), len(first))
		}
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("run %d differs at %d:\n  %s\n  %s", i, j, first[j], got[j])
			}
		}
	}
}

// TestReplayFailedScannerDoesNotCount checks that a scanner which failed at scan
// time is not replayed as having run. Replaying it would invent an opportunity
// to agree that never existed, and inflate confidence accordingly.
func TestReplayFailedScannerDoesNotCount(t *testing.T) {
	session := storedSession(t, "debian_11")
	session.Raw = append(session.Raw, model.RawResult{
		Scanner: "clair",
		Err:     "connection refused",
	})

	_, participants, _, err := replaySession(session, trust.DefaultWeights(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, p := range participants {
		if p.Name == "clair" {
			found = true
			if p.Ran {
				t.Error("a scanner that failed at scan time must not replay as having run")
			}
		}
	}
	if !found {
		t.Error("a failed scanner should still appear as a participant, so its absence is visible")
	}
}

// TestSessionRoundTrip checks that a session survives being written and read
// back. A stored session nobody can load is a record of nothing.
func TestSessionRoundTrip(t *testing.T) {
	original := storedSession(t, "debian_11")
	path := filepath.Join(t.TempDir(), "test.session")

	if err := saveSession(path, original); err != nil {
		t.Fatalf("saving: %v", err)
	}

	loaded, err := loadSession(path)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}

	if loaded.ID != original.ID {
		t.Errorf("id = %q, want %q", loaded.ID, original.ID)
	}
	if len(loaded.Raw) != len(original.Raw) {
		t.Fatalf("raw results = %d, want %d", len(loaded.Raw), len(original.Raw))
	}
	for i := range loaded.Raw {
		if !bytes.Equal(loaded.Raw[i].Payload, original.Raw[i].Payload) {
			t.Errorf("payload for %s did not survive the round trip", loaded.Raw[i].Scanner)
		}
	}

	// And the whole point: the reloaded session replays to the same findings.
	weights := trust.DefaultWeights()
	before, _, _, _ := replaySession(original, weights, io.Discard)
	after, _, _, _ := replaySession(loaded, weights, io.Discard)

	if diffs := compareFindings(before, after); len(diffs) != 0 {
		t.Errorf("a session replayed differently after a round trip:\n  %v", diffs)
	}
}

func TestLoadSessionRejectsUnknownVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.session")
	if err := os.WriteFile(path, []byte(`{"Version":999,"Session":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := loadSession(path); err == nil {
		t.Error("a session file from a version we do not understand must be refused, " +
			"not read on a guess")
	}
}
