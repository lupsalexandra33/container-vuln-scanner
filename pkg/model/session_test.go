package model

import "testing"

func TestSessionScannerOutcomes(t *testing.T) {
	// The three outcomes that must stay distinct: a scanner that failed, one
	// that ran with no data for the target, and one that ran normally.
	// Conflating the first two with "found nothing" is the most common source
	// of silently wrong results.
	s := ScanSession{
		Raw: []RawResult{
			{Scanner: "trivy", NoData: true},
			{Scanner: "grype"},
			{Scanner: "clair", Err: "connection refused"},
		},
	}

	run := s.ScannersRun()
	if len(run) != 2 {
		t.Errorf("ScannersRun() = %v, want trivy and grype — a no-data scanner still ran", run)
	}

	failed := s.ScannersFailed()
	if len(failed) != 1 || failed["clair"] == "" {
		t.Errorf("ScannersFailed() = %v, want clair with a reason", failed)
	}

	if s.IsComplete() {
		t.Error("a session with a failed scanner is not complete")
	}
}

func TestRawResultSucceeded(t *testing.T) {
	// A scanner that exits non-zero because findings exist has not failed.
	// Only a recorded error means failure.
	if !(RawResult{Scanner: "trivy"}).Succeeded() {
		t.Error("a result with no error should count as succeeded")
	}
	if (RawResult{Scanner: "trivy", Err: "timeout"}).Succeeded() {
		t.Error("a result with an error should not count as succeeded")
	}
}
