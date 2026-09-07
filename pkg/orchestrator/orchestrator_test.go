package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/scanner"
)

type mockScanner struct {
	name         string
	caps         scanner.Capabilities
	versionDelay time.Duration
	scanDelay    time.Duration
	availableErr error
	versionErr   error
	scanErr      error
	scanResult   model.RawResult
}

func (m *mockScanner) Name() string { return m.name }
func (m *mockScanner) Capabilities() scanner.Capabilities { return m.caps }
func (m *mockScanner) Available(ctx context.Context) error { return m.availableErr }
func (m *mockScanner) Version(ctx context.Context) (model.ToolVersion, error) {
	if m.versionDelay > 0 {
		time.Sleep(m.versionDelay)
	}
	return model.ToolVersion{Name: m.name, Version: "1.0.0"}, m.versionErr
}
func (m *mockScanner) Scan(ctx context.Context, target model.Target) (model.RawResult, error) {
	if m.scanDelay > 0 {
		select {
		case <-ctx.Done():
			return model.RawResult{}, ctx.Err()
		case <-time.After(m.scanDelay):
		}
	}
	return m.scanResult, m.scanErr
}

func TestOrchestrator_Run(t *testing.T) {
	scanners := []scanner.Scanner{
		&mockScanner{
			name: "scanner-a",
			scanResult: model.RawResult{
				Payload: []byte(`{"result": "a"}`),
				Format:  "format-a",
			},
		},
		&mockScanner{
			name:         "scanner-b",
			availableErr: errors.New("not installed"),
		},
		&mockScanner{
			name:       "scanner-c",
			scanErr:    errors.New("scan failed randomly"),
		},
		&mockScanner{
			name:      "scanner-d",
			scanDelay: 50 * time.Millisecond,
			scanResult: model.RawResult{
				Payload: []byte(`{"result": "d"}`),
			},
		},
	}

	orc := New(scanners, WithWorkerCount(2))
	ctx := context.Background()
	target := model.Target{Reference: "test-image"}

	session, err := orc.Run(ctx, target, RunOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if session.ID == "" {
		t.Errorf("expected session ID to be set")
	}

	if len(session.Raw) != 4 {
		t.Fatalf("expected 4 raw results, got %d", len(session.Raw))
	}

	failed := session.ScannersFailed()
	if len(failed) != 2 {
		t.Errorf("expected 2 failed scanners, got %d", len(failed))
	}

	if msg, ok := failed["scanner-b"]; !ok || msg != "unavailable: not installed" {
		t.Errorf("unexpected failure message for scanner-b: %s", msg)
	}

	if msg, ok := failed["scanner-c"]; !ok || msg != "scan failed randomly" {
		t.Errorf("unexpected failure message for scanner-c: %s", msg)
	}

	// Verify successes
	for _, r := range session.Raw {
		if r.Scanner == "scanner-a" {
			if !r.Succeeded() || string(r.Payload) != `{"result": "a"}` {
				t.Errorf("scanner-a result unexpected: %+v", r)
			}
		}
		if r.Scanner == "scanner-d" {
			if !r.Succeeded() || string(r.Payload) != `{"result": "d"}` {
				t.Errorf("scanner-d result unexpected: %+v", r)
			}
			if r.Duration < 50*time.Millisecond {
				t.Errorf("scanner-d duration too short: %v", r.Duration)
			}
		}
	}
}

func TestOrchestrator_Selection(t *testing.T) {
	scanners := []scanner.Scanner{
		&mockScanner{name: "scanner-a"},
		&mockScanner{name: "scanner-b"},
	}

	orc := New(scanners)
	session, err := orc.Run(context.Background(), model.Target{}, RunOptions{Scanners: []string{"scanner-b"}})
	if err != nil {
		t.Fatal(err)
	}

	if len(session.Raw) != 1 || session.Raw[0].Scanner != "scanner-b" {
		t.Errorf("expected only scanner-b to run, got: %+v", session.Raw)
	}
}

func TestOrchestrator_Timeout(t *testing.T) {
	scanners := []scanner.Scanner{
		&mockScanner{
			name:      "slow-scanner",
			scanDelay: 100 * time.Millisecond,
		},
	}

	// Set timeout much shorter than the scan delay
	orc := New(scanners, WithScannerTimeout(10*time.Millisecond))
	
	session, err := orc.Run(context.Background(), model.Target{}, RunOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if len(session.Raw) != 1 {
		t.Fatalf("expected 1 result")
	}

	res := session.Raw[0]
	if res.Succeeded() {
		t.Errorf("expected slow-scanner to fail due to timeout")
	}
	if res.Err != context.DeadlineExceeded.Error() {
		t.Errorf("expected deadline exceeded error, got: %v", res.Err)
	}
}

func TestOrchestrator_Capabilities(t *testing.T) {
	scanners := []scanner.Scanner{
		&mockScanner{
			name: "cloud-scanner",
			caps: scanner.Capabilities{RequiresNetwork: true, Classes: []model.FindingClass{model.ClassVulnerability}},
		},
		&mockScanner{
			name: "local-misconfig",
			caps: scanner.Capabilities{RequiresNetwork: false, Classes: []model.FindingClass{model.ClassMisconfiguration}},
		},
		&mockScanner{
			name: "local-vuln",
			caps: scanner.Capabilities{RequiresNetwork: false, Classes: []model.FindingClass{model.ClassVulnerability}},
		},
	}

	orc := New(scanners)

	// Test Offline Mode
	session, err := orc.Run(context.Background(), model.Target{}, RunOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(session.Raw) != 2 {
		t.Errorf("expected 2 local scanners to run, got %d", len(session.Raw))
	}
	for _, r := range session.Raw {
		if r.Scanner == "cloud-scanner" {
			t.Errorf("cloud-scanner should not have run in offline mode")
		}
	}

	// Test Class Filtering
	session2, err := orc.Run(context.Background(), model.Target{}, RunOptions{Classes: []model.FindingClass{model.ClassMisconfiguration}})
	if err != nil {
		t.Fatal(err)
	}
	if len(session2.Raw) != 1 || session2.Raw[0].Scanner != "local-misconfig" {
		t.Errorf("expected only local-misconfig to run, got %+v", session2.Raw)
	}
}
