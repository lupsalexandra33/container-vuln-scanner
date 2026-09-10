package adapters

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/scanner"
)

func TestTrivyAdapter_Version(t *testing.T) {
	// Mock RunTool
	origRunTool := scanner.RunTool
	defer func() { scanner.RunTool = origRunTool }()

	scanner.RunTool = func(ctx context.Context, workingDir string, command string, args ...string) (scanner.ExecResult, error) {
		if command == "trivy" && args[0] == "version" {
			return scanner.ExecResult{
				Stdout:   []byte(`{"Version":"0.38.3","VulnerabilityDB":{"Version":2,"UpdatedAt":"2023-04-10T12:00:00Z"}}`),
				ExitCode: 0,
			}, nil
		}
		return scanner.ExecResult{}, os.ErrNotExist
	}

	adapter := NewTrivyAdapter()
	ctx := context.Background()

	ver, err := adapter.Version(ctx)
	if err != nil {
		t.Fatalf("unexpected error getting trivy version: %v", err)
	}

	if ver.Version != "0.38.3" {
		t.Errorf("expected version 0.38.3, got %s", ver.Version)
	}
	if ver.DBVersion != "2" {
		t.Errorf("expected DB version 2, got %s", ver.DBVersion)
	}
}

func TestTrivyAdapter_Scan(t *testing.T) {
	origRunTool := scanner.RunTool
	defer func() { scanner.RunTool = origRunTool }()

	scanner.RunTool = func(ctx context.Context, workingDir string, command string, args ...string) (scanner.ExecResult, error) {
		if command == "trivy" && args[0] == "image" {
			// Find what we are scanning
			// Assume target.Reference is "debian:11" mapping to "debian_11/trivy.json" in testdata
			targetRef := args[len(args)-1]

			dirMap := map[string]string{
				"debian:11":   "debian_11",
				"alpine:3.14": "alpine_3.14",
			}

			dir, ok := dirMap[targetRef]
			if !ok {
				return scanner.ExecResult{ExitCode: 1, Stderr: []byte("unknown target")}, nil
			}

			path := filepath.Join("..", "..", "..", "testdata", "fixtures", dir, "trivy.json")
			b, err := os.ReadFile(path)
			if err != nil {
				return scanner.ExecResult{ExitCode: 1, Stderr: []byte(err.Error())}, nil
			}

			return scanner.ExecResult{Stdout: b, ExitCode: 0}, nil
		}
		return scanner.ExecResult{}, os.ErrNotExist
	}

	adapter := NewTrivyAdapter()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test regular scan with findings
	target := model.Target{Reference: "debian:11"}
	res, err := adapter.Scan(ctx, target)
	if err != nil {
		t.Fatalf("trivy scan failed: %v", err)
	}
	if len(res.Payload) == 0 {
		t.Errorf("expected payload, got empty")
	}
	if res.Format != "trivy-json" {
		t.Errorf("expected format trivy-json, got %s", res.Format)
	}
	if res.NoData {
		t.Errorf("expected NoData=false for debian:11, got true")
	}
	if !res.Succeeded() {
		t.Errorf("expected scan to succeed, got err: %v", res.Err)
	}

	// Test alpine:3.14 which should trigger NoData
	target2 := model.Target{Reference: "alpine:3.14"}
	res2, err := adapter.Scan(ctx, target2)
	if err != nil {
		t.Fatalf("trivy scan failed: %v", err)
	}
	if !res2.NoData {
		t.Errorf("expected NoData=true for alpine:3.14, got false")
	}
}
