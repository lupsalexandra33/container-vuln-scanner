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

func TestGrypeAdapter_Version(t *testing.T) {
	origRunTool := scanner.RunTool
	defer func() { scanner.RunTool = origRunTool }()

	scanner.RunTool = func(ctx context.Context, workingDir string, command string, args ...string) (scanner.ExecResult, error) {
		if command == "grype" && args[0] == "version" {
			return scanner.ExecResult{
				Stdout:   []byte(`{"version":"0.60.1"}`),
				ExitCode: 0,
			}, nil
		}
		if command == "grype" && args[0] == "db" {
			return scanner.ExecResult{
				Stdout:   []byte(`{"built":"2023-04-10T12:00:00Z"}`),
				ExitCode: 0,
			}, nil
		}
		return scanner.ExecResult{}, os.ErrNotExist
	}

	adapter := NewGrypeAdapter()
	ctx := context.Background()

	ver, err := adapter.Version(ctx)
	if err != nil {
		t.Fatalf("unexpected error getting grype version: %v", err)
	}

	if ver.Version != "0.60.1" {
		t.Errorf("expected version 0.60.1, got %s", ver.Version)
	}
	expectedTime, _ := time.Parse(time.RFC3339, "2023-04-10T12:00:00Z")
	if !ver.DBUpdatedAt.Equal(expectedTime) {
		t.Errorf("expected db time %v, got %v", expectedTime, ver.DBUpdatedAt)
	}
}

func TestGrypeAdapter_Scan(t *testing.T) {
	origRunTool := scanner.RunTool
	defer func() { scanner.RunTool = origRunTool }()

	scanner.RunTool = func(ctx context.Context, workingDir string, command string, args ...string) (scanner.ExecResult, error) {
		if command == "grype" {
			targetRef := args[0] // e.g. "debian:11"

			dirMap := map[string]string{
				"debian:11": "debian_11",
			}

			dir, ok := dirMap[targetRef]
			if !ok {
				return scanner.ExecResult{ExitCode: 1, Stderr: []byte("unknown target")}, nil
			}

			path := filepath.Join("..", "..", "..", "testdata", "fixtures", dir, "grype.json")
			b, err := os.ReadFile(path)
			if err != nil {
				return scanner.ExecResult{ExitCode: 1, Stderr: []byte(err.Error())}, nil
			}

			return scanner.ExecResult{Stdout: b, ExitCode: 0}, nil
		}
		return scanner.ExecResult{}, os.ErrNotExist
	}

	adapter := NewGrypeAdapter()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	target := model.Target{Reference: "debian:11"}
	res, err := adapter.Scan(ctx, target)
	if err != nil {
		t.Fatalf("grype scan failed: %v", err)
	}

	if len(res.Payload) == 0 {
		t.Errorf("expected payload, got empty")
	}
	if res.Format != "grype-json" {
		t.Errorf("expected format grype-json, got %s", res.Format)
	}
	if !res.Succeeded() {
		t.Errorf("expected scan to succeed, got err: %v", res.Err)
	}
}
