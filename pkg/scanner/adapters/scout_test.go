package adapters

import (
	"context"
	"testing"
	"time"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/scanner"
)

func TestScoutAdapter_RateLimitBackoff(t *testing.T) {
	origRunTool := scanner.RunTool
	defer func() { scanner.RunTool = origRunTool }()

	callCount := 0

	// Mock scanner execution to return rate limits for the first 2 calls, then success
	scanner.RunTool = func(ctx context.Context, workingDir string, command string, args ...string) (scanner.ExecResult, error) {
		callCount++

		if callCount <= 2 {
			// Simulate rate limit
			return scanner.ExecResult{
				ExitCode: 1,
				Stderr:   []byte("Error: 429 Too Many Requests - quota exhausted"),
			}, nil
		}

		// Simulate success on 3rd attempt
		return scanner.ExecResult{
			ExitCode: 0,
			Stdout:   []byte(`{"vulnerabilities": []}`),
		}, nil
	}

	adapter := NewScoutAdapter()
	adapter.baseDelay = 10 * time.Millisecond

	// Create context with short timeout to ensure tests run fast, but long enough for our backoff
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// In test mode, we might want a shorter base delay, but for now we'll let it sleep the 2s + 4s = 6s
	// The context timeout is 10s, so it should pass.
	start := time.Now()
	res, err := adapter.Scan(ctx, model.Target{Reference: "debian:11"})

	if err != nil {
		t.Fatalf("Expected scan to succeed after retries, got error: %v", err)
	}

	if callCount != 3 {
		t.Errorf("Expected 3 calls due to retries, got %d", callCount)
	}

	if res.Format != "scout-json" {
		t.Errorf("Expected scout-json format, got %s", res.Format)
	}

	elapsed := time.Since(start)
	if elapsed < 30*time.Millisecond {
		t.Errorf("Expected backoff to delay execution for at least 30ms, took %v", elapsed)
	}
}
