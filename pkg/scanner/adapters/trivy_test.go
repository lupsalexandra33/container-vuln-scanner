package adapters

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

func TestTrivyAdapter_Version(t *testing.T) {
	adapter := NewTrivyAdapter()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := adapter.Available(ctx); err != nil {
		t.Skip("trivy not available on system, skipping live version test")
	}

	ver, err := adapter.Version(ctx)
	if err != nil {
		t.Fatalf("unexpected error getting trivy version: %v", err)
	}

	if ver.Version == "" {
		t.Errorf("expected non-empty tool version")
	}

	t.Logf("Detected Trivy Version: %s, DB UpdatedAt: %s", ver.Version, ver.DatabaseTimestamp)
}

func TestTrivyAdapter_Scan(t *testing.T) {
	adapter := NewTrivyAdapter()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := adapter.Available(ctx); err != nil {
		t.Skip("trivy not available on system, skipping live scan test")
	}

	sbomPath, err := filepath.Abs("../../../testdata/fixtures/debian_11/sbom.json")
	if err != nil {
		t.Fatalf("failed to resolve sbom path: %v", err)
	}

	target := model.Target{SBOMPath: sbomPath}
	res, err := adapter.Scan(ctx, target)
	if err != nil {
		t.Fatalf("trivy scan failed: %v", err)
	}

	if len(res.Findings) == 0 {
		t.Errorf("expected findings from trivy scan, got 0")
	}

	t.Logf("Trivy scan successfully returned %d findings", len(res.Findings))
	if len(res.Findings) > 0 {
		f := res.Findings[0]
		t.Logf("Sample finding: ID=%s, Package=%s, Version=%s, Severity=%s",
			f.ID, f.PackageName, f.Version, f.Severity)
	}

	// Verify that scanning an invalid file returns an error (not a false-clean 0-finding result)
	badTarget := model.Target{SBOMPath: "/non/existent/path/sbom.json"}
	_, err = adapter.Scan(ctx, badTarget)
	if err == nil {
		t.Errorf("expected error when scanning non-existent target, got nil")
	} else {
		t.Logf("Correctly rejected non-existent target: %v", err)
	}
}
