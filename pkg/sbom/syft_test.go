package sbom

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/scanner"
)

func TestSyftGenerator_Generate(t *testing.T) {
	origRunTool := scanner.RunTool
	defer func() { scanner.RunTool = origRunTool }()

	scanner.RunTool = func(ctx context.Context, workingDir string, command string, args ...string) (scanner.ExecResult, error) {
		if command == "syft" && args[0] == "packages" {
			targetRef := args[1]

			dirMap := map[string]string{
				"debian:11": "debian_11",
			}

			dir, ok := dirMap[targetRef]
			if !ok {
				return scanner.ExecResult{ExitCode: 1, Stderr: []byte("unknown target")}, nil
			}

			// Return a fixture
			path := filepath.Join("..", "..", "testdata", "fixtures", dir, "sbom.cdx.json")
			b, err := os.ReadFile(path)
			if err != nil {
				return scanner.ExecResult{ExitCode: 1, Stderr: []byte(err.Error())}, nil
			}

			return scanner.ExecResult{Stdout: b, ExitCode: 0}, nil
		}
		return scanner.ExecResult{}, os.ErrNotExist
	}

	gen := NewSyftGenerator()

	target := model.Target{Reference: "debian:11"}
	sbom, err := gen.Generate(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(sbom) == 0 {
		t.Errorf("expected non-empty sbom")
	}
}
