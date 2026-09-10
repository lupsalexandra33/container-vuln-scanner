package layers

import (
	"testing"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

const sampleImageConfig = `{
  "history": [
    {
      "created_by": "/bin/sh -c #(nop) ADD file:abc in / "
    },
    {
      "created_by": "/bin/sh -c #(nop) CMD [\"bash\"]",
      "empty_layer": true
    },
    {
      "created_by": "RUN apt-get update && apt-get install -y curl"
    },
    {
      "created_by": "/bin/sh -c #(nop) COPY dir:123 in /app "
    }
  ],
  "rootfs": {
    "type": "layers",
    "diff_ids": [
      "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    ]
  }
}`

func TestProvenanceMatching(t *testing.T) {
	prov, err := NewProvenance([]byte(sampleImageConfig))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(prov.Layers) != 3 {
		t.Fatalf("expected 3 non-empty layers, got %d", len(prov.Layers))
	}

	if prov.Layers[0].Instruction != "ADD file:abc in /" {
		t.Errorf("unexpected layer 0 instruction: %s", prov.Layers[0].Instruction)
	}
	if prov.Layers[1].Instruction != "RUN apt-get update && apt-get install -y curl" {
		t.Errorf("unexpected layer 1 instruction: %s", prov.Layers[1].Instruction)
	}
	if prov.Layers[2].Instruction != "COPY dir:123 in /app" {
		t.Errorf("unexpected layer 2 instruction: %s", prov.Layers[2].Instruction)
	}

	findings := []model.Finding{
		{
			Location: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
			Package:  model.PURL{Type: "deb", Name: "curl"},
		},
	}

	origin := prov.Resolve(findings)
	if origin == nil {
		t.Fatal("expected origin, got nil")
	}
	if origin.LayerIndex != 1 {
		t.Errorf("expected layer index 1, got %d", origin.LayerIndex)
	}
	if origin.Instruction != "RUN apt-get update && apt-get install -y curl" {
		t.Errorf("expected RUN instruction, got %s", origin.Instruction)
	}
}

func TestProvenanceEcosystemFallback(t *testing.T) {
	prov, err := NewProvenance([]byte(sampleImageConfig))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	findings := []model.Finding{
		{
			Location: "",
			Package:  model.PURL{Type: "npm", Name: "express"},
		},
	}

	origin := prov.Resolve(findings)
	if origin == nil {
		t.Fatal("expected fallback origin, got nil")
	}
	if origin.LayerIndex != 2 {
		t.Errorf("expected layer index 2 for app package, got %d", origin.LayerIndex)
	}
}
