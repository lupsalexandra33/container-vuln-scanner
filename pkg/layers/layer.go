package layers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

// HistoryEntry mirrors OCI / Docker image config history entries.
type HistoryEntry struct {
	CreatedBy  string `json:"created_by"`
	EmptyLayer bool   `json:"empty_layer,omitempty"`
	Author     string `json:"author,omitempty"`
	Comment    string `json:"comment,omitempty"`
}

// ImageConfigFile represents the relevant parts of an OCI / Docker image JSON config.
type ImageConfigFile struct {
	History []HistoryEntry `json:"history"`
	RootFS  struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

// Layer represents a filesystem layer with its provenance.
type Layer struct {
	Index       int    `json:"index"`
	DiffID      string `json:"diff_id"`
	Instruction string `json:"instruction"`
	InBaseImage bool   `json:"in_base_image"`
}

// Provenance tracks the ordered layers of an image and provides attribution.
type Provenance struct {
	Layers       []Layer
	DiffIDToIdx  map[string]int
	BaseLayerCut int // layer indices <= BaseLayerCut are base image layers
}

// NewProvenance constructs a Provenance mapping from an OCI/Docker image configuration JSON.
func NewProvenance(configPayload []byte) (*Provenance, error) {
	var cfg ImageConfigFile
	if err := json.Unmarshal(configPayload, &cfg); err != nil {
		return nil, fmt.Errorf("parsing image config: %w", err)
	}

	p := &Provenance{
		DiffIDToIdx: make(map[string]int),
	}

	diffIdx := 0
	for _, h := range cfg.History {
		if h.EmptyLayer {
			continue
		}
		var diffID string
		if diffIdx < len(cfg.RootFS.DiffIDs) {
			diffID = cfg.RootFS.DiffIDs[diffIdx]
		}
		cleanInstr := cleanInstruction(h.CreatedBy)

		layer := Layer{
			Index:       diffIdx,
			DiffID:      diffID,
			Instruction: cleanInstr,
		}
		p.Layers = append(p.Layers, layer)
		if diffID != "" {
			p.DiffIDToIdx[normalizeDigest(diffID)] = diffIdx
		}
		diffIdx++
	}

	p.detectBaseCut()
	return p, nil
}

func (p *Provenance) detectBaseCut() {
	p.BaseLayerCut = 0
	for i, l := range p.Layers {
		instr := strings.ToUpper(l.Instruction)
		// Layer 0 is the initial base rootfs setup (usually ADD file:... in /).
		// Application instructions begin at the first COPY or subsequent ADD.
		if i > 0 && (strings.HasPrefix(instr, "COPY") || strings.HasPrefix(instr, "ADD")) {
			p.BaseLayerCut = i - 1
			break
		}
		p.BaseLayerCut = i
	}

	for i := range p.Layers {
		p.Layers[i].InBaseImage = p.Layers[i].Index <= p.BaseLayerCut
	}
}

// Resolve attributes findings to an Origin.
func (p *Provenance) Resolve(findings []model.Finding) *model.Origin {
	if p == nil || len(p.Layers) == 0 {
		return defaultOrigin(findings)
	}

	for _, f := range findings {
		if f.Location == "" {
			continue
		}
		key := normalizeDigest(f.Location)
		if idx, ok := p.DiffIDToIdx[key]; ok {
			layer := p.Layers[idx]
			return &model.Origin{
				LayerDigest: layer.DiffID,
				LayerIndex:  layer.Index,
				Instruction: layer.Instruction,
			}
		}
	}

	if len(findings) > 0 {
		first := findings[0]
		eco := strings.ToLower(first.Package.Ecosystem())
		switch eco {
		case "deb", "apk", "rpm":
			if len(p.Layers) > 0 {
				return &model.Origin{
					LayerDigest: p.Layers[0].DiffID,
					LayerIndex:  p.Layers[0].Index,
					Instruction: p.Layers[0].Instruction,
				}
			}
		case "npm", "pypi", "gem", "cargo", "golang":
			appIdx := p.BaseLayerCut + 1
			if appIdx >= len(p.Layers) {
				appIdx = len(p.Layers) - 1
			}
			if appIdx >= 0 && appIdx < len(p.Layers) {
				return &model.Origin{
					LayerDigest: p.Layers[appIdx].DiffID,
					LayerIndex:  p.Layers[appIdx].Index,
					Instruction: p.Layers[appIdx].Instruction,
				}
			}
		}
	}

	return defaultOrigin(findings)
}

func defaultOrigin(findings []model.Finding) *model.Origin {
	for _, f := range findings {
		if f.Location != "" {
			return &model.Origin{
				LayerDigest: f.Location,
				LayerIndex:  -1, // -1 means digest is known, but layer index/history was not provided
			}
		}
	}
	return nil
}

func normalizeDigest(d string) string {
	d = strings.TrimSpace(d)
	d = strings.TrimPrefix(d, "sha256:")
	return strings.ToLower(d)
}

func cleanInstruction(raw string) string {
	raw = strings.TrimSpace(raw)
	const nopPrefix = "#(nop) "
	if idx := strings.Index(raw, nopPrefix); idx != -1 {
		return strings.TrimSpace(raw[idx+len(nopPrefix):])
	}
	const shPrefix = "/bin/sh -c "
	if strings.HasPrefix(raw, shPrefix) {
		return strings.TrimSpace(strings.TrimPrefix(raw, shPrefix))
	}
	return raw
}
