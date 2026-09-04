package store

import (
	"context"
	"testing"
	"time"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/enrichment"
)

func TestStore_SaveAndGet(t *testing.T) {
	s, err := New(":memory:")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	td := enrichment.ThreatData{
		CVE:   "CVE-2023-45853",
		InKEV: true,
		KEVDetails: &enrichment.KEVRecord{
			VulnerabilityName: "Zlib Buffer Overflow",
			DateAdded:         "2023-11-01",
			DueDate:           "2023-11-22",
			RequiredAction:    "Apply updates",
		},
		EPSSScore:  0.00150,
		Percentile: 0.48500,
		Enriched:   true,
		EnrichedAt: now,
	}

	if err := s.SaveThreatData(ctx, td); err != nil {
		t.Fatalf("SaveThreatData: %v", err)
	}

	got, found, err := s.GetThreatData(ctx, "CVE-2023-45853")
	if err != nil {
		t.Fatalf("GetThreatData: %v", err)
	}
	if !found {
		t.Fatalf("expected record to be found")
	}
	if got.EPSSScore != td.EPSSScore {
		t.Errorf("expected EPSSScore=%v, got %v", td.EPSSScore, got.EPSSScore)
	}
	if !got.InKEV || got.KEVDetails == nil || got.KEVDetails.VulnerabilityName != "Zlib Buffer Overflow" {
		t.Errorf("expected KEV details to round-trip, got %+v", got.KEVDetails)
	}

	// Upsert: saving again with different data should overwrite, not duplicate.
	td.EPSSScore = 0.99
	if err := s.SaveThreatData(ctx, td); err != nil {
		t.Fatalf("SaveThreatData (update): %v", err)
	}
	got, _, err = s.GetThreatData(ctx, "CVE-2023-45853")
	if err != nil {
		t.Fatalf("GetThreatData after update: %v", err)
	}
	if got.EPSSScore != 0.99 {
		t.Errorf("expected updated EPSSScore=0.99, got %v", got.EPSSScore)
	}
}

func TestStore_GetThreatData_NotFound(t *testing.T) {
	s, err := New(":memory:")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	_, found, err := s.GetThreatData(context.Background(), "CVE-0000-00000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Errorf("expected found=false for missing record")
	}
}

func TestStore_SaveAll_And_ListInKEV(t *testing.T) {
	s, err := New(":memory:")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	results := map[string]enrichment.ThreatData{
		"CVE-2023-45853": {
			CVE:        "CVE-2023-45853",
			InKEV:      true,
			KEVDetails: &enrichment.KEVRecord{VulnerabilityName: "Zlib Buffer Overflow"},
			Enriched:   true,
			EnrichedAt: now,
		},
		"CVE-2024-00001": {
			CVE:        "CVE-2024-00001",
			InKEV:      false,
			EPSSScore:  0.02,
			Enriched:   true,
			EnrichedAt: now,
		},
	}

	if err := s.SaveAll(ctx, results); err != nil {
		t.Fatalf("SaveAll: %v", err)
	}

	kevOnly, err := s.ListInKEV(ctx)
	if err != nil {
		t.Fatalf("ListInKEV: %v", err)
	}
	if len(kevOnly) != 1 || kevOnly[0].CVE != "CVE-2023-45853" {
		t.Errorf("expected exactly one KEV record for CVE-2023-45853, got %+v", kevOnly)
	}
}

func TestNew_MigrationIsIdempotent(t *testing.T) {
	// Opening the same on-disk database twice should not fail even though
	// migrations were already applied on the first open.
	dir := t.TempDir()
	dbPath := dir + "/enrichment.db"

	s1, err := New(dbPath)
	if err != nil {
		t.Fatalf("first New: %v", err)
	}
	s1.Close()

	s2, err := New(dbPath)
	if err != nil {
		t.Fatalf("second New (re-open, migrations should be no-ops): %v", err)
	}
	defer s2.Close()
}
