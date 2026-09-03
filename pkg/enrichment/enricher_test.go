package enrichment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestEnricher(t *testing.T) {
	// Fake CISA KEV endpoint
	kevServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"catalogVersion": "1.0",
			"vulnerabilities": [
				{
					"cveID": "CVE-2023-45853",
					"vulnerabilityName": "Zlib Buffer Overflow",
					"dateAdded": "2023-11-01",
					"dueDate": "2023-11-22",
					"requiredAction": "Apply updates"
				}
			]
		}`))
	}))
	defer kevServer.Close()

	// Fake FIRST EPSS endpoint
	epssServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"status": "OK",
			"status-code": 200,
			"data": [
				{
					"cve": "CVE-2023-45853",
					"epss": "0.00150",
					"percentile": "0.48500",
					"date": "2026-09-02"
				}
			]
		}`))
	}))
	defer epssServer.Close()

	// Isolated temp cache for tests
	tmpDir, err := os.MkdirTemp("", "enrich_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	cache, _ := NewDiskCache(tmpDir)
	enricher := &Enricher{
		kevClient:  NewKEVClient(cache, kevServer.URL),
		epssClient: NewEPSSClient(cache, epssServer.URL),
	}

	res, err := enricher.EnrichAll(context.Background(), []string{"CVE-2023-45853", "TEMP-00000-01"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Make sure non-CVE IDs are filtered out
	if _, found := res["TEMP-00000-01"]; found {
		t.Errorf("expected non-CVE identifier to be omitted")
	}

	val, found := res["CVE-2023-45853"]
	if !found {
		t.Fatalf("expected CVE-2023-45853 in results")
	}

	if !val.InKEV {
		t.Errorf("expected InKEV=true, got false")
	}

	if val.EPSSScore != 0.00150 {
		t.Errorf("expected EPSS=0.00150, got %f", val.EPSSScore)
	}
}
