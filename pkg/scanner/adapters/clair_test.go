package adapters

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

func TestClairAdapter_Scan(t *testing.T) {
	pollCount := 0

	// Mock the Clair v4 HTTP API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/indexer/api/v1/index_report"):
			// 1. Submit for indexing
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"hash": "sha256:dummy"}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/indexer/api/v1/index_report/"):
			// 2. Poll for completion (simulate delay)
			if pollCount < 1 {
				pollCount++
				w.WriteHeader(http.StatusAccepted) // Still processing
				return
			}
			w.WriteHeader(http.StatusOK) // Complete
			w.Write([]byte(`{"state": "IndexFinished"}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/matcher/api/v1/vulnerability_report/"):
			// 3. Retrieve vulnerability report
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"vulnerabilities": {}}`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	adapter := NewClairAdapter(server.URL)
	adapter.pollInterval = 10 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	target := model.Target{Reference: "debian:11"}
	res, err := adapter.Scan(ctx, target)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if res.Format != "clair-json" {
		t.Errorf("Expected format clair-json, got %s", res.Format)
	}

	if !strings.Contains(string(res.Payload), "vulnerabilities") {
		t.Errorf("Expected vulnerabilities in payload, got %s", string(res.Payload))
	}
}
