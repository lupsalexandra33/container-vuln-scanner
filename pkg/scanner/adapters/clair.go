package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/scanner"
)

// ClairAdapter implements the Scanner interface for the Clair vulnerability scanner service.
// It communicates with Clair over its HTTP API, handling the asynchronous indexing lifecycle.
type ClairAdapter struct {
	client       *http.Client
	apiURL       string
	pollInterval time.Duration
}

// NewClairAdapter creates a new Clair adapter pointing to the given API URL.
func NewClairAdapter(apiURL string) *ClairAdapter {
	return &ClairAdapter{
		client:       &http.Client{Timeout: 30 * time.Second},
		apiURL:       apiURL,
		pollInterval: 2 * time.Second,
	}
}

// Name returns the name of the scanner.
func (c *ClairAdapter) Name() string {
	return "clair"
}

// Version queries the Clair API for its version and database status.
// Currently returns a static version since Clair v4 doesn't have a single version endpoint,
// but ensures the API is responsive.
func (c *ClairAdapter) Version(ctx context.Context) (model.ToolVersion, error) {
	if err := c.Available(ctx); err != nil {
		return model.ToolVersion{}, err
	}
	return model.ToolVersion{
		Name:    "clair",
		Version: "v4 API",
	}, nil
}

// Capabilities declares that Clair detects vulnerabilities and requires network access.
func (c *ClairAdapter) Capabilities() scanner.Capabilities {
	return scanner.Capabilities{
		Classes:         []model.FindingClass{model.ClassVulnerability},
		RequiresNetwork: true, // Needs network to reach the service and pull manifests
	}
}

// Available checks if the Clair service is up and responding.
func (c *ClairAdapter) Available(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL+"/indexer/api/v1/index_state", nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("clair service unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("clair returned unexpected status: %s", resp.Status)
	}
	return nil
}

// Scan submits the target for indexing, polls until complete, and retrieves the vulnerability report.
func (c *ClairAdapter) Scan(ctx context.Context, target model.Target) (model.RawResult, error) {
	// 1. Submit for indexing
	manifestDigest, err := c.submitForIndexing(ctx, target.Reference)
	if err != nil {
		return model.RawResult{}, fmt.Errorf("failed to submit to clair indexer: %w", err)
	}

	// 2. Poll for completion
	if err := c.pollIndexing(ctx, manifestDigest); err != nil {
		return model.RawResult{}, fmt.Errorf("failed during indexing poll: %w", err)
	}

	// 3. Retrieve vulnerability report
	reportBytes, err := c.getVulnerabilityReport(ctx, manifestDigest)
	if err != nil {
		return model.RawResult{}, fmt.Errorf("failed to retrieve vulnerability report: %w", err)
	}

	return model.RawResult{
		Payload: reportBytes,
		Format:  "clair-json",
	}, nil
}

func (c *ClairAdapter) submitForIndexing(ctx context.Context, reference string) (string, error) {
	// In a real implementation, we would resolve the reference to an OCI manifest
	// and submit it to /indexer/api/v1/index_report.
	// For this adapter abstraction proof, we simulate the submission with a placeholder payload
	// or assume a helper service provides the manifest JSON.

	// Assuming `reference` is already a digest or we use a helper to construct the manifest request.
	// For demonstration of the async adapter loop, we use a dummy manifest submission.
	manifest := map[string]interface{}{
		"hash":   reference,
		"layers": []interface{}{},
	}
	b, _ := json.Marshal(manifest)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL+"/indexer/api/v1/index_report", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("indexer returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Hash string `json:"hash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	// Fallback to the reference if the dummy API didn't return a hash.
	if result.Hash == "" {
		return reference, nil
	}
	return result.Hash, nil
}

func (c *ClairAdapter) pollIndexing(ctx context.Context, digest string) error {
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL+"/indexer/api/v1/index_report/"+digest, nil)
			if err != nil {
				return err
			}

			resp, err := c.client.Do(req)
			if err != nil {
				return err
			}

			// If status is 200, indexing is complete
			if resp.StatusCode == http.StatusOK {
				resp.Body.Close()
				return nil
			}

			// If status is 202 or 404, still indexing
			if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusNotFound {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				return fmt.Errorf("unexpected indexer status %d: %s", resp.StatusCode, string(body))
			}
			resp.Body.Close()
		}
	}
}

func (c *ClairAdapter) getVulnerabilityReport(ctx context.Context, digest string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL+"/matcher/api/v1/vulnerability_report/"+digest, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("matcher returned %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}
