package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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
	// 1. Resolve the OCI manifest from Docker Hub
	manifestJSON, err := c.resolveDockerHubManifest(ctx, reference)
	if err != nil {
		return "", fmt.Errorf("resolving manifest: %w", err)
	}

	// 2. Submit the generated Clair manifest to the indexer
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL+"/indexer/api/v1/index_report", bytes.NewReader(manifestJSON))
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
		Hash         string `json:"hash"`
		ManifestHash string `json:"manifest_hash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if result.ManifestHash != "" {
		return result.ManifestHash, nil
	}
	return result.Hash, nil
}

// resolveDockerHubManifest fetches the layer digests from Docker Hub and constructs a Clair IndexReport.
func (c *ClairAdapter) resolveDockerHubManifest(ctx context.Context, reference string) ([]byte, error) {
	repo := reference
	tag := "latest"
	if parts := strings.Split(reference, ":"); len(parts) == 2 {
		repo = parts[0]
		tag = parts[1]
	}
	if !strings.Contains(repo, "/") {
		repo = "library/" + repo
	}

	// 1. Get anonymous pull token
	resp, err := http.Get(fmt.Sprintf("https://auth.docker.io/token?service=registry.docker.io&scope=repository:%s:pull", repo))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("image not found on docker hub (local images are not supported by Clair v4)")
	}

	var tokenResp struct{ Token string }
	json.NewDecoder(resp.Body).Decode(&tokenResp)
	token := tokenResp.Token

	// 2. Get manifest list
	req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://registry-1.docker.io/v2/%s/manifests/%s", repo, tag), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json")
	resp2, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp2.Body.Close()

	var manifestList struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
		// If it's not a list but a direct manifest, Config will be populated
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	json.NewDecoder(resp2.Body).Decode(&manifestList)

	var actualManifest = manifestList

	// If it was a list, find the amd64 manifest and fetch it
	if len(manifestList.Manifests) > 0 {
		var digest string
		for _, m := range manifestList.Manifests {
			if m.Platform.Architecture == "amd64" {
				digest = m.Digest
				break
			}
		}
		if digest == "" {
			digest = manifestList.Manifests[0].Digest
		}

		req3, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://registry-1.docker.io/v2/%s/manifests/%s", repo, digest), nil)
		req3.Header.Set("Authorization", "Bearer "+token)
		req3.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json")
		resp3, err := c.client.Do(req3)
		if err != nil {
			return nil, err
		}
		defer resp3.Body.Close()
		json.NewDecoder(resp3.Body).Decode(&actualManifest)
	}

	if actualManifest.Config.Digest == "" {
		return nil, fmt.Errorf("failed to extract config digest (image might not exist on Docker Hub)")
	}

	// 3. Construct Clair Manifest
	type ClairLayer struct {
		Hash    string              `json:"hash"`
		URI     string              `json:"uri"`
		Headers map[string][]string `json:"headers"`
	}
	type ClairManifest struct {
		Hash   string       `json:"hash"`
		Layers []ClairLayer `json:"layers"`
	}

	cm := ClairManifest{
		Hash:   actualManifest.Config.Digest,
		Layers: make([]ClairLayer, 0, len(actualManifest.Layers)),
	}

	headers := map[string][]string{
		"Authorization": {"Bearer " + token},
	}

	for _, l := range actualManifest.Layers {
		cm.Layers = append(cm.Layers, ClairLayer{
			Hash:    l.Digest,
			URI:     fmt.Sprintf("https://registry-1.docker.io/v2/%s/blobs/%s", repo, l.Digest),
			Headers: headers,
		})
	}

	return json.Marshal(cm)
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
