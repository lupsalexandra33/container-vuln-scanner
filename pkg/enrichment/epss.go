package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const defaultEPSSURL = "https://api.first.org/data/v1/epss"

type EPSSClient struct {
	baseURL    string
	httpClient *http.Client
	cache      *DiskCache
}

func NewEPSSClient(cache *DiskCache, customURL string) *EPSSClient {
	endpoint := defaultEPSSURL
	if customURL != "" {
		endpoint = customURL
	}
	return &EPSSClient{
		baseURL:    endpoint,
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cache:      cache,
	}
}

// FetchScores queries EPSS scores for a slice of CVEs, hitting the cache first.
func (e *EPSSClient) FetchScores(ctx context.Context, cves []string) (map[string]ThreatData, error) {
	results := make(map[string]ThreatData)
	var missing []string

	for _, cve := range cves {
		var td ThreatData
		if e.cache != nil && e.cache.Read("epss_"+cve, 24*time.Hour, &td) {
			results[cve] = td
		} else {
			missing = append(missing, cve)
		}
	}

	if len(missing) == 0 {
		return results, nil
	}

	// Batch missing CVEs in chunks of 50 to avoid hitting URL length limits
	const chunkSize = 50
	for i := 0; i < len(missing); i += chunkSize {
		end := i + chunkSize
		if end > len(missing) {
			end = len(missing)
		}

		batch := missing[i:end]
		url := fmt.Sprintf("%s?cve=%s", e.baseURL, strings.Join(batch, ","))

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}

		resp, err := e.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("epss api request failed: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("epss api returned status %d", resp.StatusCode)
		}

		var epssResp EPSSResponse
		err = json.NewDecoder(resp.Body).Decode(&epssResp)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed decoding epss response: %w", err)
		}

		// First.org returns numeric scores as strings
		for _, item := range epssResp.Data {
			score, _ := strconv.ParseFloat(item.EPSS, 64)
			perc, _ := strconv.ParseFloat(item.Percentile, 64)

			td := ThreatData{
				CVE:        item.CVE,
				EPSSScore:  score,
				Percentile: perc,
				EnrichedAt: time.Now().UTC(),
			}

			results[item.CVE] = td
			if e.cache != nil {
				_ = e.cache.Write("epss_"+item.CVE, td)
			}
		}
	}

	return results, nil
}

