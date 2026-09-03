package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const defaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type KEVClient struct {
	url        string
	httpClient *http.Client
	cache      *DiskCache
}

func NewKEVClient(cache *DiskCache, customURL string) *KEVClient {
	endpoint := defaultKEVURL
	if customURL != "" {
		endpoint = customURL
	}
	return &KEVClient{
		url:        endpoint,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		cache:      cache,
	}
}

// FetchMap pulls the CISA KEV catalog and returns a lookup table keyed by CVE ID.
func (k *KEVClient) FetchMap(ctx context.Context) (map[string]KEVRecord, error) {
	cacheKey := "cisa_kev_feed"
	var cachedData map[string]KEVRecord

	// CISA updates this feed daily at most, 24h cache is safe
	if k.cache != nil && k.cache.Read(cacheKey, 24*time.Hour, &cachedData) {
		return cachedData, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := k.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed fetching CISA KEV feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected KEV status code: %d", resp.StatusCode)
	}

	var catalog CisaCatalog
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("failed decoding KEV catalog: %w", err)
	}

	// Index by CVE for O(1) matching later
	lookup := make(map[string]KEVRecord, len(catalog.Vulnerabilities))
	for _, v := range catalog.Vulnerabilities {
		lookup[v.CveID] = KEVRecord{
			VulnerabilityName: v.VulnerabilityName,
			DateAdded:         v.DateAdded,
			DueDate:           v.DueDate,
			RequiredAction:    v.RequiredAction,
		}
	}

	if k.cache != nil {
		_ = k.cache.Write(cacheKey, lookup)
	}

	return lookup, nil
}
