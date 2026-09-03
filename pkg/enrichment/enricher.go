package enrichment

import (
	"context"
	"strings"
	"sync"
)

// Enricher orchestrates KEV and EPSS lookups with local caching.
type Enricher struct {
	kevClient  *KEVClient
	epssClient *EPSSClient

	mu        sync.RWMutex
	kevLookup map[string]KEVRecord
}

func NewEnricher(cacheDir string) (*Enricher, error) {
	cache, err := NewDiskCache(cacheDir)
	if err != nil {
		return nil, err
	}

	return &Enricher{
		kevClient:  NewKEVClient(cache, ""),
		epssClient: NewEPSSClient(cache, ""),
	}, nil
}

// EnrichAll enriches vulnerability identifiers. Non-CVE identifiers are skipped
// since KEV and EPSS feeds only support CVE mappings.
func (en *Enricher) EnrichAll(ctx context.Context, identifiers []string) (map[string]ThreatData, error) {
	var cves []string
	for _, id := range identifiers {
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			cves = append(cves, strings.ToUpper(id))
		}
	}

	// Fetch KEV catalog once into memory if not already cached
	en.mu.Lock()
	if en.kevLookup == nil {
		lookup, err := en.kevClient.FetchMap(ctx)
		if err != nil {
			en.mu.Unlock()
			return nil, err
		}
		en.kevLookup = lookup
	}
	en.mu.Unlock()

	epssMap, err := en.epssClient.FetchScores(ctx, cves)
	if err != nil {
		return nil, err
	}

	en.mu.RLock()
	defer en.mu.RUnlock()

	result := make(map[string]ThreatData, len(cves))
	for _, cve := range cves {
		data := epssMap[cve]
		data.CVE = cve

		if record, exists := en.kevLookup[cve]; exists {
			data.InKEV = true
			data.KEVDetails = &record
		}
		result[cve] = data
	}

	return result, nil
}

