package enrichment

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
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

// EnrichAll enriches vulnerability identifiers. If an external service fails,
// findings are marked unenriched with a warning rather than failing the scan.
func (en *Enricher) EnrichAll(ctx context.Context, identifiers []string) (map[string]ThreatData, error) {
	var cves []string
	for _, id := range identifiers {
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			cves = append(cves, strings.ToUpper(id))
		}
	}

	result := make(map[string]ThreatData, len(cves))
	if len(cves) == 0 {
		return result, nil
	}

	// 1. Attempt KEV lookup (fail-soft)
	var kevErr error
	en.mu.Lock()
	if en.kevLookup == nil {
		lookup, err := en.kevClient.FetchMap(ctx)
		if err != nil {
			kevErr = err
		} else {
			en.kevLookup = lookup
		}
	}
	en.mu.Unlock()

	// 2. Attempt EPSS lookup (fail-soft)
	epssMap, epssErr := en.epssClient.FetchScores(ctx, cves)

	en.mu.RLock()
	defer en.mu.RUnlock()

	// 3. Assemble results without hard erroring
	now := time.Now().UTC()
	for _, cve := range cves {
		var td ThreatData

		if epssMap != nil {
			if val, ok := epssMap[cve]; ok {
				td = val
			}
		}

		td.CVE = cve
		td.EnrichedAt = now

		var warnings []string
		if kevErr != nil {
			warnings = append(warnings, fmt.Sprintf("KEV lookup skipped: %v", kevErr))
		} else if en.kevLookup != nil {
			if record, exists := en.kevLookup[cve]; exists {
				td.InKEV = true
				td.KEVDetails = &record
			}
		}

		if epssErr != nil {
			warnings = append(warnings, fmt.Sprintf("EPSS lookup skipped: %v", epssErr))
		}

		if len(warnings) > 0 {
			td.Warning = strings.Join(warnings, "; ")
			// If both external feeds failed, mark as unenriched
			if kevErr != nil && epssErr != nil {
				td.Enriched = false
			} else {
				td.Enriched = true
			}
		} else {
			td.Enriched = true
		}

		result[cve] = td
	}

	return result, nil
}
