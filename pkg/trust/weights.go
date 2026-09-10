package trust

import "strings"

// Weights assigns each scanner a trust value, scoped per ecosystem where the
// evidence justifies it.
//
// A single weight per scanner cannot express what the baseline measurements
// show. Trivy and Grype agree on 91% of findings on debian:11 and on 7% on
// node:12-alpine, and the difference is not that one tool got worse between
// images. Agreement depends on the ecosystem and on the state of the feed
// behind it:
//
//	deb, supported     120 vs 110, 91% agreement — both read the Debian tracker
//	npm                 44 vs 45,  near-total     — both read GHSA and OSV
//	apk, end of life     0 vs 39,  none           — Trivy's feed is silent,
//	                                                Grype falls back to NVD
//	generic              0 vs 41,  not comparable — only Grype catalogues these
//
// Weights are data rather than code so they can be adjusted without rebuilding,
// and every value carries the reasoning that produced it. A weight without a
// stated reason is indistinguishable from a guess.
type Weights struct {
	// Default applies to a scanner with no ecosystem-specific entry.
	Default map[string]float64

	// PerEcosystem[ecosystem][scanner] overrides Default for that pairing.
	PerEcosystem map[string]map[string]float64

	// Rationale records why each value is what it is, keyed by "scanner" or
	// "ecosystem/scanner".
	Rationale map[string]string
}

// For returns the weight to apply to a scanner in an ecosystem.
//
// An unknown scanner gets 1.0 rather than 0. A tool we have no opinion about
// should be counted normally, not silently ignored — zero would remove it from
// the confidence denominator entirely, which is a far stronger claim than "we
// have not calibrated this one".
func (w Weights) For(scanner, ecosystem string) float64 {
	scanner = strings.ToLower(scanner)
	ecosystem = strings.ToLower(ecosystem)

	if byScanner, ok := w.PerEcosystem[ecosystem]; ok {
		if v, ok := byScanner[scanner]; ok {
			return v
		}
	}
	if v, ok := w.Default[scanner]; ok {
		return v
	}
	return 1.0
}

// ReasonFor returns the recorded rationale for a weight, most specific first.
func (w Weights) ReasonFor(scanner, ecosystem string) string {
	scanner = strings.ToLower(scanner)
	ecosystem = strings.ToLower(ecosystem)

	if r, ok := w.Rationale[ecosystem+"/"+scanner]; ok {
		return r
	}
	if r, ok := w.Rationale[scanner]; ok {
		return r
	}
	return "no calibration recorded; treated as neutral"
}

// DefaultWeights returns the starting weights.
//
// Two inputs, as the coordinator suggested combining: adoption signals for a
// baseline, and the behaviour observed on the baseline image set for the
// ecosystem-specific adjustments.
//
// The values sit close together on purpose. Nothing measured here justifies a
// large spread between two mature scanners that agree on 91% of a supported
// distribution. The interesting differences are per ecosystem, not per tool,
// and a wide spread would encode a confidence in the ranking that the evidence
// does not support.
func DefaultWeights() Weights {
	return Weights{
		Default: map[string]float64{
			"trivy": 0.85,
			"grype": 0.85,
			"osv":   0.75,
			"clair": 0.75,
			"scout": 0.70,
		},

		PerEcosystem: map[string]map[string]float64{
			// Distribution packages. Both tools read the distribution's own
			// security tracker, which is authoritative about its backports —
			// the same reasoning that makes the distribution outrank NVD in
			// conflict resolution. Trivy edges ahead because it also surfaces
			// tracker entries with no CVE assigned.
			"deb": {"trivy": 0.90, "grype": 0.85, "osv": 0.55},
			"rpm": {"trivy": 0.90, "grype": 0.85, "osv": 0.55},

			// Alpine is where the two diverge most, and the reason cuts both
			// ways. Alpine's secdb records only fixes, so it goes silent past
			// end of life and Trivy reports nothing — a false negative. Grype
			// keeps reporting by matching upstream version ranges in NVD, which
			// catches real issues but cannot see backports — a false positive
			// risk. Neither is more trustworthy in general, so neither is
			// weighted above the other.
			"apk": {"trivy": 0.80, "grype": 0.80, "osv": 0.55},

			// Language ecosystems. All three read overlapping sources, and the
			// two we measured agree almost exactly: 44 against 45 on
			// node:12-alpine. OSV is level with them here — this is what it
			// covers well, unlike distribution packages.
			"npm":      {"trivy": 0.85, "grype": 0.85, "osv": 0.85},
			"pypi":     {"trivy": 0.85, "grype": 0.85, "osv": 0.85},
			"gem":      {"trivy": 0.85, "grype": 0.85, "osv": 0.85},
			"golang":   {"trivy": 0.85, "grype": 0.85, "osv": 0.85},
			"maven":    {"trivy": 0.85, "grype": 0.85, "osv": 0.85},
			"cargo":    {"trivy": 0.85, "grype": 0.85, "osv": 0.85},
			"composer": {"trivy": 0.85, "grype": 0.85, "osv": 0.85},

			// Compiled binaries, which Grype emits as pkg:generic. They are
			// identified by version detection rather than from a package
			// database, which is inherently less certain: a statically linked
			// library can carry a version string that does not reflect what was
			// actually compiled in. Only Grype catalogues these, so nothing
			// corroborates them either.
			"generic": {"grype": 0.65},
		},

		Rationale: map[string]string{
			"trivy": "widely adopted; prioritises distribution security feeds over generic sources",
			"grype": "widely adopted; falls back to NVD version matching where a distribution feed is silent",
			"osv":   "single well-maintained source, strong on language ecosystems and sparse on distribution packages",
			"clair": "distribution-focused and layer-indexed; not exercised in this project's baseline",
			"scout": "proprietary database; not independently verifiable from the fixtures",

			"deb/trivy": "reads the Debian Security Tracker directly, including issues with no CVE assigned — " +
				"surfaced ten TEMP-* identifiers on debian:11 that Grype does not carry",
			"deb/grype": "reads the same distribution feed; 91% agreement with Trivy on debian:11",
			"deb/osv": "osv.dev returned zero findings on debian:11, nginx:1.21 and alpine:3.14 — " +
				"it covers language ecosystems rather than distribution packages",

			"apk/trivy": "Alpine secdb records only fixes, so it reports nothing past end of life — " +
				"zero findings on alpine:3.14 against Grype's 39, a false negative " +
				"rather than a clean image",
			"apk/grype": "falls back to NVD upstream version ranges where secdb is silent, which catches " +
				"real issues but cannot account for backports",

			"npm/trivy": "GHSA and OSV are common ground; 44 findings against Grype's 45 on node:12-alpine",
			"npm/grype": "same sources, near-identical results",
			"npm/osv":   "this is what osv.dev covers well — 42 findings on node:12-alpine",

			"generic/grype": "compiled binaries, identified by version detection rather than a package " +
				"database; less certain than package metadata, and no other scanner corroborates it",
		},
	}
}

// Ecosystems returns the ecosystems that have specific weights, for reporting
// what has been calibrated.
func (w Weights) Ecosystems() []string {
	out := make([]string, 0, len(w.PerEcosystem))
	for e := range w.PerEcosystem {
		out = append(out, e)
	}
	return out
}

// Scanners returns the scanners that have a default weight.
func (w Weights) Scanners() []string {
	out := make([]string, 0, len(w.Default))
	for s := range w.Default {
		out = append(out, s)
	}
	return out
}
