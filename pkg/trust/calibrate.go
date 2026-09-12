package trust

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

// ScannerMetrics is what a scanner did across a set of consolidated findings.
//
// Precision and coverage are measured against weighted consensus, not against
// verified ground truth. Nobody checked these findings by hand, so a scanner
// that is right where the others are wrong scores badly here. That limitation
// is not a footnote — it bounds what the numbers can be used for. They are
// useful for spotting a scanner that behaves very differently from the rest on
// an ecosystem, and useless for declaring one correct.
type ScannerMetrics struct {
	Scanner   string
	Ecosystem string // empty for the aggregate across ecosystems

	// Reported is how many findings this scanner reported.
	Reported int

	// Agreed is how many of those at least one other scanner also reported.
	Agreed int

	// Missed is how many findings other scanners reported that this one did
	// not, counting only cases where it ran, was capable, and had data.
	Missed int

	// Unique is how many findings only this scanner reported, where another
	// capable scanner ran and did not.
	//
	// Being alone is not an error. On debian:11, nine of the ten findings only
	// Trivy reports use Debian tracker identifiers Grype does not carry — real
	// findings that consensus-based precision counts against it.
	Unique int

	// Excluded is how many findings this scanner had no opportunity to report:
	// it could not detect that class in that ecosystem, had no data for the
	// target, or did not run. These are kept out of both metrics.
	Excluded int
}

// Coverage is the share of the corroborated findings this scanner reported.
//
// The denominator counts only findings where this scanner could have reported —
// a scanner blind to an ecosystem is not penalised for silence there.
func (m ScannerMetrics) Coverage() float64 {
	opportunities := m.Agreed + m.Missed
	if opportunities == 0 {
		return 0
	}
	return float64(m.Agreed) / float64(opportunities)
}

// Precision is the share of this scanner's reports that another scanner
// corroborated.
//
// Low precision here means "reports things others do not", which can mean a
// broader data source as easily as it can mean noise. It is a divergence
// measure, not a correctness one.
func (m ScannerMetrics) Precision() float64 {
	if m.Reported == 0 {
		return 0
	}
	return float64(m.Agreed) / float64(m.Reported)
}

// Calibration is the result of measuring every scanner over a set of findings.
type Calibration struct {
	Overall      []ScannerMetrics
	ByEcosystem  map[string][]ScannerMetrics
	TotalFinding int
}

// Measure computes per-scanner metrics from consolidated findings.
//
// It reads the verdicts the correlator already recorded rather than re-deriving
// agreement, so the measurement and the confidence scores it is meant to
// validate rest on the same evidence.
func Measure(findings []model.ConsolidatedFinding) Calibration {
	overall := map[string]*ScannerMetrics{}
	byEco := map[string]map[string]*ScannerMetrics{}

	get := func(m map[string]*ScannerMetrics, scanner, ecosystem string) *ScannerMetrics {
		if _, ok := m[scanner]; !ok {
			m[scanner] = &ScannerMetrics{Scanner: scanner, Ecosystem: ecosystem}
		}
		return m[scanner]
	}

	for _, f := range findings {
		eco := f.Package.Ecosystem()
		if byEco[eco] == nil {
			byEco[eco] = map[string]*ScannerMetrics{}
		}

		reporters := len(f.ReportedBy())

		for _, v := range f.Verdicts {
			targets := []*ScannerMetrics{
				get(overall, v.Scanner, ""),
				get(byEco[eco], v.Scanner, eco),
			}

			for _, m := range targets {
				switch v.Participation {
				case model.Reported:
					m.Reported++
					if reporters > 1 {
						m.Agreed++
					} else if f.IsDisputed() {
						// Alone, and another capable scanner that ran did not
						// report it. This is the case consensus-based precision
						// punishes even when the finding is real.
						m.Unique++
					}

				case model.RanAndMissed:
					if reporters > 0 {
						m.Missed++
					}

				default:
					// NotCapable, NoData, DidNotRun: no opportunity to report,
					// so neither metric counts it.
					m.Excluded++
				}
			}
		}
	}

	c := Calibration{
		ByEcosystem:  map[string][]ScannerMetrics{},
		TotalFinding: len(findings),
	}
	for _, m := range overall {
		c.Overall = append(c.Overall, *m)
	}
	sort.Slice(c.Overall, func(i, j int) bool { return c.Overall[i].Scanner < c.Overall[j].Scanner })

	for eco, scanners := range byEco {
		var list []ScannerMetrics
		for _, m := range scanners {
			list = append(list, *m)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Scanner < list[j].Scanner })
		c.ByEcosystem[eco] = list
	}
	return c
}

// SuggestedWeight derives a weight from measured behaviour.
//
// Coverage and precision are combined evenly: a scanner that reports most of
// what others find and little that they do not is, on this evidence, the least
// surprising — which is the most that consensus without ground truth can say.
//
// The result is deliberately compressed into [0.5, 0.95]. Nothing measured here
// justifies removing a scanner from consideration or trusting one completely,
// and a raw score would imply a precision the method does not have.
func SuggestedWeight(m ScannerMetrics) float64 {
	if m.Reported == 0 && m.Missed == 0 {
		return 0 // no evidence either way
	}
	score := (m.Coverage() + m.Precision()) / 2
	return 0.5 + score*0.45
}

// Report renders a calibration as text.
func (c Calibration) Report(current Weights) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Calibration over %d consolidated findings\n", c.TotalFinding)
	fmt.Fprintln(&b, "\nMeasured against weighted consensus, not verified ground truth.")
	fmt.Fprintln(&b, "A scanner that is right where the others are wrong scores badly here.")

	fmt.Fprintf(&b, "\n%-10s %9s %9s %9s %8s %8s %9s %9s\n",
		"SCANNER", "REPORTED", "AGREED", "MISSED", "UNIQUE", "EXCL", "COVERAGE", "PRECISION")
	fmt.Fprintln(&b, strings.Repeat("-", 80))
	for _, m := range c.Overall {
		fmt.Fprintf(&b, "%-10s %9d %9d %9d %8d %8d %8.0f%% %8.0f%%\n",
			m.Scanner, m.Reported, m.Agreed, m.Missed, m.Unique, m.Excluded,
			m.Coverage()*100, m.Precision()*100)
	}

	ecos := make([]string, 0, len(c.ByEcosystem))
	for e := range c.ByEcosystem {
		if e != "" {
			ecos = append(ecos, e)
		}
	}
	sort.Strings(ecos)

	for _, eco := range ecos {
		fmt.Fprintf(&b, "\n  %s\n", eco)
		fmt.Fprintf(&b, "  %-10s %9s %9s %8s %9s %9s %8s %10s\n",
			"SCANNER", "REPORTED", "AGREED", "UNIQUE", "COVERAGE", "PRECISION", "CURRENT", "SUGGESTED")
		for _, m := range c.ByEcosystem[eco] {
			cur := current.For(m.Scanner, eco)
			sug := SuggestedWeight(m)
			flag := ""
			if sug > 0 && absDiff(cur, sug) > 0.15 {
				flag = "  <- differs"
			}
			fmt.Fprintf(&b, "  %-10s %9d %9d %8d %8.0f%% %8.0f%% %8.2f %10.2f%s\n",
				m.Scanner, m.Reported, m.Agreed, m.Unique,
				m.Coverage()*100, m.Precision()*100, cur, sug, flag)
		}
	}
	return b.String()
}

func absDiff(a, b float64) float64 {
	if a > b {
		return a - b
	}
	return b - a
}
