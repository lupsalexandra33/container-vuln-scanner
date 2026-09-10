package policy

import (
	"fmt"
	"strings"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

// Outcome is what a policy decides about a scan.
//
// Three outcomes rather than two. A binary pass/fail forces every finding to be
// either a blocker or invisible, and most are neither: on debian:11 all 243
// consolidated findings are unfixable, so a policy that fails on any critical
// one would block work the team has no way to do. Warn is where those go.
type Outcome string

const (
	Pass Outcome = "pass"
	Warn Outcome = "warn"
	Fail Outcome = "fail"
)

// severityRank orders outcomes so that the most severe decision wins when
// several rules match.
var outcomeRank = map[Outcome]int{Pass: 0, Warn: 1, Fail: 2}

// MoreSevereThan reports whether o is a stronger decision than other.
func (o Outcome) MoreSevereThan(other Outcome) bool {
	return outcomeRank[o] > outcomeRank[other]
}

// ExitCode maps an outcome to a process exit code.
//
// A policy failure and an execution failure are different things and must be
// distinguishable in a pipeline: one means the image is unsafe, the other means
// the tool did not work. Conflating them either blocks builds on tool problems
// or ships images because the scanner crashed.
func (o Outcome) ExitCode() int {
	if o == Fail {
		return 1
	}
	return 0
}

// Condition is what a rule matches on. A zero-valued field is not tested, so a
// rule with no conditions matches every finding.
type Condition struct {
	// MinSeverity matches findings at this severity or above.
	MinSeverity model.Severity

	// HasFix, when set, requires a fixed version to be available or absent.
	//
	// This is the field that separates a workable policy from one that gets
	// disabled: a finding with no fix is not something a build can be blocked
	// on, however severe it is.
	HasFix *bool

	// InKEV, when set, requires presence or absence in CISA's catalogue of
	// vulnerabilities confirmed to be exploited in real attacks. Where EPSS
	// predicts, this observes.
	InKEV *bool

	// MinEPSS matches findings at or above this exploitation probability.
	MinEPSS float64

	// MinConfidence matches findings the system is at least this confident
	// about. A finding one scanner reported and another capable scanner missed
	// is weaker evidence than one they agreed on, and a rule that blocks builds
	// should be able to say so.
	MinConfidence float64

	// Classes limits the rule to particular finding classes. Empty matches all.
	Classes []model.FindingClass

	// Ecosystems limits the rule to particular package ecosystems. Empty
	// matches all.
	Ecosystems []string
}

// Rule is a condition and the outcome it produces.
type Rule struct {
	Name      string
	Condition Condition
	Outcome   Outcome

	// Reason explains why this rule exists, and is reported when it matches.
	// A build blocked without a stated reason is a build the team works around.
	Reason string
}

// Matches reports whether a finding satisfies every condition on this rule.
func (r Rule) Matches(f model.ConsolidatedFinding) bool {
	c := r.Condition

	if c.MinSeverity != "" && f.Severity.Rank() < c.MinSeverity.Rank() {
		return false
	}
	if c.HasFix != nil && f.HasFix() != *c.HasFix {
		return false
	}
	if c.MinConfidence > 0 && f.Confidence < c.MinConfidence {
		return false
	}

	// Enrichment conditions cannot be evaluated when enrichment did not run.
	// Treating an unenriched finding as "not in KEV" would silently downgrade
	// it on the strength of data we never fetched.
	if c.InKEV != nil {
		if f.Enrichment == nil {
			return false
		}
		if f.Enrichment.InKEV != *c.InKEV {
			return false
		}
	}
	if c.MinEPSS > 0 {
		if f.Enrichment == nil || f.Enrichment.EPSSScore < c.MinEPSS {
			return false
		}
	}

	if len(c.Classes) > 0 && !containsClass(c.Classes, f.Class) {
		return false
	}
	if len(c.Ecosystems) > 0 && !containsString(c.Ecosystems, f.Package.Ecosystem()) {
		return false
	}
	return true
}

// Policy is an ordered set of rules and the decision they produce together.
type Policy struct {
	Name  string
	Rules []Rule

	// Exceptions suppress specific findings, each with a stated reason and an
	// expiry. An accepted risk that never expires is an accepted risk nobody
	// revisits.
	Exceptions []Exception
}

// Exception suppresses a finding a team has decided to accept.
type Exception struct {
	// VulnID is the identifier to suppress. Package narrows it to one package;
	// empty means every package.
	VulnID  string
	Package string

	Reason  string
	Expires string // RFC 3339 date; empty means it does not expire
}

// matches reports whether this exception applies to a finding.
func (e Exception) matches(f model.ConsolidatedFinding) bool {
	if e.VulnID == "" {
		return false
	}
	found := false
	for _, id := range f.Vulnerability.AllIDs() {
		if strings.EqualFold(id.ID, e.VulnID) {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	return e.Package == "" || e.Package == f.Package.Name
}

// Decision is the result of evaluating a policy over a scan.
type Decision struct {
	Outcome Outcome

	// Matches records every rule that fired, with the findings it fired on.
	Matches []RuleMatch

	// Suppressed records findings an exception silenced, so that accepting a
	// risk stays visible rather than making it disappear.
	Suppressed []SuppressedFinding

	// Counts summarises how many findings landed in each outcome.
	Counts map[Outcome]int
}

// RuleMatch is one rule and what it matched.
type RuleMatch struct {
	Rule     Rule
	Findings []model.ConsolidatedFinding
}

// SuppressedFinding pairs a silenced finding with the exception that silenced
// it.
type SuppressedFinding struct {
	Finding   model.ConsolidatedFinding
	Exception Exception
}

// Evaluate applies a policy to a set of consolidated findings.
//
// Every finding is tested against every rule, and the most severe outcome any
// rule produced for it is the one it takes. The overall decision is the most
// severe outcome across all findings.
//
// Rules are not first-match: a finding that is both critical-with-a-fix and in
// the KEV catalogue should be reported under both, because the reasons are
// different and a reader who dismisses one might not dismiss the other.
func (p Policy) Evaluate(findings []model.ConsolidatedFinding) Decision {
	d := Decision{
		Outcome: Pass,
		Counts:  map[Outcome]int{Pass: 0, Warn: 0, Fail: 0},
	}

	matchesByRule := make([]([]model.ConsolidatedFinding), len(p.Rules))

	for _, f := range findings {
		if ex, suppressed := p.suppression(f); suppressed {
			d.Suppressed = append(d.Suppressed, SuppressedFinding{Finding: f, Exception: ex})
			continue
		}

		worst := Pass
		for i, rule := range p.Rules {
			if !rule.Matches(f) {
				continue
			}
			matchesByRule[i] = append(matchesByRule[i], f)
			if rule.Outcome.MoreSevereThan(worst) {
				worst = rule.Outcome
			}
		}

		d.Counts[worst]++
		if worst.MoreSevereThan(d.Outcome) {
			d.Outcome = worst
		}
	}

	for i, rule := range p.Rules {
		if len(matchesByRule[i]) > 0 {
			d.Matches = append(d.Matches, RuleMatch{Rule: rule, Findings: matchesByRule[i]})
		}
	}
	return d
}

// suppression returns the exception that silences a finding, if any.
func (p Policy) suppression(f model.ConsolidatedFinding) (Exception, bool) {
	for _, e := range p.Exceptions {
		if e.matches(f) {
			return e, true
		}
	}
	return Exception{}, false
}

// Explain renders the decision as text, naming the rules that fired and how
// many findings each matched.
func (d Decision) Explain() string {
	var b strings.Builder

	fmt.Fprintf(&b, "Policy decision: %s\n", strings.ToUpper(string(d.Outcome)))
	fmt.Fprintf(&b, "  %d fail, %d warn, %d pass\n",
		d.Counts[Fail], d.Counts[Warn], d.Counts[Pass])

	if len(d.Suppressed) > 0 {
		fmt.Fprintf(&b, "  %d suppressed by exception\n", len(d.Suppressed))
	}

	for _, m := range d.Matches {
		fmt.Fprintf(&b, "\n  [%s] %s — %d findings\n",
			strings.ToUpper(string(m.Rule.Outcome)), m.Rule.Name, len(m.Findings))
		if m.Rule.Reason != "" {
			fmt.Fprintf(&b, "    %s\n", m.Rule.Reason)
		}
		// Name a few so the decision is actionable rather than a count.
		for i, f := range m.Findings {
			if i == 3 {
				fmt.Fprintf(&b, "    ... and %d more\n", len(m.Findings)-3)
				break
			}
			fmt.Fprintf(&b, "    %s  %s@%s\n",
				f.Vulnerability.PreferredID().ID, f.Package.Name, f.InstalledVersion)
		}
	}
	return b.String()
}

func containsClass(classes []model.FindingClass, want model.FindingClass) bool {
	for _, c := range classes {
		if c == want {
			return true
		}
	}
	return false
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// boolPtr is a helper for building conditions.
func boolPtr(b bool) *bool { return &b }
