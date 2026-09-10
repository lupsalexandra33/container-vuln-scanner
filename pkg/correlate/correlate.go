package correlate

import (
	"sort"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/layers"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/scanner"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/trust"
)

// Participant is one scanner considered during a scan, and what it was able to
// do.
//
// Correlation needs more than the findings themselves. When a scanner did not
// report a finding, the reason matters: it may have looked and disagreed, been
// incapable of detecting that class in that ecosystem, had no data for the
// target, or never run. Only the first is disagreement, and only the first two
// belong in a confidence denominator.
type Participant struct {
	Name         string
	Capabilities scanner.Capabilities

	// Ran reports whether the scanner completed. A scanner that failed or was
	// not selected has said nothing about anything.
	Ran bool

	// NoData reports that the scanner ran but had no vulnerability data for
	// this target.
	//
	// On alpine:3.14 Trivy returns zero findings because Alpine's secdb records
	// only fixes and stops receiving them past end of life. Grype returns 39.
	// Treating Trivy's silence as disagreement would be wrong; treating it as
	// a clean result would be worse.
	NoData bool

	// Weight is a fixed trust weight for this scanner, used when no weights
	// table is supplied. Zero is read as 1, so unweighted correlation degrades
	// to plain counting.
	//
	// Prefer CorrelateWith and a trust.Weights table. Agreement between the same
	// two scanners ranges from 91% on a supported distribution to none on one
	// past end of life, and a single value per scanner cannot express that.
	Weight float64
}

// weight returns the fixed trust weight, defaulting to 1.
func (p Participant) weight() float64 {
	if p.Weight <= 0 {
		return 1
	}
	return p.Weight
}

// Correlate groups findings that refer to the same vulnerability in the same
// package across scanners, and records where each participant stood.
//
// It is a pure function: the same findings and participants always produce the
// same output, in the same order. Correlation produces a key, and a key that
// changes between runs is not a key.
func Correlate(findings []model.Finding, participants []Participant) []model.ConsolidatedFinding {
	// Resolve aliases first. Scanners lead with different identifier schemes
	// for the same vulnerability, so grouping on the primary identifier alone
	// would split one finding in two and report agreement as disagreement.
	graph := newAliasGraph()
	refs := make([]model.VulnRef, 0, len(findings))
	for _, f := range findings {
		graph.add(f.Vulnerability)
		refs = append(refs, f.Vulnerability)
	}
	canonical := graph.canonicalIDs(refs)

	// Group by the pair (canonical identifier, canonical package).
	type group struct {
		key      string
		findings []model.Finding
		ids      []model.VulnID
	}
	groups := map[string]*group{}
	var order []string // insertion order, for deterministic output

	for _, f := range findings {
		key := correlationKey(f, canonical)
		g, seen := groups[key]
		if !seen {
			g = &group{key: key}
			groups[key] = g
			order = append(order, key)
		}
		g.findings = append(g.findings, f)
		for _, id := range f.Vulnerability.AllIDs() {
			if !containsID(g.ids, id) {
				g.ids = append(g.ids, id)
			}
		}
	}

	out := make([]model.ConsolidatedFinding, 0, len(groups))
	for _, key := range order {
		out = append(out, consolidate(groups[key].findings, groups[key].ids, participants))
	}
	return out
}

// CorrelateWith is Correlate with per-ecosystem trust weights.
//
// The weight is resolved per finding rather than per participant, because a
// scanner's reliability is not a property of the scanner alone. Trivy reads
// Debian's tracker directly and is authoritative on deb packages; on an Alpine
// release past end of life the same tool reports nothing at all. Resolving at
// consolidation time is what lets a single run apply both.
func CorrelateWith(
	findings []model.Finding,
	participants []Participant,
	weights trust.Weights,
) []model.ConsolidatedFinding {
	out := Correlate(findings, participants)

	for i := range out {
		ecosystem := out[i].Package.Ecosystem()
		for j := range out[i].Verdicts {
			out[i].Verdicts[j].Weight = weights.For(out[i].Verdicts[j].Scanner, ecosystem)
		}
		// Recompute now that the weights have changed. The verdicts themselves
		// are untouched: which scanner reported what does not depend on how
		// much any of them is trusted.
		out[i].Confidence = confidence(out[i])
	}
	return out
}

// CorrelateWithProvenance combines per-ecosystem trust weights with layer provenance.
func CorrelateWithProvenance(
	findings []model.Finding,
	participants []Participant,
	weights trust.Weights,
	prov *layers.Provenance,
) []model.ConsolidatedFinding {
	out := CorrelateWith(findings, participants, weights)
	if prov == nil {
		return out
	}

	for i := range out {
		var groupFindings []model.Finding
		for _, v := range out[i].Verdicts {
			if v.Finding != nil {
				groupFindings = append(groupFindings, *v.Finding)
			}
		}
		out[i].Origin = prov.Resolve(groupFindings)
	}
	return out
}

// correlationKey identifies the group a finding belongs to.
//
// A finding that cannot be correlated exactly — no parseable identifier, or no
// PURL — gets a key unique to itself, so that it stands alone rather than being
// merged with unrelated findings that happen to share the same absence. It is
// still reported; [2.2] gives these a second chance at approximate matching,
// and what survives that is surfaced as uncorrelated rather than dropped.
func correlationKey(f model.Finding, canonical map[string]model.VulnID) string {
	if !f.IsCorrelatable() {
		return "uncorrelatable|" + f.Scanner + "|" +
			f.Vulnerability.Primary.ID + "|" + f.PackageName + "|" + f.InstalledVersion
	}
	id := f.Vulnerability.PreferredID()
	if c, ok := canonical[id.ID]; ok {
		id = c
	}
	return id.ID + "|" + f.Package.Canonical()
}

// consolidate merges the findings in one group and records a verdict for every
// participant.
func consolidate(
	findings []model.Finding,
	ids []model.VulnID,
	participants []Participant,
) model.ConsolidatedFinding {
	first := findings[0]

	c := model.ConsolidatedFinding{
		Class:            first.Class,
		Vulnerability:    mergeAliases(ids),
		Package:          first.Package,
		InstalledVersion: first.InstalledVersion,
		Method:           methodFor(first),
	}

	reporters := map[string]*model.Finding{}
	for i := range findings {
		reporters[findings[i].Scanner] = &findings[i]
	}

	ecosystem := first.Package.Ecosystem()
	for _, p := range participants {
		c.Verdicts = append(c.Verdicts, verdictFor(p, ecosystem, first.Class, reporters))
	}

	c.Confidence = confidence(c)

	// Resolve the fields scanners disagree about, recording every rejected
	// value and the reason it was rejected. Disagreement is the normal case:
	// on the debian:11 fixtures, 145 of 222 findings carry severity ratings
	// from sources that do not agree.
	severity, sevConflict := ResolveSeverity(findings, ecosystem)
	fixState, versions, fixConflict := ResolveFixState(findings)

	c.Severity = severity
	c.FixState = fixState
	c.FixedVersions = versions

	if sevConflict != nil {
		c.Conflicts = append(c.Conflicts, *sevConflict)
	}
	if fixConflict != nil {
		c.Conflicts = append(c.Conflicts, *fixConflict)
	}
	c.Title, c.Description, c.References = mergeText(findings)
	c.Origin = originFrom(findings)
	return c
}

// verdictFor decides where one participant stood on one finding.
//
// The order of the checks matters. A scanner that did not run has said nothing,
// whatever its capabilities. A scanner that ran but cannot detect this class in
// this ecosystem has also said nothing — its silence is a fact about the tool,
// not about the finding. Only a capable scanner with data that still did not
// report has disagreed.
func verdictFor(
	p Participant,
	ecosystem string,
	class model.FindingClass,
	reporters map[string]*model.Finding,
) model.ScannerVerdict {
	v := model.ScannerVerdict{Scanner: p.Name, Weight: p.weight()}

	if f, reported := reporters[p.Name]; reported {
		v.Participation = model.Reported
		v.Finding = f
		return v
	}

	switch {
	case !p.Ran:
		v.Participation = model.DidNotRun
		v.Reason = "did not run"

	case !p.Capabilities.Detects(class, ecosystem):
		v.Participation = model.NotCapable
		v.Reason = "does not detect " + string(class) + " findings"
		if ecosystem != "" {
			v.Reason += " in " + ecosystem
		}

	case p.NoData:
		v.Participation = model.NoData
		v.Reason = "no vulnerability data for this target"

	default:
		v.Participation = model.RanAndMissed
	}
	return v
}

// confidence is weighted agreement among the participants whose silence carries
// information.
//
// A finding no capable scanner could contradict scores 1: there is no evidence
// against it. That is not the same as certainty, and the derivation is exposed
// through ConfidenceInputs so a reader can tell the two apart.
func confidence(c model.ConsolidatedFinding) float64 {
	in := c.ConfidenceInputs()
	if in.ParticipatingWeight == 0 {
		return 1
	}
	return in.AgreeingWeight / in.ParticipatingWeight
}

// methodFor records how a finding was assembled. Everything here is either an
// exact match or a finding that could not be correlated at all; approximate
// matching is [2.2].
func methodFor(f model.Finding) model.CorrelationMethod {
	if f.IsCorrelatable() {
		return model.CorrelatedExact
	}
	return model.Uncorrelated
}

// mergeText takes the first non-empty title and description, and the union of
// references.
func mergeText(findings []model.Finding) (title, description string, refs []string) {
	seen := map[string]bool{}
	for _, f := range findings {
		if title == "" {
			title = f.Title
		}
		if description == "" {
			description = f.Description
		}
		for _, r := range f.References {
			if !seen[r] {
				seen[r] = true
				refs = append(refs, r)
			}
		}
	}
	sort.Strings(refs)
	return title, description, refs
}

func originFrom(findings []model.Finding) *model.Origin {
	return originFromWithProvenance(findings, nil)
}

func originFromWithProvenance(findings []model.Finding, prov *layers.Provenance) *model.Origin {
	if prov != nil {
		return prov.Resolve(findings)
	}
	for _, f := range findings {
		if f.Location != "" {
			return &model.Origin{
				LayerDigest: f.Location,
				LayerIndex:  -1,
			}
		}
	}
	return nil
}
