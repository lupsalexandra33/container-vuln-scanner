package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/correlate"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/layers"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/normalize"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/policy"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/report"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/scanner"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/trust"
)

// toolVersion is reported to the TUI/web dashboard header. If the binary
// already carries a real version (e.g. set via -ldflags in the release
// build, or a var in main.go), wire that in here instead of this placeholder.
const toolVersion = "dev"

// scanSource pairs a scanner name with the format its output is in.
type scanSource struct {
	scanner string
	format  string
	path    string
}

// knownFormats maps a scanner name to the normalizer format it produces.
var knownFormats = map[string]string{
	"trivy": "trivy-json",
	"grype": "grype-json",
	"osv":   "osv-json",
}

// capabilitiesFor returns what a scanner declares it can detect.
//
// These mirror the adapters in pkg/scanner/adapters. When the orchestrator
// lands, capabilities come from the live Scanner instances instead — this is
// the stand-in for reading recorded output, where no adapter is instantiated.
func capabilitiesFor(name string) scanner.Capabilities {
	base := []string{"deb", "apk", "npm", "pypi", "gem", "cargo"}
	caps := scanner.Capabilities{
		Classes:     []model.FindingClass{model.ClassVulnerability},
		Ecosystems:  base,
		AcceptsSBOM: true,
	}
	if name == "grype" {
		// Grype catalogues compiled binaries, which it emits as pkg:generic.
		// Trivy does not. This is the difference that lets correlation tell a
		// scanner that missed a finding from one that could not have seen it.
		caps.Ecosystems = append(base, "generic")
	}
	return caps
}

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		dir        = fs.String("from", "", "directory of recorded scanner output to correlate")
		format     = fs.String("out", "table", "output format: table, json, tui, web")
		showAll    = fs.Bool("all", false, "include findings only one scanner reported")
		minConf    = fs.Float64("min-confidence", 0, "hide findings below this confidence (0 to 1)")
		explain    = fs.Bool("explain-weights", false, "print the trust weight applied to each scanner and why")
		policyName = fs.String("policy", "", "policy to apply: advisory, balanced, strict (default: none)")
	)

	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: vulnscan scan --from <directory> [flags]")
		fmt.Fprintln(stderr, "\nCorrelates recorded output from several scanners for one image.")
		fmt.Fprintln(stderr, "\n--out tui and --out web render the same correlated findings")
		fmt.Fprintln(stderr, "interactively, with confidence and resolved conflicts included.")
		fmt.Fprintln(stderr, "\nIf --policy is set, the exit code reflects the policy decision")
		fmt.Fprintln(stderr, "against the correlated findings, regardless of --out.")
		fmt.Fprintln(stderr, "\nFlags:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *dir == "" {
		fs.Usage()
		return 2
	}

	sources, err := discoverSources(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if len(sources) == 0 {
		fmt.Fprintf(stderr, "error: no recognised scanner output in %s\n", *dir)
		fmt.Fprintln(stderr, "expected files named after the scanner, e.g. trivy.json, grype.json")
		return 2
	}

	// Attempt to load image layer provenance if an image config is present.
	var prov *layers.Provenance
	for _, configName := range []string{"config.json", "manifest.json", "image.json"} {
		if cfgData, err := os.ReadFile(filepath.Join(*dir, configName)); err == nil {
			if p, err := layers.NewProvenance(cfgData); err == nil {
				prov = p
				break
			}
		}
	}

	registry := normalize.NewRegistry()

	var (
		findings     []model.Finding
		participants []correlate.Participant
	)

	for _, src := range sources {
		payload, err := os.ReadFile(src.path)
		if err != nil {
			fmt.Fprintf(stderr, "warning: cannot read %s: %v\n", src.path, err)
			// A scanner whose output we cannot read did not run, as far as
			// correlation is concerned. Recording it as a participant that did
			// not run keeps its silence out of the confidence denominator.
			participants = append(participants, correlate.Participant{
				Name:         src.scanner,
				Capabilities: capabilitiesFor(src.scanner),
				Ran:          false,
			})
			continue
		}

		got, err := registry.Normalize(model.RawResult{
			Scanner: src.scanner,
			Format:  src.format,
			Payload: payload,
		})
		if err != nil {
			fmt.Fprintf(stderr, "warning: cannot normalise %s: %v\n", src.path, err)
			participants = append(participants, correlate.Participant{
				Name:         src.scanner,
				Capabilities: capabilitiesFor(src.scanner),
				Ran:          false,
			})
			continue
		}

		findings = append(findings, got...)
		participants = append(participants, correlate.Participant{
			Name:         src.scanner,
			Capabilities: capabilitiesFor(src.scanner),
			Ran:          true,
			// A scanner that ran and produced nothing has no data for this
			// target rather than a clean result. On alpine:3.14 Trivy returns
			// zero because Alpine's secdb records only fixes and stops
			// receiving them past end of life, while Grype returns 39.
			NoData: len(got) == 0,
		})
	}

	// Trust weights are resolved per ecosystem rather than per scanner. The
	// same two tools agree on 91% of findings on a supported distribution and
	// on none of them on one past end of life, so a single weight per scanner
	// would encode a ranking the evidence does not support.
	weights := trust.DefaultWeights()
	consolidated := correlate.CorrelateWithProvenance(findings, participants, weights, prov)

	// Every --out branch below produces its view of the same consolidated
	// findings and, on success, falls through to policy evaluation rather
	// than returning early: reporting and gating are separate jobs, and a
	// --policy decision must apply the same way no matter how the findings
	// were displayed. Only parse/usage errors (2) and render/encode failures
	// (1) return from inside the switch.
	switch *format {
	case "json":
		if code := writeScanJSON(stdout, stderr, consolidated); code != 0 {
			return code
		}
	case "table":
		writeScanTable(stdout, consolidated, participants, len(findings), *showAll, *minConf)
		if *explain {
			writeWeightExplanation(stdout, participants, consolidated, weights)
		}
	case "tui":
		rep := buildReport(*dir, consolidated, len(findings))
		if err := report.RenderTUI(rep); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
	case "web":
		rep := buildReport(*dir, consolidated, len(findings))
		if err := report.ServeDashboard(rep); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
	default:
		fmt.Fprintf(stderr, "error: unknown output format %q\n", *format)
		return 2
	}

	// A policy turns the report into a decision. Without one the command
	// reports and exits zero: describing an image and gating on it are separate
	// jobs, and a tool that silently starts failing builds because a default
	// changed is worse than one that has to be asked.
	if *policyName != "" {
		p, ok := policy.ByName(*policyName)
		if !ok {
			fmt.Fprintf(stderr, "error: unknown policy %q (available: %s)\n",
				*policyName, strings.Join(policy.Names(), ", "))
			return 2
		}
		decision := p.Evaluate(consolidated)
		fmt.Fprintln(stdout)
		fmt.Fprint(stdout, decision.Explain())

		// A policy failure and an execution failure must stay distinguishable:
		// one means the image is unsafe, the other means the tool did not work.
		// Conflating them either blocks builds on tool problems or ships images
		// because the scanner crashed.
		return decision.Outcome.ExitCode()
	}
	return 0
}

// buildReport assembles the report.Report that TUI and web output share with
// the JSON/SARIF exporters, so all four render the same correlated data
// through the same shape rather than each inventing its own view of it.
func buildReport(target string, consolidated []model.ConsolidatedFinding, rawCount int) report.Report {
	rep := report.Report{
		ToolName:        "vulnscan",
		ToolVersion:     toolVersion,
		Target:          target,
		GeneratedAt:     time.Now(),
		Findings:        consolidated,
		RawFindingCount: rawCount,
	}
	rep.CalculateSummary()
	return rep
}

// discoverSources finds recorded scanner output in a directory, identifying the
// scanner from the filename.
func discoverSources(dir string) ([]scanSource, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var sources []scanSource
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		stem := strings.TrimSuffix(name, ".json")
		format, known := knownFormats[stem]
		if !known {
			continue // sbom.json and anything else we do not normalise
		}
		sources = append(sources, scanSource{
			scanner: stem,
			format:  format,
			path:    filepath.Join(dir, e.Name()),
		})
	}

	// Stable order so the participant list, and therefore the verdict order on
	// every finding, does not depend on filesystem iteration order.
	sort.Slice(sources, func(i, j int) bool { return sources[i].scanner < sources[j].scanner })
	return sources, nil
}

func writeScanTable(
	w io.Writer,
	findings []model.ConsolidatedFinding,
	participants []correlate.Participant,
	rawCount int,
	showAll bool,
	minConfidence float64,
) {
	names := make([]string, 0, len(participants))
	for _, p := range participants {
		label := p.Name
		if !p.Ran {
			label += " (did not run)"
		} else if p.NoData {
			label += " (no data)"
		}
		names = append(names, label)
	}
	fmt.Fprintf(w, "Scanners: %s\n", strings.Join(names, ", "))
	fmt.Fprintf(w, "%d raw findings correlated into %d\n\n", rawCount, len(findings))

	shown := findings
	if !showAll || minConfidence > 0 {
		shown = shown[:0:0]
		for _, f := range findings {
			if minConfidence > 0 && f.Confidence < minConfidence {
				continue
			}
			if !showAll && f.IsSingleSource() && f.IsDisputed() {
				continue
			}
			shown = append(shown, f)
		}
	}

	// Most severe first, then least confident, so the findings most worth
	// looking at sit at the top and the contested ones are easy to spot.
	sort.SliceStable(shown, func(i, j int) bool {
		if shown[i].Severity.Rank() != shown[j].Severity.Rank() {
			return shown[i].Severity.Rank() > shown[j].Severity.Rank()
		}
		return shown[i].Confidence < shown[j].Confidence
	})

	fmt.Fprintf(w, "%-22s %-28s %-9s %-6s %s\n",
		"VULNERABILITY", "PACKAGE", "SEVERITY", "CONF", "SOURCES")
	fmt.Fprintln(w, strings.Repeat("-", 100))

	for _, f := range shown {
		pkg := f.Package.Name
		if pkg == "" {
			pkg = "-"
		}
		if v := f.InstalledVersion; v != "" {
			pkg += "@" + v
		}

		in := f.ConfidenceInputs()
		sources := fmt.Sprintf("%d/%d %s",
			in.AgreeingCount, in.ParticipatingCount, strings.Join(f.ReportedBy(), ","))
		if missed := f.RanAndMissedBy(); len(missed) > 0 {
			sources += " (missed by " + strings.Join(missed, ",") + ")"
		}
		if nodata := f.HadNoDataFor(); len(nodata) > 0 {
			sources += " (no data: " + strings.Join(nodata, ",") + ")"
		}

		fmt.Fprintf(w, "%-22s %-28s %-9s %-6.2f %s\n",
			truncate(f.Vulnerability.PreferredID().ID, 22),
			truncate(pkg, 28),
			f.Severity,
			f.Confidence,
			sources,
		)

		// Print layer origin attribution if resolved
		if f.Origin != nil && (f.Origin.Instruction != "" || f.Origin.LayerIndex >= 0 || f.Origin.LayerDigest != "") {
			var desc string
			if f.Origin.LayerIndex >= 0 {
				desc = fmt.Sprintf("layer #%d", f.Origin.LayerIndex)
				if f.Origin.Instruction != "" {
					desc += " (" + truncate(f.Origin.Instruction, 50) + ")"
				}
			} else if f.Origin.LayerDigest != "" {
				desc = "layer " + truncate(f.Origin.LayerDigest, 22)
			}
			if desc != "" {
				fmt.Fprintf(w, "%-22s   origin: %s\n", "", desc)
			}
		}

		// A resolved conflict is a decision made on the reader's behalf. It is
		// shown with its reason so that it can be checked rather than trusted.
		for _, c := range f.Conflicts {
			fmt.Fprintf(w, "%-22s   %s\n", "", correlate.ConflictSummary([]model.Conflict{c}))
		}
	}

	writeScanSummary(w, findings, len(shown))
}

func writeScanSummary(w io.Writer, findings []model.ConsolidatedFinding, shownCount int) {
	var agreed, disputed, singleSource, withConflicts, fixable int
	bySeverity := map[model.Severity]int{}

	for _, f := range findings {
		bySeverity[f.Severity]++
		if len(f.ReportedBy()) > 1 {
			agreed++
		}
		if f.IsDisputed() {
			disputed++
		}
		if f.IsSingleSource() {
			singleSource++
		}
		if len(f.Conflicts) > 0 {
			withConflicts++
		}
		if f.HasFix() {
			fixable++
		}
	}

	fmt.Fprintf(w, "\n%d shown of %d total\n", shownCount, len(findings))
	fmt.Fprintf(w, "  severity      %d critical, %d high, %d medium, %d low, %d negligible, %d unknown\n",
		bySeverity[model.SeverityCritical], bySeverity[model.SeverityHigh],
		bySeverity[model.SeverityMedium], bySeverity[model.SeverityLow],
		bySeverity[model.SeverityNegligible], bySeverity[model.SeverityUnknown])
	fmt.Fprintf(w, "  agreement     %d confirmed by more than one scanner, %d disputed, %d single source\n",
		agreed, disputed, singleSource)
	fmt.Fprintf(w, "  conflicts     %d findings had disagreeing sources, resolved and recorded\n", withConflicts)
	fmt.Fprintf(w, "  remediation   %d of %d have a fix available\n", fixable, len(findings))
}

// writeWeightExplanation prints the trust weight applied to each scanner in
// each ecosystem present in this scan, with the reasoning behind it.
//
// A confidence score derived from weights the reader cannot see is an
// assertion rather than a measurement. This is how the derivation is made
// checkable without reading the source.
func writeWeightExplanation(
	w io.Writer,
	participants []correlate.Participant,
	findings []model.ConsolidatedFinding,
	weights trust.Weights,
) {
	seen := map[string]bool{}
	var ecosystems []string
	for _, f := range findings {
		e := f.Package.Ecosystem()
		if e != "" && !seen[e] {
			seen[e] = true
			ecosystems = append(ecosystems, e)
		}
	}
	sort.Strings(ecosystems)

	if len(ecosystems) == 0 {
		return
	}

	fmt.Fprintln(w, "\nTrust weights applied")
	for _, e := range ecosystems {
		fmt.Fprintf(w, "\n  %s\n", e)
		for _, p := range participants {
			fmt.Fprintf(w, "    %-8s %.2f  %s\n",
				p.Name, weights.For(p.Name, e), weights.ReasonFor(p.Name, e))
		}
	}
	fmt.Fprintln(w)
}

func writeScanJSON(stdout, stderr io.Writer, findings []model.ConsolidatedFinding) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(findings); err != nil {
		fmt.Fprintf(stderr, "error: encoding output: %v\n", err)
		return 1
	}
	return 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
