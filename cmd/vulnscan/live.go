package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/correlate"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/normalize"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/orchestrator"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/sbom"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/scanner"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/scanner/adapters"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/trust"
)

// liveResult is what a live scan produces, in the same shape the recorded path
// produces so that both feed the identical reporting and policy code.
type liveResult struct {
	Findings     []model.ConsolidatedFinding
	Participants []correlate.Participant
	Session      *model.ScanSession
	RawCount     int
}

// availableScanners returns the adapters that can run right now.
//
// A scanner that is not installed is dropped here rather than being allowed to
// fail later, but the caller is told which ones were dropped: "trivy is not
// installed" and "trivy found nothing" are different facts, and a report that
// conflates them claims an image is cleaner than the evidence supports.
func availableScanners(ctx context.Context) (usable []scanner.Scanner, unavailable map[string]string) {
	clairURL := os.Getenv("CLAIR_URL")
	if clairURL == "" {
		clairURL = "http://localhost:6060"
	}

	all := []scanner.Scanner{
		adapters.NewTrivyAdapter(),
		adapters.NewGrypeAdapter(),
		adapters.NewClairAdapter(clairURL),
		adapters.NewScoutAdapter(),
		adapters.NewOSVAdapter(),
	}

	unavailable = map[string]string{}
	for _, s := range all {
		if err := s.Available(ctx); err != nil {
			unavailable[s.Name()] = err.Error()
			continue
		}
		usable = append(usable, s)
	}
	return usable, unavailable
}

// scanLive runs the scanners against a real image and correlates what they
// report.
//
// The pipeline after this point is the same one the recorded path uses. That is
// deliberate: if live and recorded scans went through different correlation
// code, the fixtures would stop being a faithful stand-in for a real run, and
// every test built on them would be testing something the tool does not do.
func scanLive(
	ctx context.Context,
	image string,
	weights trust.Weights,
	timeout time.Duration,
	stderr io.Writer,
) (*liveResult, error) {
	usable, unavailable := availableScanners(ctx)

	// Sorted so the warnings, and the participant list built from the same map
	// below, do not depend on map iteration order.
	unavailableNames := make([]string, 0, len(unavailable))
	for name := range unavailable {
		unavailableNames = append(unavailableNames, name)
	}
	sort.Strings(unavailableNames)

	for _, name := range unavailableNames {
		fmt.Fprintf(stderr, "warning: %s is unavailable and will be skipped\n", name)
	}
	if len(usable) == 0 {
		return nil, fmt.Errorf("no scanners available — install trivy or grype, or use --from with recorded output")
	}

	names := make([]string, 0, len(usable))
	for _, s := range usable {
		names = append(names, s.Name())
	}
	fmt.Fprintf(stderr, "Scanning %s with %s...\n", image, strings.Join(names, ", "))
	fmt.Fprintln(stderr, "The first run downloads the image and each scanner's vulnerability database,")
	fmt.Fprintf(stderr, "which can take several minutes. Per-scanner timeout is %s.\n", timeout)

	// Generate the SBOM once and let the scanners consume it, rather than each
	// pulling and unpacking the image separately. Both adapters declare
	// AcceptsSBOM, and on a cold run the image pull is most of the wall time —
	// on alpine:3.14 this takes a scan from three minutes to five seconds.
	//
	// The generator is attached only when syft is present. It is an
	// optimisation, not a requirement, and failing every scan because an
	// optional tool is missing would be the wrong trade.
	opts := []orchestrator.Option{orchestrator.WithScannerTimeout(timeout)}
	if _, err := exec.LookPath("syft"); err == nil {
		opts = append(opts, orchestrator.WithSBOMGenerator(sbom.NewSyftGenerator()))
	} else {
		fmt.Fprintln(stderr, "note: syft is not installed; each scanner will pull the image separately")
	}
	fmt.Fprintln(stderr)

	target := model.Target{Reference: image}

	orc := orchestrator.New(usable, opts...)
	session, err := orc.Run(ctx, target, orchestrator.RunOptions{
		Classes: []model.FindingClass{model.ClassVulnerability, model.ClassMisconfiguration, model.ClassSecret},
	})
	if err != nil {
		return nil, fmt.Errorf("running scanners: %w", err)
	}

	registry := normalize.NewRegistry()

	var findings []model.Finding
	byScanner := map[string]model.RawResult{}

	// A scanner whose output we could not parse ran, but told us nothing we can
	// use. RawResult.NoData is set before parsing, so it cannot express this on
	// its own — tracked separately and folded in below.
	normalizeFailed := map[string]bool{}

	for _, raw := range session.Raw {
		byScanner[raw.Scanner] = raw

		if !raw.Succeeded() {
			// A process killed by the deadline exits with a code that says
			// nothing about why. Naming the timeout turns an unexplained failure
			// into something the user can act on.
			msg := raw.Err
			if raw.Duration >= timeout {
				msg = fmt.Sprintf("timed out after %s — raise --timeout and try again",
					raw.Duration.Round(time.Second))
			}
			fmt.Fprintf(stderr, "warning: %s failed: %s\n", raw.Scanner, msg)
			continue
		}

		got, err := registry.Normalize(raw)
		if err != nil {
			fmt.Fprintf(stderr, "warning: cannot normalise %s output: %v\n", raw.Scanner, err)
			// The scanner ran, so Ran stays true. But leaving NoData false would
			// make every finding another scanner reported look disputed against
			// a scanner whose output we simply could not read — a claim about
			// our parser dressed up as a claim about the image.
			normalizeFailed[raw.Scanner] = true
			continue
		}
		findings = append(findings, got...)
	}

	// Build the participant list from every scanner that was constructed, not
	// from the results. The orchestrator omits scanners it filters out during
	// selection, so a scanner that was never selected would otherwise be
	// indistinguishable from one that does not exist — and correlation needs to
	// tell those apart to keep silence out of the confidence denominator.
	participants := make([]correlate.Participant, 0, len(usable)+len(unavailable))

	for _, s := range usable {
		raw, ran := byScanner[s.Name()]
		participants = append(participants, correlate.Participant{
			Name: s.Name(),
			// Capabilities come from the live instance rather than from a table
			// keyed on the scanner's name. The instance is the authority on what
			// it can detect; a lookup table is a copy, and a copy drifts.
			Capabilities: s.Capabilities(),
			Ran:          ran && raw.Succeeded(),
			NoData:       ran && (raw.NoData || normalizeFailed[s.Name()]),
		})
	}

	// A scanner that could not run at all still belongs in the list. Its absence
	// from the results is a fact about this machine, not about the image.
	for _, name := range unavailableNames {
		participants = append(participants, correlate.Participant{
			Name:         name,
			Capabilities: scanner.Capabilities{},
			Ran:          false,
		})
	}

	// Inject unavailable scanners into the session as failed raw results
	// so their detailed errors appear in the session summary at the bottom.
	for name, errStr := range unavailable {
		session.Raw = append(session.Raw, model.RawResult{
			Scanner: name,
			Err:     errStr,
		})
	}

	return &liveResult{
		Findings:     correlate.CorrelateWith(findings, participants, weights),
		Participants: participants,
		Session:      session,
		RawCount:     len(findings),
	}, nil
}

// writeSessionProvenance prints what was actually run, so that a result can be
// reproduced or at least explained later.
//
// Vulnerability databases change daily. Without the tool and database versions,
// a difference between two runs cannot be attributed to the image rather than
// to the data, and the scan becomes an observation nobody can check.
func writeSessionProvenance(w io.Writer, s *model.ScanSession) {
	if s == nil {
		return
	}

	fmt.Fprintf(w, "\nSession %s\n", s.ID)
	if s.Target.Digest != "" {
		fmt.Fprintf(w, "  target      %s (%s)\n", s.Target.Reference, s.Target.Digest)
	} else {
		fmt.Fprintf(w, "  target      %s\n", s.Target.Reference)
	}
	if s.Target.OS != "" {
		line := fmt.Sprintf("  os          %s %s", s.Target.OS, s.Target.OSVersion)
		if s.Target.OSEndOfLife {
			line += "  (end of life — the security feed may have no entries for it)"
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintf(w, "  duration    %s\n", s.Duration.Round(time.Millisecond))

	for _, t := range s.Tools {
		line := fmt.Sprintf("  %-11s %s", t.Name, t.Version)
		if t.DBVersion != "" {
			line += fmt.Sprintf("  db %s", t.DBVersion)
		}
		if !t.DBUpdatedAt.IsZero() {
			line += fmt.Sprintf("  updated %s", t.DBUpdatedAt.Format("2006-01-02"))
		}
		fmt.Fprintln(w, line)
	}

	if failed := s.ScannersFailed(); len(failed) > 0 {
		// Sorted for the same reason the participant list is: a report that
		// reorders itself between runs cannot be diffed.
		names := make([]string, 0, len(failed))
		for name := range failed {
			names = append(names, name)
		}
		sort.Strings(names)

		fmt.Fprintln(w, "\n  failed scanners")
		for _, name := range names {
			fmt.Fprintf(w, "    %-9s %s\n", name, failed[name])
		}

	}
}
