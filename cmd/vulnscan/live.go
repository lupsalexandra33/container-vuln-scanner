package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/correlate"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/normalize"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/orchestrator"
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
	all := []scanner.Scanner{
		adapters.NewTrivyAdapter(),
		adapters.NewGrypeAdapter(),
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
	for name, reason := range unavailable {
		fmt.Fprintf(stderr, "warning: %s is unavailable and will be skipped: %s\n", name, reason)
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
	fmt.Fprintf(stderr, "which can take several minutes. Per-scanner timeout is %s.\n\n", timeout)

	target := model.Target{Reference: image}

	orc := orchestrator.New(usable, orchestrator.WithScannerTimeout(timeout))
	session, err := orc.Run(ctx, target, orchestrator.RunOptions{
		Classes: []model.FindingClass{model.ClassVulnerability},
	})
	if err != nil {
		return nil, fmt.Errorf("running scanners: %w", err)
	}

	registry := normalize.NewRegistry()

	var findings []model.Finding
	byScanner := map[string]model.RawResult{}

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
			// Normalising failed, so we have nothing from this scanner — but it
			// did run, and saying otherwise would be a claim about the image
			// rather than about our parser.
			continue
		}
		findings = append(findings, got...)
	}

	// Build the participant list from every scanner that was constructed, not
	// from the results. The orchestrator omits scanners it filtered out during
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
			NoData:       ran && raw.NoData,
		})
	}

	// A scanner that could not run at all still belongs in the list. Its absence
	// from the results is a fact about this machine, not about the image.
	for name := range unavailable {
		participants = append(participants, correlate.Participant{
			Name:         name,
			Capabilities: scanner.Capabilities{},
			Ran:          false,
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
		fmt.Fprintln(w, "\n  failed scanners")
		for name, reason := range failed {
			fmt.Fprintf(w, "    %-9s %s\n", name, reason)
		}
		fmt.Fprintln(w, "  This is a partial result. A scanner that failed has said nothing,")
		fmt.Fprintln(w, "  which is not the same as having found nothing.")
	}
}
