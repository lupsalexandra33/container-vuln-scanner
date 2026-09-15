package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/correlate"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/normalize"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/trust"
)

// runReplay re-derives consolidated findings from a stored session without
// running any scanner.
//
// This is what makes a scan checkable. A vulnerability database changes daily,
// so re-running a scan against the same image next week produces different
// results for reasons that have nothing to do with the image. Replay holds the
// scanner output fixed and re-runs everything downstream of it, which means a
// difference between two replays is a difference in our logic, and a difference
// between two scans is a difference in the world.
func runReplay(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		format  = fs.String("out", "table", "output format: table, json")
		showAll = fs.Bool("all", false, "include findings only one scanner reported")
		verify  = fs.String("verify", "", "compare the replayed findings against a stored JSON result and report any difference")
	)

	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: vulnscan replay <session file> [flags]")
		fmt.Fprintln(stderr, "\nRe-runs normalisation, correlation and conflict resolution against the")
		fmt.Fprintln(stderr, "raw scanner output stored in a session, without invoking any scanner.")
		fmt.Fprintln(stderr, "\nWith --verify, compares the result to a stored JSON output and reports")
		fmt.Fprintln(stderr, "any difference. Since the scanner output is fixed, a difference there is")
		fmt.Fprintln(stderr, "a change in this tool rather than in the image or the vulnerability data.")
		fmt.Fprintln(stderr, "\nFlags:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}

	session, err := loadSession(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	writeSessionSummary(stdout, session)
	fmt.Fprintln(stdout)

	weights := trust.DefaultWeights()
	consolidated, participants, rawCount, err := replaySession(session, weights, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	if *verify != "" {
		return verifyAgainst(*verify, consolidated, stdout, stderr)
	}

	switch *format {
	case "json":
		return writeScanJSON(stdout, stderr, consolidated)
	case "table":
		writeScanTable(stdout, consolidated, participants, rawCount, *showAll, 0)
		return 0
	default:
		fmt.Fprintf(stderr, "error: unknown output format %q\n", *format)
		return 2
	}
}

// replaySession re-derives findings from stored raw output.
//
// It reconstructs participants from the stored results rather than from live
// scanner instances, which means capabilities have to come from the name-keyed
// table. That is a real limitation: a session stored before a scanner's
// capabilities changed replays against the current understanding of them, not
// the one in force at the time. Storing declared capabilities in the session
// would close that gap.
func replaySession(
	s *model.ScanSession,
	weights trust.Weights,
	stderr io.Writer,
) ([]model.ConsolidatedFinding, []correlate.Participant, int, error) {
	if len(s.Raw) == 0 {
		return nil, nil, 0, fmt.Errorf("session holds no scanner output to replay")
	}

	registry := normalize.NewRegistry()

	var findings []model.Finding
	participants := make([]correlate.Participant, 0, len(s.Raw))

	for _, raw := range s.Raw {
		if !raw.Succeeded() {
			// A scanner that failed at scan time failed for this replay too.
			// Replaying it as having run would invent an opportunity to agree
			// that never existed.
			participants = append(participants, correlate.Participant{
				Name:         raw.Scanner,
				Capabilities: capabilitiesFor(raw.Scanner),
				Ran:          false,
			})
			continue
		}

		got, err := registry.Normalize(raw)
		if err != nil {
			fmt.Fprintf(stderr, "warning: cannot normalise stored %s output: %v\n",
				raw.Scanner, err)
			// The scanner ran and we hold its output; what we cannot do is read
			// it. Excluding it from disagreement rather than counting it as
			// having found nothing keeps that a statement about our parser.
			participants = append(participants, correlate.Participant{
				Name:         raw.Scanner,
				Capabilities: capabilitiesFor(raw.Scanner),
				Ran:          true,
				NoData:       true,
			})
			continue
		}

		findings = append(findings, got...)
		participants = append(participants, correlate.Participant{
			Name:         raw.Scanner,
			Capabilities: capabilitiesFor(raw.Scanner),
			Ran:          true,
			NoData:       raw.NoData || len(got) == 0,
		})
	}

	return correlate.CorrelateWith(findings, participants, weights), participants, len(findings), nil
}

// verifyAgainst compares replayed findings to a stored JSON result and reports
// whether they match.
//
// The comparison is on the identity and the resolved values of each finding,
// not on the whole structure: pointers and slice capacities differ between runs
// without anything meaningful having changed.
func verifyAgainst(path string, replayed []model.ConsolidatedFinding, stdout, stderr io.Writer) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(stderr, "error: reading %s: %v\n", path, err)
		return 2
	}

	var stored []model.ConsolidatedFinding
	if err := json.Unmarshal(data, &stored); err != nil {
		fmt.Fprintf(stderr, "error: parsing %s: %v\n", path, err)
		return 2
	}

	diffs := compareFindings(stored, replayed)

	fmt.Fprintf(stdout, "Verifying replay against %s\n", path)
	fmt.Fprintf(stdout, "  stored    %d findings\n", len(stored))
	fmt.Fprintf(stdout, "  replayed  %d findings\n", len(replayed))

	if len(diffs) == 0 {
		fmt.Fprintln(stdout, "\nIdentical. Correlation, conflict resolution and weighting")
		fmt.Fprintln(stdout, "reproduced the stored result exactly from the raw scanner output.")
		return 0
	}

	fmt.Fprintf(stdout, "\n%d differences:\n", len(diffs))
	for i, d := range diffs {
		if i == 20 {
			fmt.Fprintf(stdout, "  ... and %d more\n", len(diffs)-20)
			break
		}
		fmt.Fprintf(stdout, "  %s\n", d)
	}

	fmt.Fprintln(stdout, "\nThe raw scanner output did not change, so this is a difference in")
	fmt.Fprintln(stdout, "our own logic rather than in the image or the vulnerability data.")
	return 1
}

// findingKey identifies a consolidated finding for comparison.
func findingKey(f model.ConsolidatedFinding) string {
	return f.Vulnerability.PreferredID().ID + "|" + f.Package.Canonical()
}

// compareFindings reports how two sets of consolidated findings differ, using
// the wording verify's caller expects: a missing finding is "missing from
// replay" and a new one is "new in replay," since neither should happen when
// the raw scanner output is held fixed.
func compareFindings(stored, replayed []model.ConsolidatedFinding) []string {
	return compareFindingSets(stored, replayed, "missing from replay", "new in replay")
}

// compareFindingSets reports how two sets of consolidated findings differ.
// removedLabel and addedLabel let a caller phrase what "gone" and "new" mean
// for its situation: verify is checking for a bug and calls them "missing
// from replay"/"new in replay"; diff.go is checking for real change over time
// and calls them "resolved"/"new".
func compareFindingSets(a, b []model.ConsolidatedFinding, removedLabel, addedLabel string) []string {
	byKey := func(fs []model.ConsolidatedFinding) map[string]model.ConsolidatedFinding {
		m := make(map[string]model.ConsolidatedFinding, len(fs))
		for _, f := range fs {
			m[findingKey(f)] = f
		}
		return m
	}

	am, bm := byKey(a), byKey(b)
	var diffs []string

	for key, s := range am {
		r, present := bm[key]
		if !present {
			diffs = append(diffs, fmt.Sprintf("%s: %s", removedLabel, key))
			continue
		}
		if s.Severity != r.Severity {
			diffs = append(diffs, fmt.Sprintf("%s: severity %s -> %s", key, s.Severity, r.Severity))
		}
		if s.FixState != r.FixState {
			diffs = append(diffs, fmt.Sprintf("%s: fix state %s -> %s", key, s.FixState, r.FixState))
		}
		if absFloat(s.Confidence-r.Confidence) > 0.001 {
			diffs = append(diffs, fmt.Sprintf("%s: confidence %.3f -> %.3f",
				key, s.Confidence, r.Confidence))
		}
		if len(s.Conflicts) != len(r.Conflicts) {
			diffs = append(diffs, fmt.Sprintf("%s: %d conflicts -> %d",
				key, len(s.Conflicts), len(r.Conflicts)))
		}
	}

	for key := range bm {
		if _, present := am[key]; !present {
			diffs = append(diffs, fmt.Sprintf("%s: %s", addedLabel, key))
		}
	}

	// Sorted so that running the comparison twice on the same inputs produces
	// the same report — the property verify exists to demonstrate, and diff
	// should keep for the same reason.
	sort.Strings(diffs)
	return diffs
}

func absFloat(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}
