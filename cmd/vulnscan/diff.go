package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/trust"
)

// runDiff replays two saved sessions and reports what changed between them.
//
// This asks a different question than replay --verify does. Verify checks
// whether our own logic reproduces a fixed input the same way twice — a
// difference there is a bug, because the raw scanner output never changed.
// Diff compares two sessions that were scanned at different times, where the
// scanner output is expected to differ because the vulnerability databases
// moved between them. A difference here is information about the image over
// time, not evidence that anything is broken.
func runDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)

	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: vulnscan diff <old session file> <new session file>")
		fmt.Fprintln(stderr, "\nReplays two saved sessions and reports which findings are new,")
		fmt.Fprintln(stderr, "which are resolved, and which changed severity, fix state, or")
		fmt.Fprintln(stderr, "confidence between the two scans.")
		fmt.Fprintln(stderr, "\nUse \"vulnscan history\" to find session files to compare.")
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return 2
	}

	oldPath, newPath := fs.Arg(0), fs.Arg(1)

	oldSession, err := loadSession(oldPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: reading %s: %v\n", oldPath, err)
		return 2
	}
	newSession, err := loadSession(newPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: reading %s: %v\n", newPath, err)
		return 2
	}

	weights := trust.DefaultWeights()

	oldFindings, _, _, err := replaySession(oldSession, weights, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: replaying %s: %v\n", oldPath, err)
		return 1
	}
	newFindings, _, _, err := replaySession(newSession, weights, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: replaying %s: %v\n", newPath, err)
		return 1
	}

	// A diff across two different images would be meaningless — every finding
	// would look "resolved" and "new" purely because the packages differ, not
	// because anything changed. Refusing this outright is better than
	// producing a report that looks like a real comparison and is not one.
	if oldSession.Target.Reference != newSession.Target.Reference {
		fmt.Fprintf(stderr, "error: sessions are for different targets (%s vs %s); diff compares two scans of the same image\n",
			oldSession.Target.Reference, newSession.Target.Reference)
		return 2
	}

	fmt.Fprintf(stdout, "Comparing %s\n", oldSession.Target.Reference)
	fmt.Fprintf(stdout, "  %s  (%s)\n", oldSession.StartedAt.Format("2006-01-02 15:04:05"), oldPath)
	fmt.Fprintf(stdout, "  %s  (%s)\n\n", newSession.StartedAt.Format("2006-01-02 15:04:05"), newPath)

	diffs := compareFindingSets(oldFindings, newFindings, "resolved", "new")

	if len(diffs) == 0 {
		fmt.Fprintln(stdout, "No differences. Same findings, same severities, same fix states.")
		return 0
	}

	fmt.Fprintf(stdout, "%d differences:\n", len(diffs))
	for _, d := range diffs {
		fmt.Fprintf(stdout, "  %s\n", d)
	}

	fmt.Fprintln(stdout, "\nThis reflects real change between the two scans — a new database")
	fmt.Fprintln(stdout, "entry, a fix that landed, or a rating that moved — not a bug in this tool.")
	return 0
}
