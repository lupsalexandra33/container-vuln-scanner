package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

// runHistory lists saved scan sessions, most recent first.
//
// A single session answers "what did we find." History answers "what have we
// found over time," which is what makes diff usable: diff needs two sessions
// to compare, and this is how a reader finds them without remembering exact
// filenames.
func runHistory(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		dir    = fs.String("from", ".", "directory to search for saved session files")
		target = fs.String("target", "", "show only sessions for this image reference")
	)

	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: vulnscan history [flags]")
		fmt.Fprintln(stderr, "\nLists saved scan sessions under a directory, most recent first.")
		fmt.Fprintln(stderr, "Use the listed paths with \"vulnscan diff\" to compare two of them.")
		fmt.Fprintln(stderr, "\nFlags:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}

	sessions, err := discoverSessions(*dir, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if len(sessions) == 0 {
		fmt.Fprintf(stderr, "no session files found under %s\n", *dir)
		return 0
	}

	if *target != "" {
		filtered := sessions[:0]
		for _, s := range sessions {
			if s.session.Target.Reference == *target {
				filtered = append(filtered, s)
			}
		}
		sessions = filtered
	}

	// Most recent first: a reader comparing "then" against "now" almost always
	// wants the latest sessions, not the oldest.
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].session.StartedAt.After(sessions[j].session.StartedAt)
	})

	fmt.Fprintf(stdout, "%-20s %-28s %-16s %s\n", "SCANNED AT", "TARGET", "SCANNERS", "FILE")
	fmt.Fprintln(stdout, strings.Repeat("-", 100))
	for _, s := range sessions {
		names := make([]string, 0, len(s.session.Tools))
		for _, t := range s.session.Tools {
			names = append(names, t.Name)
		}
		fmt.Fprintf(stdout, "%-20s %-28s %-16s %s\n",
			s.session.StartedAt.Format("2006-01-02 15:04:05"),
			truncate(s.session.Target.Reference, 28),
			strings.Join(names, ","),
			s.path,
		)
	}
	return 0
}

// sessionEntry pairs a session with the file it was loaded from, so history
// can report where to find it.
type sessionEntry struct {
	path    string
	session *model.ScanSession
}

// discoverSessions finds every valid session file directly under dir.
//
// A file that is not a session — wrong version, corrupt, unrelated JSON — is
// skipped with a warning rather than failing history outright. One bad file
// should not hide every good one; history is a directory listing, not a
// validator.
func discoverSessions(dir string, stderr io.Writer) ([]sessionEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var sessions []sessionEntry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		s, err := loadSession(path)
		if err != nil {
			// Most files in a directory of interest will not be session
			// files at all (results.json, sbom.json, ...). That is normal,
			// not a warning-worthy event, so it stays silent here.
			continue
		}
		sessions = append(sessions, sessionEntry{path: path, session: s})
	}
	return sessions, nil
}
