package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

// sessionFileVersion identifies the on-disk layout.
//
// A stored session is only useful if a later version of this tool can still
// read it. Writing the version now means a reader can refuse a file it does not
// understand rather than misinterpreting it, which is the difference between a
// failed replay and a wrong one.
const sessionFileVersion = 1

// sessionFile is a scan session as written to disk.
//
// It holds the raw scanner output rather than the consolidated findings. That
// is the point: correlation, conflict resolution and weighting can all be re-run
// against stored raw results after the logic changes, and the result compared
// against what the same inputs produced before. Storing only the conclusions
// would make the session a record of what we decided rather than of what we saw.
type sessionFile struct {
	Version int
	Session *model.ScanSession
}

// saveSession writes a session to a file.
func saveSession(path string, s *model.ScanSession) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating session file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sessionFile{Version: sessionFileVersion, Session: s}); err != nil {
		return fmt.Errorf("writing session: %w", err)
	}
	return nil
}

// loadSession reads a session written by saveSession.
func loadSession(path string) (*model.ScanSession, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading session file: %w", err)
	}

	var sf sessionFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("parsing session file: %w", err)
	}
	if sf.Version != sessionFileVersion {
		return nil, fmt.Errorf("session file version %d, this build reads version %d",
			sf.Version, sessionFileVersion)
	}
	if sf.Session == nil {
		return nil, fmt.Errorf("session file contains no session")
	}
	return sf.Session, nil
}

// writeSessionSummary prints what a stored session contains, for the reader
// deciding whether it is the one they want.
func writeSessionSummary(w io.Writer, s *model.ScanSession) {
	fmt.Fprintf(w, "Session %s\n", s.ID)
	fmt.Fprintf(w, "  target      %s\n", s.Target.Reference)
	if s.Target.Digest != "" {
		fmt.Fprintf(w, "  digest      %s\n", s.Target.Digest)
	}
	fmt.Fprintf(w, "  scanned at  %s\n", s.StartedAt.Format("2006-01-02 15:04:05"))

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

	var raw int
	for _, r := range s.Raw {
		raw += len(r.Payload)
	}
	fmt.Fprintf(w, "  raw output  %d scanners, %d KB\n", len(s.Raw), raw/1024)
}
