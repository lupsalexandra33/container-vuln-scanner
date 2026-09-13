// Command vulnscan is the command-line entry point.
//
// It is deliberately thin: it parses arguments, calls the library under pkg/,
// and formats the result. No business logic lives here.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/normalize"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/report"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type normalizeOptions struct {
	filePath    string
	scanner     string
	format      string
	outFormat   string
	minSeverity string
	failOn      string
	outputFile  string
}

func main() {
	if len(os.Args) < 2 {
		printRootUsage(os.Stderr)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "version":
		fmt.Printf("vulnscan %s (commit: %s, built: %s)\n", version, commit, date)

	case "scan":
		os.Exit(runScan(os.Args[2:], os.Stdout, os.Stderr))

	case "normalize", "inspect", "view", "tui":
		os.Exit(runNormalize(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))

	case "help", "-h", "--help":
		printRootUsage(os.Stdout)
		os.Exit(0)

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printRootUsage(os.Stderr)
		os.Exit(2)
	}
}

func printRootUsage(w io.Writer) {
	usageText := `vulnscan - Multi-scanner container vulnerability correlation & triage engine

Usage:
  vulnscan <command> [flags]

Commands:
  scan        Correlate vulnerability findings across multiple scanners (live or recorded)
  normalize   Ingest and normalize raw scanner outputs into standard findings (alias: inspect)
  tui         Launch the interactive terminal UI for a scan or saved report
  view        Launch the interactive web dashboard for a scan or saved report
  calibrate   Evaluate cross-scanner agreement and calibrate per-ecosystem trust weights
  version     Print version and build metadata
  help        Show available commands and flags

Examples:
  # Scan recorded fixtures and launch interactive TUI:
  vulnscan scan --from testdata/fixtures/debian_11 --out tui

  # Run live multi-scanner scan against a container image:
  vulnscan scan debian:11-slim

  # Normalize a raw Grype/Trivy JSON file:
  cat grype.json | vulnscan normalize --format table

Use "vulnscan <command> --help" for detailed documentation on a specific command.
`
	fmt.Fprint(w, usageText)
}

func runNormalize(args []string, inReader io.Reader, outWriter, errWriter io.Writer) int {
	fs := flag.NewFlagSet("normalize", flag.ContinueOnError)
	fs.SetOutput(errWriter)

	opts := normalizeOptions{}
	fs.StringVar(&opts.filePath, "file", "", "Path to raw scanner output file or '-' for stdin (required)")
	fs.StringVar(&opts.scanner, "scanner", "", "Scanner engine: trivy, grype (auto-detected from filename if omitted; required for stdin)")
	fs.StringVar(&opts.format, "format", "", "Input format: trivy-json, grype-json (auto-detected from filename if omitted; required for stdin)")
	fs.StringVar(&opts.outFormat, "out", "table", "Output display format: table, json, markdown, web, tui")
	fs.StringVar(&opts.minSeverity, "min-severity", "UNKNOWN", "Minimum severity to display (UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL)")
	fs.StringVar(&opts.failOn, "fail-on", "", "Exit with code 1 if any finding meets/exceeds severity (e.g. HIGH, CRITICAL)")
	fs.StringVar(&opts.outputFile, "o", "", "Write output to file instead of stdout")

	fs.Usage = func() {
		fmt.Fprintln(errWriter, `Usage: vulnscan normalize -file <path|-> [flags]

Parses raw scanner reports into standard normalized vulnerability findings.
Scanner and format are inferred from the filename when possible; reading from
stdin ('-file -') requires -scanner and -format to be given explicitly, since
there is no filename to infer from.

Flags:`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	if len(os.Args) > 1 && os.Args[1] == "view" && opts.outFormat == "table" {
		opts.outFormat = "web"
	}

	if len(os.Args) > 1 && os.Args[1] == "tui" && opts.outFormat == "table" {
		opts.outFormat = "tui"
	}

	if opts.filePath == "" {
		fmt.Fprintln(errWriter, "error: -file flag is required")
		fs.Usage()
		return 2
	}

	fromStdin := opts.filePath == "-"

	if !fromStdin && (opts.scanner == "" || opts.format == "") {
		detectedScanner, detectedFormat := inferScanner(opts.filePath)
		if opts.scanner == "" {
			opts.scanner = detectedScanner
		}
		if opts.format == "" {
			opts.format = detectedFormat
		}
	}

	if opts.scanner == "" || opts.format == "" {
		if fromStdin {
			fmt.Fprintln(errWriter, "error: -scanner and -format are required when reading from stdin (-file -); there is no filename to infer them from")
		} else {
			fmt.Fprintln(errWriter, "error: -scanner and -format must be specified when they cannot be inferred from the filename")
		}
		fs.Usage()
		return 2
	}

	minSev, err := parseSeverity(opts.minSeverity)
	if err != nil {
		fmt.Fprintf(errWriter, "error: -min-severity: %v\n", err)
		return 2
	}

	var failThreshold model.Severity
	failEnabled := opts.failOn != ""
	if failEnabled {
		failThreshold, err = parseSeverity(opts.failOn)
		if err != nil {
			fmt.Fprintf(errWriter, "error: -fail-on: %v\n", err)
			return 2
		}
	}

	var data []byte
	if fromStdin {
		data, err = io.ReadAll(inReader)
	} else {
		data, err = os.ReadFile(opts.filePath)
	}
	if err != nil {
		fmt.Fprintf(errWriter, "error reading input: %v\n", err)
		return 1
	}

	registry := normalize.NewRegistry()
	findings, err := registry.Normalize(model.RawResult{
		Scanner: opts.scanner,
		Format:  opts.format,
		Payload: data,
	})
	if err != nil {
		fmt.Fprintf(errWriter, "error normalizing report: %v\n", err)
		return 1
	}

	filtered := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		if meetsThreshold(f.PrimarySeverity(), minSev) {
			filtered = append(filtered, f)
		}
	}

	dest := outWriter
	if opts.outputFile != "" {
		file, err := os.Create(opts.outputFile)
		if err != nil {
			fmt.Fprintf(errWriter, "error creating output file: %v\n", err)
			return 1
		}
		defer file.Close()
		dest = file
	}

	var renderErr error
	switch strings.ToLower(opts.outFormat) {
	case "tui":
		renderErr = report.RenderTUI(report.SingleScannerReport(filtered, opts.scanner, opts.filePath))
	case "web", "ui":
		renderErr = report.ServeDashboard(report.SingleScannerReport(filtered, opts.scanner, opts.filePath))
	case "json":
		renderErr = renderJSON(dest, filtered)
	case "markdown", "md":
		renderErr = renderMarkdown(dest, filtered, opts.scanner, opts.filePath)
	case "table":
		renderErr = renderTable(dest, filtered, opts.scanner, opts.filePath)
	default:
		fmt.Fprintf(errWriter, "error: unsupported format %q (allowed: table, json, markdown, web, tui)\n", opts.outFormat)
		return 2
	}

	if renderErr != nil {
		fmt.Fprintf(errWriter, "error rendering output: %v\n", renderErr)
		return 1
	}

	if failEnabled {
		violations := 0
		for _, f := range filtered {
			if meetsThreshold(f.PrimarySeverity(), failThreshold) {
				violations++
			}
		}
		if violations > 0 {
			fmt.Fprintf(errWriter, "\n[FAIL] Found %d finding(s) meeting or exceeding %s\n", violations, strings.ToUpper(opts.failOn))
			return 1
		}
	}

	return 0
}

func inferScanner(path string) (scanner, format string) {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "trivy"):
		return "trivy", "trivy-json"
	case strings.Contains(lower, "grype"):
		return "grype", "grype-json"
	default:
		return "", ""
	}
}

func meetsThreshold(sev, threshold model.Severity) bool {
	return sev == threshold || sev.MoreSevereThan(threshold)
}

func parseSeverity(s string) (model.Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return model.SeverityCritical, nil
	case "HIGH":
		return model.SeverityHigh, nil
	case "MEDIUM":
		return model.SeverityMedium, nil
	case "LOW":
		return model.SeverityLow, nil
	case "UNKNOWN":
		return model.SeverityUnknown, nil
	default:
		return "", fmt.Errorf("invalid severity %q (want UNKNOWN, LOW, MEDIUM, HIGH, or CRITICAL)", s)
	}
}

func renderJSON(w io.Writer, findings []model.Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

func renderTable(w io.Writer, findings []model.Finding, scannerName, path string) error {
	fmt.Fprintf(w, "Normalized %d findings from %s (%s)\n\n", len(findings), scannerName, path)
	fmt.Fprintf(w, "%-10s %-18s %-25s %-14s %-12s\n",
		"SEVERITY", "VULNERABILITY", "PACKAGE", "VERSION", "FIX STATE")
	fmt.Fprintln(w, strings.Repeat("-", 83))

	counts := map[model.Severity]int{}
	for _, f := range findings {
		sev := f.PrimarySeverity()
		counts[sev]++

		id := f.Vulnerability.PreferredID().ID
		pkgName := f.PackageName
		if len(pkgName) > 24 {
			pkgName = pkgName[:21] + "..."
		}

		fmt.Fprintf(w, "%-10s %-18s %-25s %-14s %-12s\n",
			sev, id, pkgName, f.InstalledVersion, f.FixState)
	}

	fmt.Fprintln(w, strings.Repeat("-", 83))
	fmt.Fprintf(w, "Total: %d findings (%d critical, %d high, %d medium, %d low, %d unknown)\n",
		len(findings),
		counts[model.SeverityCritical],
		counts[model.SeverityHigh],
		counts[model.SeverityMedium],
		counts[model.SeverityLow],
		counts[model.SeverityUnknown],
	)

	return nil
}

func renderMarkdown(w io.Writer, findings []model.Finding, scannerName, path string) error {
	fmt.Fprintf(w, "# Normalized Vulnerability Report\n\n")
	fmt.Fprintf(w, "- **Scanner:** %s\n", scannerName)
	fmt.Fprintf(w, "- **Source File:** `%s`\n", path)
	fmt.Fprintf(w, "- **Total Findings:** %d\n\n", len(findings))

	fmt.Fprintln(w, "| Severity | Vulnerability | Package | Installed Version | Fix State | Fixed In |")
	fmt.Fprintln(w, "| :--- | :--- | :--- | :--- | :--- | :--- |")

	for _, f := range findings {
		id := f.Vulnerability.PreferredID().ID
		fixed := "-"
		if len(f.FixedVersions) > 0 {
			fixed = strings.Join(f.FixedVersions, ", ")
		}

		fmt.Fprintf(w, "| %s | `%s` | %s | %s | %s | %s |\n",
			f.PrimarySeverity(), id, f.PackageName, f.InstalledVersion, f.FixState, fixed)
	}
	return nil
}
