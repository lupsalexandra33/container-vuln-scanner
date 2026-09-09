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
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		printRootUsage(os.Stderr)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "version":
		fmt.Printf("vulnscan %s (commit: %s, built: %s)\n", version, commit, date)

	case "normalize", "inspect":
		runNormalize(os.Args[2:])

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
	fmt.Fprintln(w, `vulnscan - Container vulnerability scanning & normalization CLI

Usage:
  vulnscan <command> [flags]

Commands:
  normalize    Ingest and normalize raw scanner output into standard findings
  version      Print version and build metadata
  help         Show available commands and flags

Use "vulnscan <command> --help" for more information about a command.`)
}

type normalizeOptions struct {
	filePath    string
	scanner     string
	format      string
	outFormat   string
	minSeverity string
	failOn      string
	outputFile  string
}

func runNormalize(args []string) {
	fs := flag.NewFlagSet("normalize", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	opts := normalizeOptions{}
	fs.StringVar(&opts.filePath, "file", "", "Path to raw scanner output file (required)")
	fs.StringVar(&opts.scanner, "scanner", "", "Scanner engine: trivy, grype (required)")
	fs.StringVar(&opts.format, "format", "", "Input format: trivy-json, grype-json (required)")
	fs.StringVar(&opts.outFormat, "out", "table", "Output display format: table, json, markdown")
	fs.StringVar(&opts.minSeverity, "min-severity", "UNKNOWN", "Minimum severity to display (UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL)")
	fs.StringVar(&opts.failOn, "fail-on", "", "Exit with code 1 if any finding meets/exceeds severity (e.g. HIGH, CRITICAL)")
	fs.StringVar(&opts.outputFile, "o", "", "Write output to file instead of stdout")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: vulnscan normalize -file <path> -scanner <trivy|grype> -format <format> [flags]

Parses raw scanner reports into standard normalized vulnerability findings.

Flags:`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	if opts.filePath == "" || opts.scanner == "" || opts.format == "" {
		fmt.Fprintln(os.Stderr, "error: -file, -scanner, and -format flags are all required")
		fs.Usage()
		os.Exit(2)
	}

	// 1. Read Payload
	data, err := os.ReadFile(opts.filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading file: %v\n", err)
		os.Exit(1)
	}

	// 2. Normalize
	registry := normalize.NewRegistry()
	findings, err := registry.Normalize(model.RawResult{
		Scanner: opts.scanner,
		Format:  opts.format,
		Payload: data,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error normalizing report: %v\n", err)
		os.Exit(1)
	}

	// 3. Filter Findings
	minSev := parseSeverity(opts.minSeverity)
	filtered := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		primary := f.PrimarySeverity()
		if primary.MoreSevereThan(minSev) || primary == minSev {
			filtered = append(filtered, f)
		}
	}

	// 4. Output Destination
	var outWriter io.Writer = os.Stdout
	if opts.outputFile != "" {
		file, err := os.Create(opts.outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		outWriter = file
	}

	// 5. Render
	var renderErr error
	switch strings.ToLower(opts.outFormat) {
	case "json":
		renderErr = renderJSON(outWriter, filtered)
	case "markdown", "md":
		renderErr = renderMarkdown(outWriter, filtered, opts.scanner, opts.filePath)
	case "table":
		renderErr = renderTable(outWriter, filtered, opts.scanner, opts.filePath)
	default:
		fmt.Fprintf(os.Stderr, "error: unsupported format %q (allowed: table, json, markdown)\n", opts.outFormat)
		os.Exit(2)
	}

	if renderErr != nil {
		fmt.Fprintf(os.Stderr, "error rendering output: %v\n", renderErr)
		os.Exit(1)
	}

	// 6. Threshold / CI Enforcement
	if opts.failOn != "" {
		threshold := parseSeverity(opts.failOn)
		violations := 0
		for _, f := range filtered {
			primary := f.PrimarySeverity()
			if primary.MoreSevereThan(threshold) || primary == threshold {
				violations++
			}
		}
		if violations > 0 {
			fmt.Fprintf(os.Stderr, "\n[FAIL] Found %d finding(s) meeting or exceeding %s\n", violations, strings.ToUpper(opts.failOn))
			os.Exit(1)
		}
	}
}

func parseSeverity(s string) model.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "MEDIUM":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	default:
		return model.SeverityUnknown
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
	fmt.Fprintln(w, strings.Repeat("-", 85))

	for _, f := range findings {
		id := f.Vulnerability.PreferredID().ID
		pkgName := f.PackageName
		if len(pkgName) > 24 {
			pkgName = pkgName[:21] + "..."
		}

		fmt.Fprintf(w, "%-10s %-18s %-25s %-14s %-12s\n",
			f.PrimarySeverity(), id, pkgName, f.InstalledVersion, f.FixState)
	}
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

