package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/correlate"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/normalize"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/trust"
)

// runCalibrate measures how each scanner behaves across a set of recorded scans
// and compares the result to the weights currently configured.
//
// The measurement is against weighted consensus rather than verified ground
// truth, because nobody checked these findings by hand. That bounds what the
// numbers mean: they show which scanner diverges from the others and where, not
// which one is right. A scanner correct where the rest are wrong scores badly
// here by construction, which is why unique findings are reported separately.
func runCalibrate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("calibrate", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		root   = fs.String("from", "", "directory containing one subdirectory of recorded output per image")
		perImg = fs.Bool("per-image", false, "report each image separately as well as the aggregate")
	)

	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: vulnscan calibrate --from <fixtures directory> [flags]")
		fmt.Fprintln(stderr, "\nMeasures per-scanner coverage and precision against weighted consensus,")
		fmt.Fprintln(stderr, "and compares the result to the configured trust weights.")
		fmt.Fprintln(stderr, "\nFlags:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *root == "" {
		fs.Usage()
		return 2
	}

	images, err := imageDirs(*root)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if len(images) == 0 {
		fmt.Fprintf(stderr, "error: no image directories with recognised scanner output under %s\n", *root)
		return 2
	}

	weights := trust.DefaultWeights()
	var all []model.ConsolidatedFinding

	fmt.Fprintf(stdout, "Calibrating across %d images\n\n", len(images))

	for _, dir := range images {
		name := filepath.Base(dir)

		consolidated, err := consolidateDir(dir, weights)
		if err != nil {
			fmt.Fprintf(stdout, "  %-18s skipped: %v\n", name, err)
			continue
		}
		if len(consolidated) == 0 {
			fmt.Fprintf(stdout, "  %-18s no findings\n", name)
			continue
		}

		fmt.Fprintf(stdout, "  %-18s %d consolidated findings\n", name, len(consolidated))

		if *perImg {
			c := trust.Measure(consolidated)
			fmt.Fprintf(stdout, "\n=== %s\n%s\n", name, c.Report(weights))
		}
		all = append(all, consolidated...)
	}

	if len(all) == 0 {
		fmt.Fprintln(stderr, "error: nothing to measure")
		return 2
	}

	c := trust.Measure(all)
	fmt.Fprintf(stdout, "\n=== Aggregate across all images\n%s", c.Report(weights))

	// Where both metrics are zero, nothing corroborated anything — on apk that
	// is alpine:3.14 past end of life, where Trivy's feed is silent and Grype
	// falls back to NVD; on generic, only Grype catalogues binaries at all.
	// Reporting a suggested weight there without saying so would invite someone
	// to apply a number that measures the absence of agreement.
	fmt.Fprintln(stdout, "\nWhere coverage and precision are both zero, no scanner corroborated")
	fmt.Fprintln(stdout, "another — on apk that is alpine:3.14 past end of life, where Trivy's")
	fmt.Fprintln(stdout, "feed is silent and Grype falls back to NVD, and on generic only Grype")
	fmt.Fprintln(stdout, "catalogues binaries at all. A suggested weight there measures the")
	fmt.Fprintln(stdout, "absence of agreement rather than the quality of the scanner, and the")
	fmt.Fprintln(stdout, "configured value should stand.")

	return 0
}

// imageDirs returns the subdirectories of root that contain recognised scanner
// output.
func imageDirs(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}

	var dirs []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(root, e.Name())
		if sources, err := discoverSources(path); err == nil && len(sources) > 0 {
			dirs = append(dirs, path)
		}
	}
	sort.Strings(dirs)
	return dirs, nil
}

// consolidateDir runs normalisation and correlation over one image's recorded
// output.
//
// It repeats what runScan does rather than sharing it, because runScan writes
// to a writer and returns an exit code. Extracting the common part is worth
// doing once a third caller appears.
func consolidateDir(dir string, weights trust.Weights) ([]model.ConsolidatedFinding, error) {
	sources, err := discoverSources(dir)
	if err != nil {
		return nil, err
	}

	registry := normalize.NewRegistry()

	var (
		findings     []model.Finding
		participants []correlate.Participant
	)

	for _, src := range sources {
		payload, err := os.ReadFile(src.path)
		if err != nil {
			// A scanner whose output cannot be read did not run, as far as
			// correlation is concerned — its silence stays out of the
			// confidence denominator.
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
			// target rather than a clean result.
			NoData: len(got) == 0,
		})
	}

	if len(findings) == 0 {
		return nil, fmt.Errorf("no findings normalised")
	}
	return correlate.CorrelateWith(findings, participants, weights), nil
}
