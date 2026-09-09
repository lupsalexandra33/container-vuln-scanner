package orchestrator

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/sbom"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/scanner"
)

// Orchestrator manages the parallel execution of multiple scanners against a target.
type Orchestrator struct {
	scanners      []scanner.Scanner
	sbomGenerator sbom.Generator
	workerCount   int
	timeout       time.Duration
}

// Option configures the orchestrator.
type Option func(*Orchestrator)

// WithSBOMGenerator sets the SBOM generator to be used by the orchestrator.
func WithSBOMGenerator(gen sbom.Generator) Option {
	return func(o *Orchestrator) {
		o.sbomGenerator = gen
	}
}

// WithWorkerCount sets the maximum number of scanners to run concurrently.
func WithWorkerCount(n int) Option {
	return func(o *Orchestrator) {
		if n > 0 {
			o.workerCount = n
		}
	}
}

// WithScannerTimeout sets the timeout for individual scanner execution.
func WithScannerTimeout(t time.Duration) Option {
	return func(o *Orchestrator) {
		if t > 0 {
			o.timeout = t
		}
	}
}

// New creates a new Orchestrator with the given scanners and options.
func New(scanners []scanner.Scanner, opts ...Option) *Orchestrator {
	o := &Orchestrator{
		scanners:    scanners,
		workerCount: 4,                // Default bounded worker count
		timeout:     10 * time.Minute, // Default per-scanner timeout
	}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// RunOptions specifies parameters for a scan run.
type RunOptions struct {
	// Scanners is an explicit list of scanner names to run. If empty, all capable scanners run.
	Scanners []string

	// Classes restricts the scan to specific finding classes (e.g. only vulnerabilities).
	// If empty, all classes are scanned.
	Classes []model.FindingClass

	// Offline restricts the run to scanners that do not require network access.
	Offline bool
}

// Run executes the selected scanners against the target concurrently.
func (o *Orchestrator) Run(ctx context.Context, target model.Target, opts RunOptions) (*model.ScanSession, error) {
	session := &model.ScanSession{
		ID:        uuid.New().String(),
		Target:    target,
		StartedAt: time.Now(),
		Config:    make(map[string]string),
	}

	// 0. Generate SBOM if a generator is configured
	if o.sbomGenerator != nil {
		sbomBytes, err := o.sbomGenerator.Generate(ctx, target)
		if err == nil && len(sbomBytes) > 0 {
			session.SBOM = sbomBytes

			// Expose as pipeline artifact (temp file)
			if tmpFile, err := os.CreateTemp("", "sbom-*.json"); err == nil {
				_, _ = tmpFile.Write(sbomBytes)
				tmpFile.Close()

				// Expose artifact path to target so scanners can consume it
				target.SBOMPath = tmpFile.Name()
				session.Target = target
			}
		}
	}

	// 1. Scanner Selection
	var toRun []scanner.Scanner
	for _, s := range o.scanners {
		// Filter by user selection
		if len(opts.Scanners) > 0 {
			requested := false
			for _, r := range opts.Scanners {
				if r == s.Name() {
					requested = true
					break
				}
			}
			if !requested {
				continue
			}
		}

		// Filter by capabilities
		caps := s.Capabilities()

		if opts.Offline && caps.RequiresNetwork {
			continue
		}

		if len(opts.Classes) > 0 {
			capable := false
			for _, reqClass := range opts.Classes {
				// The Detects method on Capabilities takes ecosystem; empty means any ecosystem
				if caps.Detects(reqClass, "") {
					capable = true
					break
				}
			}
			if !capable {
				continue
			}
		}

		// Filter by availability
		// A scanner that is unavailable is recorded as a failure so it's not treated as a silent agreement.
		if err := s.Available(ctx); err != nil {
			session.Raw = append(session.Raw, model.RawResult{
				Scanner: s.Name(),
				Target:  target,
				Err:     fmt.Sprintf("unavailable: %v", err),
			})
			continue
		}

		toRun = append(toRun, s)
	}

	// 2. Concurrent Execution with Bounded Workers
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, o.workerCount)

	for _, s := range toRun {
		wg.Add(1)
		go func(sc scanner.Scanner) {
			defer wg.Done()

			// Acquire worker slot
			sem <- struct{}{}
			defer func() { <-sem }()

			// Apply per-scanner timeout
			scanCtx, cancel := context.WithTimeout(ctx, o.timeout)
			defer cancel()

			start := time.Now()

			// Retrieve tool version
			ver, err := sc.Version(scanCtx)
			if err != nil {
				mu.Lock()
				session.Raw = append(session.Raw, model.RawResult{
					Scanner:  sc.Name(),
					Target:   target,
					Started:  start,
					Duration: time.Since(start),
					Err:      fmt.Sprintf("failed to get version: %v", err),
				})
				mu.Unlock()
				return
			}

			mu.Lock()
			session.Tools = append(session.Tools, ver)
			mu.Unlock()

			// Execute scan
			res, err := sc.Scan(scanCtx, target)

			// Aggregate execution metadata
			res.Scanner = sc.Name()
			res.Target = target
			res.Tool = ver

			if res.Started.IsZero() {
				res.Started = start
			}
			if res.Duration == 0 {
				res.Duration = time.Since(start)
			}

			// Handle errors and context timeouts during scan
			if err != nil {
				res.Err = err.Error()
			} else if scanCtx.Err() != nil {
				res.Err = scanCtx.Err().Error()
			}

			mu.Lock()
			session.Raw = append(session.Raw, res)
			mu.Unlock()

		}(s)
	}

	wg.Wait()

	session.Duration = time.Since(session.StartedAt)
	return session, nil
}
