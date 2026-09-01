#!/usr/bin/env bash
set -euo pipefail

MODULE="github.com/lupsalexandra33/container-vuln-scanner"
GO_VERSION="1.23"

echo "Scaffolding $MODULE ..."

# directories
mkdir -p cmd/vulnscan
mkdir -p pkg/{model,scanner,orchestrator,sbom,normalize,correlate,trust,policy,enrich,layers,store,report}
mkdir -p pkg/scanner/adapters
mkdir -p testdata/fixtures
mkdir -p deploy docs .github/workflows

# go module
cat > go.mod <<EOF
module $MODULE

go $GO_VERSION
EOF

# package markers
# Each package gets a doc.go stating its purpose and owner, so the ownership
# split from the work plan is visible in the code itself.
write_doc() {
  local dir="$1" pkg="$2" owner="$3" desc="$4"
  cat > "$dir/doc.go" <<EOF
// Package $pkg $desc
//
// Owner: $owner
package $pkg
EOF
}

write_doc pkg/model        model        "Alexandra" "defines the core data types shared by every other package: Finding, ConsolidatedFinding, ScanSession, RawResult and Target."
write_doc pkg/normalize    normalize    "Alexandra" "converts per-scanner output into the unified model."
write_doc pkg/correlate    correlate    "Alexandra" "groups findings that refer to the same vulnerability across scanners."
write_doc pkg/trust        trust        "Alexandra" "holds per-scanner trust weights and computes weighted confidence."
write_doc pkg/policy       policy       "Alexandra" "evaluates rules over consolidated findings to produce a pass, warn or fail decision."

write_doc pkg/scanner      scanner      "Razvan"    "defines the Scanner interface every tool integration must satisfy."
write_doc pkg/orchestrator orchestrator "Razvan"    "runs scanners concurrently with per-tool timeouts and failure isolation."
write_doc pkg/sbom         sbom         "Razvan"    "generates the package inventory for a target image."

write_doc pkg/enrich       enrich       "Daiana"    "adds CVSS, EPSS and CISA KEV context to findings."
write_doc pkg/layers       layers       "Daiana"    "attributes findings to the image layer that introduced them."
write_doc pkg/store        store        "Daiana"    "persists scan sessions and supports history queries."
write_doc pkg/report       report       "Daiana"    "renders a completed session in the supported output formats."

cat > pkg/scanner/adapters/doc.go <<'EOF'
// Package adapters contains one file per integrated scanner. Each adapter
// implements scanner.Scanner and translates that tool's native output into
// model.RawResult. Adding a scanner should require no changes outside this
// package.
//
// Owner: Razvan
package adapters
EOF

# entrypoint
cat > cmd/vulnscan/main.go <<'EOF'
// Command vulnscan is the command-line entry point.
//
// It is deliberately thin: it parses arguments, calls the library under pkg/,
// and formats the result. No business logic lives here.
package main

import (
	"fmt"
	"os"
)

var version = "dev" // overridden at build time via -ldflags

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: vulnscan <command> [flags]")
		os.Exit(2)
	}

	switch os.Args[1] {
	case "version":
		fmt.Println("vulnscan", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(2)
	}
}
EOF

# fixtures
cat > testdata/fixtures/README.md <<'EOF'
# Scanner output fixtures

Raw, unmodified scanner output captured in Stage 0.2. Every package in this
project is developed and tested against these files rather than against live
scanners, so no one has to wait for someone else's adapter to exist.

Layout:

    testdata/fixtures/<image-slug>/<scanner>.json

Images are identified by digest, not by tag. A tag is a moving pointer and
resolves to different content over time, which would make these fixtures
silently stale.

Each image directory contains a `SOURCE.md` recording the exact image digest,
the scanner versions used, and the vulnerability database timestamp at capture
time.
EOF

# deploy
cat > deploy/docker-compose.yml <<'EOF'
# Service dependencies for local development.
#
# Currently empty. Clair and PostgreSQL are added in Stage 3.1 and 4.3.
services: {}
EOF

# docs
cat > docs/architecture.md <<'EOF'
# Architecture

> Status: placeholder. Filled in by PR [0.3] together with the core types.

## Pipeline

    image reference
      -> SBOM generation
      -> parallel scanner execution
      -> normalisation
      -> correlation
      -> confidence scoring
      -> enrichment
      -> policy evaluation
      -> reporting

## Package layout and ownership

| Package | Purpose | Owner |
|---|---|---|
| `pkg/model` | shared data types | Alexandra |
| `pkg/normalize` | tool output to unified model | Alexandra |
| `pkg/correlate` | cross-scanner finding identity | Alexandra |
| `pkg/trust` | trust weights, confidence scoring | Alexandra |
| `pkg/policy` | rule evaluation | Alexandra |
| `pkg/scanner` | scanner interface | Razvan |
| `pkg/scanner/adapters` | one file per tool | Razvan |
| `pkg/orchestrator` | concurrent execution | Razvan |
| `pkg/sbom` | package inventory | Razvan |
| `pkg/enrich` | CVSS, EPSS, KEV | Daiana |
| `pkg/layers` | layer attribution | Daiana |
| `pkg/store` | persistence and history | Daiana |
| `pkg/report` | output formats | Daiana |

## Rules

1. Nothing under `pkg/` prints to stdout, reads environment variables, or calls
   `os.Exit`. Configuration is passed in; errors are returned.
2. `cmd/vulnscan` contains no business logic.
3. Every package is tested against `testdata/fixtures`, not against live tools.
EOF

# code owners
cat > .github/CODEOWNERS <<'EOF'
# Reviewers are assigned automatically from the directory a pull request
# touches. Anything not listed here needs a review from anyone on the team.

/pkg/model/         @lupsalexandra33
/pkg/normalize/     @lupsalexandra33
/pkg/correlate/     @lupsalexandra33
/pkg/trust/         @lupsalexandra33
/pkg/policy/        @lupsalexandra33

/pkg/scanner/       @RazvanMasgras
/pkg/orchestrator/  @RazvanMasgras
/pkg/sbom/          @RazvanMasgras
/deploy/            @RazvanMasgras

/pkg/enrich/        @loonailove
/pkg/layers/        @loonailove
/pkg/store/         @loonailove
/pkg/report/        @loonailove
/cmd/               @loonailove

# Shared contracts: changes here affect everyone.
/docs/architecture.md  @lupsalexandra33 @RazvanMasgras @loonailove
EOF

# PR template
cat > .github/pull_request_template.md <<'EOF'
### Stage

<!-- e.g. [1.1] — the stage from the work plan this PR implements -->

### What this changes

<!-- one sentence; if you need "and", this is probably two pull requests -->

### Checklist

- [ ] Tests added or updated, running against fixtures
- [ ] `make check` passes
- [ ] No business logic added under `cmd/`
- [ ] No shared interface changed (if it was, that belongs in its own PR)
EOF

# CI
cat > .github/workflows/ci.yml <<EOF
name: CI

on:
  pull_request:
  push:
    branches: [main]

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '$GO_VERSION'
          cache: true

      - name: Build
        run: go build ./...

      - name: Vet
        run: go vet ./...

      - name: Test
        run: go test -race ./...

      - name: Format check
        run: |
          unformatted=\$(gofmt -l .)
          if [ -n "\$unformatted" ]; then
            echo "These files are not gofmt'ed:"
            echo "\$unformatted"
            exit 1
          fi
EOF

# makefile
cat > Makefile <<'EOF'
BINARY  := vulnscan
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test check fmt clean

build:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/$(BINARY) ./cmd/vulnscan

test:
	go test -race ./...

check: fmt
	go vet ./...
	go test -race ./...

fmt:
	gofmt -w .

clean:
	rm -rf bin/
EOF

# gitignore
cat > .gitignore <<'EOF'
bin/
*.exe
*.test
*.out
coverage.*
.env
.idea/
.vscode/
.DS_Store
EOF

# readme
if [ ! -f README.md ]; then
cat > README.md <<'EOF'
# container-vuln-scanner

Multi-scanner container vulnerability analysis with cross-tool correlation and
confidence scoring.

> Scaffold only. See `docs/architecture.md` for the package layout and the work
> plan for the full scope.

## Development

    make build
    make check

Tests run against recorded scanner output in `testdata/fixtures` and require no
scanners to be installed.
EOF
fi

# verify
gofmt -l . >/dev/null
go build ./... && go vet ./...

echo
echo "Done. Structure created and building cleanly."
echo "Next: git checkout -b stage/0.1-scaffold && git add -A && git commit"
