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
| `pkg/enrichment` | CVSS, EPSS, KEV | Daiana |
| `pkg/layers` | layer attribution | Daiana |
| `pkg/store` | persistence and history | Daiana |
| `pkg/report` | output formats | Daiana |

## Rules

1. Nothing under `pkg/` prints to stdout, reads environment variables, or calls
   `os.Exit`. Configuration is passed in; errors are returned.
2. `cmd/vulnscan` contains no business logic.
3. Every package is tested against `testdata/fixtures`, not against live tools.
