#!/usr/bin/env bash

set -uo pipefail

OUT_ROOT="testdata/fixtures"

# Baseline set. Each entry exercises a different code path:
#   debian:11        supported distribution, LTS security feed
#   alpine:3.14      end of life: expect zero findings despite being vulnerable
#   node:12-alpine   old image with language-level dependencies
#   python:3.9-slim  Debian base plus pip packages, mixed ecosystems
#   nginx:1.21       common real-world image
IMAGES=(
  "debian:11"
  "alpine:3.14"
  "node:12-alpine"
  "python:3.9-slim"
  "nginx:1.21"
)

slugify() { echo "$1" | tr '/:' '__'; }

have() { command -v "$1" >/dev/null 2>&1; }

tool_version() {
  case "$1" in
    trivy)       trivy --version 2>/dev/null | head -1 ;;
    grype)       grype version 2>/dev/null | grep -i '^version' | head -1 ;;
    syft)        syft version 2>/dev/null | grep -i '^version' | head -1 ;;
    osv-scanner) osv-scanner --version 2>/dev/null | head -1 ;;
  esac
}

echo "Checking tools..."
for t in docker trivy grype syft osv-scanner; do
  if have "$t"; then
    printf '  %-12s ok\n' "$t"
  else
    printf '  %-12s MISSING — its output will be skipped\n' "$t"
  fi
done
echo

for image in "${IMAGES[@]}"; do
  slug=$(slugify "$image")
  dir="$OUT_ROOT/$slug"
  mkdir -p "$dir"

  echo "=== $image"

  echo "  pulling..."
  docker pull -q "$image" >/dev/null 2>&1 || { echo "  pull failed, skipping"; continue; }

  digest=$(docker inspect --format='{{index .RepoDigests 0}}' "$image" 2>/dev/null || echo "unknown")

  # Trivy
  if have trivy; then
    echo "  trivy..."
    trivy image --scanners vuln --format json --quiet \
          --output "$dir/trivy.json" "$image" 2>/dev/null \
      || echo "    trivy returned non-zero (findings present is normal)"
  fi

  # Syft SBOM
  if have syft; then
    echo "  syft..."
    syft "$image" -o cyclonedx-json="$dir/sbom.json" -q 2>/dev/null \
      || echo "    syft failed"
  fi

  # Grype
  if have grype; then
    echo "  grype..."
    grype "$image" -o json -q > "$dir/grype.json" 2>/dev/null \
      || echo "    grype failed"
  fi

  # OSV-Scanner
  if have osv-scanner && [ -s "$dir/sbom.json" ]; then
    echo "  osv-scanner..."
    osv-scanner scan --sbom "$dir/sbom.json" --format json \
      > "$dir/osv.json" 2>/dev/null \
      || echo "    osv-scanner returned non-zero (findings present is normal)"
  fi

  # Provenance record
  cat > "$dir/SOURCE.md" <<EOF
# $image

Captured: $(date -u +"%Y-%m-%d %H:%M UTC")
Digest:   $digest

## Tool versions

| Tool | Version |
|---|---|
| trivy | $(tool_version trivy) |
| grype | $(tool_version grype) |
| syft | $(tool_version syft) |
| osv-scanner | $(tool_version osv-scanner) |

## Observations

<!--
Fill this in by hand. For each tool, note:
  - how many findings it reported
  - whether PURL identifiers are present and complete
  - how package names are written
  - whether "no data available" is distinguishable from "no findings"
  - anything surprising
-->
EOF

  echo "  done"
done

echo
echo "Fixture summary:"
printf '%-22s %8s %8s %8s\n' "IMAGE" "TRIVY" "GRYPE" "OSV"
for image in "${IMAGES[@]}"; do
  dir="$OUT_ROOT/$(slugify "$image")"
  count() {
    [ -s "$1" ] || { echo "-"; return; }
    grep -o 'CVE-[0-9]\{4\}-[0-9]\+' "$1" 2>/dev/null | sort -u | wc -l
  }
  printf '%-22s %8s %8s %8s\n' "$image" \
    "$(count "$dir/trivy.json")" \
    "$(count "$dir/grype.json")" \
    "$(count "$dir/osv.json")"
done

echo
echo "Unique CVE counts above. Differences between columns are the raw material"
echo "for the correlator — record what you notice in each SOURCE.md."