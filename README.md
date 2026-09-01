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
