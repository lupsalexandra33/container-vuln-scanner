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
