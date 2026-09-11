# Release notes

One file per release, named for its tag: `docs/releases/v0.3.0.md`. The file holds the
human description of the release — what it is and what changed — and nothing about the
mechanics (the reproducible sha256 and the BUSL Change Date footnote are appended by the
release workflow, which is the only thing that can attest them).

## Before you tag

1. Write `docs/releases/<tag>.md`. Describe the release for someone deciding whether to
   adopt it: what it adds, what changed, anything that affects how they pin or run it.
2. Cut the annotated tag from the release commit **with that file as the message**, so the
   tag object and the GitHub Release carry the same words:

   ```
   git tag -a v0.3.0 -F docs/releases/v0.3.0.md <release-commit>
   git push origin v0.3.0
   ```

The push triggers `.github/workflows/release.yml`, which **fails if the notes file is
missing or empty** — a release with no notes is a documentation gap the moment it ships, so
the gate is deliberate. The workflow then appends the reproducible-build provenance line and
a footnote recording the BUSL Change Date this tag is stamped with, and publishes the
release with its pinned, checksum-verified scanner asset.

Keep the notes to what a reader can verify from this repository or the release itself.
