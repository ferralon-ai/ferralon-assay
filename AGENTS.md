# Repository guide for coding assistants

This file orients an automated assistant — and any human — working in this
repository. Match the surrounding code's style, keep changes small and focused,
and open a pull request rather than pushing to `main`.

## Build and test

- Build: `go build ./...`
- Test:  `go test ./...`

The release scanner asset is produced by `scripts/build-release.sh`. Read the
release rule below before you run it.

## Releasing — use the front door

**Never cut, build, or publish a release from a local checkout.** A release is
minted entirely by CI, and the only way to start one is to push a version tag.
If a release was built on a workstation, it is not a release — it bypassed every
gate that makes the published asset trustworthy.

To release `vMAJOR.MINOR.PATCH`:

1. Write `docs/releases/<tag>.md` — the human release notes.
2. Tag a clean `main` commit and push the tag:

   ```
   git tag vX.Y.Z <clean-main-commit>
   git push origin vX.Y.Z
   ```

3. `.github/workflows/release.yml` does the rest: it mints the BUSL Change Date
   onto a release-only leaf commit, builds the scanner asset **twice** and
   fails unless the two sha256 digests match, publishes the GitHub Release, and
   floats the `vX.Y` minor alias.

Do **not**:

- Publish a locally-built asset. Running `scripts/build-release.sh` to build the
  tarball is fine — for testing, or to reproduce a published release's sha256 and
  verify it. But that output is **not** a release: never `gh release create` it,
  push a hand-minted tag or leaf, or hand it off as "the release." Only CI,
  reached by pushing a tag, publishes.
- Edit `LICENSE`'s Change Date, or `.github/workflows/release.yml`, by hand. The
  Change Date is minted by the workflow and must stay `TBD` on every branch.
- Build from an unpushed or diverged local tree. CI builds from the reviewed
  ref; your working copy is not it.

Full mechanics, including the supported-release bugfix path, are in
[docs/releases/README.md](docs/releases/README.md).
