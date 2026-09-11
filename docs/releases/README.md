# Release notes

One file per release, named for its tag: `docs/releases/v0.3.0.md`. The file holds the
human description of the release — what it is and what changed — and nothing about the
mechanics (the reproducible sha256 and the BUSL Change Date footnote are appended by the
release workflow, which is the only thing that can attest them).

## The Change Date is minted, never committed

`LICENSE` carries `Change Date: TBD` on every branch — `main` and every bugfix branch — and
it stays that way. The BUSL Change Date is **minted by the release workflow**, not written
by a person: when a tag is pushed, `.github/workflows/release.yml` computes the date
(today + 4 years, the BUSL "fourth anniversary"), writes it onto a single leaf commit that
changes only that one line of `LICENSE`, and re-points the tag at that leaf. The leaf is the
released source — pinning the tag gets a `LICENSE` with a real date — but it is reachable
only through the tag and never merges back to a branch.

Two guards keep this honest:

- `release.yml` **refuses to build** if the tagged commit already shows a concrete Change
  Date (that would mean someone stamped it by hand) or if the notes file is missing.
- `license-guard.yml` **fails any push or pull request** whose `LICENSE` names a Change Date,
  on any branch — so a date can never reach a branch by hand or by merge.

## Cutting a release

1. Write `docs/releases/<tag>.md`. Describe the release for someone deciding whether to adopt
   it: what it adds, what changed, anything that affects how they pin or run it.
2. Tag a **clean (TBD) commit** on the branch you are releasing from — usually `main` — and
   push the tag. The tag can be lightweight; the workflow re-creates it as an annotated tag on
   the minted leaf, with your notes file as its message:

   ```
   git tag v0.3.0 <release-commit>
   git push origin v0.3.0
   ```

The push triggers `release.yml`, which validates the notes and the TBD state, mints the
Change Date onto the leaf, re-points the tag at it, builds the pinned scanner asset twice
(reproducibility is a gate), and publishes the release — its body the notes file plus the
reproducible-sha256 provenance line and the minted Change Date footnote.

## Fixing an old release

A bugfix for a supported older release is **not** a rewind of `main`. Fork a branch from that
release's tagged base — `<tag>^`, the leaf's parent, which is a clean TBD commit — apply the
fix there, write the new tag's notes, and cut the new tag from that branch. The workflow mints
a fresh leaf off your bugfix branch exactly as it does off `main`.

Keep the notes to what a reader can verify from this repository or the release itself.
