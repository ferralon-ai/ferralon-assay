# Release notes

One file per release, named for its tag: `docs/releases/v0.3.0.md`. The file holds the
human description of the release — what it is and what changed — and nothing about the
mechanics (the reproducible sha256 and the BUSL Change Date footnote are appended by the
release workflow, which is the only thing that can attest them).

> **Releases are cut only by pushing a `vX.Y.Z` tag.** Building the asset locally is fine
> — to test a change, or to reproduce a published release's sha256 and verify it — but
> never *publish* one from a local checkout: no `gh release create`, no hand-minted
> `LICENSE` Change Date, no hand-moved tag, no uploading a locally-built asset. Only the
> release workflow builds the asset reproducibly and can attest its sha256 and Change Date,
> and it builds from the reviewed ref rather than whatever is in your working copy. A
> locally-built tarball bypasses every gate below (the reproducibility check, the
> TBD-`LICENSE` check, the notes check) and is not a release until CI builds it from a
> pushed tag.

## The Change Date is minted, never committed

`LICENSE` carries `Change Date: TBD` on every branch — `main` and every bugfix branch — and
it stays that way. The BUSL Change Date is **minted by the release workflow**, not written
by a person: when a tag is pushed, `.github/workflows/release.yml` computes the date
(today + 4 years, the BUSL "fourth anniversary"), writes it onto a single leaf commit that
changes only that one line of `LICENSE`, and re-points the tag at that leaf. The leaf is the
released source — pinning the tag gets a `LICENSE` with a real date — but it is reachable
only through the tag and never merges back to a branch.

The same leaf also stamps the Action's scanner pin. Every branch's `action.yml` defaults
`scanner-version` to a minor alias (`vX.Y`), which the Action resolves at run time to that
minor's current patch release. The leaf rewrites that one line to the exact `vX.Y.Z` being
cut, so every tag of the Action names one scanner release and only a branch ref floats.
`scripts/stamp-scanner-version.sh` does the rewrite. A branch moves its alias to a new minor in
the change that needs that minor's scanner, never as a release step.

Three guards keep this honest:

- `release.yml` **refuses to build** if the tagged commit already shows a concrete Change
  Date (that would mean someone stamped it by hand) or if the notes file is missing.
- `release.yml` **refuses to build** if the tagged commit's `scanner-version` default is not a
  `vX.Y` alias. The alias does not have to match the tag's minor.
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

The push triggers `release.yml`, which validates the notes, the TBD state and the
`scanner-version` alias, mints the Change Date and the exact scanner version onto the leaf,
re-points the tag at it, builds the pinned scanner asset twice
(reproducibility is a gate), and publishes the release — its body the notes file plus the
reproducible-sha256 provenance line and the minted Change Date footnote.

## Fixing an old release

A bugfix for a supported older release is **not** a rewind of `main`. Fork a branch from that
release's tagged base — `<tag>^`, the leaf's parent, which is a clean TBD commit — apply the
fix there (setting `scanner-version` to its `vX.Y` alias if that base names an exact version), write the new tag's notes, and cut the new tag from that branch. The workflow mints
a fresh leaf off your bugfix branch exactly as it does off `main`.

Keep the notes to what a reader can verify from this repository or the release itself.
