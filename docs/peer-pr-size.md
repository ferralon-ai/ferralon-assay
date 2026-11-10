# Peer PR size check

`scripts/pr-size-check.sh` tells you, before you mark a PR ready, whether it is small enough for a
reviewer to read and merge in one pass. Large, multi-concern diffs take longer to pick up and draw
more findings; splitting them is cheaper than waiting.

## When to run it

Run it from your branch **before marking the PR ready for review**:

```
scripts/pr-size-check.sh            # measures origin/main...HEAD
scripts/pr-size-check.sh <base-ref> # measures <base-ref>...HEAD
```

Fetch first so `origin/main` is current. On a shallow clone (`git clone --depth`, or a default CI
checkout) fetch enough history for the base and your branch to share a merge base:
`git fetch --deepen=<n>` or `git fetch --unshallow`. It is a local, offline check; it reads only
your git history.

## What it measures

- **Lines:** added plus deleted lines across the diff.
- **Files:** files changed.
- **Areas:** distinct top-level directories touched (files at the repository root count as one area,
  `(root)`).

A moved or renamed file counts once: one file, with only the lines that changed in it, in the
directory it moved to. A pure move is one file and no lines. This uses git's rename detection, so a
file that was also heavily rewritten (under git's 50% similarity) counts as a delete plus an add.

Vendored and generated files count toward none of these:

- any path with a `vendor/` component;
- the lock files `go.sum`, `package-lock.json`, `yarn.lock` and `pnpm-lock.yaml`;
- files named `*.pb.go`, `*_gen.go`, `*.gen.go`, `*.generated.*` or `zz_generated.*`;
- a `.go` file with Go's generated-code marker, a `// Code generated ... DO NOT EDIT.` line before its
  package clause (a deleted file is judged by its last version).

Any other fixture or data file counts in full. A PR that adds a large one is expected to trip the
check: raise the limit for that run and say why in the PR description.

| Limit | Default | Override |
|---|---|---|
| Lines | 600 | `PR_SIZE_MAX_LINES` |
| Files | 20 | `PR_SIZE_MAX_FILES` |
| Areas | 3 | `PR_SIZE_MAX_AREAS` |

These defaults were chosen as a starting point when the check was added, not derived from
measurements of past PRs; expect them to be tuned as peer PRs go through it.

Example: `PR_SIZE_MAX_LINES=900 scripts/pr-size-check.sh`.

## Exit codes and output

| Exit | Meaning |
|---|---|
| 0 | Within every limit. Prints `pr-size-check: OK`. |
| 1 | A limit is exceeded. One `OVER:` line per exceeded limit, then one `SPLIT:` line per top-level directory with its line count, largest first. |
| 2 | Usage or git error (unknown base ref, not a git repository, a non-numeric limit, or no merge base between the base and `HEAD`, which a shallow clone without enough history gives: `git fetch --deepen=<n>` or `--unshallow`). |

Use the `SPLIT:` lines as the suggested seams: one PR per directory, or per group of directories that
change together. If the PR must stay whole, say why in its description.

The check never blocks a merge and does not mark or merge anything; merging stays a person's act.
