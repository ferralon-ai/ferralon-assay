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

Fetch first so `origin/main` is current. It is a local, offline check; it reads only your git history.

## What it measures

- **Lines:** added plus deleted lines across the diff.
- **Files:** files changed.
- **Areas:** distinct top-level directories touched (files at the repository root count as one area,
  `(root)`).

`go.sum` and generated files (`*.pb.go`, `*_gen.go`, `*.gen.go`, `*.generated.*`, `zz_generated.*`)
count toward none of these.

| Limit | Default | Override |
|---|---|---|
| Lines | 600 | `PR_SIZE_MAX_LINES` |
| Files | 20 | `PR_SIZE_MAX_FILES` |
| Areas | 3 | `PR_SIZE_MAX_AREAS` |

Example: `PR_SIZE_MAX_LINES=900 scripts/pr-size-check.sh`.

## Exit codes and output

| Exit | Meaning |
|---|---|
| 0 | Within every limit. Prints `pr-size-check: OK`. |
| 1 | A limit is exceeded. One `OVER:` line per exceeded limit, then one `SPLIT:` line per top-level directory with its line count. |
| 2 | Usage or git error (unknown base ref, not a git repository, a non-numeric limit). |

Use the `SPLIT:` lines as the suggested seams: one PR per directory, or per group of directories that
change together. If the PR must stay whole, say why in its description.

The check never blocks a merge and does not mark or merge anything; merging stays a person's act.
