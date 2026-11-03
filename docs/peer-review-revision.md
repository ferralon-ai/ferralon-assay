# Closing review feedback before you push a revision

A revision that misses one reviewer finding (a nit, an inline comment, an unanswered question)
costs another full review round. Before pushing a revision, check that every finding is either
changed in your diff or answered in writing:

```
scripts/review-closure-check.sh <findings-file> [base-ref]
```

`base-ref` defaults to `origin/main`. The script compares against the diff `base-ref...HEAD`.

## Findings file

Save the review's findings as plain text or markdown, one per line:

```
path[:line] - text
```

A finding is closed when its `path` appears in the diff. A finding that needs no code change, or
has no path, is closed by an entry under an `## Answered` heading: the finding line, then ` => `,
then the reason. An entry without a reason does not close it.

```
docs/floor.md:12 - matrix wording is wrong
docs/api.md:40 - why not a constant?
Title is too long

## Answered
docs/api.md:40 - why not a constant? => value is derived per call, see the new comment
Title is too long => renamed on the PR, no file change
```

## Output

Each unaddressed finding prints its own `OPEN: <finding>` line and the script exits 1. When all
are closed it prints `review-closure-check: OK` and exits 0. Exit 2 means a usage or git error.

The check shortens revision rounds only. It does not change how quickly a PR is merged.
