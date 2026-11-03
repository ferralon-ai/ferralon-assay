# Closing review feedback before you push a revision

A revision that misses one reviewer finding (a nit, an inline comment, an unanswered question)
costs another full review round. Before pushing a revision, check that every finding is either
changed in your diff or answered in writing:

```
scripts/review-closure-check.sh <findings-file> <reviewed-sha>
```

`reviewed-sha` is required: it is the head commit the review covered. The script compares against
the diff `<reviewed-sha>...HEAD`, which is your revision only while `reviewed-sha` is an ancestor of
`HEAD` and no merge commit follows it. Two common steps break that, and both exit 2:

- A rebase onto the default branch. The reviewed commit is no longer an ancestor of `HEAD`, so the
  range widens back to the whole PR and findings could read as closed by changes the review already
  saw. Transcribe the findings against the rebased commits instead.
- A merge of the default branch into the PR branch. The range then carries the merged changes, so a
  finding on a line only the default branch changed could read as closed. Run the check on the
  revision before the merge.

## Findings file

The script does not read a review as posted. Transcribe each finding by hand into one line: each
summary line with its **major**, **minor** or **nit** label, and each inline comment, becomes

```
path[:line] - text
```

For example, the review summary line `**minor**: any change to a file closes every finding on that
file (scripts/review-closure-check.sh:64-71)` becomes
`scripts/review-closure-check.sh:64 - any change to a file closes every finding on that file`.
`line` is one number, so a range is written as its first line. Backticks around the location are
ignored. A line of one or more `#` followed by a space is a heading, so `#409 duplicates the
parser` is a finding.

A finding with `:line` is closed when a hunk of the diff covers that line of the reviewed file, or
inserts lines next to it. A finding with only a path prints `TOUCHED` when the path changed: a
changed path is a hint, not proof that the finding is fixed, so it stays unclosed until answered.
A finding that needs no code change, or has no path, is closed by an entry under an `## Answered`
heading: the finding line, then ` => `, then the reason. The entry counts as a finding itself, so the
finding does not also have to be listed above the heading, and a file of Answered entries alone is
not empty. An entry without a reason, or a line there without ` => `, does not close anything and is
checked as a finding. An entry is split at its last ` =>`, so a finding whose text contains ` =>`
can be answered, but a reason that contains ` =>` is not supported.

```
docs/floor.md:12 - matrix wording is wrong
docs/api.md:40 - why not a constant?
Title is too long

## Answered
docs/api.md:40 - why not a constant? => value is derived per call, see the new comment
Title is too long => renamed on the PR, no file change
```

## Output

Each finding that is not closed prints its own `OPEN: <finding>` or `TOUCHED: <finding>` line and
the script exits 1. When all are closed it prints `review-closure-check: OK` and exits 0. Exit 2
means a usage or git error, a findings file that cannot be read, a file with no findings in it, a
reviewed commit that is not an ancestor of `HEAD` (a rebase), or a merge commit since the reviewed
commit.

The check shortens revision rounds only. It does not change how quickly a PR is merged.
