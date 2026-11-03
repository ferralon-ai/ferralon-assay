# Peer PR checklist

## Before marking ready

Commit your work, then run the self-check once, from your branch, before you take the PR out
of draft:

```
scripts/pr-ready-check.sh origin/main path/to/pr-description.md
```

The first argument is the base ref (default `origin/main`); the second is the file holding
the PR description you are about to submit. The script looks at the committed diff
`base...HEAD`, skipping files under `testdata/` and `vendor/` as CI does, and exits 1, with
one `FAIL:` line per cause, when:

- a changed non-test Go package has no changed `_test.go` file in it;
- the description file is missing, empty, or still the template (comments, headings, rules
  and the task-list lines of `.github/PULL_REQUEST_TEMPLATE.md`, ticked or not, do not count
  as a description);
- `gofmt -l` or `go vet` reports on the changed Go files or packages. `go vet` runs from each
  package's nearest `go.mod`, so a change under `plugins/cfamily` is vetted in that module. A
  package that only lost a file is vetted too.

It exits 2, and checks nothing, when it cannot run: it is not run inside a git repository, the
base ref is unknown, the base and `HEAD` share no merge base (fetch more history), `perl` is
missing, `go` or `gofmt` is missing while there are Go files to check, any tracked Go file has
uncommitted changes, or a changed package holds an untracked Go file. `gofmt` and `go vet` read
the working tree, and `go vet` also compiles the packages the changed ones import, so commit or
stash those first.

Fix each line, commit, and re-run until it prints `pr-ready-check: OK`. If a package needs no
new test (a comment-only change or a rename), the missing-test line stays: say in the PR
description why no test applies, and the reviewer decides. The script catches only
mechanical causes of a rework round; it does not replace review.
