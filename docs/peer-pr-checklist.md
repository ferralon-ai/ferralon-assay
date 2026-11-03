# Peer PR checklist

## Before marking ready

Run the self-check once, from your branch, before you take the PR out of draft:

```
scripts/pr-ready-check.sh origin/main path/to/pr-description.md
```

The first argument is the base ref (default `origin/main`); the second is the file holding
the PR description you are about to submit. The script looks at the committed diff
`base...HEAD` and exits non-zero, with one `FAIL:` line per cause, when:

- a changed non-test Go package has no changed `_test.go` file in it;
- the description file is missing, empty, or still the template placeholder;
- `gofmt -l` or `go vet` reports on the changed Go files or packages.

Fix each line, commit, and re-run until it prints `pr-ready-check: OK`. It catches only
mechanical causes of a rework round; it does not replace review.
