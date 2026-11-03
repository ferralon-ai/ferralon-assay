#!/usr/bin/env bash
# pr-ready-check.sh [base-ref] [description-file]
#
# Run before marking a PR ready for review. Against the committed diff base-ref...HEAD
# (base-ref defaults to origin/main) it fails, listing every cause, when:
#   (a) a changed non-test Go package has no changed _test.go file,
#   (b) the PR description file is missing, empty, or still the template placeholder,
#   (c) gofmt -l or go vet reports on the changed Go files/packages.
# Exit 0 means none of the three fired. Run it from inside the repository.
set -u

base="${1:-origin/main}"
desc="${2:-}"
fail=0
problem() { echo "FAIL: $*"; fail=1; }

cd "$(git rev-parse --show-toplevel)" || exit 2
if ! git rev-parse --verify --quiet "$base^{commit}" >/dev/null; then
  echo "pr-ready-check: unknown base ref '$base'" >&2
  exit 2
fi

changed=$(git diff --name-only --diff-filter=ACMR "$base"...HEAD -- '*.go')

# (a) every changed non-test package needs a changed test file.
pkgs=""
tested=""
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in vendor/*|*/vendor/*|testdata/*|*/testdata/*) continue ;; esac
  d=$(dirname "$f")
  case "$f" in
    *_test.go) tested="$tested $d " ;;
    *) pkgs="$pkgs $d " ;;
  esac
done <<<"$changed"
for d in $(printf '%s\n' $pkgs | sort -u); do
  case "$tested" in
    *" $d "*) ;;
    *) problem "package $d changed but no _test.go file in it changed (missing tests)" ;;
  esac
done

# (b) description present and not just the template.
if [ -z "$desc" ]; then
  problem "no PR description file given (second argument)"
elif [ ! -f "$desc" ]; then
  problem "PR description file '$desc' does not exist"
else
  body=$(perl -0pe 's/<!--.*?-->//gs' "$desc" | grep -vE '^[[:space:]]*(#.*)?$' | grep -viE '^[[:space:]]*(tbd|todo|n/a|_no response_|describe .*)[[:space:]]*$')
  if [ -z "$body" ]; then
    problem "PR description '$desc' is empty or still the template placeholder"
  fi
fi

# (c) gofmt and vet on what changed.
if [ -n "$changed" ]; then
  unformatted=$(echo "$changed" | xargs gofmt -l 2>&1)
  if [ -n "$unformatted" ]; then
    while IFS= read -r f; do problem "gofmt reports $f"; done <<<"$unformatted"
  fi
  vetpkgs=$(echo "$changed" | xargs -n1 dirname | sort -u | sed 's|^|./|')
  if ! vetout=$(echo "$vetpkgs" | xargs go vet 2>&1); then
    problem "go vet reports problems:"
    echo "$vetout" | sed 's/^/    /'
  fi
fi

if [ "$fail" -eq 0 ]; then
  echo "pr-ready-check: OK"
fi
exit "$fail"
