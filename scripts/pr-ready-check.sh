#!/usr/bin/env bash
# pr-ready-check.sh [base-ref] [description-file]
#
# Run before marking a PR ready for review. Against the committed diff base-ref...HEAD
# (base-ref defaults to origin/main) it fails, listing every cause, when:
#   (a) a changed non-test Go package has no changed _test.go file,
#   (b) the PR description file is missing, empty, or still the template placeholder,
#   (c) gofmt -l or go vet reports on the changed Go files/packages.
# Like CI, files under testdata/ and vendor/ are skipped, and go vet runs from each
# package's nearest go.mod. gofmt and go vet read the working tree, so the script refuses
# to run while a Go file in a changed package has uncommitted changes.
# Exit 0 means none of the three fired, 1 that at least one did, and 2 that the check could
# not run (unknown base, no merge base, uncommitted changes, perl missing).
# Run it from inside the repository.
set -u

base="${1:-origin/main}"
desc="${2:-}"
fail=0
problem() { echo "FAIL: $*"; fail=1; }
cannot() { echo "pr-ready-check: $*" >&2; exit 2; }

command -v perl >/dev/null 2>&1 || cannot "perl is required to read the PR description"
case "$desc" in ""|/*) ;; *) desc="$PWD/$desc" ;; esac
cd "$(git rev-parse --show-toplevel)" || exit 2
if ! git rev-parse --verify --quiet "$base^{commit}" >/dev/null; then
  cannot "unknown base ref '$base'"
fi
if ! git merge-base "$base" HEAD >/dev/null 2>&1; then
  cannot "no merge base between '$base' and HEAD (unrelated history, or a shallow clone: fetch more history)"
fi

if ! changed=$(git diff --name-only --diff-filter=ACMR "$base"...HEAD -- '*.go'); then
  cannot "cannot diff '$base'...HEAD"
fi
changed=$(printf '%s\n' "$changed" | grep -vE '(^|/)(testdata|vendor)/')
dirs=""
if [ -n "$changed" ]; then
  dirs=$(while IFS= read -r f; do dirname "$f"; done <<<"$changed" | sort -u)
fi

# gofmt and go vet read the working tree; it must match the commit for the result to hold.
if [ -n "$dirs" ]; then
  specs=()
  while IFS= read -r d; do
    if [ "$d" = . ]; then specs+=(":(glob)*.go"); else specs+=(":(glob)$d/*.go"); fi
  done <<<"$dirs"
  dirty=$(git status --porcelain --untracked-files=all -- "${specs[@]}")
  if [ -n "$dirty" ]; then
    echo "pr-ready-check: Go files in the changed packages differ from the commit; commit or stash them first:" >&2
    echo "$dirty" | sed 's/^/    /' >&2
    exit 2
  fi
fi

# (a) every changed non-test package needs a changed test file.
pkgs=""
tested=""
while IFS= read -r f; do
  [ -n "$f" ] || continue
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

# (b) description present and not just the template: comments, blank lines, headings,
# rules, task-list lines and placeholder words do not count.
if [ -z "$desc" ]; then
  problem "no PR description file given (second argument)"
elif [ ! -f "$desc" ]; then
  problem "PR description file '$desc' does not exist"
else
  body=$(perl -0pe 's/<!--.*?-->//gs' "$desc" |
    grep -vE '^[[:space:]]*(#.*)?$' |
    grep -vE '^[[:space:]]*(-{3,}|\*{3,}|_{3,})[[:space:]]*$' |
    grep -vE '^[[:space:]]*[-*+] \[[ xX]\]' |
    grep -viE '^[[:space:]]*(tbd|todo|n/a|_no response_|describe .*)[[:space:]]*$')
  if [ -z "$body" ]; then
    problem "PR description '$desc' is empty or still the template placeholder"
  fi
fi

# (c) gofmt and vet on what changed; vet runs per module, as CI does.
modroot() {
  local d=$1
  while :; do
    if [ -f "$d/go.mod" ]; then echo "$d"; return 0; fi
    if [ "$d" = . ]; then return 1; fi
    d=$(dirname "$d")
  done
}
if [ -n "$changed" ]; then
  files=()
  while IFS= read -r f; do files+=("$f"); done <<<"$changed"
  unformatted=$(gofmt -l "${files[@]}" 2>&1)
  if [ -n "$unformatted" ]; then
    while IFS= read -r f; do problem "gofmt reports $f"; done <<<"$unformatted"
  fi
  vetlist=""
  while IFS= read -r d; do
    if ! r=$(modroot "$d"); then
      echo "NOTE: $d is in no Go module (no go.mod above it); not vetted"
      continue
    fi
    if [ "$d" = "$r" ]; then p=.; elif [ "$r" = . ]; then p="./$d"; else p="./${d#"$r"/}"; fi
    vetlist="$vetlist$r	$p
"
  done <<<"$dirs"
  while IFS= read -r r; do
    [ -n "$r" ] || continue
    vetpkgs=()
    while IFS='	' read -r m p; do
      if [ "$m" = "$r" ]; then vetpkgs+=("$p"); fi
    done <<<"$vetlist"
    if ! vetout=$(cd "$r" && GOWORK=off go vet "${vetpkgs[@]}" 2>&1); then
      problem "go vet reports problems in module $r:"
      echo "$vetout" | sed 's/^/    /'
    fi
  done <<<"$(printf '%s' "$vetlist" | cut -f1 | sort -u)"
fi

if [ "$fail" -eq 0 ]; then
  echo "pr-ready-check: OK"
fi
exit "$fail"
