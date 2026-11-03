#!/usr/bin/env bash
# pr-size-check.sh — fail when a branch is too big to review in one pass.
#
# USAGE
#   scripts/pr-size-check.sh [base-ref]
#
# Measures `base-ref...HEAD` (base-ref defaults to origin/main): files changed, added plus deleted
# lines, and distinct top-level directories touched. go.sum and generated files (*.pb.go, *_gen.go,
# *.gen.go, *.generated.*, zz_generated.*) count toward none of them.
#
# LIMITS (environment variables)
#   PR_SIZE_MAX_LINES  default 600
#   PR_SIZE_MAX_FILES  default 20
#   PR_SIZE_MAX_AREAS  default 3
#
# EXIT CODES
#   0  within every limit; prints `pr-size-check: OK`
#   1  a limit is exceeded; prints one `OVER:` line per limit and a `SPLIT:` line per top-level directory
#   2  usage or git error
set -euo pipefail

usage_error() {
  echo "pr-size-check: $*" >&2
  exit 2
}

[ "$#" -le 1 ] || usage_error "usage: pr-size-check.sh [base-ref]"
base="${1:-origin/main}"

max_lines="${PR_SIZE_MAX_LINES:-600}"
max_files="${PR_SIZE_MAX_FILES:-20}"
max_areas="${PR_SIZE_MAX_AREAS:-3}"
for v in "$max_lines" "$max_files" "$max_areas"; do
  case "$v" in
    '' | *[!0-9]*) usage_error "limits must be non-negative integers, got '$v'" ;;
  esac
done

git rev-parse --git-dir >/dev/null 2>&1 || usage_error "not inside a git repository"
git rev-parse --verify --quiet "$base^{commit}" >/dev/null || usage_error "unknown base ref '$base'"
numstat="$(git -c core.quotepath=off diff --numstat --no-renames "$base...HEAD")" ||
  usage_error "git diff $base...HEAD failed"

# One line per directory, sorted: "<lines> <area>". A file at the repository root is area "(root)".
summary="$(printf '%s\n' "$numstat" | awk -F '\t' '
  NF < 3 { next }
  {
    path = $3
    n = split(path, parts, "/")
    base = parts[n]
    if (path == "go.sum" || base == "go.sum" || base ~ /(\.pb\.go|_gen\.go|\.gen\.go)$/ ||
        base ~ /\.generated\./ || base ~ /^zz_generated\./) next
    lines = ($1 == "-" ? 0 : $1 + $2)   # binary files carry "-": a file, no lines
    area = (n > 1 ? parts[1] : "(root)")
    files++
    total += lines
    byarea[area] += lines
  }
  END {
    printf "TOTAL %d %d\n", files, total
    for (a in byarea) printf "AREA %d %s\n", byarea[a], a
  }' | LC_ALL=C sort)"

read -r _ files lines < <(printf '%s\n' "$summary" | grep '^TOTAL ')
areas="$(printf '%s\n' "$summary" | grep -c '^AREA ' || true)"

over=0
if [ "$lines" -gt "$max_lines" ]; then
  echo "OVER: $lines changed lines (limit $max_lines)"
  over=1
fi
if [ "$files" -gt "$max_files" ]; then
  echo "OVER: $files files changed (limit $max_files)"
  over=1
fi
if [ "$areas" -gt "$max_areas" ]; then
  echo "OVER: $areas top-level directories touched (limit $max_areas)"
  over=1
fi

if [ "$over" -eq 1 ]; then
  printf '%s\n' "$summary" | while read -r kind n area; do
    [ "$kind" = AREA ] && echo "SPLIT: $area: $n lines"
  done
  exit 1
fi
echo "pr-size-check: OK"
