#!/usr/bin/env bash
# pr-size-check.sh — fail when a branch is too big to review in one pass.
#
# USAGE
#   scripts/pr-size-check.sh [base-ref]
#
# Measures `base-ref...HEAD` (base-ref defaults to origin/main): files changed, added plus deleted
# lines, and distinct top-level directories touched. A rename is one file with its own line delta, in
# the directory it moved to. Vendored and generated files count toward none of them: any path with a
# vendor/ component; go.sum, package-lock.json, yarn.lock and pnpm-lock.yaml; *.pb.go, *_gen.go,
# *.gen.go, *.generated.* and zz_generated.*; and a .go file with a `// Code generated ... DO NOT
# EDIT.` line before its package clause.
#
# LIMITS (environment variables)
#   PR_SIZE_MAX_LINES  default 600
#   PR_SIZE_MAX_FILES  default 20
#   PR_SIZE_MAX_AREAS  default 3
#
# EXIT CODES
#   0  within every limit; prints `pr-size-check: OK`
#   1  a limit is exceeded; prints one `OVER:` line per limit and a `SPLIT:` line per top-level
#      directory, largest first
#   2  usage or git error, including no merge base between base-ref and HEAD (a shallow clone)
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
base_sha="$(git rev-parse --verify --quiet --end-of-options "$base^{commit}")" ||
  usage_error "unknown base ref '$base'"
merge_base="$(git merge-base "$base_sha" HEAD)" ||
  usage_error "no merge base between '$base' and HEAD; a shallow clone needs more history (git fetch --deepen=<n> or git fetch --unshallow)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# -z: paths come NUL-terminated and unquoted. diff.renames=true keeps a user's "copies" setting from
# reporting a copy as a zero-line change.
git -c diff.renames=true diff --numstat -z -M "$merge_base" HEAD >"$work/numstat" ||
  usage_error "git diff $base...HEAD failed"

# is_generated_go <commit> <path>: the file carries Go's generated-code marker before its package clause.
is_generated_go() {
  git cat-file blob "$1:$2" 2>/dev/null | awk '
    /^package[ \t]/ { past = 1 }
    !past && /^\/\/ Code generated .* DO NOT EDIT\.$/ { found = 1 }
    END { exit !found }'
}

excluded() {
  case "/$1" in */vendor/*) return 0 ;; esac
  case "${1##*/}" in
    go.sum | package-lock.json | yarn.lock | pnpm-lock.yaml | \
      *.pb.go | *_gen.go | *.gen.go | *.generated.* | zz_generated.*) return 0 ;;
    *.go)
      # A deleted file is read where it last existed.
      if git cat-file -e "HEAD:$1" 2>/dev/null; then
        is_generated_go HEAD "$1"
      else
        is_generated_go "$merge_base" "$1"
      fi
      ;;
    *) return 1 ;;
  esac
}

# One "<lines> <area>" line per counted file. A file at the repository root is area "(root)".
tab="$(printf '\t')"
files=0
lines=0
while IFS= read -r -d '' rec; do
  added="${rec%%"$tab"*}"
  rest="${rec#*"$tab"}"
  deleted="${rest%%"$tab"*}"
  path="${rest#*"$tab"}"
  if [ -z "$path" ]; then # a rename: its old and new paths follow as records of their own
    IFS= read -r -d '' _ && IFS= read -r -d '' path || usage_error "truncated git diff output"
  fi
  excluded "$path" && continue
  n=0
  [ "$added" = - ] || n=$((added + deleted)) # binary files carry "-": a file, no lines
  area="${path%%/*}"
  [ "$area" != "$path" ] || area="(root)"
  files=$((files + 1))
  lines=$((lines + n))
  printf '%d %s\n' "$n" "${area//$'\n'/?}"
done <"$work/numstat" >"$work/areas"

# One line per directory, largest first: "<lines> <area>".
split="$(awk '
  { n = $1; sub(/^[0-9]+ /, ""); byarea[$0] += n }
  END { for (a in byarea) printf "%d %s\n", byarea[a], a }' "$work/areas" | LC_ALL=C sort -k1,1nr -k2)"
areas="$(printf '%s' "$split" | grep -c '' || true)"

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
  printf '%s\n' "$split" | sed 's/^\([0-9]*\) \(.*\)$/SPLIT: \2: \1 lines/'
  exit 1
fi
echo "pr-size-check: OK"
