#!/usr/bin/env bash
# pr-dup-check.sh — before opening a PR for a peer order, fail if an open PR or a remote branch
# already carries that order's id.
#
# Usage: scripts/pr-dup-check.sh <order-id>
#
# Exit 0: nothing found. Exit 1: found; each existing PR or branch is named on stdout.
# Exit 2: usage error or a listing could not be read.
#
# The id matches as a whole token, case-insensitively, in a PR's title, body or head branch, or in
# a remote branch name: "ASY-09" does not match "ASY-099" or "XASY-09". A token is bounded by
# anything that is not a letter or digit.
#
# Listings (env; each, when set, replaces the live lookup so tests need no network):
#   PR_DUP_PRS_FILE       open PRs, records ended by RS (\036), fields by US (\037):
#                         number, title, head branch, body
#   PR_DUP_BRANCHES_FILE  remote branches, one per line ("origin/x", "refs/heads/x" and
#                         `git ls-remote --heads` lines are all accepted)
#   PR_DUP_SELF_BRANCH    the branch being checked from, left out of the branch matches
#                         (default: the current branch)
#
# Live lookups: `gh pr list` when gh is installed and signed in, otherwise the PR check is skipped
# with a note on stderr and only branches are checked; branches come from `git ls-remote --heads origin`.
set -euo pipefail

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  echo "usage: $0 <order-id>" >&2
  exit 2
fi
id="$1"
export PR_DUP_ID="$id"

RS=$'\036'
US=$'\037'
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Reads RS-separated, US-delimited records on stdin and prints "first-field<TAB>second-field" for
# each record whose later fields hold the id as a whole token.
matches() {
  awk -v RS="$RS" -v FS="$US" '
    BEGIN { id = tolower(ENVIRON["PR_DUP_ID"]); n = length(id) }
    function has(s,   i, j, p, b, a) {
      s = tolower(s)
      i = 1
      while ((j = index(substr(s, i), id)) > 0) {
        p = i + j - 1
        b = (p == 1) ? "" : substr(s, p - 1, 1)
        a = substr(s, p + n, 1)
        if (b !~ /[a-z0-9]/ && a !~ /[a-z0-9]/) return 1
        i = p + 1
      }
      return 0
    }
    { for (k = 2; k <= NF; k++) if (has($k)) { print $1 "\t" $2; break } }
  '
}

found=0

# Open PRs.
prs="$tmp/prs"
if [ -n "${PR_DUP_PRS_FILE:-}" ]; then
  cp "$PR_DUP_PRS_FILE" "$prs" || { echo "pr-dup-check: cannot read $PR_DUP_PRS_FILE" >&2; exit 2; }
elif command -v gh >/dev/null 2>&1 && gh pr list --state open --limit 200 \
  --json number,title,headRefName,body \
  --template '{{range .}}{{.number}}{{"\u001f"}}{{.title}}{{"\u001f"}}{{.headRefName}}{{"\u001f"}}{{.body}}{{"\u001e"}}{{end}}' \
  >"$prs" 2>/dev/null; then
  :
else
  echo "pr-dup-check: gh unavailable or not signed in; open PRs not checked, branches only" >&2
  : >"$prs"
fi
while IFS=$'\t' read -r num title; do
  [ -n "$num" ] || continue
  echo "open PR #$num already mentions $id: $title"
  found=1
done < <(matches <"$prs")

# Remote branches.
branches="$tmp/branches"
if [ -n "${PR_DUP_BRANCHES_FILE:-}" ]; then
  cp "$PR_DUP_BRANCHES_FILE" "$branches" || { echo "pr-dup-check: cannot read $PR_DUP_BRANCHES_FILE" >&2; exit 2; }
else
  git ls-remote --heads origin >"$branches" 2>/dev/null || {
    echo "pr-dup-check: git ls-remote failed; remote branches not checked" >&2
    : >"$branches"
  }
fi
self="${PR_DUP_SELF_BRANCH-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)}"
while IFS= read -r line; do
  name="${line##*refs/heads/}"
  name="${name#origin/}"
  name="${name##*[[:space:]]}"
  [ -n "$name" ] || continue
  [ "$name" != "$self" ] || continue
  printf 'branch%s%s%s' "$US" "$name" "$RS"
done <"$branches" >"$tmp/branch-records"
while IFS=$'\t' read -r _ name; do
  [ -n "$name" ] || continue
  echo "remote branch already carries $id: $name"
  found=1
done < <(matches <"$tmp/branch-records")

if [ "$found" -ne 0 ]; then
  echo "pr-dup-check: $id already has an open PR or branch; push revisions there instead of opening a new PR (docs/peer-pr-checklist.md)" >&2
  exit 1
fi
exit 0
