#!/usr/bin/env bash
# pr-order-audit.sh — report order ids that more than one open PR carries.
#
# An order id is `ASY-<n>` or `eric-req-<slug>`, matched case-insensitively as a whole token in a
# PR's head branch or title: `ASY-09` does not match `ASY-099`, and `xasy-9` is not `ASY-9`. An
# eric-req slug is the whole hyphenated run after `eric-req-`, the rule scripts/githooks/pre-push
# uses: `eric-req-x/r2` and `eric-req-x_r2` carry `eric-req-x`, while `eric-req-x-r2` is another id.
#
# Input: the open PRs as JSON (number, title, headRefName). Live, from
#   gh pr list --state open --json number,title,headRefName
# or, when PR_ORDER_AUDIT_JSON names a file, from that file (offline, for tests).
#
# Exit: 0 no id has more than one open PR; 1 at least one does (each is printed with its PRs, sorted);
#       2 the listing could not be read (never "safe" on a failed read).
# The live listing stops at 500 PRs; when exactly 500 come back, stderr says the audit may be short.
set -uo pipefail

fail() { echo "pr-order-audit: $*" >&2; exit 2; }

command -v jq >/dev/null 2>&1 || fail "jq is required"

if [ -n "${PR_ORDER_AUDIT_JSON:-}" ]; then
  [ -r "$PR_ORDER_AUDIT_JSON" ] || fail "cannot read $PR_ORDER_AUDIT_JSON"
  listing=$(cat "$PR_ORDER_AUDIT_JSON") || fail "cannot read $PR_ORDER_AUDIT_JSON"
else
  command -v gh >/dev/null 2>&1 || fail "gh is required when PR_ORDER_AUDIT_JSON is unset"
  limit=500
  listing=$(gh pr list --state open --limit "$limit" --json number,title,headRefName) ||
    fail "gh pr list failed"
  if [ "$(printf '%s' "$listing" | jq 'if type == "array" then length else 0 end' 2>/dev/null)" = "$limit" ]; then
    echo "pr-order-audit: gh returned $limit open PRs, its listing limit; any past that were not checked" >&2
  fi
fi

rows=$(printf '%s' "$listing" |
  jq -r 'if type == "array" then .[] | [.number, .headRefName, .title] | @tsv else error("not an array") end') ||
  fail "listing is not a JSON array of pull requests"

printf '%s\n' "$rows" | awk -F '\t' '
  # ids(str): fill out[] with the whole-token order ids in str.
  function ids(str, out,    s, pos, rest, tok, pre, post) {
    s = tolower(str); pos = 1
    while (pos <= length(s)) {
      rest = substr(s, pos)
      if (!match(rest, /(asy-[0-9]+|eric-req-[a-z0-9]+(-[a-z0-9]+)*)/)) break
      tok = substr(rest, RSTART, RLENGTH)
      pre = (pos + RSTART - 1 > 1) ? substr(s, pos + RSTART - 2, 1) : ""
      post = substr(s, pos + RSTART - 1 + RLENGTH, 1)
      if (pre !~ /[a-z0-9]/ && post !~ /[a-z0-9]/) {
        out[tok] = 1
        pos += RSTART - 1 + RLENGTH
      } else {
        pos += RSTART
      }
    }
  }
  NF >= 3 {
    delete found
    ids($2, found); ids($3, found)
    for (id in found) {
      n[id]++
      list[id] = list[id] (n[id] > 1 ? ", " : "") "#" $1 " (" $2 ")"
    }
  }
  END {
    dup = 0
    for (id in n) if (n[id] > 1) {
      shown = id; if (shown ~ /^asy-/) shown = toupper(shown)
      print shown ": " n[id] " open PRs: " list[id]
      dup = 1
    }
    exit dup
  }' | LC_ALL=C sort
