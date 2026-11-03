#!/usr/bin/env bash
# pr-order-audit.sh — report order ids that more than one open PR carries.
#
# An order id is `ASY-<n>` or `eric-req-<slug>`, matched case-insensitively as a whole token in a
# PR's head branch or title: `ASY-09` does not match `ASY-099`, and `xasy-9` is not `ASY-9`.
#
# Input: the open PRs as JSON (number, title, headRefName). Live, from
#   gh pr list --state open --json number,title,headRefName
# or, when PR_ORDER_AUDIT_JSON names a file, from that file (offline, for tests).
#
# Exit: 0 no id has more than one open PR; 1 at least one does (each is printed with its PRs);
#       2 the listing could not be read (never "safe" on a failed read).
set -uo pipefail

fail() { echo "pr-order-audit: $*" >&2; exit 2; }

command -v jq >/dev/null 2>&1 || fail "jq is required"

if [ -n "${PR_ORDER_AUDIT_JSON:-}" ]; then
  [ -r "$PR_ORDER_AUDIT_JSON" ] || fail "cannot read $PR_ORDER_AUDIT_JSON"
  listing=$(cat "$PR_ORDER_AUDIT_JSON") || fail "cannot read $PR_ORDER_AUDIT_JSON"
else
  command -v gh >/dev/null 2>&1 || fail "gh is required when PR_ORDER_AUDIT_JSON is unset"
  listing=$(gh pr list --state open --limit 500 --json number,title,headRefName) ||
    fail "gh pr list failed"
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
  }'
