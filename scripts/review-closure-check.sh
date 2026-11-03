#!/usr/bin/env bash
# review-closure-check.sh <findings-file> <reviewed-sha>
#
# Checks that every review finding saved in <findings-file> is closed before a revision is pushed.
# <reviewed-sha> is the head the review covered, and the revision is the diff `<reviewed-sha>...HEAD`.
# That diff is the revision only while <reviewed-sha> is an ancestor of HEAD and no merge commit
# follows it, so a rebase since the review, or a merge into the branch, exits 2.
# A finding is one line, `path[:line] - text`; backticks around the location are ignored. A finding
# with `:line` is closed when a hunk of the revision covers that line or is inserted next to it. A
# finding with only a path prints `TOUCHED` when the path changed: a changed path is a hint, not
# proof, so it stays unclosed. Any finding is closed when it is listed under an `## Answered`
# heading as `<finding line> => <reason>` with a non-empty reason, split at the last ` =>`; that
# entry is itself a finding, so it need not also be listed above the heading. A line there with no
# reason is read as a finding.
#
# Prints one `OPEN: <finding>` or `TOUCHED: <finding>` line per finding that is not closed and
# exits 1; prints `review-closure-check: OK` and exits 0 when all are closed. Exit 2 is a usage or
# git error, an unreadable findings file, a file with no findings in it, a reviewed head that is
# not an ancestor of HEAD, or a merge commit since the reviewed head.
set -u

if [ $# -ne 2 ]; then
  echo "usage: review-closure-check.sh <findings-file> <reviewed-sha>" >&2
  exit 2
fi
file=$1
base=$2
if [ ! -f "$file" ] || [ ! -r "$file" ]; then
  echo "review-closure-check: cannot read findings file: $file" >&2
  exit 2
fi

# trim sets $trimmed to its argument without surrounding whitespace, without a subshell.
trim() {
  trimmed="${1#"${1%%[![:space:]]*}"}"
  trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
}

findings=()
nfindings=0
add_finding() {
  local f
  for f in ${findings[@]+"${findings[@]}"}; do
    [ "$f" = "$1" ] && return
  done
  findings+=("$1")
  nfindings=$((nfindings + 1))
}

# A heading is one or more `#` then whitespace, so `#409 duplicates the parser` is a finding.
heading_re='^#+[[:space:]]'
answered=() # finding lines that carry a non-empty reason
in_answered=0
while IFS= read -r raw || [ -n "$raw" ]; do
  trim "${raw%$'\r'}"
  line=$trimmed
  [ -z "$line" ] && continue
  if [[ $line =~ $heading_re ]]; then
    case $line in
      '## Answered'*) in_answered=1 ;;
      *) in_answered=0 ;;
    esac
    continue
  fi
  case $line in
    '- '* | '* '*) trim "${line:2}" && line=$trimmed ;;
  esac
  if [ "$in_answered" = 1 ]; then
    case $line in
      *' =>'*)
        # Split at the last arrow, so a finding whose own text holds ` =>` can still be answered.
        trim "${line##* =>}" && reason=$trimmed
        trim "${line% =>*}" && line=$trimmed
        if [ -n "$reason" ]; then
          add_finding "$line"
          answered+=("$line")
          continue
        fi
        ;;
    esac
  fi
  add_finding "$line"
done <"$file"

if [ "$nfindings" -eq 0 ]; then
  echo "review-closure-check: no findings in $file" >&2
  exit 2
fi

# Resolve the base before any other git command sees it, so a value starting with `-` is never
# read as an option.
if ! rev=$(git rev-parse --verify --quiet --end-of-options "$base^{commit}"); then
  echo "review-closure-check: not a commit: $base" >&2
  exit 2
fi
# `<rev>...HEAD` diffs from the merge base. After a rebase the reviewed head is no longer an
# ancestor and the merge base falls back to the branch point, and after a merge of the default
# branch the diff carries its changes, so either would close findings the revision never touched.
git merge-base --is-ancestor "$rev" HEAD
case $? in
  0) ;;
  1)
    echo "review-closure-check: the reviewed head $base is not an ancestor of HEAD (rebased since the review?); transcribe the findings against the rebased commits" >&2
    exit 2
    ;;
  *)
    echo "review-closure-check: git merge-base --is-ancestor $rev HEAD failed" >&2
    exit 2
    ;;
esac
if ! merges=$(git rev-list --merges "$rev..HEAD" 2>&1); then
  echo "review-closure-check: git rev-list --merges $rev..HEAD failed: $merges" >&2
  exit 2
fi
if [ -n "$merges" ]; then
  echo "review-closure-check: merge commits since the reviewed head $base would put the merged changes in the diff; run the check on the revision before the merge" >&2
  exit 2
fi
diff=$(git diff --no-color --no-ext-diff --no-relative --src-prefix=a/ --dst-prefix=b/ -U0 "$rev...HEAD" 2>&1) || {
  echo "review-closure-check: git diff $rev...HEAD failed: $diff" >&2
  exit 2
}

# One pass over the diff keeps each file header and each hunk's start and length on the reviewed
# side, tagged with the index of its header. Content lines start with +, - or a space, so neither
# pattern can match one.
hunk_re='^@@ -([0-9]+)(,([0-9]+))? '
headers=()
hunks=()
nheaders=0
while IFS= read -r h; do
  case $h in
    'diff --git '*)
      headers+=("$h")
      nheaders=$((nheaders + 1))
      ;;
    '@@ -'*)
      [[ $h =~ $hunk_re ]] && hunks+=("$((nheaders - 1)) ${BASH_REMATCH[1]} ${BASH_REMATCH[3]:-1}")
      ;;
  esac
done <<<"$diff"

# changed <path>: sets $idx to the index of the header of the file the revision changed at <path>
# (either side of a rename), or fails.
changed() {
  idx=0
  while [ "$idx" -lt "$nheaders" ]; do
    case ${headers[$idx]} in
      "diff --git a/$1 b/"* | *" b/$1") return 0 ;;
    esac
    idx=$((idx + 1))
  done
  return 1
}

# covers <idx> <line>: a hunk of file <idx> covers <line> of the reviewed file, or inserts lines
# directly before or after it.
covers() {
  local hk start count
  for hk in ${hunks[@]+"${hunks[@]}"}; do
    [ "${hk%% *}" = "$1" ] || continue
    hk=${hk#* }
    start=${hk%% *}
    count=${hk#* }
    if [ "$count" -eq 0 ]; then
      if [ "$2" -eq "$start" ] || [ "$2" -eq $((start + 1)) ]; then return 0; fi
    elif [ "$2" -ge "$start" ] && [ "$2" -lt $((start + count)) ]; then
      return 0
    fi
  done
  return 1
}

open=0
for f in "${findings[@]}"; do
  state=OPEN
  case $f in
    *' - '*)
      loc=${f%% - *}
      loc=${loc//\`/}
      path=${loc%%:*}
      lineno=${loc#"$path"}
      lineno=${lineno#:}
      # A path is a single token; anything with spaces before " - " is prose, not a location.
      case $path in
        *[[:space:]]* | '') ;;
        *)
          if changed "$path"; then
            case $lineno in
              '' | *[!0-9]*) state=TOUCHED ;;
              *) covers "$idx" "$lineno" && state=closed ;;
            esac
          fi
          ;;
      esac
      ;;
  esac
  if [ "$state" != closed ]; then
    for a in ${answered[@]+"${answered[@]}"}; do
      [ "$a" = "$f" ] && state=closed && break
    done
  fi
  if [ "$state" != closed ]; then
    echo "$state: $f"
    open=$((open + 1))
  fi
done

if [ "$open" -gt 0 ]; then
  exit 1
fi
echo "review-closure-check: OK"
