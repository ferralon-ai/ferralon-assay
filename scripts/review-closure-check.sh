#!/usr/bin/env bash
# review-closure-check.sh <findings-file> [base-ref]
#
# Checks that every review finding saved in <findings-file> is closed before a revision is pushed.
# A finding is one line, `path[:line] - text`. It is closed when its path appears in the diff
# `base-ref...HEAD` (base-ref defaults to origin/main), or when the same line is listed under an
# `## Answered` heading as `<finding line> => <reason>` with a non-empty reason. A finding with no
# path can only be closed by an answer.
#
# Prints one `OPEN: <finding>` line per unaddressed finding and exits 1; prints
# `review-closure-check: OK` and exits 0 when all are closed. Exit 2 is a usage or git error.
set -u

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "usage: review-closure-check.sh <findings-file> [base-ref]" >&2
  exit 2
fi
file=$1
base=${2:-origin/main}
if [ ! -f "$file" ]; then
  echo "review-closure-check: no such file: $file" >&2
  exit 2
fi
changed=$(git diff --name-only "$base...HEAD" 2>&1) || {
  echo "review-closure-check: git diff $base...HEAD failed: $changed" >&2
  exit 2
}

trim() {
  local s=$1
  s="${s#"${s%%[![:space:]]*}"}"
  printf '%s' "${s%"${s##*[![:space:]]}"}"
}

findings=()
answered=() # finding lines that carry a non-empty reason
in_answered=0
while IFS= read -r raw || [ -n "$raw" ]; do
  line=$(trim "${raw%$'\r'}")
  case $line in
    '') continue ;;
    '## Answered'*) in_answered=1; continue ;;
    '#'*) in_answered=0; continue ;;
  esac
  case $line in
    '- '* | '* '*) line=$(trim "${line:2}") ;;
  esac
  if [ "$in_answered" = 1 ]; then
    case $line in
      *' => '*)
        reason=$(trim "${line##* => }")
        [ -n "$reason" ] && answered+=("$(trim "${line%% => *}")")
        ;;
    esac
  else
    findings+=("$line")
  fi
done <"$file"

open=0
for f in ${findings[@]+"${findings[@]}"}; do
  closed=0
  case $f in
    *' - '*)
      loc=${f%% - *}
      path=${loc%%:*}
      # A path is a single token; anything with spaces before " - " is prose, not a location.
      case $path in
        *[[:space:]]* | '') ;;
        *) printf '%s\n' "$changed" | grep -Fxq -- "$path" && closed=1 ;;
      esac
      ;;
  esac
  if [ "$closed" = 0 ]; then
    for a in ${answered[@]+"${answered[@]}"}; do
      [ "$a" = "$f" ] && closed=1 && break
    done
  fi
  if [ "$closed" = 0 ]; then
    echo "OPEN: $f"
    open=$((open + 1))
  fi
done

if [ "$open" -gt 0 ]; then
  exit 1
fi
echo "review-closure-check: OK"
