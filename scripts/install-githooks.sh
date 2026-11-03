#!/usr/bin/env bash
# install-githooks.sh [--force] — point this clone's core.hooksPath at the tracked scripts/githooks.
# Idempotent: running it again leaves the same setting.
#
# When core.hooksPath already names another directory (a .husky, say), it prints that value and
# stops without changing anything (exit 1); --force replaces it. Before switching, it lists the
# executable hooks (other than *.sample) in the directory git runs hooks from now, since git stops
# running them once core.hooksPath points elsewhere.
set -euo pipefail

force=0
case "${1:-}" in
  "") ;;
  --force) force=1 ;;
  *) echo "usage: install-githooks.sh [--force]" >&2; exit 2 ;;
esac

want=scripts/githooks
root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
current=$(git -C "$root" config --get core.hooksPath || true)

if [ "$current" = "$want" ]; then
  echo "core.hooksPath = $want (already set)"
  exit 0
fi

# The directory git runs hooks from today: core.hooksPath if set, else the clone's hooks directory.
dir=$(git -C "$root" rev-parse --git-path hooks)
case "$dir" in /*) ;; *) dir="$root/$dir" ;; esac
active=()
if [ -d "$dir" ]; then
  for f in "$dir"/*; do
    [ -f "$f" ] && [ -x "$f" ] && [[ "$f" != *.sample ]] && active+=("${f##*/}")
  done
fi

if [ -n "$current" ] && [ "$force" != 1 ]; then
  echo "install-githooks: core.hooksPath is already '$current'; leaving it unchanged." >&2
  [ "${#active[@]}" -gt 0 ] && echo "  These hooks in $dir would stop running: ${active[*]}" >&2
  echo "  Re-run with --force to replace it." >&2
  exit 1
fi

git -C "$root" config core.hooksPath "$want"
echo "core.hooksPath = $(git -C "$root" config --get core.hooksPath)"
[ -n "$current" ] && echo "  (was '$current')"
if [ "${#active[@]}" -gt 0 ]; then
  echo "install-githooks: git no longer runs these hooks in $dir: ${active[*]}" >&2
fi
exit 0
