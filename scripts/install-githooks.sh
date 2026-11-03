#!/usr/bin/env bash
# install-githooks.sh [--force] — point this clone's core.hooksPath at the tracked scripts/githooks.
# Idempotent: running it again leaves the same setting. A value that names the same directory in
# another spelling (./scripts/githooks, or the absolute path to it) counts as already set.
#
# When core.hooksPath already names another directory (a .husky, say), it prints that value and the
# config it comes from (local, global, ...) and stops without changing anything (exit 1); --force
# sets scripts/githooks in this clone's local config. A global or system setting is never changed:
# the local value overrides it in this clone only. Before switching, it lists the executable hooks
# (other than *.sample) in the directory git runs hooks from now, since git stops running them once
# core.hooksPath points elsewhere.
set -euo pipefail

force=0
case "${1:-}" in
  "") ;;
  --force) force=1 ;;
  *) echo "usage: install-githooks.sh [--force]" >&2; exit 2 ;;
esac

want=scripts/githooks
root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
# "<scope><TAB><value>" for the core.hooksPath git uses, or nothing when it is unset.
line=$(git -C "$root" config --show-scope --get core.hooksPath || true)
scope=${line%%$'\t'*}
current=${line#*$'\t'}

# resolve <hooksPath>: the directory a core.hooksPath value names. git reads a relative value from
# the top of the working tree and expands a leading ~/.
resolve() {
  local p=$1
  case "$p" in
    "~/"*) p="$HOME/${p#"~/"}" ;;
    /*) ;;
    *) p="$root/$p" ;;
  esac
  if [ -d "$p" ]; then (cd "$p" && pwd -P); else printf '%s\n' "${p%/}"; fi
}

if [ -n "$current" ] && [ "$(resolve "$current")" = "$(resolve "$want")" ]; then
  echo "core.hooksPath = $current (already set, $scope config)"
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
  echo "install-githooks: core.hooksPath is already '$current' ($scope config); leaving it unchanged." >&2
  [ "${#active[@]}" -gt 0 ] && echo "  These hooks in $dir would stop running: ${active[*]}" >&2
  if [ "$scope" = local ]; then
    echo "  Re-run with --force to replace it." >&2
  else
    echo "  Re-run with --force to override it in this clone's local config; the $scope setting itself is left alone." >&2
  fi
  exit 1
fi

git -C "$root" config core.hooksPath "$want"
if [ -z "$current" ]; then
  echo "core.hooksPath = $want"
elif [ "$scope" = local ]; then
  echo "core.hooksPath = $want (was '$current')"
else
  echo "core.hooksPath = $want in local config (overrides '$current' from $scope config, which is left unchanged)"
fi
if [ "${#active[@]}" -gt 0 ]; then
  echo "install-githooks: git no longer runs these hooks in $dir: ${active[*]}" >&2
fi
exit 0
