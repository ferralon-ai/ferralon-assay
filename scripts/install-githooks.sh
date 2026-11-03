#!/usr/bin/env bash
# install-githooks.sh — point this clone's core.hooksPath at the tracked scripts/githooks.
# Idempotent: running it again leaves the same setting.
set -euo pipefail

root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
git -C "$root" config core.hooksPath scripts/githooks
echo "core.hooksPath = $(git -C "$root" config --get core.hooksPath)"
