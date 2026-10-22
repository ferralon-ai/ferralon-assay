#!/usr/bin/env bash
# install-cosign.sh — download the pinned cosign release binary and verify its sha256 before anything
# runs it. Called by action.yml's corpus-bundle step, ahead of scripts/fetch-corpus-bundle.sh, which
# uses it to verify the corpus release signature. Also runnable by hand.
#
# Inputs (env):
#   DEST           directory the verified binary is written into, as DEST/cosign
#   COSIGN_GITHUB  (optional) base URL for release downloads, default https://github.com
#
# Output: DEST/cosign, executable, only after its sha256 matched the pin below. Put DEST first on
# PATH for the fetch script.
#
# THE PIN. The version and the digest are fixed here, not inputs: a caller cannot swap in other
# bytes, and a different cosign is a reviewed change to this file. The digest is the
# cosign-linux-amd64 line of cosign_checksums.txt in the sigstore/cosign v3.1.3 release
# (https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign_checksums.txt), which matches
# the asset digest GitHub reports for that release. linux/amd64 only, like the scanner tarball.
#
# Presents NO credential: sigstore/cosign releases are public.
set -euo pipefail

COSIGN_VERSION="v3.1.3"
COSIGN_ASSET="cosign-linux-amd64"
COSIGN_SHA256="4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"

: "${DEST:?DEST is required}"
GH="${COSIGN_GITHUB:-https://github.com}"

unset GITHUB_TOKEN GH_TOKEN || true

die() {
  echo "::error::ferralon-assay: cosign: $*" >&2
  exit 1
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

command -v curl >/dev/null 2>&1 || die "curl is required to fetch cosign and was not found on this runner"

mkdir -p "$DEST"
rm -f "$DEST/cosign"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

url="$GH/sigstore/cosign/releases/download/$COSIGN_VERSION/$COSIGN_ASSET"
echo "==> Fetching cosign $COSIGN_VERSION ($COSIGN_ASSET)"
curl -fsSL --retry 3 --retry-connrefused -o "$WORK/cosign" "$url" ||
  die "could not download cosign $COSIGN_VERSION from $url; the runner needs to reach GitHub releases"
got="$(sha256_of "$WORK/cosign")"
[ "$got" = "$COSIGN_SHA256" ] ||
  die "cosign $COSIGN_VERSION download hashes to $got, not the pinned $COSIGN_SHA256; refusing to run it"

chmod 0755 "$WORK/cosign"
mv "$WORK/cosign" "$DEST/cosign"
echo "==> cosign $COSIGN_VERSION verified (sha256 $got): $DEST/cosign"
