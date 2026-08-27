#!/usr/bin/env bash
# build-release.sh — the ONE recipe that produces the Ferralon Assay scanner release tarball.
#
# WHY IT LIVES INSIDE THE PUBLISHED TREE. Two surfaces build this release, and they must build it
# identically:
#
#   1. this repository's own release workflow (.github/workflows/release.yml), which is what a
#      consumer can read and re-run to check the pinned asset for themselves;
#   2. the operator cut script in the private monorepo (deploy/assay/publish.sh), which is NOT
#      published and which no consumer can ever see.
#
# Before this file existed the recipe lived only in (2), so the public repo shipped source it had no
# way to build. The obvious fix — a workflow that re-lists the binaries, the ldflags and the
# packaging flags beside the cut script — is the same value spelled in two places with nothing
# reconciling them: the first time someone adds a language, one of the two silently ships the wrong
# binary set and the tarball stops being reproducible across the two surfaces. So there is exactly
# one target table and exactly one set of build flags, and they are here.
#
# USAGE — run from anywhere; the module root is derived from $0, and <destdir> may be relative.
#   scripts/build-release.sh name    <version>                   -> the tarball filename
#   scripts/build-release.sh binaries                            -> the baked asset names, one/line
#   scripts/build-release.sh members                             -> the tar members, in tar order
#   scripts/build-release.sh build   <version> <destdir>            compile + stage NOTICE
#   scripts/build-release.sh verify  <destdir>                      fail-closed payload check
#   scripts/build-release.sh package <destdir> <tarball-path>     -> the tarball sha256
#   scripts/build-release.sh release <version> <destdir>          -> the tarball sha256
#                                                                    (build + verify + package,
#                                                                     writes <destdir>/<name> and
#                                                                     <destdir>/<name>.sha256)
#
# ENVIRONMENT — all optional; the defaults ARE the release posture.
#   TARGET_GOOS / TARGET_GOARCH   cross-compile target. Default linux/amd64 (native Go
#                                 cross-compile — no docker, no QEMU).
#   REPRO_EPOCH                   mtime stamped on every tar member, in seconds since the Unix
#                                 epoch. Default 1577836800 (2020-01-01T00:00:00Z). An epoch, not a
#                                 wall-clock stamp, because a wall-clock stamp has a timezone.
#   CLEAN=1                       force a full rebuild (`go build -a`).
#   BAKE INPUTS — properties of THIS cut, not of the caller's repository, folded into the same
#   -ldflags string as the version stamp. Empty by default, which is a valid (revoke-inert,
#   endpoint-inert) release: the OSS/dogfood build.
#   ASSAY_REVOKE_PUBKEY / ASSAY_REVOKE_KEY_ID   self-cleanup revoke-signing public key + key id.
#   ASSAY_INGEST_URL / ASSAY_RUNS_URL           the two Ferralon endpoints.
#
# REPRODUCIBILITY — the whole point. Same version + same bake inputs + same source + same Go
# toolchain -> byte-identical tarball, on any host. Everything that could vary is pinned:
#   GOWORK=off      resolve the module from ./go.mod alone. In this repo there is no go.work; in
#                   the monorepo there is, and disabling it is what makes this build a proof that
#                   the published tree is self-contained rather than quietly bridged to a sibling
#                   module. Same env either way, so the same bytes either way.
#   CGO_ENABLED=0   pure-Go static binaries; no host toolchain leaks in.
#   -trimpath       strips absolute build paths — determinism, and it also keeps the operator's
#                   checkout path out of a public artifact.
#   -buildvcs=false drops the embedded VCS stamp (revision/time/dirty), which differs per checkout.
#   -buildid=       pins the Go build id to empty.
#   -s -w           strips the symbol table + DWARF.
#   scripts/repropack   the archive itself. It replaced `touch -t` + tar + gzip, none of which were
#                   pinnable: `touch -t` reads local time, so the digest moved with the operator's
#                   timezone; `--format=ustar` is a header layout that bsdtar and GNU tar fill in
#                   differently; and Apple gzip and GNU gzip compress the same bytes differently.
#                   Every header field and the compressor are now written by one implementation.
# NOT pinned by this script: the Go toolchain version. Two different toolchains produce two
# different binaries, correctly — and, now that the archive is written in Go, two different
# archives. Every caller must pin it (CI does so with actions/setup-go). That is the whole of the
# remaining variance: same source + same bake inputs + same toolchain -> same bytes, on any host,
# in any timezone, whatever tar and gzip it ships.
set -euo pipefail

MODULE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE_PATH="github.com/ferralon-ai/ferralon-assay"

TARGET_GOOS="${TARGET_GOOS:-linux}"
TARGET_GOARCH="${TARGET_GOARCH:-amd64}"
REPRO_EPOCH="${REPRO_EPOCH:-1577836800}"   # 2020-01-01T00:00:00Z
CLEAN="${CLEAN:-0}"
ASSAY_REVOKE_PUBKEY="${ASSAY_REVOKE_PUBKEY:-}"
ASSAY_REVOKE_KEY_ID="${ASSAY_REVOKE_KEY_ID:-}"
ASSAY_INGEST_URL="${ASSAY_INGEST_URL:-}"
ASSAY_RUNS_URL="${ASSAY_RUNS_URL:-}"

# ---- the target table -------------------------------------------------------
# <baked asset name>=<cmd package>. The CLI plus the per-language analyzer plugins. The ASSET names
# are codename-free because they ship to customers; the cmd/ package paths are not, and stay as they
# are — cmd/tegron-plugin-* is this repository's package layout, not a released name.
#
# ORDER IS LOAD-BEARING. It is the tar member order, and member order is part of the
# byte-identical-tarball guarantee. APPEND, never insert.
BAKED_TARGETS=(
  ferralon-assay-scan=./cmd/ferralon-assay
  ferralon-assay-scan-plugin=./cmd/tegron-plugin-go
  ferralon-assay-scan-plugin-python=./cmd/tegron-plugin-python
  ferralon-assay-scan-plugin-js=./cmd/tegron-plugin-js
  ferralon-assay-scan-plugin-java=./cmd/tegron-plugin-java
  ferralon-assay-scan-plugin-dotnet=./cmd/tegron-plugin-dotnet
  ferralon-assay-scan-plugin-kotlin=./cmd/tegron-plugin-kotlin
)

BAKED_BINARIES=()
for _t in "${BAKED_TARGETS[@]}"; do BAKED_BINARIES+=("${_t%%=*}"); done
# Everything the tarball carries, in that fixed order: the binaries plus the attribution NOTICE.
# Kept separate from BAKED_BINARIES so `verify` can still say exactly "did the compiler produce
# every binary" independently of "did the attribution file get staged".
TARBALL_MEMBERS=("${BAKED_BINARIES[@]}" NOTICE)

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# absdir <path> — create it if absent and echo its absolute path. Every path this script hands to
# `go build -o` or `tar -C` must be absolute, because the build runs with `go -C ${MODULE_ROOT}`
# and would otherwise resolve a relative destination against the module root instead of the
# caller's working directory.
absdir() {
  install -d "$1"
  (cd -- "$1" && pwd)
}

tarball_name() {   # <version>
  printf 'ferralon-assay-scanner_%s_%s_%s.tar.gz\n' "$1" "${TARGET_GOOS}" "${TARGET_GOARCH}"
}

# ldflags_for <version> — the single -ldflags string every binary is built with.
#
# -X stamps THE version symbol: package brand's Version var. Deliberately the brand package and not
# `main`, because brand.Version is what BOTH surfaces read — the CLI `version` subcommand and,
# through brand.AnalyzerVersion(), the customer-facing provenance in report.json, the Tier-0/Tier-1
# analyzer line, and the SARIF driver block. brand.Version is a var precisely so this -X lands; if
# it is ever changed back to a const the linker cannot patch it and every release silently reports
# itself as "ferralon-assay/dev" again.
#
# The bake inputs fold into the SAME string, so the reproducibility invariant reads "same version +
# same key + same endpoints -> identical binary".
ldflags_for() {
  local v="$1"
  local f="-s -w -buildid= -X ${MODULE_PATH}/internal/brand.Version=${v}"
  if [[ -n "${ASSAY_REVOKE_PUBKEY}" ]]; then
    f+=" -X ${MODULE_PATH}/internal/selfcleanup.bakedRevokePubKey=${ASSAY_REVOKE_PUBKEY}"
  fi
  if [[ -n "${ASSAY_REVOKE_KEY_ID}" ]]; then
    f+=" -X ${MODULE_PATH}/internal/selfcleanup.bakedRevokeKeyID=${ASSAY_REVOKE_KEY_ID}"
  fi
  if [[ -n "${ASSAY_INGEST_URL}" ]]; then
    f+=" -X main.bakedIngestURL=${ASSAY_INGEST_URL}"
  fi
  if [[ -n "${ASSAY_RUNS_URL}" ]]; then
    f+=" -X main.bakedRunsURL=${ASSAY_RUNS_URL}"
  fi
  printf '%s' "${f}"
}

# build_into <version> <destdir> — stage the full release payload into destdir.
#
# It also stages NOTICE, because the tarball is a DISTRIBUTION of a derivative work: the scanner
# statically links google.golang.org/grpc (Apache-2.0, ships a NOTICE), so Apache-2.0 section 4(d)
# obliges the tarball to carry that attribution. This repository vendors nothing, so the obligation
# lands on the binary artifact and nowhere else.
build_into() {
  local v="$1" dest name pkg t
  dest="$(absdir "$2")"

  local goflags=(-trimpath -buildvcs=false -ldflags "$(ldflags_for "${v}")")
  if [[ "${CLEAN}" == "1" ]]; then
    goflags+=(-a)
  fi

  for t in "${BAKED_TARGETS[@]}"; do
    name="${t%%=*}"
    pkg="${t#*=}"
    env GOWORK=off GOOS="${TARGET_GOOS}" GOARCH="${TARGET_GOARCH}" CGO_ENABLED=0 \
      go -C "${MODULE_ROOT}" build "${goflags[@]}" -o "${dest}/${name}" "${pkg}"
  done

  install -m 0644 "${MODULE_ROOT}/NOTICE" "${dest}/NOTICE"
}

# verify_payload <destdir> — fail closed; never package an incomplete payload.
verify_payload() {
  local dest b
  dest="$(cd -- "$1" && pwd)"
  for b in "${BAKED_BINARIES[@]}"; do
    if [[ ! -s "${dest}/${b}" ]]; then
      echo "ERROR: build produced an incomplete set (missing/empty ${b} in ${dest})." >&2
      echo "       Aborting — NOTHING packaged." >&2
      exit 1
    fi
  done
  # Fail closed on the NOTICE too. A dropped attribution file is silent at every later step — the
  # tarball still builds, still pins, still publishes — so it has to be caught here.
  if [[ ! -s "${dest}/NOTICE" ]]; then
    echo "ERROR: NOTICE missing/empty in ${dest} (expected staged from ${MODULE_ROOT}/NOTICE)." >&2
    echo "       The release tarball statically links Apache-2.0 code that ships a NOTICE;" >&2
    echo "       publishing it without one drops an attribution obligation. Aborting." >&2
    exit 1
  fi
}

# package_into <srcdir> <tarball-path> — reproducibly package + echo the tarball sha256.
#
# Both paths are absolutized first: `go -C` runs the packer with the module root as its working
# directory, so a relative -C or -o would resolve against the module instead of against the caller.
package_into() {
  local src out
  src="$(cd -- "$1" && pwd)"
  out="$(absdir "$(dirname -- "$2")")/$(basename -- "$2")"
  # GOOS/GOARCH are cleared, not inherited: the packer is the one thing here that RUNS on the build
  # host rather than shipping to the target, and an ambient GOOS=linux in the caller's environment
  # would otherwise cross-compile it and fail to execute it.
  env GOWORK=off GOOS= GOARCH= go -C "${MODULE_ROOT}" run ./scripts/repropack \
    -C "${src}" -o "${out}" -epoch "${REPRO_EPOCH}" "${TARBALL_MEMBERS[@]}"
  sha256_of "${out}"
}

usage() {
  sed -n '/^# USAGE/,/^#$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

case "${1:-}" in
  name)
    [[ $# -eq 2 ]] || usage
    tarball_name "$2"
    ;;
  # The two lists, for a caller that has to name or count them — an operator script's dry-run
  # banner, a release note. Exposed so no caller ever re-types the table.
  binaries)
    [[ $# -eq 1 ]] || usage
    printf '%s\n' "${BAKED_BINARIES[@]}"
    ;;
  members)
    [[ $# -eq 1 ]] || usage
    printf '%s\n' "${TARBALL_MEMBERS[@]}"
    ;;
  build)
    [[ $# -eq 3 ]] || usage
    build_into "$2" "$3"
    ;;
  verify)
    [[ $# -eq 2 ]] || usage
    verify_payload "$2"
    ;;
  package)
    [[ $# -eq 3 ]] || usage
    package_into "$2" "$3"
    ;;
  release)
    [[ $# -eq 3 ]] || usage
    VERSION="$2"
    DEST="$(absdir "$3")"
    TARBALL="$(tarball_name "${VERSION}")"
    build_into "${VERSION}" "${DEST}"
    verify_payload "${DEST}"
    SHA="$(package_into "${DEST}" "${DEST}/${TARBALL}")"
    printf '%s  %s\n' "${SHA}" "${TARBALL}" > "${DEST}/${TARBALL}.sha256"
    printf '%s\n' "${SHA}"
    ;;
  *)
    usage
    ;;
esac
