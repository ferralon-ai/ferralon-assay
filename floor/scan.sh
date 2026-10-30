#!/usr/bin/env bash
# floor/scan.sh — scan one checked-out demo repository with the floor run's own scanner build.
# Called by .github/workflows/floor.yml's scan job; docs/floor.md describes the run.
#
# Inputs (env):
#   BIN_DIR        the build job's artifact: ferralon-assay, assay-plugin-<lang>, and corpus/ holding
#                  the verified <policy>.jsonl.gz bundle and signals.json.gz
#   TARGET_DIR     the checked-out demo repository
#   OUT_DIR        where report.json and the projections go, and where this script records
#                  exit_code and duration_seconds for the meta step
#   POLICY         the corpus policy the bundle was fetched for
#   SUBJECT_REPO   owner/name recorded on the Report
#   REVISION       the ref recorded on the Report; empty records the checked-out branch
#   HOUSE_CANARIES 'true' to include the first-party house-canary advisories, as the target's own
#                  workflow does
#   SCAN_TIMEOUT   the scanner's own time limit (e.g. 22m), set below the job's timeout so the scan
#                  ends itself and publishes what it assessed
#   CORPUS_SIGNER_IDENTITY, CORPUS_SIGNER_ISSUER
#                  the signer the build job verified the corpus release against, recorded on the Report
set -euo pipefail

: "${BIN_DIR:?}" "${TARGET_DIR:?}" "${OUT_DIR:?}" "${POLICY:?}" "${SUBJECT_REPO:?}"
: "${SCAN_TIMEOUT:?}" "${CORPUS_SIGNER_IDENTITY:?}" "${CORPUS_SIGNER_ISSUER:?}"

# The artifact round trip drops the executable bit.
chmod +x "$BIN_DIR/ferralon-assay" "$BIN_DIR"/assay-plugin-*
# The scanner finds the analyzer for the detected language on PATH as assay-plugin-<lang>.
export PATH="$BIN_DIR:$PATH"

# This job's GITHUB_* context is ferralon-assay's, not the scanned repository's: the scanner's
# GitHub surfaces stay off, and the console link stays unset, so the scan writes only OUT_DIR and
# this job's summary.
export ASSAY_ISSUE=0 ASSAY_PR_COMMENT=0 ASSAY_CODE_SCANNING=0
export ASSAY_ADVISORY_CORPUS_SIGNER_IDENTITY="$CORPUS_SIGNER_IDENTITY"
export ASSAY_ADVISORY_CORPUS_SIGNER_ISSUER="$CORPUS_SIGNER_ISSUER"
unset FERRALON_LINK_TO_CONSOLE GITHUB_TOKEN GH_TOKEN || true

mkdir -p "$OUT_DIR"
commit="$(git -C "$TARGET_DIR" rev-parse HEAD)"
revision="${REVISION:-$(git -C "$TARGET_DIR" rev-parse --abbrev-ref HEAD)}"
args=(
  baseline
  -target "$TARGET_DIR"
  -out "$OUT_DIR"
  -subject-repo "$SUBJECT_REPO"
  -revision "$revision"
  -commit "$commit"
  -advisory-corpus "$BIN_DIR/corpus/$POLICY.jsonl.gz"
  -advisory-corpus-policy "$POLICY"
  -advisory-signals "$BIN_DIR/corpus/signals.json.gz"
  -require-advisory-corpus
  -scan-timeout "$SCAN_TIMEOUT"
)
if [ "${HOUSE_CANARIES:-}" = "true" ]; then
  args+=(-include-house-canaries)
fi

# On a job timeout or cancellation the runner signals this shell, not the scanner, and bash runs a
# trap only once its foreground child exits. So the scanner runs in the background and the first
# signal is forwarded as TERM; the scanner then stops analysis and publishes what it has (the same
# handling as action.yml's run step).
start="$(date +%s)"
"$BIN_DIR/ferralon-assay" "${args[@]}" &
scan_pid=$!
signalled=0
forwarded=0
trap 'signalled=1; if [ "$forwarded" = 0 ]; then forwarded=1; kill -TERM "$scan_pid" 2>/dev/null || true; fi' INT TERM
while :; do
  signalled=0
  rc=0
  wait "$scan_pid" || rc=$?
  [ "$signalled" = 1 ] || break
done

echo "$rc" > "$OUT_DIR/exit_code"
echo "$(( $(date +%s) - start ))" > "$OUT_DIR/duration_seconds"
exit "$rc"
