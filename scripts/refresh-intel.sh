#!/usr/bin/env bash
# refresh-intel.sh — download fresh EPSS and CISA KEV snapshots into intel/data/, and update the
# EPSSModelVersion / SnapshotDate consts in intel/intel.go to match (both are go:embed'd into the
# binary at build time, so the Go consts must track the data files exactly or the code and the
# embedded snapshot silently drift apart).
#
# Usage: run from the ferralon-assay module root.
#   ./scripts/refresh-intel.sh
#
# Exits non-zero (no files touched beyond the download) if the EPSS header doesn't parse — a
# malformed/unexpected upstream format must fail loud, never silently leave stale consts in place.
set -euo pipefail

MODULE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INTEL_DATA="${MODULE_ROOT}/intel/data"
INTEL_GO="${MODULE_ROOT}/intel/intel.go"

echo "Refreshing KEV catalog..."
curl -fsSL \
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
  -o "${INTEL_DATA}/kev.json"
echo "  -> wrote ${INTEL_DATA}/kev.json"

echo "Refreshing EPSS scores..."
curl -fsSL -L \
  "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz" \
  -o "${INTEL_DATA}/epss.csv.gz"
echo "  -> wrote ${INTEL_DATA}/epss.csv.gz"

# Process substitution (not a `| head` pipe): under `set -o pipefail`, head closing the pipe after
# one line sends gunzip a SIGPIPE, and gunzip's non-zero (128+13) exit status then fails the whole
# assignment even though the header was read successfully. `< <(...)` keeps gunzip out of the
# pipeline whose status this command substitution reports.
HEADER=$(head -1 < <(gunzip -c "${INTEL_DATA}/epss.csv.gz"))
echo ""
echo "New EPSS header: ${HEADER}"

# Header shape: #model_version:v2026.06.15,score_date:2026-06-17T12:03:21Z
MODEL_VERSION=$(echo "${HEADER}" | grep -oE 'model_version:[^,]+' | cut -d: -f2)
SCORE_DATE=$(echo "${HEADER}" | grep -oE 'score_date:[0-9]{4}-[0-9]{2}-[0-9]{2}' | cut -d: -f2)

if [ -z "${MODEL_VERSION}" ] || [ -z "${SCORE_DATE}" ]; then
  echo "ERROR: could not parse model_version/score_date from EPSS header: ${HEADER}" >&2
  echo "       intel/intel.go was NOT updated — fix the parse before relying on this run." >&2
  exit 1
fi

echo "Updating ${INTEL_GO}: EPSSModelVersion=${MODEL_VERSION}, SnapshotDate=${SCORE_DATE}"
sed -i.bak \
  -e "s/^const EPSSModelVersion = \".*\"/const EPSSModelVersion = \"${MODEL_VERSION}\"/" \
  -e "s/^const SnapshotDate = \".*\"/const SnapshotDate = \"${SCORE_DATE}\"/" \
  "${INTEL_GO}"
rm -f "${INTEL_GO}.bak"

if ! grep -qF "const EPSSModelVersion = \"${MODEL_VERSION}\"" "${INTEL_GO}" \
   || ! grep -qF "const SnapshotDate = \"${SCORE_DATE}\"" "${INTEL_GO}"; then
  echo "ERROR: post-write check failed — ${INTEL_GO} does not carry the expected consts." >&2
  exit 1
fi
echo "  -> ${INTEL_GO} updated and verified"
