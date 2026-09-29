#!/usr/bin/env bash
# resolve-scanner-version.sh — turn the Action's `scanner-version` input into the exact release tag
# to download. Called by action.yml's scanner fetch step; also runnable by hand.
#
# Inputs (env):
#   SCANNER_REPO     owner/repo hosting the scanner releases
#   SCANNER_VERSION  an exact release tag (vX.Y.Z) or a minor alias (vX.Y)
#   SCANNER_SHA256   (optional) the consumer's checksum pin; only valid with an exact vX.Y.Z
#   SCANNER_GITHUB   (optional) base URL for git, default https://github.com
#
# Output: the exact vX.Y.Z on stdout (one line). Diagnostics go to stderr.
#
# EXACT vX.Y.Z is returned as given, with no network access.
#
# ALIAS vX.Y resolves through the floating tag itself. release.yml moves `vX.Y` onto a release's
# minted leaf only after that release and its assets exist, and only when it is the highest patch on
# the minor. So the answer is the one `vX.Y.Z` tag whose commit is the commit `vX.Y` points at. That
# has no window in which a newer patch tag exists before its assets do, which "the highest vX.Y.Z tag"
# would have. Zero matches or more than one match fails the run rather than guessing.
#
# The lookup is a single unauthenticated `git ls-remote`: no token, no REST API rate limit. An alias
# therefore needs a publicly readable SCANNER_REPO; a private one takes an exact vX.Y.Z.
set -euo pipefail

: "${SCANNER_REPO:?SCANNER_REPO is required}"
SCANNER_VERSION="${SCANNER_VERSION:-}"
SCANNER_SHA256="${SCANNER_SHA256:-}"
GH="${SCANNER_GITHUB:-https://github.com}"

die() {
  echo "::error::ferralon-assay: $*" >&2
  exit 1
}

# Every value below reaches a URL or a ref pattern, so each is shape-checked before use.
[[ "${SCANNER_REPO}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ && "${SCANNER_REPO}" != *..* ]] \
  || die "scanner-repo '${SCANNER_REPO}' is not an owner/repo."

if [[ -z "${SCANNER_VERSION}" || "${SCANNER_VERSION}" == "REPLACE_WITH_RELEASE_TAG" ]]; then
  die "scanner-version is unset (still '${SCANNER_VERSION}'). Set it to a release tag (vX.Y.Z) or a minor alias (vX.Y) of ${SCANNER_REPO}."
fi

if [[ "${SCANNER_VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "==> scanner-version ${SCANNER_VERSION} is an exact release; no resolution needed" >&2
  printf '%s\n' "${SCANNER_VERSION}"
  exit 0
fi

if [[ ! "${SCANNER_VERSION}" =~ ^v[0-9]+\.[0-9]+$ ]]; then
  die "scanner-version '${SCANNER_VERSION}' is neither a release tag (vX.Y.Z) nor a minor alias (vX.Y)."
fi

ALIAS="${SCANNER_VERSION}"

# A checksum names one exact set of bytes; an alias names whichever patch is current. Pairing them
# either fails on the next patch release or silently means "only ever this patch", which is what an
# exact version already says.
if [[ -n "${SCANNER_SHA256}" && "${SCANNER_SHA256}" != "REPLACE_WITH_RELEASE_SHA256" ]]; then
  die "scanner-sha256 is set, but scanner-version '${ALIAS}' is a minor alias that follows the newest ${ALIAS}.Z patch. A checksum pins one exact release: set scanner-version to that vX.Y.Z as well, or clear scanner-sha256."
fi

REMOTE="${GH%/}/${SCANNER_REPO}.git"
echo "==> Resolving scanner-version ${ALIAS} against ${REMOTE}" >&2

# Present no credential: the alias must resolve for a stranger's runner exactly as it does here.
# The `^{}` pattern is what lists an annotated alias's peeled commit; the `.*` glob already lists
# the patch tags' peeled lines.
refs="$(
  unset GITHUB_TOKEN GH_TOKEN GIT_ASKPASS SSH_ASKPASS
  GIT_TERMINAL_PROMPT=0 git -c credential.helper= -c http.https://github.com/.extraheader= \
    ls-remote --tags "${REMOTE}" "refs/tags/${ALIAS}" "refs/tags/${ALIAS}^{}" "refs/tags/${ALIAS}.*"
)" || die "could not list tags of ${REMOTE} (an alias needs a publicly readable scanner-repo)."

# commit_of <tag> — the commit a tag names: its peeled ^{} line when annotated, else its direct line.
commit_of() {
  local tag="$1" peeled direct
  peeled="$(awk -v r="refs/tags/$tag^{}" '$2 == r {print $1}' <<<"${refs}")"
  direct="$(awk -v r="refs/tags/$tag" '$2 == r {print $1}' <<<"${refs}")"
  printf '%s\n' "${peeled:-$direct}"
}

target="$(commit_of "${ALIAS}")"
[[ -n "${target}" ]] || die "${SCANNER_REPO} has no tag ${ALIAS}, so the minor alias cannot resolve. Set scanner-version to an existing vX.Y alias or an exact vX.Y.Z."
[[ "${target}" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || die "tag ${ALIAS} names '${target}', which is not a commit id."

esc="${ALIAS//./\\.}"
matches=()
while IFS= read -r tag; do
  [[ -n "${tag}" ]] || continue
  if [[ "$(commit_of "${tag}")" == "${target}" ]]; then
    matches+=("${tag}")
  fi
done < <(awk '{print $2}' <<<"${refs}" | sed -n 's#^refs/tags/##p' | grep -E "^${esc}\.[0-9]+$" | sort -u || true)

case "${#matches[@]}" in
  1) ;;
  0) die "tag ${ALIAS} (${target}) is not the commit of any ${ALIAS}.Z release tag, so it names no release. Set scanner-version to an exact vX.Y.Z." ;;
  *) die "tag ${ALIAS} (${target}) matches more than one release (${matches[*]}); refusing to guess. Set scanner-version to an exact vX.Y.Z." ;;
esac

echo "==> scanner-version ${ALIAS} resolved to ${matches[0]}" >&2
printf '%s\n' "${matches[0]}"
