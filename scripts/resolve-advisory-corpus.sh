#!/usr/bin/env bash
# resolve-advisory-corpus.sh — turn the Action's advisory-corpus inputs into the corpus this run reads.
# Called by action.yml's "Resolve the advisory corpus" step; also runnable by hand.
#
# Inputs (env), each the raw Action input:
#   IN_CORPUS_DIR            advisory-corpus
#   IN_CORPUS_REPO           advisory-corpus-repo
#   IN_CORPUS_POLICY         advisory-corpus-policy
#   IN_SIGNER_IDENTITY       corpus-signer-identity
#   IN_SIGNER_ISSUER         corpus-signer-issuer
#   IN_BUILTIN_ONLY          builtin-test-advisories-only ("true" | "false" | empty)
#
# Output: key=value lines appended to $GITHUB_OUTPUT (stdout when unset):
#   repo, policy, signer-identity, signer-issuer   the resolved corpus; empty when none is fetched
#   required                                       1 when the run requires a corpus, else 0
#
# THE DEFAULT IS THE PUBLIC CORPUS. With no corpus input set, the run reads the public
# ferralon-ai/vulnerability-corpus under its `full` policy, signature-verified against the identity
# that corpus's publisher signs its releases with. When advisory-corpus-repo names that same corpus,
# an empty policy or signer input takes the same default. A different corpus repository gets no
# default policy or signer: its owner decides what it publishes and whose signature to trust.
#
# The default is the Action's, never the scanner's. The scanner reads only the corpus it is handed.
#
# THE OPT-OUT. builtin-test-advisories-only: "true" fetches nothing and runs on the scanner's
# built-in test advisories, for an offline or air-gapped runner. That run is not a vulnerability
# scan, and its Report says so. Combined with any corpus input it is a contradiction, and fails.
set -euo pipefail

DEFAULT_REPO="ferralon-ai/vulnerability-corpus"
DEFAULT_POLICY="full"
DEFAULT_SIGNER_IDENTITY="ferralon-intel-publisher@ferralon.iam.gserviceaccount.com"
DEFAULT_SIGNER_ISSUER="https://accounts.google.com"

dir="${IN_CORPUS_DIR:-}"
repo="${IN_CORPUS_REPO:-}"
policy="${IN_CORPUS_POLICY:-}"
identity="${IN_SIGNER_IDENTITY:-}"
issuer="${IN_SIGNER_ISSUER:-}"
builtin_only="${IN_BUILTIN_ONLY:-}"

die() {
  echo "::error::ferralon-assay: $*" >&2
  exit 1
}

# Every value is written as a key=value line, so a newline in one would forge another output.
for v in "$dir" "$repo" "$policy" "$identity" "$issuer"; do
  [[ "$v" != *$'\n'* && "$v" != *$'\r'* ]] || die "an advisory-corpus input contains a line break."
done

case "$builtin_only" in
  "" | false) builtin_only=false ;;
  true) ;;
  *) die "builtin-test-advisories-only is '$builtin_only'; set it to 'true' or 'false'." ;;
esac

emit() {
  local out="${GITHUB_OUTPUT:-/dev/stdout}"
  {
    printf 'repo=%s\n' "$1"
    printf 'policy=%s\n' "$2"
    printf 'signer-identity=%s\n' "$3"
    printf 'signer-issuer=%s\n' "$4"
    printf 'required=%s\n' "$5"
  } >>"$out"
}

if [[ "$builtin_only" == true ]]; then
  if [[ -n "$dir$repo$policy$identity$issuer" ]]; then
    die "builtin-test-advisories-only is 'true', but an advisory-corpus input is also set. Clear the corpus inputs to run offline, or set builtin-test-advisories-only to 'false' to read the corpus."
  fi
  echo "==> builtin-test-advisories-only: no advisory corpus; this run evaluates the scanner's built-in test advisories only and is not a vulnerability scan" >&2
  emit "" "" "" "" 0
  exit 0
fi

# A directory the workflow checked out itself wins, and nothing is fetched.
if [[ -n "$dir" ]]; then
  echo "==> Advisory corpus: the directory $dir" >&2
  emit "" "" "" "" 1
  exit 0
fi

repo="${repo:-$DEFAULT_REPO}"
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ && "$repo" != *..* ]] \
  || die "advisory-corpus-repo '$repo' is not an owner/repo."

if [[ "$repo" == "$DEFAULT_REPO" ]]; then
  policy="${policy:-$DEFAULT_POLICY}"
  identity="${identity:-$DEFAULT_SIGNER_IDENTITY}"
  issuer="${issuer:-$DEFAULT_SIGNER_ISSUER}"
fi

echo "==> Advisory corpus: $repo, policy '${policy:-<none>}'" >&2
emit "$repo" "$policy" "$identity" "$issuer" 1
