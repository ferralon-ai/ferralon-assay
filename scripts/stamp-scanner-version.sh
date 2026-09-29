#!/usr/bin/env bash
# stamp-scanner-version.sh — read or stamp the `scanner-version` input default in action.yml.
# Called by release.yml; also runnable by hand.
#
# USAGE
#   scripts/stamp-scanner-version.sh check [action.yml]
#       Succeed only when the default is a minor alias (vX.Y), the shape every branch carries.
#   scripts/stamp-scanner-version.sh stamp <vX.Y.Z> [action.yml]
#       Rewrite that default to the exact release. The file must carry a vX.Y alias going in, and the
#       rewrite changes exactly that one line.
#
# The alias is not required to match <vX.Y.Z>'s minor: a branch moves its alias only when a change
# needs a newer minor's scanner, so it may lag the Action version being cut.
#
# The action.yml path defaults to the one beside this script.
set -euo pipefail

ACTION_DEFAULT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/action.yml"

die() {
  echo "::error::stamp-scanner-version: $*" >&2
  exit 1
}

usage() {
  sed -n '/^# USAGE/,/^#$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

# default_lineno <file> — the line number of `default:` inside the `scanner-version:` input block.
# Exactly one, or the file is not shaped the way this script can safely edit.
default_lineno() {
  local f="$1" lines n
  lines="$(awk '
    /^  scanner-version:[[:space:]]*$/ { inb = 1; next }
    inb && /^  [^ ]/                   { inb = 0 }
    inb && /^    default:/             { print NR }
  ' "${f}")"
  n="$(grep -c . <<<"${lines}" || true)"
  [[ "${n}" == "1" ]] || die "${f}: expected exactly one 'default:' under the scanner-version input, found ${n}."
  printf '%s\n' "${lines}"
}

# default_value <file> <lineno> — the default's value with any surrounding quotes removed.
default_value() {
  sed -n "$2{s/^    default:[[:space:]]*//;s/[[:space:]]*\$//;s/^\"\\(.*\\)\"\$/\\1/;s/^'\\(.*\\)'\$/\\1/;p;}" "$1"
}

check_alias() {
  local f="$1" n v
  n="$(default_lineno "${f}")"
  v="$(default_value "${f}" "${n}")"
  [[ "${v}" =~ ^v[0-9]+\.[0-9]+$ ]] \
    || die "${f}:${n}: scanner-version default is '${v}', expected a minor alias (vX.Y). Every branch carries the alias; only the release workflow writes an exact vX.Y.Z, onto the minted leaf."
  printf '%s\n' "${n}"
}

case "${1:-}" in
  check)
    [[ $# -le 2 ]] || usage
    f="${2:-${ACTION_DEFAULT}}"
    n="$(check_alias "${f}")"
    echo "scanner-version default is the minor alias $(default_value "${f}" "${n}")"
    ;;
  stamp)
    [[ $# -ge 2 && $# -le 3 ]] || usage
    version="$2"
    f="${3:-${ACTION_DEFAULT}}"
    [[ "${version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "'${version}' is not a vX.Y.Z release version."
    n="$(check_alias "${f}")"
    alias="$(default_value "${f}" "${n}")"
    tmp="$(mktemp)"
    trap 'rm -f "${tmp}"' EXIT
    awk -v n="${n}" -v v="${version}" 'NR == n { print "    default: \"" v "\""; next } { print }' "${f}" > "${tmp}"
    changed="$(diff "${f}" "${tmp}" | grep -c '^[<>]' || true)"
    [[ "${changed}" == "2" ]] || die "stamping ${f} would change ${changed} diff lines, expected exactly one line replaced."
    cat "${tmp}" > "${f}"
    [[ "$(default_value "${f}" "${n}")" == "${version}" ]] || die "stamp did not take: ${f}:${n} reads '$(default_value "${f}" "${n}")'."
    echo "stamped scanner-version default ${alias} -> ${version} (${f}:${n})"
    ;;
  *)
    usage
    ;;
esac
