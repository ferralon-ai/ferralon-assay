#!/usr/bin/env bash
# generate-captures.sh — the capture driver baked into the jvm-toolchain image.
#
# Usage (inside the container):  run.sh <case-name>
# Expects the benchmarks tree mounted at /work, i.e. /work/<case-name>/proj is the
# BuildDir (pom.xml / build.gradle / settings / gradle.lockfile / libs.versions.toml).
#
# Per case it (1) warms a per-case-local cache with an ONLINE resolve, (2) captures
# the NATIVE tool's output as the oracle (native.tree.txt for Maven,
# native.deps.txt for Gradle), (3) snapshots ONLY the resolved POM metadata the
# resolver reads (POM/.sha1/.module — JARs excluded, they are never opened) into
# m2/ | modules2/, and (4) stamps tool-version.txt with the JDK+Maven+Gradle triple.
#
# Determinism: tool versions are pinned by the image; a per-case-local repo means
# the snapshot contains only THIS project's closure, so the same image run
# reproduces the same fixture. Cold-fixture discipline: this output is committed
# BEFORE the resolver's tests exist — the oracle is the native tool, not the resolver.
#
# The tool step tolerates a non-zero exit (M4 deliberately declares an
# unresolvable node): its combined stdout+stderr IS the honest-absent oracle.
set -uo pipefail

CASE="${1:?usage: run.sh <case-name>}"
ROOT="/work/${CASE}"
PROJ="${ROOT}/proj"

if [[ ! -d "${PROJ}" ]]; then
  echo "no proj/ dir at ${PROJ}" >&2
  exit 2
fi

stamp_versions() {
  {
    echo "# toolchain provenance — jvm-toolchain image"
    echo "## java"
    java -version 2>&1
    echo "## maven"
    mvn -v 2>&1
    echo "## gradle"
    gradle --version 2>&1
  } >"${ROOT}/tool-version.txt"
}

# --- Maven ------------------------------------------------------------------
if [[ -f "${PROJ}/pom.xml" ]]; then
  REPO="${ROOT}/.m2repo"
  rm -rf "${REPO}"; mkdir -p "${REPO}"

  # (1) online resolve into the per-case-local repo (deps closure only).
  mvn -q -f "${PROJ}/pom.xml" -Dmaven.repo.local="${REPO}" \
      dependency:resolve >/dev/null 2>&1 || true

  # (2) the oracle: full text dependency tree (reactor-aware; -Dverbose keeps
  #     mediated/omitted nodes visible). Non-zero exit is captured, not fatal.
  mvn -B -f "${PROJ}/pom.xml" -Dmaven.repo.local="${REPO}" \
      dependency:tree -Dverbose -DoutputType=text \
      >"${ROOT}/native.tree.txt" 2>&1 || \
      echo "[capture] mvn dependency:tree exited non-zero (see output above)" \
      >>"${ROOT}/native.tree.txt"
  # strip wall-clock lines so the same container run reproduces byte-identical output.
  sed -i -E '/^\[INFO\] Total time:/d; /^\[INFO\] Finished at:/d' "${ROOT}/native.tree.txt"

  # (3) snapshot the cache slice: POM metadata only (JARs excluded — never opened),
  #     as a lean ALLOWLIST. Copy only the POMs for the coordinates the native tree
  #     names, then follow <parent> references to a fixpoint. This deliberately
  #     excludes the build-plugin closure the resolve pulled into the same repo, so
  #     the fixture is the dependency-metadata set the resolver actually reads.
  OUT="${ROOT}/m2"
  rm -rf "${OUT}"; mkdir -p "${OUT}"

  copy_pom_dir() { # $1 = relative repo dir (group-as-path/artifact/version)
    local d="$1"
    [[ -d "${REPO}/${d}" ]] || return 0
    ( cd "${REPO}" && \
      find "${d}" -maxdepth 1 -type f \( -name '*.pom' -o -name '*.pom.sha1' \) -print0 \
        | tar --null --no-recursion -cf - --files-from=- 2>/dev/null ) \
      | tar -C "${OUT}" -xf - 2>/dev/null || true
  }

  # seed from the tree coordinates (verbose tree includes mediated/omitted nodes).
  grep -oE '[A-Za-z0-9_.-]+(:[A-Za-z0-9_.-]+){3,5}' "${ROOT}/native.tree.txt" 2>/dev/null \
    | awk -F: '{n=NF; last=$n;
        if (last ~ /^(compile|provided|runtime|test|system|import)$/) ver=$(n-1); else ver=$n;
        g=$1; a=$2; gsub(/\./,"/",g); print g"/"a"/"ver}' \
    | sort -u > "${ROOT}/.pomdirs"
  while IFS= read -r d; do [[ -n "$d" ]] && copy_pom_dir "$d"; done < "${ROOT}/.pomdirs"
  rm -f "${ROOT}/.pomdirs"

  # fixpoint: parents are load-bearing (property inheritance, dependencyManagement).
  for _ in 1 2 3 4 5 6 7 8; do
    before=$(find "${OUT}" -name '*.pom' | wc -l)
    while IFS= read -r pom; do
      blk=$(sed -n '/<parent>/,/<\/parent>/p' "$pom")
      [[ -z "$blk" ]] && continue
      pg=$(printf '%s' "$blk" | grep -oE '<groupId>[^<]+' | head -1 | sed 's/<groupId>//')
      pa=$(printf '%s' "$blk" | grep -oE '<artifactId>[^<]+' | head -1 | sed 's/<artifactId>//')
      pv=$(printf '%s' "$blk" | grep -oE '<version>[^<]+' | head -1 | sed 's/<version>//')
      [[ -n "$pg" && -n "$pa" && -n "$pv" ]] || continue
      copy_pom_dir "$(printf '%s' "$pg" | tr '.' '/')/${pa}/${pv}"
    done < <(find "${OUT}" -name '*.pom')
    after=$(find "${OUT}" -name '*.pom' | wc -l)
    [[ "$before" == "$after" ]] && break
  done

  stamp_versions
  rm -rf "${REPO}"   # drop the working repo (JARs); only the m2/ slice is kept.
  echo "[capture] ${CASE}: maven fixture written (native.tree.txt + m2/)"
  exit 0
fi

# --- Gradle -----------------------------------------------------------------
if [[ -f "${PROJ}/build.gradle" || -f "${PROJ}/settings.gradle" ]]; then
  export GRADLE_USER_HOME="${ROOT}/.gradlehome"
  rm -rf "${GRADLE_USER_HOME}"; mkdir -p "${GRADLE_USER_HOME}"

  GARGS=(--no-daemon --console=plain -g "${GRADLE_USER_HOME}" -p "${PROJ}")

  # (1)+(2): `gradle dependencies` both warms modules-2 and IS the oracle. A
  #     multi-project build only reports the ROOT project, so enumerate subprojects
  #     and capture each — otherwise cross-project divergence (G3) is invisible.
  #     --write-locks refreshes gradle.lockfile only where locking is declared.
  mapfile -t SUBS < <(gradle "${GARGS[@]}" -q projects 2>/dev/null \
      | grep -oE "Project '[^']+'" | sed "s/Project '//;s/'\$//" )
  {
    echo "### root project dependencies"
    gradle "${GARGS[@]}" dependencies --write-locks 2>&1
    for sp in "${SUBS[@]:-}"; do
      [[ -n "$sp" && "$sp" != ":" ]] || continue
      echo; echo "### ${sp} dependencies"
      gradle "${GARGS[@]}" "${sp}:dependencies" --write-locks 2>&1
    done
  } >"${ROOT}/native.deps.txt" 2>&1 || \
      echo "[capture] gradle dependencies exited non-zero (see output above)" \
      >>"${ROOT}/native.deps.txt"
  # strip daemon/timing/download noise so the same container run reproduces
  # byte-identical output (selected versions + edges are what the resolver reads).
  sed -i -E \
      -e '/single-use Daemon process will be forked/d' \
      -e '/Daemon will be stopped at the end of the build/d' \
      -e '/^Download /d' \
      -e '/^Welcome to Gradle/d' \
      -e 's/^BUILD SUCCESSFUL in .*/BUILD SUCCESSFUL/' \
      -e 's/^[0-9]+ actionable task.*/actionable tasks (normalized)/' \
      "${ROOT}/native.deps.txt"

  # (3) snapshot modules-2: Maven-format POMs + Gradle Module Metadata only.
  OUT="${ROOT}/modules2"
  rm -rf "${OUT}"; mkdir -p "${OUT}"
  SRC="${GRADLE_USER_HOME}/caches/modules-2/files-2.1"
  if [[ -d "${SRC}" ]]; then
    ( cd "${SRC}" && \
      find . -type f \( -name '*.pom' -o -name '*.module' \) -print0 \
        | tar --null --no-recursion -cf - --files-from=- \
        | tar -C "${OUT}" -xf - )
  fi

  stamp_versions
  rm -rf "${GRADLE_USER_HOME}"   # drop the working cache (JARs); only modules2/ kept.
  find "${PROJ}" -type d -name '.gradle' -exec rm -rf {} + 2>/dev/null || true # per-project build cache.
  echo "[capture] ${CASE}: gradle fixture written (native.deps.txt + modules2/)"
  exit 0
fi

echo "no pom.xml or build.gradle/settings.gradle under ${PROJ}" >&2
exit 2
