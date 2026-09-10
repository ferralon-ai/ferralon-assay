package javaanalysis

// manifest.go — the ecosystem-neutral BuildManifest for the JVM lanes (Java live + Kotlin
// delegating). BuildManifest is invoked ONCE per BuildDir and returns ONE flat
// plugin.BuildManifestResult (PLAN-000 froze the 5-field shape — no per-module list, no
// property bag). It reads the checkout LEXICALLY — pom.xml <properties>, build.gradle(.kts)
// version/toolchain lines, and the exact-pin files (.tool-versions / .sdkmanrc) — and NEVER
// runs mvn/gradle/javac or touches the network (§3.3 zero-egress). Build-file parsing is
// JVM-generic, not Java-source-specific, so the impl lives here and Kotlin delegates — the
// same precedent as ResolveDependencyVersions / ResolveInventory. The `lang` param keeps
// Runtime.Name honest per lane ("java" | "kotlin"); it is otherwise cosmetic downstream.
//
// Honest partiality (inv.5): where the flat shape cannot carry a fact, or the fact does not
// exist statically, the result names it via a declared partiality reason — never a guessed
// value, never Complete() over what could not be read. Because JVM emits portable bytecode
// (no platform Target) and Maven/Gradle carry no first-class static build profile, the JVM
// manifest is structurally never Complete: reasonTargetNotApplicable and
// reasonNoBuildConfiguration are permanent declared residue, and the exact toolchain pin is
// unresolvable without executing the build unless a pin file records it.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Lane-local partiality reason codes for the JVM BuildManifest. They name the irreducible
// residue the frozen plugin.PartialReason* vocabulary has no code for. Per the PLAN-150
// barrier decision they live HERE, not in the PLAN-000-owned plugin/plugin.go:
// plugin.Partiality.Reasons is a free []string, so a distinguishable named reason needs no
// contract edit, and every value below is canonical/generic (any JVM build has these
// properties), so it is promotion-ready — a later lift into plugin.go is a pure move.
const (
	// reasonTargetNotApplicable: the JVM emits portable bytecode — there is no RID/platform
	// Target to record (the analog of Go's empty Target). A permanent declared not-applicable,
	// never a guessed platform.
	reasonTargetNotApplicable = "target_not_applicable"

	// reasonNoBuildConfiguration: Maven/Gradle carry no first-class static build profile
	// (release/Debug) on disk without executing the build. Declared-absent, never guessed.
	reasonNoBuildConfiguration = "no_build_configuration"

	// reasonToolchainUnpinned: the exact toolchain pin is not resolvable without executing the
	// build. Emitted UNLESS a pin file (.tool-versions / .sdkmanrc) records an exact version; a
	// Gradle JavaLanguageVersion.of(N) is a major FLOOR (→ Runtime.Version), not an exact pin.
	reasonToolchainUnpinned = "toolchain_unpinned"

	// reasonNoRuntimeVersion: no declared JVM target/source version could be read from the
	// build file. The version is left empty and NEVER guessed.
	reasonNoRuntimeVersion = "no_runtime_version"

	// reasonMultiModule: >1 module (aggregator POM / Gradle multi-project); the flat
	// BuildManifestResult cannot enumerate members. True enumeration is PLAN-400; here the
	// members are named in a declared reason.
	reasonMultiModule = "multi_module_project"
)

// BuildManifest derives the flat, ecosystem-neutral build manifest for one JVM BuildDir from
// DECLARED on-disk state only. lang selects Runtime.Name ("java" | "kotlin"). A missing or
// unreadable build dir is a hard error (inv.4); every unrepresentable or non-existent fact
// becomes a declared partiality reason.
func BuildManifest(_ context.Context, req plugin.BuildManifestRequest, lang string) (plugin.BuildManifestResult, error) {
	info, err := os.Stat(req.BuildDir)
	if err != nil {
		return plugin.BuildManifestResult{}, fmt.Errorf("javaanalysis: stat build dir %q: %w", req.BuildDir, err)
	}
	if !info.IsDir() {
		return plugin.BuildManifestResult{}, fmt.Errorf("javaanalysis: build dir %q is not a directory", req.BuildDir)
	}

	buildDir := req.BuildDir
	res := plugin.BuildManifestResult{Runtime: plugin.RuntimeSpec{Name: lang}}
	var reasons []string

	poms, gradles := buildFiles(buildDir)

	// Target and Configuration are permanently declared-absent for the JVM: portable bytecode
	// has no platform Target, and no first-class static build profile lives on disk.
	reasons = mergeManifestReasons(reasons, reasonTargetNotApplicable, reasonNoBuildConfiguration)

	var (
		version string
		members []string
	)
	switch {
	case len(poms) > 0:
		// Maven wins when a POM is present (the more explicit, primary declaration).
		root := shortestPath(poms)
		res.Resolver = plugin.ResolverSpec{Name: "maven", Command: "mvn -o -DskipTests package"}
		proj, ok := parsePOMProject(root)
		if ok {
			res.ProjectRoot = mavenProjectRoot(buildDir, root, proj)
			version = mavenRuntimeVersion(proj)
		} else {
			res.ProjectRoot = relManifestDir(buildDir, filepath.Dir(root))
		}
		members = moduleMembers(buildDir, poms)
	case len(gradles) > 0:
		root := shortestPath(gradles)
		res.Resolver = plugin.ResolverSpec{Name: "gradle", Command: "gradle --offline assemble"}
		res.ProjectRoot = gradleProjectRoot(buildDir)
		version = parseGradleManifest(root)
		members = moduleMembers(buildDir, gradles)
	default:
		// No Maven/Gradle build file at all: a normal shape for some checkouts, degraded to
		// declared partiality rather than a hard failure (mirrors ResolveDependencyVersions).
		res.ProjectRoot = "."
		reasons = mergeManifestReasons(reasons, plugin.PartialReasonNoManifest)
	}

	res.Runtime.Version = version
	if version == "" && (len(poms) > 0 || len(gradles) > 0) {
		reasons = mergeManifestReasons(reasons, reasonNoRuntimeVersion)
	}

	// Exact toolchain pin: only from a real pin file; a Gradle languageVersion is a floor, not
	// an exact pin. Absent ⇒ declared unpinned, never guessed.
	if pin := toolchainPin(buildDir); pin != "" {
		res.Runtime.Toolchain = pin
	} else {
		reasons = mergeManifestReasons(reasons, reasonToolchainUnpinned)
	}

	// Multi-module: the flat shape names the members in a declared reason (PLAN-400 owns true
	// enumeration).
	if len(members) >= 2 {
		detail := fmt.Sprintf("%s: %d module(s): %s", reasonMultiModule, len(members), strings.Join(members, ", "))
		reasons = mergeManifestReasons(reasons, reasonMultiModule, detail)
	}

	res.Partiality = plugin.Partial(reasons...)
	return res, nil
}

// parsePOMProject decodes a pom.xml into pomProject via the charset-aware POM decoder. The
// bool is false when the file cannot be read or is undecodable XML.
func parsePOMProject(path string) (pomProject, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return pomProject{}, false
	}
	var proj pomProject
	if err := unmarshalPOM(data, &proj); err != nil {
		return pomProject{}, false
	}
	return proj, true
}

// mavenProjectRoot is the module identity: the declared groupId:artifactId (groupId inherited
// from <parent> when the module omits it), falling back to the POM's relative directory when
// no coordinate is declared.
func mavenProjectRoot(buildDir, pomPath string, proj pomProject) string {
	gid := strings.TrimSpace(proj.GroupID)
	if gid == "" {
		gid = strings.TrimSpace(proj.Parent.GroupID)
	}
	aid := strings.TrimSpace(proj.ArtifactID)
	switch {
	case gid != "" && aid != "":
		return gid + ":" + aid
	case aid != "":
		return aid
	default:
		return relManifestDir(buildDir, filepath.Dir(pomPath))
	}
}

// mavenRuntimeVersion reads the declared JVM target version from a POM's <properties>, in
// Maven's own precedence: release ⊐ target ⊐ source, then the java.version convention. A
// ${prop} indirection is resolved one level against the same <properties> map; anything that
// does not reduce to a literal leaves the version empty (→ reasonNoRuntimeVersion), never
// guessed.
func mavenRuntimeVersion(proj pomProject) string {
	props := proj.Properties.Entries
	for _, key := range []string{"maven.compiler.release", "maven.compiler.target", "maven.compiler.source", "java.version"} {
		raw, ok := props[key]
		if !ok {
			continue
		}
		if v, resolved := resolvePOMVersion(strings.TrimSpace(raw), props); resolved {
			return v
		}
	}
	return ""
}

// gradleProjectRoot reads rootProject.name from settings.gradle(.kts) when declared, else
// falls back to the build dir's base name (or "." at the filesystem root).
func gradleProjectRoot(buildDir string) string {
	for _, name := range []string{"settings.gradle", "settings.gradle.kts"} {
		data, err := os.ReadFile(filepath.Join(buildDir, name))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(stripGradleComment(line))
			if !strings.HasPrefix(line, "rootProject.name") {
				continue
			}
			if s, ok := firstQuoted(line); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	if base := filepath.Base(buildDir); base != "" && base != "." && base != string(filepath.Separator) {
		return base
	}
	return "."
}

var (
	reGradleLangVersion = regexp.MustCompile(`JavaLanguageVersion\.of\(\s*(\d+)\s*\)`)
	reGradleVersionEnum = regexp.MustCompile(`VERSION_(\d+)(?:_(\d+))?`)
	reGradleJvmEnum     = regexp.MustCompile(`JVM_(\d+)`)
	reGradleQuotedNum   = regexp.MustCompile(`['"](\d+(?:\.\d+)?)['"]`)
	reGradleBareNum     = regexp.MustCompile(`=\s*(\d+(?:\.\d+)?)\s*$`)
)

// parseGradleManifest line-scans a build.gradle(.kts) for the declared JVM target version — a
// major FLOOR, never an exact toolchain pin. Precedence: java.toolchain
// JavaLanguageVersion.of(N) (strongest floor) ⊐ source/targetCompatibility ⊐
// kotlinOptions.jvmTarget. Undeterminable stays "" (→ reasonNoRuntimeVersion), never guessed.
// It reads declared text only — no Gradle is executed (§3.3).
func parseGradleManifest(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var languageVersion, compat, jvmTarget string
	for _, raw := range strings.Split(string(data), "\n") {
		line := stripGradleComment(raw)
		if m := reGradleLangVersion.FindStringSubmatch(line); m != nil && languageVersion == "" {
			languageVersion = m[1]
		}
		if strings.Contains(line, "sourceCompatibility") || strings.Contains(line, "targetCompatibility") {
			if v := gradleVersionToken(line); v != "" && compat == "" {
				compat = v
			}
		}
		if strings.Contains(line, "jvmTarget") {
			if v := gradleVersionToken(line); v != "" && jvmTarget == "" {
				jvmTarget = v
			}
		}
	}
	switch {
	case languageVersion != "":
		return languageVersion
	case compat != "":
		return compat
	default:
		return jvmTarget
	}
}

// gradleVersionToken extracts a version literal from one Gradle line, tolerating the common
// forms: JavaVersion.VERSION_17 / VERSION_1_8 (→ "17" / "1.8"), JvmTarget.JVM_17 (→ "17"), a
// quoted "17"/"1.8", or a bare = 17. "" when no literal is present (e.g. an interpolation).
func gradleVersionToken(line string) string {
	if m := reGradleVersionEnum.FindStringSubmatch(line); m != nil {
		if m[2] != "" {
			return m[1] + "." + m[2]
		}
		return m[1]
	}
	if m := reGradleJvmEnum.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	if m := reGradleQuotedNum.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	if m := reGradleBareNum.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	return ""
}

// toolchainPin reads an EXACT interpreter pin from a pin file at the build root: asdf's
// .tool-versions (the token after `java`) or SDKMAN's .sdkmanrc (`java=<version>`). Absent ⇒
// "" (an honest "no exact pin," disclosed as reasonToolchainUnpinned), never guessed.
func toolchainPin(buildDir string) string {
	if data, err := os.ReadFile(filepath.Join(buildDir, ".tool-versions")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 2 && fields[0] == "java" {
				return fields[1]
			}
		}
	}
	if data, err := os.ReadFile(filepath.Join(buildDir, ".sdkmanrc")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if v, ok := strings.CutPrefix(line, "java="); ok {
				if v = strings.TrimSpace(v); v != "" {
					return v
				}
			}
		}
	}
	return ""
}

// moduleMembers returns the sorted, unique relative directories of the given build files —
// the aggregator's member modules. A single-element result is not multi-module.
func moduleMembers(buildDir string, files []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range files {
		rel := relManifestDir(buildDir, filepath.Dir(f))
		if seen[rel] {
			continue
		}
		seen[rel] = true
		out = append(out, rel)
	}
	sort.Strings(out)
	return out
}

// shortestPath returns the build file closest to the build root (shortest path; lexical
// tie-break) — the aggregator/root module.
func shortestPath(paths []string) string {
	best := paths[0]
	for _, p := range paths[1:] {
		if len(p) < len(best) || (len(p) == len(best) && p < best) {
			best = p
		}
	}
	return best
}

// relManifestDir renders target relative to base as a forward-slash path ("." for base
// itself), so ProjectRoot / member names are stable across platforms (C3 determinism).
func relManifestDir(base, target string) string {
	r, err := filepath.Rel(base, target)
	if err != nil || r == "" {
		return "."
	}
	return filepath.ToSlash(r)
}

// mergeManifestReasons appends reasons preserving order and dropping duplicates (a bare code
// plus its detail line both land, once each), so the output is deterministic (C3).
func mergeManifestReasons(base []string, add ...string) []string {
	seen := make(map[string]bool, len(base)+len(add))
	out := make([]string, 0, len(base)+len(add))
	for _, r := range append(append([]string{}, base...), add...) {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}
