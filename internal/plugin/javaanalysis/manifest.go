package javaanalysis

// manifest.go — the ecosystem-neutral BuildManifest for the JVM lanes (Java live + Kotlin
// delegating). BuildManifest is invoked ONCE per BuildDir and returns ONE flat
// plugin.BuildManifestResult (PLAN-000 froze the 5-field shape — no per-module list, no
// property bag). It reads the build graph: the tool that resolved it, the JDK it ran on, and
// its modules. The `lang` param keeps RuntimeSpec.Name honest per lane ("java" | "kotlin").
//
// Honest partiality (inv.5): JVM bytecode is portable (no platform Target) and Maven/Gradle
// carry no first-class build profile, so reasonTargetNotApplicable and
// reasonNoBuildConfiguration are permanent declared residue and the manifest is never Complete.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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

	// reasonToolchainUnpinned: the build graph does not name the JDK the build ran on.
	reasonToolchainUnpinned = "toolchain_unpinned"

	// reasonNoRuntimeVersion: no JVM version is known. The version is left empty and NEVER
	// guessed.
	reasonNoRuntimeVersion = "no_runtime_version"

	// reasonMultiModule: >1 module (aggregator POM / Gradle multi-project); the flat
	// BuildManifestResult cannot enumerate members. True enumeration is PLAN-400; here the
	// members are named in a declared reason.
	reasonMultiModule = "multi_module_project"
)

// BuildManifest derives the flat build manifest for one JVM BuildDir from its build graph. lang
// selects the runtime Name ("java" | "kotlin"). The runtime is the JDK the build tool ran on,
// which is the job's own (ambient), exact. A missing or unreadable build dir is a hard error
// (inv.4); without a graph the result names build_graph_absent and nothing else is known.
func BuildManifest(_ context.Context, req plugin.BuildManifestRequest, lang string, opts ...Option) (plugin.BuildManifestResult, error) {
	info, err := os.Stat(req.BuildDir)
	if err != nil {
		return plugin.BuildManifestResult{}, fmt.Errorf("javaanalysis: stat build dir %q: %w", req.BuildDir, err)
	}
	if !info.IsDir() {
		return plugin.BuildManifestResult{}, fmt.Errorf("javaanalysis: build dir %q is not a directory", req.BuildDir)
	}

	// Target and Configuration are permanently declared-absent for the JVM: portable bytecode
	// has no platform Target, and no first-class static build profile lives on disk.
	reasons := []string{reasonTargetNotApplicable, reasonNoBuildConfiguration}
	rt := plugin.RuntimeSpec{Name: lang, Source: plugin.RuntimeSourceAmbient}
	res := plugin.BuildManifestResult{ProjectRoot: "."}

	g := BuildGraph(opts...)
	if g == nil {
		reasons = mergeManifestReasons(reasons, PartialReasonBuildGraphAbsent, reasonToolchainUnpinned, reasonNoRuntimeVersion)
		res.Runtimes = []plugin.RuntimeSpec{rt}
		res.Partiality = plugin.Partial(reasons...)
		return res, nil
	}

	switch g.Tool.Name {
	case "maven":
		res.Resolvers = []plugin.ResolverSpec{{Name: "maven", Command: "mvn -o -DskipTests package", Source: plugin.RuntimeSourceAmbient}}
	case "gradle":
		res.Resolvers = []plugin.ResolverSpec{{Name: "gradle", Command: "gradle --offline assemble", Source: plugin.RuntimeSourceAmbient}}
	}
	var members []string
	for _, m := range g.Modules {
		if _, isCopy := m.Project(); isCopy {
			continue
		}
		members = append(members, m.Path)
		if m.Path == "." {
			res.ProjectRoot = m.ID
		}
	}
	sort.Strings(members)

	if v := g.JVM.Version; v != "" {
		rt.Toolchain = v
		rt.Version = javaMajor(v)
	} else {
		reasons = mergeManifestReasons(reasons, reasonToolchainUnpinned, reasonNoRuntimeVersion)
	}

	// Multi-module: the flat shape names the members in a declared reason (PLAN-400 owns true
	// enumeration).
	if len(members) >= 2 {
		detail := fmt.Sprintf("%s: %d module(s): %s", reasonMultiModule, len(members), strings.Join(members, ", "))
		reasons = mergeManifestReasons(reasons, reasonMultiModule, detail)
	}

	res.Runtimes = []plugin.RuntimeSpec{rt}
	res.Partiality = plugin.Partial(reasons...)
	return res, nil
}

// javaMajor is a Java version's feature release: "1.8.0_402" is 8, "21.0.4" is 21.
func javaMajor(v string) string {
	v = strings.TrimPrefix(v, "1.")
	if i := strings.IndexAny(v, "._+-"); i >= 0 {
		v = v[:i]
	}
	return v
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
