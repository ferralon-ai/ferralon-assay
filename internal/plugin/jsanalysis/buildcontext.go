package jsanalysis

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// moduleMode is the ES-module-vs-CommonJS mode a package.json declares via its "type"
// field. It is the project-level default: `"type":"module"` is esm; absent or
// `"commonjs"` is cjs (Node's default). Per-file mode — which additionally honors the
// .mjs/.cjs extension rule and the tsconfig `module` setting — is resolve.go's
// determineModuleMode; this is the coarser package-level default.
type moduleMode string

const (
	moduleModeCJS moduleMode = "cjs" // "type" absent or "commonjs"
	moduleModeESM moduleMode = "esm" // "type":"module"
)

// buildContext is the jsanalysis-internal build-context artifact (PLAN-163 A3). It
// carries the ES-module mode and project root(s) that stage 1 populates, plus
// zero-value extension fields the stage-3 bundler wiring fills in from bundler.go.
//
// It deliberately does NOT live on the frozen plugin.BuildManifestResult wire type:
// §4.6 enumerates exactly five neutral field groups and none is bundler-related, and
// overloading module mode onto Configuration would recreate the GoVersion anti-pattern
// C1 removes. resolve.go consumes this side table at PLAN-162's resolver injection
// point (wired by stage 3), keeping the wire type frozen (C7).
type buildContext struct {
	// ModuleMode is the package.json "type" default for the primary root. Populated by
	// stage 1.
	ModuleMode moduleMode

	// Roots are the project root(s): the build directory, and — for a workspaces
	// layout — its declared member globs (joined to the build dir). These are the
	// *declared* globs, not a filesystem walk of matching members; per-member subgraph
	// attribution is ResolveInventory's DependencyMembership (A2), not this artifact.
	// Populated by stage 1.
	Roots []string

	// --- extension fields: populated by PLAN-163 stage 3 from the bundler readers ---
	//
	// Stage 1 leaves each at its zero value and does NOT import bundler.go (written
	// concurrently by stage 2). Stage 3 owns the exact shape and the provenance
	// side-table the resolver injection point needs (C5 requires each alias/define to
	// record its producing config file and tool, and a declared conflict where two
	// tools disagree) — stage 3 may therefore replace these plain-typed placeholders
	// with provenance-carrying representations.

	// AliasMap holds bundler alias -> target-specifier rewrites. // populated by PLAN-163 stage 3
	AliasMap map[string]string
	// Defines holds compile-time define substitutions (e.g. process.env.NODE_ENV). // populated by PLAN-163 stage 3
	Defines map[string]string
	// EntryPoints are the bundler-declared build entry points. // populated by PLAN-163 stage 3
	EntryPoints []string
	// ServerSideRoots marks roots/entry points a bundler config identifies as server-side. // populated by PLAN-163 stage 3
	ServerSideRoots []string
}

// newBuildContext reads dir/package.json and populates the stage-1 half of the build
// context: module mode (from the "type" field) and the project root(s) (dir plus any
// declared workspace member globs). It reads package.json only — never node_modules,
// never a bundler config, never a lifecycle script — and executes nothing.
//
// A missing or malformed package.json yields cjs (Node's default) with dir as the sole
// root: this artifact reports the module-resolution default, not partiality. Callers
// that must declare an unreadable package.json get that from BuildManifest, whose
// declared partiality this function does not duplicate or override.
func newBuildContext(dir string) buildContext {
	bc := buildContext{ModuleMode: moduleModeCJS, Roots: []string{dir}}

	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return bc
	}
	var pkg struct {
		Type       string          `json:"type"`
		Workspaces json.RawMessage `json:"workspaces"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return bc
	}
	if pkg.Type == "module" {
		bc.ModuleMode = moduleModeESM
	}
	for _, glob := range parseWorkspaceGlobs(pkg.Workspaces) {
		bc.Roots = append(bc.Roots, filepath.Join(dir, filepath.FromSlash(glob)))
	}
	return bc
}

// parseWorkspaceGlobs decodes package.json's `workspaces` in both the array form
// (["packages/*"]) and the object form ({"packages":["packages/*"]}). Returns nil when
// the field is absent or neither shape decodes.
func parseWorkspaceGlobs(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var arr []string
	if json.Unmarshal(raw, &arr) == nil {
		return arr
	}
	var obj struct {
		Packages []string `json:"packages"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return obj.Packages
	}
	return nil
}
