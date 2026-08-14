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
	// Stage 1 left plain map[string]string placeholders here and its doc note sanctioned
	// replacing them, because a primitive map can carry neither the §3.5 provenance C5
	// requires (which config file and which tool produced each entry) nor a declared
	// conflict where two tools disagree about the same key. Stage 3 replaced them with
	// the provenance-carrying, explicitly-ordered representations below. newBuildContext
	// (stage 1) still leaves every one of these at its zero value; buildContextFor wires
	// in the bundler readers (bundler.go, stage 2) via populateBundler.
	//
	// Every collection here is an ordered slice — NOT a map — so the canonical encoding
	// (canonicalEncoding) is byte-identical across runs and processes (C6). Conflict
	// detection uses maps internally but they never feed the encoder.

	// Aliases is every statically-read bundler alias, in discovery order (bundler
	// candidate order, then source order within a config). Both sides of a conflict are
	// retained; none is dropped by last-wins. Each carries its producing tool + config
	// file (§3.5). Populated by PLAN-163 stage 3.
	Aliases []aliasBinding
	// Defines is every statically-read compile-time define, same ordering/provenance
	// discipline as Aliases. Populated by PLAN-163 stage 3.
	Defines []defineBinding
	// EntryPoints are the bundler-declared build entry points, each attributed to its
	// tool + config file and flagged server-side per its config's target. Populated by
	// PLAN-163 stage 3.
	EntryPoints []entryPoint
	// ServerSideRoots are the project roots a node/SSR bundler target identifies as
	// server-side (a browser-only target does not mark its root). Ordered, deduplicated.
	// Populated by PLAN-163 stage 3.
	ServerSideRoots []string
	// AliasConflicts declares each alias key two configs disagree about — a first-class
	// conflict marker (C5), never resolved by ordering/last-wins. Populated by PLAN-163
	// stage 3.
	AliasConflicts []aliasConflict
	// DefineConflicts declares each define key two configs disagree about, same
	// first-class discipline as AliasConflicts. Populated by PLAN-163 stage 3.
	DefineConflicts []defineConflict
}

// aliasBinding is one statically-read bundler alias carrying its §3.5 provenance: the
// tool and config file that declared it. Conflict is true when another binding for the
// same Key declares a different Target — the binding is retained either way (C5: both
// sides recorded, the conflict declared, never silently resolved by ordering).
type aliasBinding struct {
	Key        string // the specifier being rewritten (aliasEntry.From)
	Target     string // what it rewrites to (aliasEntry.To)
	Tool       string // producing bundler (bundlerKind string): webpack, vite, …
	ConfigFile string // producing config file, relative to the scanned dir
	Conflict   bool   // participates in an AliasConflict
}

// defineBinding is one statically-read compile-time define with the same provenance and
// conflict discipline as aliasBinding.
type defineBinding struct {
	Key        string
	Value      string
	Tool       string
	ConfigFile string
	Conflict   bool
}

// entryPoint is one bundler-declared build entry point with provenance, flagged
// server-side when its config targets node/SSR.
type entryPoint struct {
	Path       string
	Tool       string
	ConfigFile string
	ServerSide bool
}

// aliasConflict is a first-class declaration that two or more configs disagree about
// one alias key. Bindings holds every divergent binding in discovery order — the
// declaration a C5 test asserts on, INSTEAD of any single "winning" target.
type aliasConflict struct {
	Key      string
	Bindings []aliasBinding
}

// defineConflict is the define-map analogue of aliasConflict.
type defineConflict struct {
	Key      string
	Bindings []defineBinding
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

// buildContextFor produces the fully-populated jsanalysis-internal build context for
// dir: the stage-1 half (module mode + roots, from newBuildContext) plus the stage-3
// half (bundler alias/define map, entry points, server-side roots, and declared
// conflicts, from the static bundler readers). It reads statically only and executes
// nothing (C4); readBundlerConfigs never runs Node or a bundler. This is the value the
// resolver injection point (resolve.go) exposes for PLAN-162 to consult.
func buildContextFor(dir string) buildContext {
	bc := newBuildContext(dir)
	configs, _ := readBundlerConfigs(dir)
	bc.populateBundler(dir, configs)
	return bc
}

// populateBundler folds the per-config bundler readings into the build context's
// extension fields, attributing every alias/define/entry to its producing tool + config
// file (§3.5) and declaring — never silently resolving — cross-config conflicts (C5).
// Iteration follows the ordered configs slice and each config's ordered entries, so the
// resulting collections are deterministic (C6).
func (bc *buildContext) populateBundler(dir string, configs []bundlerConfig) {
	serverSide := false
	for _, cfg := range configs {
		tool := string(cfg.Tool)
		for _, a := range cfg.Aliases {
			bc.Aliases = append(bc.Aliases, aliasBinding{Key: a.From, Target: a.To, Tool: tool, ConfigFile: cfg.ConfigFile})
		}
		for _, d := range cfg.Defines {
			bc.Defines = append(bc.Defines, defineBinding{Key: d.Key, Value: d.Value, Tool: tool, ConfigFile: cfg.ConfigFile})
		}
		for _, e := range cfg.Entries {
			bc.EntryPoints = append(bc.EntryPoints, entryPoint{Path: e, Tool: tool, ConfigFile: cfg.ConfigFile, ServerSide: cfg.ServerSide})
		}
		if cfg.ServerSide {
			serverSide = true
		}
	}
	if serverSide {
		bc.ServerSideRoots = append(bc.ServerSideRoots, dir)
	}
	bc.AliasConflicts = markAliasConflicts(bc.Aliases)
	bc.DefineConflicts = markDefineConflicts(bc.Defines)
}

// markAliasConflicts declares every alias key on which two configs disagree. It marks
// each participating binding's Conflict flag in place and returns one aliasConflict per
// divergent key, in first-appearance order. The distinct-target detection uses a map,
// but that map never feeds the encoder — the returned slice and the mutated bindings are
// ordered by first appearance in entries, preserving C6 determinism.
func markAliasConflicts(entries []aliasBinding) []aliasConflict {
	distinct := map[string]map[string]bool{}
	var order []string
	seen := map[string]bool{}
	for _, e := range entries {
		if !seen[e.Key] {
			seen[e.Key] = true
			order = append(order, e.Key)
		}
		if distinct[e.Key] == nil {
			distinct[e.Key] = map[string]bool{}
		}
		distinct[e.Key][e.Target] = true
	}
	var out []aliasConflict
	for _, k := range order {
		if len(distinct[k]) < 2 {
			continue
		}
		var bindings []aliasBinding
		for i := range entries {
			if entries[i].Key == k {
				entries[i].Conflict = true
				bindings = append(bindings, entries[i])
			}
		}
		out = append(out, aliasConflict{Key: k, Bindings: bindings})
	}
	return out
}

// markDefineConflicts is the define-map analogue of markAliasConflicts.
func markDefineConflicts(entries []defineBinding) []defineConflict {
	distinct := map[string]map[string]bool{}
	var order []string
	seen := map[string]bool{}
	for _, e := range entries {
		if !seen[e.Key] {
			seen[e.Key] = true
			order = append(order, e.Key)
		}
		if distinct[e.Key] == nil {
			distinct[e.Key] = map[string]bool{}
		}
		distinct[e.Key][e.Value] = true
	}
	var out []defineConflict
	for _, k := range order {
		if len(distinct[k]) < 2 {
			continue
		}
		var bindings []defineBinding
		for i := range entries {
			if entries[i].Key == k {
				entries[i].Conflict = true
				bindings = append(bindings, entries[i])
			}
		}
		out = append(out, defineConflict{Key: k, Bindings: bindings})
	}
	return out
}

// canonicalEncoding renders the build context as a deterministic byte string (C6). It is
// byte-identical across runs and processes because buildContext contains ONLY strings
// and explicitly-ordered slices — no map feeds this encoder, so Go's per-process map-hash
// seed and per-iteration map randomization cannot perturb the output. json.Marshal emits
// struct fields in declaration order and slice elements in slice order, both deterministic.
func (bc buildContext) canonicalEncoding() []byte {
	// json.Marshal cannot fail for a value of only string/bool/slice fields.
	b, _ := json.Marshal(bc)
	return b
}

// lookupAlias returns the alias binding for key and whether the key is in conflict. It is
// the read hook PLAN-162's resolver consults at the injection point; PLAN-163 exposes it
// but does NOT apply it (resolution logic is unchanged this cycle). On a conflicted key
// the first-discovered binding is returned alongside conflicted=true, so a caller that
// does not handle conflicts still sees the conflict flag rather than a silent winner.
func (bc *buildContext) lookupAlias(key string) (binding aliasBinding, found, conflicted bool) {
	for _, a := range bc.Aliases {
		if a.Key == key {
			return a, true, a.Conflict
		}
	}
	return aliasBinding{}, false, false
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
