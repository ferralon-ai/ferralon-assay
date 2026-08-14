package jsanalysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Bundler configuration is executable JavaScript, and this package NEVER executes
// it (§3.3/§10.1, cycle criterion C4). The readers below extract only what §5.3
// deliverable 6 asks for — aliases, defines, target/platform (browser vs node), and
// entry points — by reading STATIC syntax: literal object/array expressions in
// .js/.ts/.mjs/.cjs config (parsed via the same comment/string-stripping lexer the
// call-graph uses) and the declarative .json forms (.swcrc, babel.config.json,
// package.json#babel). Where a value is computed at load time — a call, a spread, a
// require, an env read, a ternary — the reader NEVER guesses, defaults, or silently
// drops it: it records a declared-partial result that NAMES the unreadable key
// (§3.1/§3.6). No os/exec, no Node, no JS interpreter is used or imported.

// --- bundler-config partiality reason localisers (PLAN-163) ---
//
// These name the conditions a static bundler-config read cannot resolve without executing the
// configuration. Each is a DECLARED gap carrying the unreadable key (see unreadableRef), never a
// silent omission. RECONCILED to the onyx-q6 shared bases in plugin.go (§4 "code:suffix" naming):
// an alias/entry is an unexpressible resolution EDGE (relationship_unexpressed); a define/target/
// whole-config is an unresolved build-environment value (env_condition_unresolved); a read/parse
// failure is a tool_failure. The suffix carries the JS bundler specific.
const (
	// reasonComputedBundlerAlias: an alias whose target is computed at load time
	// (path.resolve, a variable, a template with interpolation, a spread) — the alias→target edge.
	reasonComputedBundlerAlias = plugin.PartialReasonRelationshipUnexpressed + ":bundler_alias"
	// reasonComputedBundlerDefine: a define whose value is computed at load time
	// (e.g. JSON.stringify(x), process.env.X, a ternary) — a build-env value substitution.
	reasonComputedBundlerDefine = plugin.PartialReasonEnvConditionUnresolved + ":bundler_define"
	// reasonComputedBundlerEntry: an entry point whose specifier is computed — the graph-root edge.
	reasonComputedBundlerEntry = plugin.PartialReasonRelationshipUnexpressed + ":bundler_entry"
	// reasonComputedBundlerTarget: a target/platform value computed at load time (browser/node env).
	reasonComputedBundlerTarget = plugin.PartialReasonEnvConditionUnresolved + ":bundler_target"
	// reasonUninspectableBundlerConfig: the whole configuration value is computed —
	// a config exported as a function (`module.exports = (env) => ({…})`) or an
	// unreadable reference — so nothing beneath it (an env of values) can be read statically.
	reasonUninspectableBundlerConfig = plugin.PartialReasonEnvConditionUnresolved + ":bundler_config"
	// reasonBundlerConfigUnreadable: the config file could not be read or parsed
	// (I/O error, malformed JSON). A surfaced tool failure, never a clean empty read.
	reasonBundlerConfigUnreadable = plugin.PartialReasonToolFailure + ":bundler_config"
)

// bundlerKind identifies which of the six supported tools produced a reading.
type bundlerKind string

const (
	bundlerWebpack bundlerKind = "webpack"
	bundlerRollup  bundlerKind = "rollup"
	bundlerEsbuild bundlerKind = "esbuild"
	bundlerVite    bundlerKind = "vite"
	bundlerSWC     bundlerKind = "swc"
	bundlerBabel   bundlerKind = "babel"
)

// bundlerPlatform is the browser-vs-node target a configuration selects; it is what
// lets downstream analysis tell server-side code from browser-only code (§5.3). The
// empty value means the configuration declared no platform this reader recognizes.
type bundlerPlatform string

const (
	platformUnknown bundlerPlatform = ""
	platformBrowser bundlerPlatform = "browser"
	platformNode    bundlerPlatform = "node"
	platformNeutral bundlerPlatform = "neutral"
)

// aliasEntry is one statically-read module alias: the specifier `From` is rewritten
// to `To` by the build before module resolution runs (PLAN-162 consumes this).
type aliasEntry struct {
	From string
	To   string
}

// defineEntry is one statically-read compile-time constant substitution.
type defineEntry struct {
	Key   string
	Value string // the literal value text as written (unquoted for string literals)
}

// unreadableRef names one configuration key whose value could not be read statically
// and the reason code for why. This is how a partial read "names the key" (C3): the
// declared partiality carries the reason codes, and this slice carries the keys.
type unreadableRef struct {
	Key    string // dotted path locating the unreadable key, e.g. "resolve.alias.@app"
	Reason string // one of the reason* codes above
}

// bundlerConfig is one configuration file's statically-read build context. Every
// alias/define entry is attributed to this struct's Tool + ConfigFile (§3.5
// provenance), which is what stage 3 needs to declare a cross-config conflict (C5).
type bundlerConfig struct {
	Tool       bundlerKind
	ConfigFile string // path relative to the scanned dir (usually the bare filename)
	Aliases    []aliasEntry
	Defines    []defineEntry
	Platform   bundlerPlatform
	ServerSide bool // Platform == platformNode
	Entries    []string
	Unreadable []unreadableRef
	Partiality plugin.Partiality
}

// candidate names one config file to look for and the tool + parse dialect it uses.
type candidate struct {
	name    string
	tool    bundlerKind
	dialect configDialect
}

type configDialect int

const (
	dialectJS   configDialect = iota // executable JS/TS: parse literal expressions statically
	dialectJSON                      // declarative JSON (.swcrc, *.json): always literal
	dialectPkg                       // config embedded in package.json under a top-level key
)

// bundlerCandidates is the fixed, ordered set of config files each tool is read
// from. The order is deterministic (C6): the returned []bundlerConfig follows it.
//
// SWC note: SWC's canonical config (.swcrc) is JSON and therefore ALWAYS statically
// readable — it has no load-time-computed form by construction. A load-time-computed
// SWC configuration only arises when the options object is hosted in a JS module
// (swc.config.js), which this reader also handles. See the cycle report.
var bundlerCandidates = []candidate{
	{"webpack.config.js", bundlerWebpack, dialectJS},
	{"webpack.config.ts", bundlerWebpack, dialectJS},
	{"webpack.config.cjs", bundlerWebpack, dialectJS},
	{"webpack.config.mjs", bundlerWebpack, dialectJS},
	{"webpack.config.babel.js", bundlerWebpack, dialectJS},

	{"rollup.config.js", bundlerRollup, dialectJS},
	{"rollup.config.mjs", bundlerRollup, dialectJS},
	{"rollup.config.cjs", bundlerRollup, dialectJS},
	{"rollup.config.ts", bundlerRollup, dialectJS},

	{"esbuild.config.js", bundlerEsbuild, dialectJS},
	{"esbuild.config.mjs", bundlerEsbuild, dialectJS},
	{"esbuild.config.cjs", bundlerEsbuild, dialectJS},
	{"esbuild.config.ts", bundlerEsbuild, dialectJS},

	{"vite.config.js", bundlerVite, dialectJS},
	{"vite.config.ts", bundlerVite, dialectJS},
	{"vite.config.mjs", bundlerVite, dialectJS},
	{"vite.config.cjs", bundlerVite, dialectJS},
	{"vite.config.mts", bundlerVite, dialectJS},
	{"vite.config.cts", bundlerVite, dialectJS},

	{".swcrc", bundlerSWC, dialectJSON},
	{".swcrc.json", bundlerSWC, dialectJSON},
	{"swc.config.js", bundlerSWC, dialectJS},
	{"swc.config.ts", bundlerSWC, dialectJS},

	{"babel.config.json", bundlerBabel, dialectJSON},
	{"babel.config.js", bundlerBabel, dialectJS},
	{"babel.config.cjs", bundlerBabel, dialectJS},
	{"babel.config.mjs", bundlerBabel, dialectJS},
	{".babelrc", bundlerBabel, dialectJSON},
	{".babelrc.json", bundlerBabel, dialectJSON},
	{".babelrc.js", bundlerBabel, dialectJS},
	{".babelrc.cjs", bundlerBabel, dialectJS},
	{".babelrc.mjs", bundlerBabel, dialectJS},
	{"package.json", bundlerBabel, dialectPkg},
}

// readBundlerConfigs discovers and statically reads every supported bundler
// configuration directly under dir, returning one bundlerConfig per config file
// found (ordered per bundlerCandidates for determinism, C6) and the union
// partiality across them. Configurations are read STATICALLY only; none is executed
// (C4). Absence of any bundler config is not a gap — it returns an empty slice and a
// Complete partiality (no bundler in use is an honest, complete answer).
func readBundlerConfigs(dir string) ([]bundlerConfig, plugin.Partiality) {
	var out []bundlerConfig
	reasonSet := map[string]bool{}
	complete := true

	for _, c := range bundlerCandidates {
		full := filepath.Join(dir, c.name)
		data, err := os.ReadFile(full)
		if err != nil {
			continue // not present
		}
		cfg, ok := readOne(c, c.name, data)
		if !ok {
			continue // package.json without a "babel" key: not a config, not a gap
		}
		out = append(out, cfg)
		if !cfg.Partiality.Complete {
			complete = false
			for _, r := range cfg.Partiality.Reasons {
				reasonSet[r] = true
			}
		}
	}

	if complete {
		return out, plugin.Complete()
	}
	reasons := make([]string, 0, len(reasonSet))
	for r := range reasonSet {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	return out, plugin.Partial(reasons...)
}

// readOne reads a single config file's bytes into a bundlerConfig. The bool is false
// only for a package.json that carries no "babel" key (a non-config file), which the
// caller skips silently.
func readOne(c candidate, rel string, data []byte) (bundlerConfig, bool) {
	cfg := bundlerConfig{Tool: c.tool, ConfigFile: rel}

	switch c.dialect {
	case dialectJSON:
		var root interface{}
		if err := json.Unmarshal(data, &root); err != nil {
			cfg.Partiality = plugin.Partial(reasonBundlerConfigUnreadable)
			return cfg, true
		}
		extractFromJSON(&cfg, root)
	case dialectPkg:
		var pkg map[string]json.RawMessage
		if err := json.Unmarshal(data, &pkg); err != nil {
			return cfg, false // malformed package.json is manifest.go's concern, not ours
		}
		raw, ok := pkg["babel"]
		if !ok {
			return cfg, false
		}
		var root interface{}
		if err := json.Unmarshal(raw, &root); err != nil {
			cfg.Partiality = plugin.Partial(reasonBundlerConfigUnreadable)
			return cfg, true
		}
		extractFromJSON(&cfg, root)
	default: // dialectJS
		clean := []rune(stripJS(string(data)))
		src := []rune(string(data))
		root, ok := locateJSConfig(c.tool, clean, src)
		if !ok {
			// No recognizable config object at any known form.
			cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: "(config export)", Reason: reasonUninspectableBundlerConfig})
			cfg.Partiality = plugin.Partial(reasonUninspectableBundlerConfig)
			return cfg, true
		}
		extractFromJS(&cfg, root, clean, src)
	}

	finalizePartiality(&cfg)
	return cfg, true
}

// finalizePartiality derives the config's Partiality from its Unreadable refs and
// sets ServerSide from Platform. A config with no unreadable keys is Complete for
// what it statically declared.
func finalizePartiality(cfg *bundlerConfig) {
	cfg.ServerSide = cfg.Platform == platformNode
	if len(cfg.Unreadable) == 0 {
		if len(cfg.Partiality.Reasons) == 0 {
			cfg.Partiality = plugin.Complete()
		}
		return
	}
	set := map[string]bool{}
	for _, u := range cfg.Unreadable {
		set[u.Reason] = true
	}
	reasons := make([]string, 0, len(set))
	for r := range set {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	cfg.Partiality = plugin.Partial(reasons...)
}

// ============================================================================
// JS/TS dialect: extraction from a located literal config value
// ============================================================================

func extractFromJS(cfg *bundlerConfig, root jsVal, clean, src []rune) {
	if root.kind == jvComputed {
		cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: "(config export)", Reason: reasonUninspectableBundlerConfig})
		return
	}
	// An array of configs (webpack/rollup multi-config): read every object element.
	if root.kind == jvArray {
		for _, el := range root.arr {
			if el.kind == jvObject {
				extractJSObject(cfg, el.obj, clean, src)
			} else if el.kind == jvComputed {
				cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: "(config[])", Reason: reasonUninspectableBundlerConfig})
			}
		}
		return
	}
	if root.kind != jvObject {
		cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: "(config export)", Reason: reasonUninspectableBundlerConfig})
		return
	}
	extractJSObject(cfg, root.obj, clean, src)
}

// extractJSObject dispatches on tool to pull the four deliverables from a parsed
// literal config object. Plugin-hosted aliases/defines (webpack DefinePlugin, rollup
// @rollup/plugin-alias/-replace, babel module-resolver) are read by targeted scans of
// the raw config source, because a `new X({…})` / `alias({…})` call is a computed
// expression the object parser (correctly) does not descend into.
func extractJSObject(cfg *bundlerConfig, o *jsObj, clean, src []rune) {
	switch cfg.Tool {
	case bundlerWebpack:
		extractWebpack(cfg, o, clean, src)
	case bundlerRollup:
		extractRollup(cfg, o, clean, src)
	case bundlerEsbuild:
		extractEsbuild(cfg, o)
	case bundlerVite:
		extractVite(cfg, o)
	case bundlerSWC:
		extractSWCObject(cfg, o)
	case bundlerBabel:
		extractBabelObject(cfg, o)
	}
}

func extractWebpack(cfg *bundlerConfig, o *jsObj, clean, src []rune) {
	if resolve, ok := objGet(o, "resolve"); ok && resolve.kind == jvObject {
		if alias, ok := objGet(resolve.obj, "alias"); ok {
			readAliasValue(cfg, alias, "resolve.alias")
		}
	}
	if entry, ok := objGet(o, "entry"); ok {
		readEntryValue(cfg, entry, "entry")
	}
	if target, ok := objGet(o, "target"); ok {
		readPlatformValue(cfg, target, "target")
	}
	// webpack.DefinePlugin({...}) — read its literal object argument statically.
	if obj, found, computed := findCallObjectArg(clean, src, "DefinePlugin"); found {
		readDefineObject(cfg, obj, "DefinePlugin")
	} else if computed {
		cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: "DefinePlugin(<computed>)", Reason: reasonComputedBundlerDefine})
	}
}

func extractRollup(cfg *bundlerConfig, o *jsObj, clean, src []rune) {
	if input, ok := objGet(o, "input"); ok {
		readEntryValue(cfg, input, "input")
	}
	// @rollup/plugin-alias: alias({ entries: {…} | [{find,replacement}] })
	if obj, found, computed := findCallObjectArg(clean, src, "alias"); found {
		if entries, ok := objGet(obj, "entries"); ok {
			readAliasValue(cfg, entries, "alias.entries")
		}
	} else if computed {
		cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: "alias(<computed>)", Reason: reasonComputedBundlerAlias})
	}
	// @rollup/plugin-replace: replace({ values: {…} }) or replace({ KEY: VAL })
	if obj, found, computed := findCallObjectArg(clean, src, "replace"); found {
		if values, ok := objGet(obj, "values"); ok && values.kind == jvObject {
			readDefineObject(cfg, values.obj, "replace.values")
		} else {
			readDefineObject(cfg, obj, "replace")
		}
	} else if computed {
		cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: "replace(<computed>)", Reason: reasonComputedBundlerDefine})
	}
}

func extractEsbuild(cfg *bundlerConfig, o *jsObj) {
	if a, ok := objGet(o, "alias"); ok {
		readAliasValue(cfg, a, "alias")
	}
	if d, ok := objGet(o, "define"); ok && d.kind == jvObject {
		readDefineObject(cfg, d.obj, "define")
	}
	if p, ok := objGet(o, "platform"); ok {
		readPlatformValue(cfg, p, "platform")
	}
	if e, ok := objGet(o, "entryPoints"); ok {
		readEntryValue(cfg, e, "entryPoints")
	}
}

func extractVite(cfg *bundlerConfig, o *jsObj) {
	if resolve, ok := objGet(o, "resolve"); ok && resolve.kind == jvObject {
		if alias, ok := objGet(resolve.obj, "alias"); ok {
			readAliasValue(cfg, alias, "resolve.alias")
		}
	}
	if d, ok := objGet(o, "define"); ok && d.kind == jvObject {
		readDefineObject(cfg, d.obj, "define")
	}
	// Server-side is signalled by an ssr config (top-level `ssr` or `build.ssr`).
	if _, ok := objGet(o, "ssr"); ok {
		cfg.Platform = platformNode
	}
	if build, ok := objGet(o, "build"); ok && build.kind == jvObject {
		if _, ok := objGet(build.obj, "ssr"); ok {
			cfg.Platform = platformNode
		}
		if ro, ok := objGet(build.obj, "rollupOptions"); ok && ro.kind == jvObject {
			if input, ok := objGet(ro.obj, "input"); ok {
				readEntryValue(cfg, input, "build.rollupOptions.input")
			}
		}
		if lib, ok := objGet(build.obj, "lib"); ok && lib.kind == jvObject {
			if entry, ok := objGet(lib.obj, "entry"); ok {
				readEntryValue(cfg, entry, "build.lib.entry")
			}
		}
	}
	if cfg.Platform == platformUnknown {
		cfg.Platform = platformBrowser // Vite is browser-first unless ssr is configured
	}
}

func extractSWCObject(cfg *bundlerConfig, o *jsObj) {
	if jsc, ok := objGet(o, "jsc"); ok && jsc.kind == jvObject {
		if paths, ok := objGet(jsc.obj, "paths"); ok {
			readTsPathsAlias(cfg, paths, "jsc.paths")
		}
		if vars := swcGlobalsVars(jsc.obj); vars != nil {
			readDefineObject(cfg, vars, "jsc.transform.optimizer.globals.vars")
		}
	}
}

func extractBabelObject(cfg *bundlerConfig, o *jsObj) {
	if targets, ok := objGet(o, "targets"); ok {
		readBabelTargets(cfg, targets, "targets")
	}
	if plugins, ok := objGet(o, "plugins"); ok && plugins.kind == jvArray {
		readBabelPlugins(cfg, plugins.arr)
	}
}

// readBabelPlugins scans a plugins array for the alias/define-bearing plugins
// (module-resolver, transform-define). A plugin entry is `["name", {options}]`.
func readBabelPlugins(cfg *bundlerConfig, plugins []jsVal) {
	for _, p := range plugins {
		if p.kind != jvArray || len(p.arr) < 2 {
			continue
		}
		name := p.arr[0]
		opts := p.arr[1]
		if name.kind != jvString || opts.kind != jvObject {
			continue
		}
		switch {
		case strings.Contains(name.str, "module-resolver"):
			if alias, ok := objGet(opts.obj, "alias"); ok {
				readAliasValue(cfg, alias, "module-resolver.alias")
			}
		case strings.Contains(name.str, "transform-define") || strings.Contains(name.str, "transform-inline-environment"):
			readDefineObject(cfg, opts.obj, name.str)
		}
	}
}

// ============================================================================
// value readers shared by the JS extractors
// ============================================================================

// readAliasValue reads an alias declaration in object form `{from: to}` or Vite's
// array form `[{find, replacement}]`. A non-literal target names the key unreadable.
func readAliasValue(cfg *bundlerConfig, v jsVal, prefix string) {
	switch v.kind {
	case jvObject:
		if v.obj.hasSpread {
			cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: prefix + ".<spread>", Reason: reasonComputedBundlerAlias})
		}
		for _, e := range v.obj.entries {
			key := e.key
			if e.keyComputed {
				key = "[computed]"
			}
			if !e.keyComputed && e.val.kind == jvString {
				cfg.Aliases = append(cfg.Aliases, aliasEntry{From: e.key, To: e.val.str})
			} else {
				cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: prefix + "." + key, Reason: reasonComputedBundlerAlias})
			}
		}
	case jvArray:
		for i, el := range v.arr {
			if el.kind != jvObject {
				cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: prefix + "[" + strconv.Itoa(i) + "]", Reason: reasonComputedBundlerAlias})
				continue
			}
			find, okF := objGet(el.obj, "find")
			repl, okR := objGet(el.obj, "replacement")
			if okF && okR && find.kind == jvString && repl.kind == jvString {
				cfg.Aliases = append(cfg.Aliases, aliasEntry{From: find.str, To: repl.str})
			} else {
				name := prefix + "[" + strconv.Itoa(i) + "]"
				if okF && find.kind == jvString {
					name = prefix + "." + find.str
				}
				cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: name, Reason: reasonComputedBundlerAlias})
			}
		}
	default:
		cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: prefix, Reason: reasonComputedBundlerAlias})
	}
}

// readTsPathsAlias reads a tsconfig-style paths map `{ "@/*": ["./src/*"] }` (SWC
// jsc.paths), taking the first target of each entry as the alias replacement.
func readTsPathsAlias(cfg *bundlerConfig, v jsVal, prefix string) {
	if v.kind != jvObject {
		cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: prefix, Reason: reasonComputedBundlerAlias})
		return
	}
	for _, e := range v.obj.entries {
		key := e.key
		if e.keyComputed {
			cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: prefix + ".[computed]", Reason: reasonComputedBundlerAlias})
			continue
		}
		if e.val.kind == jvArray && len(e.val.arr) > 0 && e.val.arr[0].kind == jvString {
			cfg.Aliases = append(cfg.Aliases, aliasEntry{From: key, To: e.val.arr[0].str})
		} else {
			cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: prefix + "." + key, Reason: reasonComputedBundlerAlias})
		}
	}
}

// readDefineObject reads a define/replace map. Literal string/number/bool/null values
// are recorded; a computed value (a call, a member access, a ternary) names the key.
func readDefineObject(cfg *bundlerConfig, o *jsObj, prefix string) {
	if o.hasSpread {
		cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: prefix + ".<spread>", Reason: reasonComputedBundlerDefine})
	}
	for _, e := range o.entries {
		key := e.key
		if e.keyComputed {
			cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: prefix + ".[computed]", Reason: reasonComputedBundlerDefine})
			continue
		}
		val, ok := literalValueText(e.val)
		if !ok {
			cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: prefix + "." + key, Reason: reasonComputedBundlerDefine})
			continue
		}
		cfg.Defines = append(cfg.Defines, defineEntry{Key: key, Value: val})
	}
}

// readEntryValue reads an entry-point declaration in string, array, or object form.
func readEntryValue(cfg *bundlerConfig, v jsVal, prefix string) {
	switch v.kind {
	case jvString:
		cfg.Entries = append(cfg.Entries, v.str)
	case jvArray:
		for i, el := range v.arr {
			if el.kind == jvString {
				cfg.Entries = append(cfg.Entries, el.str)
			} else {
				cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: prefix + "[" + strconv.Itoa(i) + "]", Reason: reasonComputedBundlerEntry})
			}
		}
	case jvObject:
		if v.obj.hasSpread {
			cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: prefix + ".<spread>", Reason: reasonComputedBundlerEntry})
		}
		for _, e := range v.obj.entries {
			key := e.key
			if e.keyComputed {
				cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: prefix + ".[computed]", Reason: reasonComputedBundlerEntry})
				continue
			}
			switch {
			case e.val.kind == jvString:
				cfg.Entries = append(cfg.Entries, e.val.str)
			case e.val.kind == jvArray:
				for _, el := range e.val.arr {
					if el.kind == jvString {
						cfg.Entries = append(cfg.Entries, el.str)
					} else {
						cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: prefix + "." + key, Reason: reasonComputedBundlerEntry})
					}
				}
			case e.val.kind == jvObject:
				// esbuild/webpack `{ import: './x' }` descriptor form.
				if imp, ok := objGet(e.val.obj, "import"); ok && imp.kind == jvString {
					cfg.Entries = append(cfg.Entries, imp.str)
				} else if imp, ok := objGet(e.val.obj, "in"); ok && imp.kind == jvString {
					cfg.Entries = append(cfg.Entries, imp.str)
				} else {
					cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: prefix + "." + key, Reason: reasonComputedBundlerEntry})
				}
			default:
				cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: prefix + "." + key, Reason: reasonComputedBundlerEntry})
			}
		}
	default:
		cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: prefix, Reason: reasonComputedBundlerEntry})
	}
}

// readPlatformValue reads a target/platform declaration in string or array form.
func readPlatformValue(cfg *bundlerConfig, v jsVal, prefix string) {
	switch v.kind {
	case jvString:
		if p := classifyPlatform(v.str); p != platformUnknown {
			cfg.Platform = p
		}
	case jvArray:
		for _, el := range v.arr {
			if el.kind == jvString {
				if p := classifyPlatform(el.str); p != platformUnknown {
					cfg.Platform = p
					return
				}
			}
		}
	default:
		cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: prefix, Reason: reasonComputedBundlerTarget})
	}
}

// classifyPlatform maps a webpack/esbuild target/platform token to browser vs node.
func classifyPlatform(s string) bundlerPlatform {
	switch strings.ToLower(s) {
	case "node", "async-node", "electron-main", "electron-preload", "node-webkit", "nwjs":
		return platformNode
	case "web", "webworker", "browser", "browserslist", "electron-renderer":
		return platformBrowser
	case "neutral":
		return platformNeutral
	}
	return platformUnknown
}

// literalValueText renders a literal jsVal as define text; ok=false for a computed value.
func literalValueText(v jsVal) (string, bool) {
	switch v.kind {
	case jvString:
		return v.str, true
	case jvNumber:
		return v.num, true
	case jvBool:
		return strconv.FormatBool(v.b), true
	case jvNull:
		return "null", true
	}
	return "", false
}

// swcGlobalsVars navigates jsc → transform → optimizer → globals → vars.
func swcGlobalsVars(jsc *jsObj) *jsObj {
	t, ok := objGet(jsc, "transform")
	if !ok || t.kind != jvObject {
		return nil
	}
	opt, ok := objGet(t.obj, "optimizer")
	if !ok || opt.kind != jvObject {
		return nil
	}
	g, ok := objGet(opt.obj, "globals")
	if !ok || g.kind != jvObject {
		return nil
	}
	vars, ok := objGet(g.obj, "vars")
	if !ok || vars.kind != jvObject {
		return nil
	}
	return vars.obj
}

// readBabelTargets reads Babel `targets`: a string ("node"/"defaults"), or an object
// with node/browsers/esmodules keys, mapping to browser vs node.
func readBabelTargets(cfg *bundlerConfig, v jsVal, prefix string) {
	switch v.kind {
	case jvString:
		if strings.EqualFold(v.str, "node") || strings.HasPrefix(strings.ToLower(v.str), "node ") {
			cfg.Platform = platformNode
		} else {
			cfg.Platform = platformBrowser
		}
	case jvObject:
		if _, ok := objGet(v.obj, "node"); ok {
			cfg.Platform = platformNode
			return
		}
		if _, ok := objGet(v.obj, "browsers"); ok {
			cfg.Platform = platformBrowser
			return
		}
		if _, ok := objGet(v.obj, "esmodules"); ok {
			cfg.Platform = platformBrowser
		}
	default:
		cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: prefix, Reason: reasonComputedBundlerTarget})
	}
}

// ============================================================================
// JSON dialect: extraction (SWC .swcrc, babel.config.json, package.json#babel)
// ============================================================================

func extractFromJSON(cfg *bundlerConfig, root interface{}) {
	m, ok := root.(map[string]interface{})
	if !ok {
		cfg.Unreadable = append(cfg.Unreadable, unreadableRef{Key: "(config root)", Reason: reasonBundlerConfigUnreadable})
		return
	}
	switch cfg.Tool {
	case bundlerSWC:
		extractSWCJSON(cfg, m)
	case bundlerBabel:
		extractBabelJSON(cfg, m)
	}
}

func extractSWCJSON(cfg *bundlerConfig, m map[string]interface{}) {
	jsc, _ := m["jsc"].(map[string]interface{})
	if jsc == nil {
		return
	}
	if paths, ok := jsc["paths"].(map[string]interface{}); ok {
		for _, k := range sortedKeys(paths) {
			if arr, ok := paths[k].([]interface{}); ok && len(arr) > 0 {
				if s, ok := arr[0].(string); ok {
					cfg.Aliases = append(cfg.Aliases, aliasEntry{From: k, To: s})
				}
			}
		}
	}
	if vars := jsonPath(jsc, "transform", "optimizer", "globals", "vars"); vars != nil {
		if vm, ok := vars.(map[string]interface{}); ok {
			for _, k := range sortedKeys(vm) {
				cfg.Defines = append(cfg.Defines, defineEntry{Key: k, Value: jsonScalarText(vm[k])})
			}
		}
	}
}

func extractBabelJSON(cfg *bundlerConfig, m map[string]interface{}) {
	if t, ok := m["targets"]; ok {
		switch tv := t.(type) {
		case string:
			if strings.EqualFold(tv, "node") {
				cfg.Platform = platformNode
			} else {
				cfg.Platform = platformBrowser
			}
		case map[string]interface{}:
			if _, ok := tv["node"]; ok {
				cfg.Platform = platformNode
			} else if _, ok := tv["browsers"]; ok {
				cfg.Platform = platformBrowser
			} else if _, ok := tv["esmodules"]; ok {
				cfg.Platform = platformBrowser
			}
		}
	}
	if plugins, ok := m["plugins"].([]interface{}); ok {
		for _, p := range plugins {
			arr, ok := p.([]interface{})
			if !ok || len(arr) < 2 {
				continue
			}
			name, ok := arr[0].(string)
			if !ok {
				continue
			}
			opts, ok := arr[1].(map[string]interface{})
			if !ok {
				continue
			}
			switch {
			case strings.Contains(name, "module-resolver"):
				if alias, ok := opts["alias"].(map[string]interface{}); ok {
					for _, k := range sortedKeys(alias) {
						if s, ok := alias[k].(string); ok {
							cfg.Aliases = append(cfg.Aliases, aliasEntry{From: k, To: s})
						}
					}
				}
			case strings.Contains(name, "transform-define"):
				for _, k := range sortedKeys(opts) {
					cfg.Defines = append(cfg.Defines, defineEntry{Key: k, Value: jsonScalarText(opts[k])})
				}
			}
		}
	}
}

func jsonPath(m map[string]interface{}, keys ...string) interface{} {
	var cur interface{} = m
	for _, k := range keys {
		mm, ok := cur.(map[string]interface{})
		if !ok {
			return nil
		}
		cur, ok = mm[k]
		if !ok {
			return nil
		}
	}
	return cur
}

func jsonScalarText(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case nil:
		return "null"
	}
	return ""
}

func sortedKeys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ============================================================================
// literal JS value parser (over the comment/string-stripped rune stream)
// ============================================================================

// jsValKind classifies a parsed literal value. jvComputed marks a value that is not
// statically readable (a call, a reference, a template with interpolation, a spread).
type jsValKind int

const (
	jvString jsValKind = iota
	jvNumber
	jvBool
	jvNull
	jvObject
	jvArray
	jvComputed
)

type jsVal struct {
	kind jsValKind
	str  string // jvString value (unescaped one level)
	num  string // jvNumber raw token
	b    bool   // jvBool
	obj  *jsObj // jvObject
	arr  []jsVal
}

type jsEntry struct {
	key         string
	keyComputed bool // a computed property key `[expr]:` — the key itself is unreadable
	val         jsVal
}

type jsObj struct {
	entries   []jsEntry
	hasSpread bool // a `...spread` made the object incompletely known
}

// isStrAt reports whether position p begins a string/template literal. stripJS marks
// a former string's opening quote with '_' in clean, but '_' is ALSO a valid
// identifier character, so the two are distinguished only by consulting the raw
// source: a marker iff src[p] is an actual quote. (stripJS keeps src and clean
// length-identical, so p indexes both.)
func isStrAt(src []rune, p int) bool {
	if p < 0 || p >= len(src) {
		return false
	}
	c := src[p]
	return c == '\'' || c == '"' || c == '`'
}

func objGet(o *jsObj, key string) (jsVal, bool) {
	if o == nil {
		return jsVal{}, false
	}
	for i := range o.entries {
		if !o.entries[i].keyComputed && o.entries[i].key == key {
			return o.entries[i].val, true
		}
	}
	return jsVal{}, false
}

// locateJSConfig finds a tool's literal config object in an executable JS/TS file.
// esbuild has no `export default` convention — its options object is the argument to
// `esbuild.build({…})` / `buildSync` / `context` — so it is located by reading that
// call's literal object argument (never by evaluating the call). Every other tool
// exports its config via `export default` / `module.exports =`.
func locateJSConfig(tool bundlerKind, clean, src []rune) (jsVal, bool) {
	if tool == bundlerEsbuild {
		for _, fn := range []string{"build", "buildSync", "context"} {
			if o, found, _ := findCallObjectArg(clean, src, fn); found {
				return jsVal{kind: jvObject, obj: o}, true
			}
		}
	}
	return locateConfigValue(clean, src)
}

// locateConfigValue finds the config value a JS/TS config file exports: the RHS of
// `export default …` or `module.exports = …`. An identity wrapper call
// (`defineConfig({…})`, `esbuild.build({…})`) is unwrapped to its literal object
// argument. A function-valued config (`(env) => ({…})`) is returned as jvComputed.
func locateConfigValue(clean, src []rune) (jsVal, bool) {
	n := len(clean)
	i := 0
	for i < n {
		if !isIdentStart(clean[i]) {
			i++
			continue
		}
		w, nx := readWord(clean, i)
		switch w {
		case "export":
			p := skipSpace(clean, nx)
			if ww, nnx := peekWord(clean, p); ww == "default" {
				p = skipSpace(clean, nnx)
				return parseConfigRHS(clean, src, p), true
			}
			i = nx
		case "module":
			p := skipSpace(clean, nx)
			if p < n && clean[p] == '.' {
				p = skipSpace(clean, p+1)
				if ww, nnx := peekWord(clean, p); ww == "exports" {
					p = skipSpace(clean, nnx)
					if p < n && clean[p] == '=' {
						p = skipSpace(clean, p+1)
						return parseConfigRHS(clean, src, p), true
					}
				}
			}
			i = nx
		default:
			i = nx
		}
	}
	return jsVal{}, false
}

// parseConfigRHS parses the right-hand side of the config export, unwrapping a single
// identity-wrapper call around a literal object/array argument.
func parseConfigRHS(clean, src []rune, p int) jsVal {
	n := len(clean)
	p = skipSpace(clean, p)
	if p >= n {
		return jsVal{kind: jvComputed}
	}
	switch clean[p] {
	case '{', '[':
		v, _ := parseJSValue(clean, src, p)
		return v
	}
	if clean[p] == '_' && isStrAt(src, p) {
		v, _ := parseJSValue(clean, src, p)
		return v
	}
	if isIdentStart(clean[p]) {
		w, nx := readWord(clean, p)
		if w == "function" || w == "async" {
			return jsVal{kind: jvComputed}
		}
		q := skipSpace(clean, nx)
		for q < n && clean[q] == '.' { // member wrapper: esbuild.build(...)
			q = skipSpace(clean, q+1)
			_, nq := readWord(clean, q)
			q = skipSpace(clean, nq)
		}
		if q < n && clean[q] == '(' {
			a := skipSpace(clean, q+1)
			if a < n && (clean[a] == '{' || clean[a] == '[') {
				v, _ := parseJSValue(clean, src, a)
				return v
			}
			return jsVal{kind: jvComputed} // wrapper with a non-literal (function) argument
		}
		return jsVal{kind: jvComputed} // bare reference
	}
	v, _ := parseJSValue(clean, src, p)
	return v
}

// parseJSValue parses one literal value at pos (pointing at its first significant
// rune) and returns it with the index just past it. A non-literal value is jvComputed
// and the returned index is advanced past the whole value expression.
func parseJSValue(clean, src []rune, pos int) (jsVal, int) {
	n := len(clean)
	pos = skipSpace(clean, pos)
	if pos >= n {
		return jsVal{kind: jvComputed}, pos
	}
	switch {
	case clean[pos] == '{':
		o, np := parseJSObject(clean, src, pos)
		return jsVal{kind: jvObject, obj: o}, np
	case clean[pos] == '[':
		arr, np := parseJSArray(clean, src, pos)
		return jsVal{kind: jvArray, arr: arr}, np
	case clean[pos] == '_' && isStrAt(src, pos):
		s, lit, np := readStr(clean, src, pos)
		if lit {
			return jsVal{kind: jvString, str: s}, np
		}
		return jsVal{kind: jvComputed}, np
	case isIdentStart(clean[pos]):
		w, nw := readWord(clean, pos)
		after := skipSpace(clean, nw)
		if isValueEnd(clean, after) {
			switch w {
			case "true":
				return jsVal{kind: jvBool, b: true}, after
			case "false":
				return jsVal{kind: jvBool, b: false}, after
			case "null", "undefined":
				return jsVal{kind: jvNull}, after
			}
		}
		return jsVal{kind: jvComputed}, skipValue(clean, pos)
	case unicode.IsDigit(clean[pos]) || clean[pos] == '-' || clean[pos] == '+' || clean[pos] == '.':
		end := skipValue(clean, pos)
		tok := strings.TrimSpace(string(clean[pos:end]))
		if isNumericToken(tok) {
			return jsVal{kind: jvNumber, num: tok}, end
		}
		return jsVal{kind: jvComputed}, end
	default:
		return jsVal{kind: jvComputed}, skipValue(clean, pos)
	}
}

func parseJSObject(clean, src []rune, open int) (*jsObj, int) {
	n := len(clean)
	o := &jsObj{}
	p := open + 1
	for p < n {
		p = skipSpace(clean, p)
		if p >= n {
			break
		}
		if clean[p] == '}' {
			p++
			break
		}
		if clean[p] == ',' {
			p++
			continue
		}
		if clean[p] == '.' && p+2 < n && clean[p+1] == '.' && clean[p+2] == '.' {
			o.hasSpread = true
			p = skipValue(clean, p+3)
			continue
		}
		key, keyComputed, np := readObjKey(clean, src, p)
		p = skipSpace(clean, np)
		if p < n && clean[p] == '(' { // method shorthand: value is a function → computed
			o.entries = append(o.entries, jsEntry{key: key, keyComputed: keyComputed, val: jsVal{kind: jvComputed}})
			p = skipGroup(clean, p)
			p = skipSpace(clean, p)
			if p < n && clean[p] == '{' {
				p = skipGroup(clean, p)
			}
			continue
		}
		if p < n && clean[p] == ':' {
			p = skipSpace(clean, p+1)
			val, vp := parseJSValue(clean, src, p)
			o.entries = append(o.entries, jsEntry{key: key, keyComputed: keyComputed, val: val})
			p = vp
			continue
		}
		// shorthand `{ key }` → the value is a reference → computed
		o.entries = append(o.entries, jsEntry{key: key, keyComputed: keyComputed, val: jsVal{kind: jvComputed}})
	}
	return o, p
}

func parseJSArray(clean, src []rune, open int) ([]jsVal, int) {
	n := len(clean)
	var out []jsVal
	p := open + 1
	for p < n {
		p = skipSpace(clean, p)
		if p >= n {
			break
		}
		if clean[p] == ']' {
			p++
			break
		}
		if clean[p] == ',' {
			p++
			continue
		}
		if clean[p] == '.' && p+2 < n && clean[p+1] == '.' && clean[p+2] == '.' {
			out = append(out, jsVal{kind: jvComputed})
			p = skipValue(clean, p+3)
			continue
		}
		val, vp := parseJSValue(clean, src, p)
		out = append(out, val)
		p = vp
	}
	return out, p
}

// readObjKey reads an object property key at p: a string-literal key, a computed
// `[expr]` key (keyComputed=true), or an identifier/numeric key.
func readObjKey(clean, src []rune, p int) (key string, keyComputed bool, np int) {
	n := len(clean)
	if p >= n {
		return "", false, p
	}
	if clean[p] == '_' && isStrAt(src, p) {
		s, lit, e := readStr(clean, src, p)
		if !lit {
			return "", true, e
		}
		return s, false, e
	}
	if clean[p] == '[' {
		return "", true, skipGroup(clean, p)
	}
	start := p
	for p < n && isIdentPart(clean[p]) {
		p++
	}
	return string(clean[start:p]), false, p
}

// readStr reads a string/template literal from the RAW source at the '_' marker in
// clean. It returns the unescaped value, whether it is a plain string LITERAL (a
// template with `${…}` interpolation is NOT a literal — it is computed), and the
// index just past the closing quote (valid in both clean and src, which stripJS keeps
// length-identical).
func readStr(clean, src []rune, pos int) (val string, literal bool, np int) {
	n := len(src)
	if pos >= n {
		return "", false, pos
	}
	q := src[pos]
	if q != '\'' && q != '"' && q != '`' {
		return "", false, skipSpace(clean, pos+1)
	}
	var b strings.Builder
	i := pos + 1
	if q == '`' {
		interp := false
		depth := 0
		for i < n {
			c := src[i]
			if c == '\\' && i+1 < n {
				b.WriteRune(src[i+1])
				i += 2
				continue
			}
			if depth == 0 && c == '`' {
				break
			}
			if c == '$' && i+1 < n && src[i+1] == '{' {
				interp = true
				depth++
				i += 2
				continue
			}
			if depth > 0 && c == '{' {
				depth++
				i++
				continue
			}
			if depth > 0 && c == '}' {
				depth--
				i++
				continue
			}
			if depth == 0 {
				b.WriteRune(c)
			}
			i++
		}
		if interp {
			return "", false, i + 1
		}
		return b.String(), true, i + 1
	}
	for i < n {
		c := src[i]
		if c == '\\' && i+1 < n {
			b.WriteRune(src[i+1])
			i += 2
			continue
		}
		if c == q {
			break
		}
		b.WriteRune(c)
		i++
	}
	return b.String(), true, i + 1
}

// skipValue advances past a value expression, returning the index of the top-level
// terminator (',' '}' ']' ';') that ends it. Balancing uses the stripped stream, so
// commas/braces inside former strings or comments cannot mislead it.
func skipValue(clean []rune, pos int) int {
	n := len(clean)
	depth := 0
	for pos < n {
		switch clean[pos] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return pos
			}
			depth--
		case ',', ';':
			if depth == 0 {
				return pos
			}
		}
		pos++
	}
	return pos
}

// isValueEnd reports whether pos sits at a value terminator (or EOF), used to tell a
// bare `true`/`false`/`null` literal from an identifier that begins a larger
// expression (`true && flag`, `foo.bar`).
func isValueEnd(clean []rune, pos int) bool {
	if pos >= len(clean) {
		return true
	}
	switch clean[pos] {
	case ',', '}', ']', ';', ')':
		return true
	}
	return false
}

// isNumericToken reports whether tok is a JS numeric literal (decimal, hex, binary,
// octal, float, exponent, with optional sign and `_` separators). A token that is not
// purely numeric (e.g. `1 + x`) is not a literal number.
func isNumericToken(tok string) bool {
	if tok == "" {
		return false
	}
	s := tok
	if s[0] == '+' || s[0] == '-' {
		s = s[1:]
	}
	if s == "" {
		return false
	}
	if len(s) > 2 && s[0] == '0' {
		switch s[1] {
		case 'x', 'X', 'b', 'B', 'o', 'O':
			for _, c := range s[2:] {
				if !isHexDigit(c) && c != '_' {
					return false
				}
			}
			return true
		}
	}
	seenDot, seenExp := false, false
	for i, c := range s {
		switch {
		case c >= '0' && c <= '9' || c == '_':
		case c == '.' && !seenDot && !seenExp:
			seenDot = true
		case (c == 'e' || c == 'E') && !seenExp && i > 0:
			seenExp = true
		case (c == '+' || c == '-') && i > 0 && (s[i-1] == 'e' || s[i-1] == 'E'):
		default:
			return false
		}
	}
	return true
}

func isHexDigit(c rune) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// findCallObjectArg scans the stripped stream for the first call `name( { … } )` (or
// `new …name( { … } )`) whose first argument is a literal OBJECT, returning the parsed
// object. `found` is true when such a literal-object argument was read; `computed` is
// true when the name was called but with a non-object (computed) first argument, so
// the caller can name that as unreadable. This reads a literal object ARGUMENT — it
// never evaluates the call.
func findCallObjectArg(clean, src []rune, name string) (obj *jsObj, found bool, computed bool) {
	n := len(clean)
	i := 0
	for i < n {
		if !isIdentStart(clean[i]) {
			i++
			continue
		}
		w, nx := readWord(clean, i)
		if w != name {
			i = nx
			continue
		}
		p := skipSpace(clean, nx)
		if p < n && clean[p] == '(' {
			a := skipSpace(clean, p+1)
			if a < n && clean[a] == '{' {
				o, _ := parseJSObject(clean, src, a)
				return o, true, false
			}
			computed = true // called, but not with a literal object
		}
		i = nx
	}
	return nil, false, computed
}
