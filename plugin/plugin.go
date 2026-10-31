// Package plugin defines the LanguagePlugin contract: the interface a
// language-specific evidence producer implements, the value types it exchanges with
// the pipeline, the first-class Partiality declaration (inv.5), and an in-memory
// StubPlugin used by hermetic tests.
//
// This package is import-light by design: the pipeline package imports it, and
// it MUST NOT import internal/plugin/goanalysis (which links the heavy analysis
// libraries). That import boundary is the inv.8 mechanism — analysis code lives only in
// the cmd/assay-plugin-go subprocess binary, never in-process in the host.
package plugin

import (
	"context"

	"github.com/ferralon-ai/ferralon-assay/capability"
)

// LanguagePlugin is the contract for one language's evidence production. Every operation
// returns artifacts (as typed results the pipeline marshals), never verdicts: the
// language-agnostic core forms the verdict, so that judgment stays uniform across languages
// (inv.6). Partiality is first-class: an operation that cannot fully resolve its answer
// declares it, never returns a confident-looking incomplete result.
type LanguagePlugin interface {
	// Language returns the language tag this plugin serves, e.g. "go".
	Language() string

	// --- Operations every lane implements ---

	// IndexSymbols emits SCIP-qualified symbol ids stable across app + dependencies.
	IndexSymbols(ctx context.Context, req IndexSymbolsRequest) (SymbolIndexResult, error)

	// ResolveDependencySymbols maps an advisory's vulnerable symbol(s) to concrete symbols
	// in this codebase. The advisory identifiers are GIVEN (inv.7) — the plugin never
	// originates them.
	ResolveDependencySymbols(ctx context.Context, req ResolveSymbolsRequest) (SymbolResolutionResult, error)

	// ResolveDependencyVersions reads the codebase's declared dependency versions
	// (pom.xml / build.gradle for Java; Go resolves versions from go.mod in-pipeline and returns Unsupported) for the given advisory
	// coordinate. It NEVER guesses a version: a coordinate it cannot resolve confidently
	// (BOM-managed, unresolvable property indirection) is returned with Resolved=false so
	// the disqualification predicate fails OPEN (inv.5: unknown is never not-affected).
	ResolveDependencyVersions(ctx context.Context, req ResolveVersionsRequest) (DependencyVersionResult, error)

	// CallGraph builds the (possibly partial) call graph for the codebase.
	CallGraph(ctx context.Context, req CallGraphRequest) (CallGraphResult, error)

	// FindIngresses identifies framework-idiomatic entry points (HTTP routes, handlers).
	FindIngresses(ctx context.Context, req FindIngressesRequest) (IngressResult, error)

	// Reachability derives reachable (ingress, sink, path) candidate pairs for the given
	// vulnerable symbols, via govulncheck reconciled with the call graph.
	Reachability(ctx context.Context, req ReachabilityRequest) (ReachabilityResult, error)

	// --- Operations whose support varies by lane (a lane that lacks one returns declared partiality, Unsupported) ---

	// ComputeTaint computes source→sink taint flows.
	ComputeTaint(ctx context.Context, req ComputeTaintRequest) (TaintResult, error)

	// GenerateHarness scaffolds a fuzz/unit/integration harness. Go and JavaScript implement it; the other lanes return Unsupported.
	GenerateHarness(ctx context.Context, req GenerateHarnessRequest) (HarnessResult, error)

	// BuildManifest produces enough to build and run the app under test.
	BuildManifest(ctx context.Context, req BuildManifestRequest) (BuildManifestResult, error)

	// ResolveInventory resolves the whole dependency graph for the buildable module (§4.1).
	// A plugin without a resolver returns DependencyInventory{Partiality: Unsupported()} (honest
	// absence, never an empty-but-successful inventory).
	ResolveInventory(ctx context.Context, req ResolveInventoryRequest) (DependencyInventory, error)

	// CapabilityManifest returns the lane's static capability manifest — the up-front
	// declaration of what this analyzer supports (the compile-time complement to the per-run
	// Partiality). Support varies by lane; each manifest and each operation's Partiality state what
	// that lane implements. A lane without a manifest returns capability.Manifest{Supported:false}
	// (honest absence, never a Supported:true manifest with empty axes).
	CapabilityManifest(ctx context.Context, req CapabilityManifestRequest) (capability.Manifest, error)
}

// Partiality declares whether an operation fully resolved its answer. A plugin that cannot
// (reflection, dynamic dispatch, cgo, tool failure) returns Complete=false with one or more
// machine-readable Reasons rather than a confident-looking incomplete result.
// It NEVER renders an unknown as "safe"/"not reachable" — the inv.5 boundary.
type Partiality struct {
	Complete bool     `json:"complete"`
	Reasons  []string `json:"reasons,omitempty"` // canonical reason codes; see PartialReason*
	// Scoped carries limits the lane can bound to the packages the hidden code could reach. Reasons
	// stay run-wide; a scoped reason counts against an advisory exactly as a run-wide one unless its
	// Targets exclude the advisory's package (trigger/assess.go). Only the ingress, reachability
	// and vulnerable-symbol results' Scoped limits reach the verdict; set on any other result, they
	// are dropped.
	Scoped []ScopedReason `json:"scoped,omitempty"`
}

// ScopedReason is a partiality reason bounded by what it could hide. Package and every Targets entry
// are PURLs without a version; "" means first-party.
type ScopedReason struct {
	Reason  string `json:"reason"`            // same vocabulary and classifier as Partiality.Reasons
	Package string `json:"package,omitempty"` // package whose code holds the blind spot
	Path    string `json:"path,omitempty"`    // location inside Package (import path, class, module file); disclosure only
	// Targets over-approximates every package an edge hidden by this limit could reach, including
	// callbacks and the hidden code's transitive dependencies. Empty (nil or []) = unbounded, which
	// counts against every advisory; a bounded limit names at least one target.
	Targets []string `json:"targets,omitempty"`
}

// Canonical partiality reason codes (machine-readable, stable strings).
const (
	PartialReasonReflection      = "reflection"         // calls via reflect.* invisible to static analysis
	PartialReasonDynamicDispatch = "dynamic_dispatch"   // interface dispatch not fully resolved
	PartialReasonCgo             = "cgo"                // native-code boundary (cgo) crossed
	PartialReasonUnsupported     = "unsupported_phase1" // operation not implemented by the lane
	PartialReasonToolFailure     = "tool_failure"       // a wrapped tool failed; surfaced, not retried (inv.4)
	PartialReasonNoIngress       = "no_known_ingress"   // reachable sink, no entry point found
	PartialReasonNoManifest      = "no_manifest"        // no lockfile/manifest to read installed versions from

	// PartialReasonPolicyAdvisoryNoCoordinates: advisories in the selected corpus policy name no
	// affected package, so there is nothing to match against the repository's dependencies. The
	// gap is in the corpus data, the same on every scan of that policy, so it is an inherent limit
	// (report.ClassifyPartialityReason); its count and ids are still disclosed in the Report.
	PartialReasonPolicyAdvisoryNoCoordinates = "policy_advisory_no_coordinates"

	// PartialReasonReachabilityUndetermined is declared when a reachability pass could
	// not reach a determination — the advisory applies to this module and the analysis
	// neither found a path to the vulnerable code nor established that none exists.
	//
	// It exists to keep that case OFF the reflection/dynamic_dispatch codes. Those two
	// name limits of the METHOD, true of every scan of a language, and surfaces disclose
	// them quietly (report.ClassifyPartialityReason). An undetermined result is the
	// opposite: it is specific to THIS run and it is precisely what the run failed to
	// establish, so it must be disclosed as loudly as any other step that did not
	// happen. Overloading the quiet codes for it renders an unknown as a clean scan —
	// the inv.5 boundary this vocabulary exists to hold.
	PartialReasonReachabilityUndetermined = "reachability_undetermined"

	// PartialReasonAdvisorySymbolUnresolved: the package's code was read in full, but an advisory
	// symbol named nothing in it.
	PartialReasonAdvisorySymbolUnresolved = "advisory_symbol_unresolved"

	// Shared dependency-resolution partiality codes (onyx-q6, cross-lane vocabulary owned by
	// platform-core). Each names a distinct way an inventory/graph resolution is honestly partial;
	// a lane appends a suffix to localise it (§4 naming: "code:python_version"-style on the reason
	// string), so the base codes stay language-agnostic while the suffix carries the lane specific.
	//
	// PartialReasonEnvConditionUnresolved: an environment-conditional dependency could not be
	// resolved because the deciding environment fact is unknown (a marker/condition such as a target
	// platform or language-version gate). The dependency's presence is undetermined, not absent —
	// resolve it by supplying ResolveInventoryRequest.TargetEnv.
	PartialReasonEnvConditionUnresolved = "env_condition_unresolved"
	// PartialReasonSourceUnpinned: a dependency's source is not pinned to an exact, verifiable
	// version/artifact (an unlocked range, a VCS/path source with no lock entry), so the installed
	// identity cannot be established — undetermined, never guessed to a concrete version.
	PartialReasonSourceUnpinned = "source_unpinned"
	// PartialReasonRelationshipUnexpressed: a dependency relationship (edge) is not expressed in the
	// manifest/lock the resolver read (a transitive/optional/extra edge the lock does not record), so
	// the graph is partial — an unexpressed edge is absent from the graph, never inferred to exist.
	PartialReasonRelationshipUnexpressed = "relationship_unexpressed"

	// --- dependency-inventory reason localisers ---
	//
	// These name conditions a whole-graph dependency inventory (ResolveInventory, §4.1) cannot
	// resolve from lockfile/manifest metadata alone, under the no-package-manager constraint
	// (§3.3/§10.1). Each is a DECLARED gap on a node (or the graph), never a silent omission:
	// §3.1 forbids inferring safety from missing evidence.
	//
	// RECONCILED to the onyx-q6 shared bases (§4 "code:suffix" naming): each value localises one
	// canonical base above, so a cross-lane consumer reads the base and the JS suffix carries the
	// lane specific. The named consts stay for call-site readability; their VALUES are the wire
	// strings (base + ":" + suffix).
	PartialReasonGitRefUnpinned     = PartialReasonSourceUnpinned + ":git_ref"                        // git dep, no pinned commit sha (moving ref); Artifact.Digest empty
	PartialReasonLocalPathDep       = PartialReasonSourceUnpinned + ":local_path"                     // file:/link: local dependency; path identity, no registry version/integrity
	PartialReasonPlatformCondition  = PartialReasonEnvConditionUnresolved + ":platform"               // optional dep gated on os/cpu/libc; Target unevaluable from metadata, never guessed
	PartialReasonAliasTargetAbsent  = PartialReasonRelationshipUnexpressed + ":alias_target"          // npm: alias whose target is absent from the lockfile
	PartialReasonWorkspaceAttrib    = PartialReasonRelationshipUnexpressed + ":workspace_attribution" // workspace membership needs a manifest join that is missing/unreadable
	PartialReasonPeerMetadataAbsent = PartialReasonRelationshipUnexpressed + ":peer_metadata"         // peer relationships not derivable from this dialect's lockfile (Yarn Classic)

	// lockfile_ambiguous is the one JS localiser that does NOT fit the three onyx bases
	// (env/source/relationship): it names a root-level dialect-selection failure (two authoritative
	// locks, no packageManager signal → no nodes emitted for that root), not a per-dependency gap.
	// Mapped onto the existing tool_failure base and flagged to L0 (quartz-q14) for cross-lane
	// adjudication — anvil may want a fourth base for "resolution could not proceed".
	PartialReasonLockfileAmbiguous = PartialReasonToolFailure + ":lockfile_ambiguous"

	// --- module-resolution reason localisers ---
	//
	// These name conditions the JS/TS import-scoped module resolver (CallGraph) cannot turn into a
	// first-party edge, under the no-Node/no-package-manager, node_modules-excluded constraint
	// (§3.3/§10.1). Each is a DECLARED gap, never a silent decline or a fabricated edge (§3.1). They
	// split dynamic_dispatch into three reviewer-legible conditions;
	// dynamic_dispatch keeps its meaning (a callee name resolved to >1 in-tree
	// decl / prototype dispatch).
	//
	// RECONCILED to the onyx-q6 shared bases (quartz-q7 resolution): all three localise
	// relationship_unexpressed — each is an import/call EDGE that could not be expressed. Cross-lane
	// consumers (Python bare imports, .NET package refs) read the base; the suffix is the JS specific.
	PartialReasonUninspectablePackage     = PartialReasonRelationshipUnexpressed + ":uninspectable_package" // static bare specifier into a package whose source is not in-tree (node_modules excluded); declined-but-attributed, never an edge
	PartialReasonDynamicImportSpecifier   = PartialReasonRelationshipUnexpressed + ":dynamic_import"        // runtime-computed ESM target (import(expr)); never evaluated, never guessed
	PartialReasonComputedRequireSpecifier = PartialReasonRelationshipUnexpressed + ":computed_require"      // runtime-computed CJS target (require(var)); never evaluated, never guessed
	PartialReasonUnresolvedModule         = PartialReasonRelationshipUnexpressed + ":unresolved_module"     // static relative specifier naming no in-tree source module (native addon, build-generated file), or a process.dlopen load; its code runs on load but is never read
	PartialReasonEvaluatedCode            = PartialReasonRelationshipUnexpressed + ":evaluated_code"        // code built from a string at run time (eval, new Function); never read, so its calls and loads are never seen

	// PartialReasonUnlistedSites is set on a CallGraphResult if and only if at least one call or
	// load the lane declined to connect is missing from CallGraphResult.Unresolved: the body of
	// evaluated code, a source file the lane could not read, a skipped construct, a limit the lane
	// records for the whole run rather than for a site. Its absence is the lane's promise that
	// Unresolved lists every declined site. A reader that narrows a result by the listed sites
	// must treat it as partial whenever this reason is present, whatever the list says.
	PartialReasonUnlistedSites = PartialReasonRelationshipUnexpressed + ":unlisted_sites"

	// --- Spring semantic-decode partiality codes (edge-seam.md §3) ---
	//
	// The six honest-residue conditions the JVM Spring bean-model + AOP/repo/SpEL/guard
	// overlays declare when a wiring fact is irreducible statically. Declared ONCE here
	// (shared vocabulary; overlays import these, none invents its own). Never a fabricated
	// edge or a flipped verdict — each is the tri-state UNKNOWN arm made legible (§3.1).
	//
	// PartialReasonBeanAmbiguous localises dynamic_dispatch (it does
	// NOT retire the base): a @Autowired injection point satisfied by >1 candidate bean
	// with no @Primary/@Qualifier winner, so the wired implementation is undetermined and
	// the interface hop stays unresolved. Raised by the bean resolver.
	PartialReasonBeanAmbiguous = PartialReasonDynamicDispatch + ":bean_ambiguous"
	// PartialReasonProxyMediated (new base): an AOP proxy/advice sits between caller and
	// target, so no clean value-flow claim can be made through the unread interceptor.
	// Raised by the AOP overlay (#2).
	PartialReasonProxyMediated = "proxy_mediated"
	// PartialReasonAsyncBoundary (new base): @Async/@Scheduled severs the synchronous-call
	// assumption — a control-flow discontinuity, distinct from advice mediation. Raised by
	// the AOP overlay (#2).
	PartialReasonAsyncBoundary = "async_boundary"
	// PartialReasonSpELPresent (new base): a string-embedded SpEL expression at or guarding
	// a sink the analyzer cannot evaluate (presence only; content is unrecoverable on the
	// Java source path). Raised by the SpEL overlay (#4).
	PartialReasonSpELPresent = "spel_present"
	// PartialReasonRepositorySynthesized (new base): a Spring Data repository method modeled
	// as a body-absent DB sink — the implementation bytecode is runtime-synthesized, its
	// body not analyzed. Raised by the repository overlay (#3).
	PartialReasonRepositorySynthesized = "repository_synthesized_sink"
	// PartialReasonGuardUnknown (new base): a filter/interceptor/security annotation on the
	// path whose effect (sanitize/authorize) is undeterminable — the tri-state UNKNOWN arm,
	// NOT a positive "guarded" signal. Raised by the guard overlay (#5).
	PartialReasonGuardUnknown = "guard_unknown"

	// --- C/C++ partiality codes (c-cpp-parity-map-2026-09-28.md §5) ---
	//
	// New bases for the C/C++ lane's own limits — distinct from the Go-caller-into-native
	// cgo boundary above, which names a Go program crossing OUT to native code, not a C/C++
	// program's own analysis limits.

	// PartialReasonAdvisorySymbolAbsent (new base, run-specific/loud): the advisory carries
	// a version range but declares no vulnerable symbol, so symbol-level reachability was
	// never ATTEMPTED for it — there is nothing to search for. Distinct from a symbol lookup
	// that ran and found nothing: a lane declares it from ResolveDependencySymbols when the
	// request names no symbol to resolve. It is loud by default (ClassifyPartialityReason's
	// default arm) because it says a step of THIS run did not happen, not a property of the
	// method true on every run.
	PartialReasonAdvisorySymbolAbsent = "advisory_symbol_absent"
	// PartialReasonAdvisoryUnknownToAnalyzer (loud): the analyzer that would search for the
	// advisory's symbols emitted no evidence about the advisory at all. It may not know the
	// advisory, or may never have analyzed the affected module (a test-only or tool dependency
	// outside the graph it loads). Either way its silence is not a search that came back empty.
	PartialReasonAdvisoryUnknownToAnalyzer = "advisory_unknown_to_analyzer"
	// PartialReasonExcludedFiles (loud): files the build left out (another GOOS or GOARCH, a build
	// tag) may call into the module an analyzer found no path to, and the analyzer never traced
	// them, so its refutation does not cover the builds that compile them.
	PartialReasonExcludedFiles = "excluded_files"
	// PartialReasonUnsearchedMethods (loud): exported methods a caller can invoke that the analyzer's
	// search never started from (Go: a method of a generic type, or one promoted by embedding from a
	// type outside the search) may call into the module it found no path to, so its refutation does
	// not cover them.
	PartialReasonUnsearchedMethods = "unsearched_methods"
	// PartialReasonLibraryEscape (loud): a package code outside the build can import reaches the
	// module an analyzer found no path to. A value the package hands its importer (a function, an
	// interface value, a struct carrying either) can run the module's code from the importer,
	// outside the analyzer's search, so its refutation does not cover the package's importers.
	PartialReasonLibraryEscape = "library_escape"
	// PartialReasonReflectiveCall: the program reaches a call to code picked at run time by a value
	// or a name (Go's reflect.Value.Call or Method, or a template's Execute), which the call graph
	// cannot follow, and those calls may reach the advisory's vulnerable code. The Go lane declares
	// it per advisory, when what those calls can reach holds a vulnerable symbol or is unknown.
	// Unlike reflection, which the classifier treats as an inherent limit, this says the program
	// does it, so it is loud.
	PartialReasonReflectiveCall = PartialReasonReflection + ":call"
	// PartialReasonPluginLoad: the program reaches a load of Go code the build never compiled
	// (plugin.Open), so none of that code's calls were read.
	PartialReasonPluginLoad = "plugin_load"
	// PartialReasonCgoUnresolved: the go command did not resolve whether cgo is on (`go env
	// CGO_ENABLED` failed), so which of the build's cgo and non-cgo files the shipped binary
	// compiles is unknown.
	PartialReasonCgoUnresolved = PartialReasonCgo + ":env_unresolved"
	// PartialReasonIfdefConfigVariance (new base, run-specific/loud): a preprocessor
	// conditional (#ifdef/#if) gates code the analysis cannot resolve without the build's
	// actual macro definitions, so the compiled configuration is undetermined. Every
	// existing lane assumes one checkout approximates one program; a C/C++ build's
	// conditional-compilation axis has no analog there, so this is genuinely new, not a
	// reuse of an existing code.
	PartialReasonIfdefConfigVariance = "ifdef_config_variance"
	// PartialReasonNativeLinkBoundary (new base, quiet/inherent; localise with ":suffix",
	// e.g. ":dlopen", ":inline_asm"): a native-code construct opaque to the C/C++ lane's own
	// static analysis — a runtime-resolved symbol (dlopen) or inline assembly the analyzer
	// does not disassemble. A limit of the METHOD, true on every scan that crosses it, so it
	// is classified inherent in ClassifyPartialityReason rather than defaulting loud. Minted
	// fresh rather than reusing cgo: cgo names the Go-caller-into-native boundary
	// specifically, not a C/C++ lane's own limit.
	PartialReasonNativeLinkBoundary = "native_link_boundary"
	// PartialReasonMacroExpansion (new base, quiet/inherent): a macro whose expansion the
	// analyzer did not evaluate, so code introduced or altered by it is invisible to the
	// call graph. A limit of the method's source-level reading, not a per-run failure, so it
	// is classified inherent alongside native_link_boundary.
	PartialReasonMacroExpansion = "macro_expansion"
)

// Complete is the constructor for a fully-resolved result.
func Complete() Partiality { return Partiality{Complete: true} }

// Partial constructs a declared-partial result with the given reason codes.
func Partial(reasons ...string) Partiality { return Partiality{Complete: false, Reasons: reasons} }

// Unsupported is the canonical partiality for an operation a lane does not implement.
func Unsupported() Partiality { return Partial(PartialReasonUnsupported) }

// --- shared inputs (the plugin is GIVEN ground truth; inv.7) ---

// IndexSymbolsRequest carries the buildable module to index.
type IndexSymbolsRequest struct {
	BuildDir string `json:"build_dir"` // checked-out module root (contains go.mod)
}

// CallGraphRequest carries the buildable module and the desired graph algorithm.
type CallGraphRequest struct {
	BuildDir  string `json:"build_dir"`
	Algorithm string `json:"algorithm,omitempty"` // "vta" (default) | "rta" | "cha"
	// DependencyCache is a store of lock-pinned dependency tarballs the host verified for this
	// build. A lane that reads dependency code reads it only from there; empty, none is read.
	DependencyCache string `json:"dependency_cache,omitempty"`
}

// FindIngressesRequest carries the buildable module to scan for entry points.
type FindIngressesRequest struct {
	BuildDir string `json:"build_dir"`
}

// ResolveSymbolsRequest carries advisory identifiers from authoritative sources (inv.7).
type ResolveSymbolsRequest struct {
	BuildDir        string   `json:"build_dir"`
	PURL            string   `json:"purl"`             // e.g. pkg:golang/github.com/x/y@v1.2.3
	AdvisorySymbols []string `json:"advisory_symbols"` // vulnerable symbols from the advisory
	VulnID          string   `json:"vuln_id"`          // e.g. GO-2021-0001 (for govulncheck)
	// TargetEnv is the run's stated target-environment conditions, as on ReachabilityRequest:
	// a lane that resolves the inventory to choose which dependency versions to read resolves it
	// under these. Nil means none were stated.
	TargetEnv map[string]string `json:"target_env,omitempty"`
	// Package is the advisory's package pinned to the version the build installs, as on
	// ReachabilityRequest. A lane that tells installed copies apart resolves the advisory's
	// symbols only on the copy at that version. Empty means unknown.
	Package string `json:"package,omitempty"`
	// PackageVersions, when Package carries no version because the installed copies disagree,
	// lists the installed versions not shown outside the advisory's affected ranges; the lane
	// resolves the symbols on a copy at any of them.
	PackageVersions []string `json:"package_versions,omitempty"`
	// DependencyCache is a store of lock-pinned dependency tarballs the host verified for this
	// build. A lane that reads dependency code reads it only from there; empty, none is read.
	DependencyCache string `json:"dependency_cache,omitempty"`
}

// ResolveVersionsRequest carries the advisory's dependency coordinate whose declared
// version the plugin should read from the build files. Coordinate identifies the wanted
// dependency in the language's native form ("groupId:artifactId" for Maven); the plugin
// matches it against the parsed pom.xml/build.gradle dependency declarations.
type ResolveVersionsRequest struct {
	BuildDir   string `json:"build_dir"`
	Coordinate string `json:"coordinate"` // e.g. "com.fasterxml.jackson.core:jackson-databind"
}

// ResolvedDependency is one declared dependency coordinate with its resolved version.
// Resolved is false (and Version empty) when the version could not be determined
// confidently (BOM-managed, unresolvable property indirection): an UNRESOLVED marker the
// disqualification predicate treats as "unknown" and fails OPEN on (inv.5).
type ResolvedDependency struct {
	Coordinate string `json:"coordinate"`        // "groupId:artifactId"
	Version    string `json:"version,omitempty"` // declared version; empty when Resolved=false
	Resolved   bool   `json:"resolved"`          // true ONLY when a concrete version was determined
	Source     string `json:"source,omitempty"`  // "pom" | "gradle" (provenance, informational)
	// Constraint is the declared version specifier (e.g. ">=2.0,<3") when the manifest states a
	// range rather than an exact pin. It is evidence only: a range never becomes Version, and a
	// consumer must not derive a resolved version from it. Empty for exact pins and bare names.
	Constraint string `json:"constraint,omitempty"`
}

// DependencyVersionResult reports the resolved declared version for the requested
// coordinate. Match is the dependency the plugin found for the request coordinate (with
// Resolved indicating whether its version is known); Found is false when no declaration of
// that coordinate exists in the build files at all.
type DependencyVersionResult struct {
	Partiality Partiality         `json:"partiality"`
	Found      bool               `json:"found"` // a declaration of the request coordinate exists
	Match      ResolvedDependency `json:"match"`
	// Presence is the first resolved declaration of the request coordinate in All, with no
	// requirement that other copies agree. It answers only "is some copy declared at this exact
	// version", which is what a malicious-package advisory asks, and it must never feed a
	// not-affected verdict. Nil means Match answers it too.
	Presence *ResolvedDependency  `json:"presence,omitempty"`
	All      []ResolvedDependency `json:"all,omitempty"` // every parsed declaration (evidence)
	// Matches is every copy of the request coordinate the plugin read, Match among them: a
	// package declared or installed at several versions (one per module, a nested install) lists
	// each. It is evidence; on its own it does not claim no other version exists.
	Matches []ResolvedDependency `json:"matches,omitempty"`
	// MatchesComplete asserts that Matches holds every version of the request coordinate the
	// build can install: every version source in scope is a form the plugin recognises and read
	// in full, and every project that could carry the coordinate transitively is covered by a
	// lockfile or pins it directly. False (the default) means other versions cannot be ruled out.
	MatchesComplete bool `json:"matches_complete,omitempty"`
	// Exhaustive asserts that All enumerates every package the build can install: the plugin read
	// a complete, edge-bearing lockfile covering every manifest it found, or a JVM build graph
	// whose producer observed every way the build installs a dependency (buildgraph.Graph.Complete)
	// and that marks nothing it installs as unlisted. A coordinate absent from All is then provably
	// not installed by the build. The claim covers the build alone: what a container image, a
	// deploy step or a Java agent adds at run time is outside it. A shaded copy inside another
	// artifact is not a package of its own. Build-isolation environments are not runtime installs:
	// a build requirement (PEP 517 build-system.requires, setup_requires) is a declaration in All,
	// but what the build backend pulls in transitively is not enumerated.
	// The .NET lane, whose All lists declarations only, sets it for the request's coordinate
	// alone: every project is settled on a trusted project.assets.json, the coordinate is not
	// one the SDK delivers outside it, and nothing else can bring a package in, so a coordinate
	// that is not Found is provably not a dependency.
	// False (the default, and every plugin that does not set it) means absence from All proves
	// nothing and a consumer must fail open.
	Exhaustive bool `json:"exhaustive,omitempty"`
}

// ReachabilityRequest carries the resolved sinks to trace toward.
type ReachabilityRequest struct {
	BuildDir string   `json:"build_dir"`
	VulnID   string   `json:"vuln_id"` // drives govulncheck's advisory selection
	Symbols  []string `json:"symbols"` // resolved SCIP/symbol strings to confirm reachable
	// GoToolchain is the SUBJECT's Go toolchain the analysis must execute under, normalized
	// "go1.21.3". Empty — the default and the only value any non-Go lane ever sees —
	// means "run under whatever toolchain the analyzer already has", i.e. today's behavior.
	//
	// The caller sets it ONLY when it holds an EXACT subject-toolchain fact: absence of a symbol is
	// evidence about the toolchain the analysis actually ran on, so a lower bound licenses nothing
	// here. A plugin that cannot honor the request must fall back and say so via
	// ReachabilityResult.ScanToolchain rather than failing the scan.
	GoToolchain string `json:"go_toolchain,omitempty"`
	// Package is the PURL of the package the advisory was admitted on, pinned to the version the
	// inventory resolved ("pkg:npm/lodash@4.17.20"). A lane that can prove that package's code never
	// loads answers with a RefutationPackageNotLoaded ReachabilityResult.Refutation. Package is
	// empty when either the PURL or the resolved version is unknown, and a lane MUST NOT emit a
	// package_not_loaded Refutation then: with no admitted version there is nothing to refute, so
	// the advisory stays undetermined, never not_exploitable.
	//
	// Package carries the name as the advisory spells it (pkg:pypi/pyjwt while the lockfile pins
	// PyJWT). A lane compares it with installed and loaded names only after canonicalizing both
	// sides: PyPI by PEP 503 (lowercase, every run of "-", "_" and "." becomes "-"), NuGet by
	// lowercasing, every other ecosystem exactly (npm `name` or `@scope/name`, Maven
	// `group:artifact`, Go module path). The gate matches a Refutation's Package on type and name,
	// never on version, so a lane refutes only when no installed copy of that canonical name loads,
	// at any version, and refutes nothing when it cannot enumerate the copies.
	Package string `json:"package,omitempty"`
	// TargetEnv carries the run's stated target-environment conditions, with the same keys and
	// meaning as ResolveInventoryRequest.TargetEnv, so a lane that resolves the inventory to build
	// its search space resolves it under the conditions the inventory stage used. Like there, it is
	// configuration handed to the plugin, never read from the tree: nil means none were stated, and
	// whatever they would have decided stays unresolved and is disclosed, not assumed.
	TargetEnv map[string]string `json:"target_env,omitempty"`
	// DependencyCache is a store of lock-pinned dependency tarballs the host verified for this
	// build. A lane that reads dependency code reads it only from there; empty, none is read.
	DependencyCache string `json:"dependency_cache,omitempty"`
	// LibraryEntrypoints is the caller's statement of which of the build's packages code outside
	// the build may import. Nil is auto with nothing declared. A lane that withholds a refutation an
	// importer may contradict resolves its entry points from it and reports them in
	// ReachabilityResult.LibraryEntrypoints.
	LibraryEntrypoints *LibraryEntrypoints `json:"library_entrypoints,omitempty"`
}

// --- result payloads ---

// SymbolKind discriminates the eight §4.3 symbol categories. Comparable (string kind).
type SymbolKind string

const (
	SymbolKindPackage     SymbolKind = "package"     // packages / modules
	SymbolKindType        SymbolKind = "type"        // types (incl. nested types)
	SymbolKindFunction    SymbolKind = "function"    // free functions
	SymbolKindMethod      SymbolKind = "method"      // methods on a type
	SymbolKindConstructor SymbolKind = "constructor" // constructors (Java <init>, Go NewT idiom, …)
	SymbolKindField       SymbolKind = "field"       // fields / properties / constants
)

// Symbol is the canonical, COMPARABLE symbol identity shared by first-party and dependency code.
// Every field is scalar so Symbol is usable as a map key, == operand, and array element (see §1).
type Symbol struct {
	Kind        SymbolKind `json:"kind"`                 // §4.3 discriminator; separates function/method/type/package/constructor and drives category distinction
	Package     string     `json:"package"`              // §4.3 packages/modules: import path or module coordinate ("github.com/x/y", "com.fasterxml.jackson.core:jackson-databind")
	Enclosing   string     `json:"enclosing,omitempty"`  // §4.3 nested declarations: enclosing type/decl chain, segments joined by "." (see separator spec below); empty for package- or file-scope symbols
	Name        string     `json:"name,omitempty"`       // §4.3 member name (function/method/type/field/constructor); empty for a package Symbol
	Descriptor  string     `json:"descriptor,omitempty"` // §4.3 overloads/generics: signature / type-argument descriptor that separates same-named members ("(int)", "<T>")
	Generated   bool       `json:"generated,omitempty"`  // §4.3 generated symbols: true for compiler/codegen-synthesized symbols (accessors, proxies, protobuf, lombok, …)
	DisplayName string     `json:"display_name"`         // human-readable rendering; the string projected into report.CallFrame/EntryPoint at the flatten seam
	SCIP        string     `json:"scip"`                 // self-emitted canonical SCIP id; opaque wire/report bridge and the "load-bearing sink id source" (stages.go:2496). NOT the matching identity — matchers key on the structured fields (symbolform_guard_test contract)
}

// SymbolIndexResult is IndexSymbols' response: the SCIP-qualified symbols it found.
type SymbolIndexResult struct {
	Partiality Partiality `json:"partiality"`
	Symbols    []Symbol   `json:"symbols"`
}

// SymbolResolutionResult is ResolveDependencySymbols' response: the given advisory
// symbols mapped onto concrete symbols in this codebase.
type SymbolResolutionResult struct {
	Partiality Partiality `json:"partiality"`
	Resolved   []Symbol   `json:"resolved"` // advisory symbol → concrete codebase symbols
	// Origins maps a Resolved symbol's SCIP to the package the symbol belongs to, as a PURL without a
	// version. Absent means first-party. The lane derives it from code it read or from its own
	// import-binding → lockfile resolution, never from the request PURL. An origin alone grounds
	// nothing: only a sink in ReachabilityResult.Searched does, and that requires loaded code.
	Origins map[string]string `json:"origins,omitempty"`
	// Matched maps each request advisory symbol, verbatim, to the SCIPs of the Resolved symbols it
	// resolved to. A lane that fills Origins fills this too: the not_exploitable gate needs every
	// advisory symbol accounted for, and only the lane's own matcher knows which resolved symbol
	// answered which advisory symbol.
	Matched map[string][]string `json:"matched,omitempty"`
	// ModuleSearch is a search of the source of every module in the build for the request's
	// advisory symbols, for an advisory whose package no module in the build holds. Nil when no
	// such search ran.
	ModuleSearch *ModuleSearch `json:"module_search,omitempty"`
}

// ModuleSearch reports which of the build's modules the lane read in full and which of those
// declare a function, method or variable named like one of the request's advisory symbols. A
// module whose source the lane could not obtain or parse is left out of Searched, so a reader
// that needs every module searched sees the gap.
type ModuleSearch struct {
	// Searched holds each searched module's path, and beside it the path of the module a
	// replace directive substitutes for it.
	Searched []string `json:"searched"`
	// Declaring holds the paths of the searched modules that declare such a name.
	Declaring []string `json:"declaring,omitempty"`
}

// CallEdge is one directed call-graph edge between canonical symbols.
type CallEdge struct {
	Caller Symbol `json:"caller"`
	Callee Symbol `json:"callee"`
}

// CallGraphResult is CallGraph's response: the graph edges and roots actually built,
// plus which algorithm produced them.
type CallGraphResult struct {
	Partiality Partiality `json:"partiality"`
	Algorithm  string     `json:"algorithm"` // the algorithm actually used
	Edges      []CallEdge `json:"edges"`
	Roots      []Symbol   `json:"roots"` // entrypoint symbols (main, init, etc.)
	// Unresolved lists every call or load the lane declined to connect, one entry per declined
	// call site, except module-level dynamic loads (a computed import() or require(), a native
	// load, evaluated code), which aggregate to one entry per module per kind, and a module's
	// literal loads of an out-of-tree package or an unread module, one entry per specifier on the
	// module's top-level frame: the sites behind the result's dynamic_dispatch and
	// relationship_unexpressed:* reasons. It is
	// complete unless Partiality carries PartialReasonUnlistedSites, which the lane sets if and
	// only if a declined site is missing here. A reason no entry carries, tool_failure and
	// unsupported_phase1 among them, is attributable to no listed site, so a reader treats it as
	// partial. A lane that does not list its sites leaves this empty, which makes every reason it
	// declares unattributable. Scoped limits are not sites: they keep their own package Targets.
	Unresolved []UnresolvedCall `json:"unresolved,omitempty"`
	// Escaped is every first-party frame a call or load the lane cannot see may run: each
	// function opaque code can call back (a class member, a function whose name is used as a
	// value, an exported function, a named function expression, every function of a module that
	// reaches functions by computed name) and each module's top-level frame, which any load may
	// run. A reader treats an escaped symbol as callable from any Unresolved entry without
	// Targets. A frame missing from Escaped runs only as one of Roots or through the Edges and
	// Targets that reach it.
	Escaped []Symbol `json:"escaped,omitempty"`
}

// UnresolvedCall is one call or load the lane declined to connect.
type UnresolvedCall struct {
	// Caller is the frame holding the site, in the same SCIP space as CallEdge.Caller. For a
	// load the lane records per module rather than per call (a package load, a computed or
	// unread specifier, evaluated code), it is the module's top-level frame, standing for
	// whichever frame of that module holds the load.
	Caller Symbol `json:"caller"`
	// Callee is the callee as written: "name" or its dotted chain "head.name". A load names its
	// loader: "require", "import", "dlopen" (native code) or "eval" (code built at run time). A
	// callee that is neither a name nor a chain is its source text, whitespace collapsed and cut
	// at 80 runes: "get()", "t[k]", "(0, f)", "tag" of a tagged template, "new C", "super",
	// "@decorator".
	Callee string `json:"callee"`
	// Arity is the argument count at the site; a load counts its one specifier or source, a
	// tagged template its strings and each substitution, and a bare decorator the one value it
	// decorates.
	Arity int `json:"arity"`
	// Reason is the PartialReason* code this site contributed to Partiality.Reasons.
	Reason string `json:"reason"`
	// Targets, when present, over-approximates every frame the site can reach: the lane lists it
	// only when the candidate set is complete and bounded, as for a name that resolves to more
	// than one first-party declaration, and then lists all of it. Omitted means the site could
	// reach anything, so every Escaped symbol.
	Targets []Symbol `json:"targets,omitempty"`
}

// Ingress is one framework-idiomatic entry point.
type Ingress struct {
	Kind     string `json:"kind"`     // "http_route" | "main" | "handler" | ...
	Symbol   Symbol `json:"symbol"`   // canonical symbol of the entry function
	Selector string `json:"selector"` // e.g. "GET /users/{id}" when known
}

// IngressResult is FindIngresses' response: the entry points found in the codebase.
type IngressResult struct {
	Partiality Partiality `json:"partiality"`
	Ingresses  []Ingress  `json:"ingresses"`
}

// ReachPath is one govulncheck-derived (ingress, sink, path) trace.
type ReachPath struct {
	Sink    Symbol   `json:"sink"`              // vuln symbol (the resolved sink)
	Ingress Symbol   `json:"ingress,omitempty"` // entrypoint symbol; zero value if unknown (partial)
	Trace   []Symbol `json:"trace"`             // ordered symbols ingress→sink
}

// ReachabilityResult is Reachability's response: the candidate (ingress, sink, path)
// traces the plugin found, reconciling govulncheck with the call graph.
type ReachabilityResult struct {
	Partiality Partiality  `json:"partiality"`
	Paths      []ReachPath `json:"paths"`
	// ScanToolchain is the Go toolchain the analysis ACTUALLY executed under, populated only when
	// the request asked for one (ReachabilityRequest.GoToolchain). It equals the requested version
	// exactly when the request was honored; any other value — including empty — means it was not,
	// and the caller must treat the empty path set as evidence about the analyzer's toolchain
	// rather than the subject's. It is a measurement, never a promise: the caller compares.
	ScanToolchain string `json:"scan_toolchain,omitempty"`
	// Searched lists the request sinks the lane stands behind as searched: the sink is a node built
	// from code the lane loaded (never a boundary node), it traced from every ingress it found (at
	// least one), and no path reached the sink. A lane that lists a sink here must not declare
	// no_known_ingress on its account. A lane whose call graph omits reflective calls must exclude
	// sinks those calls can reach.
	Searched []string `json:"searched,omitempty"`
	// Refutation is lane-held positive evidence that the package's vulnerable code cannot run.
	Refutation *Refutation `json:"refutation,omitempty"`
	// LibraryEntrypoints is the entry-point set the lane resolved from
	// ReachabilityRequest.LibraryEntrypoints, when it resolved one.
	LibraryEntrypoints *ResolvedLibraryEntrypoints `json:"library_entrypoints,omitempty"`
}

// Refutation grounds a not_exploitable verdict without a searched sink. Package is a PURL (version
// optional) and must name the package the advisory was admitted on; Detail is one checkable line
// saying what was observed.
type Refutation struct {
	Basis   string `json:"basis"`
	Package string `json:"package"`
	Detail  string `json:"detail"`
	// Assumptions are the caller's declarations the refutation holds only under, each one
	// checkable line; the verdict carries them. Empty means it rests on the lane's evidence alone.
	Assumptions []string `json:"assumptions,omitempty"`
}

// Refutation bases.
const (
	// RefutationAnalyzerSymbolNotReached: govulncheck reported the advisory against a module or
	// package in the build and found no call path to any of its vulnerable symbols.
	RefutationAnalyzerSymbolNotReached = "analyzer_symbol_not_reached"
	// RefutationPackageNotLoaded: the package is installed at the admitted version and no
	// runtime-loaded module imports it.
	RefutationPackageNotLoaded = "package_not_loaded"
)

// --- whole-graph dependency inventory (§4.1) ---

// ResolveInventoryRequest carries the buildable module to resolve the whole dependency graph for.
type ResolveInventoryRequest struct {
	BuildDir string `json:"build_dir"` // checked-out module/workspace root

	// TargetEnv is the §4.6 target-environment override the resolver evaluates environment-conditional
	// dependencies against (onyx-q6). It rides on the REQUEST, not on BuildDir: the override is Assay
	// configuration, not a repo file, so a plugin must not read it from the checked-out tree. Keys are
	// environment facts (platform, language/runtime version, …); an absent map (nil) means no override
	// and preserves today's behavior — the resolver falls back to whatever the repo declares, and an
	// unresolved condition is disclosed as PartialReasonEnvConditionUnresolved rather than assumed.
	TargetEnv map[string]string `json:"target_env,omitempty"`

	// Selection restricts resolution to a named subset of the dependency set (optional groups / extras
	// / features the request opts into), also Assay config carried on the request (onyx-q6). An absent
	// slice (nil) means no restriction — the full declared set is resolved, today's behavior.
	Selection []string `json:"selection,omitempty"`
}

// CapabilityManifestRequest carries no inputs: a capability manifest is a static per-lane fact,
// independent of any checked-out build. The type exists for protocol uniformity/extensibility.
type CapabilityManifestRequest struct{}

// DependencyInventory is the whole-graph resolver result (§4.1). A lane without a resolver
// returns Unsupported() (see §5). Nodes and Edges are
// emitted in explicit sorted order (see §7); no map is an iteration source on the encoding path.
type DependencyInventory struct {
	Partiality Partiality       `json:"partiality"` // graph-level declared partiality for unresolved conditions (§4.1 "declared partiality")
	Nodes      []DependencyNode `json:"nodes"`      // one per resolved package instance; sorted by Node.ID
	Edges      []DependencyEdge `json:"edges"`      // parent→child relationships; sorted by (Parent, Child)
	// BuildList names the resolver output Nodes were taken from when they are the build's whole
	// module list, replace targets included ("go mod graph"); empty otherwise. Partiality still
	// says whether that resolution completed.
	BuildList string `json:"build_list,omitempty"`
	// MainModule is the path of the module the build list was resolved for (Go), which is part of
	// the build but not one of Nodes; set with BuildList.
	MainModule string `json:"main_module,omitempty"`
}

// BuildListGoModGraph is the BuildList of a Go inventory resolved from `go mod graph`: the selected
// module build list, which a vendored module resolves to the same list.
const BuildListGoModGraph = "go mod graph"

// DependencyNode is one resolved package instance in the dependency graph.
type DependencyNode struct {
	ID         string               `json:"id"`                // stable package-instance key; DependencyEdge endpoints reference it. Distinct instances of the same PURL (different resolution scopes) get distinct IDs
	PURL       string               `json:"purl"`              // §4.1 normalized Package URL ("pkg:golang/github.com/x/y@v1.2.3")
	Version    string               `json:"version"`           // §4.1 exact resolved version
	Direct     bool                 `json:"direct"`            // §4.1 direct (true) vs transitive (false) relationship. NOT omitempty: false is load-bearing
	Membership DependencyMembership `json:"membership"`        // §4.1 project/workspace/target membership
	Artifact   DependencyArtifact   `json:"artifact"`          // §4.1 selected artifact identity + integrity digest
	Provenance DependencyProvenance `json:"provenance"`        // §4.1 manifest/lockfile/resolver/runtime-target provenance
	Partiality Partiality           `json:"partiality"`        // §4.1 per-node declared partiality (unresolved condition on THIS node)
	Replace    string               `json:"replace,omitempty"` // module path a replace directive substitutes for this one (Go); empty when not replaced or replaced by a directory
	// NotInstalled marks a package a lockfile declares that every install the build is known to
	// run leaves out, such as a poetry group no install selects. Version is still the declared pin.
	NotInstalled bool `json:"not_installed,omitempty"`
}

// DependencyEdge is one parent→child dependency relationship (§4.1 "parent edges"). This is the
// distinct field ResolvedDependency lacks today (plugin.go:143-148), enabling the package-instance
// tree (§5.3 deliverable 9).
type DependencyEdge struct {
	Parent string `json:"parent"` // DependencyNode.ID of the depending instance
	Child  string `json:"child"`  // DependencyNode.ID of the depended-on instance
}

// DependencyMembership records which project/workspace/target a node belongs to (§4.1).
type DependencyMembership struct {
	Project   string `json:"project,omitempty"`   // owning project/module root
	Workspace string `json:"workspace,omitempty"` // enclosing workspace (monorepo), when applicable
	Target    string `json:"target,omitempty"`    // build target/configuration the node is scoped to (e.g. "test", "runtime")
}

// DependencyArtifact identifies the selected artifact and its integrity digest (§4.1).
type DependencyArtifact struct {
	Identity string `json:"identity"` // selected artifact identity (chosen filename/coordinate, e.g. wheel/jar/zip name)
	Digest   string `json:"digest"`   // integrity digest, algorithm-prefixed ("sha256:…", "sha512:…")
}

// DependencyProvenance records how the node's resolution was determined (§4.1).
type DependencyProvenance struct {
	Manifest string `json:"manifest,omitempty"` // manifest file that declared it (go.mod, package.json, pom.xml)
	Lockfile string `json:"lockfile,omitempty"` // lockfile that pinned it (go.sum, package-lock.json)
	Resolver string `json:"resolver"`           // resolver/tool that produced the resolution ("go mod", "npm", "pip")
	Runtime  string `json:"runtime,omitempty"`  // runtime the resolution targeted ("go1.21", "node18")
	Target   string `json:"target,omitempty"`   // target platform the resolution targeted ("linux/amd64")
}

// --- stub-only results ---

// ComputeTaintRequest carries the buildable module and the resolved sinks to trace
// source→sink flows toward.
type ComputeTaintRequest struct {
	BuildDir string   `json:"build_dir"`
	Sinks    []string `json:"sinks,omitempty"` // resolved sink SCIP ids to trace toward
	// DependencyCache is a store of lock-pinned dependency tarballs the host verified for this
	// build. A lane that reads dependency code reads it only from there; empty, none is read.
	DependencyCache string `json:"dependency_cache,omitempty"`
}

// TaintResult is ComputeTaint's response: the source→sink graph paths found.
type TaintResult struct {
	Partiality Partiality `json:"partiality"`
	// Paths holds the ingress→sink graph paths that exist over the call graph.
	// Minimal taint is call-graph PATH PRESENCE, not variable-level dataflow —
	// PrecisionNote records that limit so the result never overclaims dataflow.
	Paths         []ReachPath `json:"paths,omitempty"`
	PrecisionNote string      `json:"precision_note,omitempty"`
}

// GenerateHarnessRequest names the sink (and optionally the ingress) to scaffold a
// reproducer harness for.
type GenerateHarnessRequest struct {
	Sink    string `json:"sink"`
	Ingress string `json:"ingress,omitempty"`
	Kind    string `json:"kind"` // "fuzz" | "unit" | "integration"
}

// HarnessResult is GenerateHarness's response: the generated reproducer skeleton.
type HarnessResult struct {
	Partiality Partiality `json:"partiality"`
	// Source is the generated runnable reproducer SKELETON (Go source text) that
	// imports the sink's package and calls the sink symbol. Skeleton is always
	// true: it compiles structurally but does NOT prove exploitability.
	Source   string `json:"source,omitempty"`
	Skeleton bool   `json:"skeleton,omitempty"`
}

// BuildManifestRequest carries the buildable module to derive a build manifest for.
type BuildManifestRequest struct {
	BuildDir string `json:"build_dir"`
}

// RuntimeSource records where a resolved toolchain identity came from.
type RuntimeSource string

const (
	// RuntimeSourceDeclared: parsed from a committed manifest (go.mod, package.json, .csproj, pyproject).
	RuntimeSourceDeclared RuntimeSource = "declared"
	// RuntimeSourceAmbient: CI/host state that is not committed (a compiler on PATH, the environment).
	RuntimeSourceAmbient RuntimeSource = "ambient"
	// RuntimeSourceCompileDB: reconstructed from compile_commands.json invocations.
	RuntimeSourceCompileDB RuntimeSource = "compile_db"
)

// RuntimeSpec is the ecosystem-neutral descriptor of one toolchain the build uses.
type RuntimeSpec struct {
	Name      string        `json:"name,omitempty"`      // runtime/language identity ("go", "node", "python", "dotnet")
	Version   string        `json:"version,omitempty"`   // declared/minimum runtime version (JS: node engine range)
	Toolchain string        `json:"toolchain,omitempty"` // exact toolchain pin when the manifest declares one; a stronger floor than Version
	Source    RuntimeSource `json:"source,omitempty"`    // provenance of this identity
	Target    string        `json:"target,omitempty"`    // this toolchain's target platform/architecture ("linux/amd64", "x86_64-linux-gnu")
	Lang      string        `json:"lang,omitempty"`      // language mode this toolchain compiles ("c", "c++")
	StdLevel  string        `json:"std_level,omitempty"` // language standard level ("c17", "c++20")

	// Resolved is the toolchain the build's environment resolves for this runtime, when the analyzer
	// established it (Go: `go env GOVERSION` for the build directory under the build's environment).
	// It is an ambient observation whatever Source says, and a statement about the subject only when
	// the caller asserts the analyzer runs where the subject builds. Empty when not established.
	Resolved string `json:"resolved,omitempty"`
}

// ResolverSpec is the ecosystem-neutral resolver/build descriptor.
type ResolverSpec struct {
	Name    string        `json:"name,omitempty"`    // resolver/build tool ("go", "npm", "maven", "gradle")
	Command string        `json:"command,omitempty"` // neutral build invocation (e.g. "go build ./...")
	Source  RuntimeSource `json:"source,omitempty"`  // provenance of this resolver
}

// BuildManifestResult carries ecosystem-neutral build context (§4.6). A build may use several
// toolchains, so Runtimes and Resolvers are sets; an empty Resolvers means no resolver was
// identified, not an error.
type BuildManifestResult struct {
	Partiality    Partiality     `json:"partiality"`
	Runtimes      []RuntimeSpec  `json:"runtimes"`                // §4.6 runtimes, one per distinct toolchain
	Configuration string         `json:"configuration,omitempty"` // §4.6 build configuration/profile ("release", "Debug")
	ProjectRoot   string         `json:"project_root,omitempty"`  // §4.6 project root: module/package root identity
	Resolvers     []ResolverSpec `json:"resolvers"`               // §4.6 resolvers
}

// PrimaryRuntime returns the build's runtime when it has exactly one. With zero runtimes, or
// several with none privileged, it returns false: a reader that needs "the" runtime must not
// take an arbitrary element as the subject's identity.
func (r BuildManifestResult) PrimaryRuntime() (RuntimeSpec, bool) {
	if len(r.Runtimes) != 1 {
		return RuntimeSpec{}, false
	}
	return r.Runtimes[0], true
}

// PrimaryResolver returns the build's resolver when it has exactly one, with the same
// zero-or-many rule as PrimaryRuntime.
func (r BuildManifestResult) PrimaryResolver() (ResolverSpec, bool) {
	if len(r.Resolvers) != 1 {
		return ResolverSpec{}, false
	}
	return r.Resolvers[0], true
}

// StubPlugin implements LanguagePlugin with canned, in-memory results — the analog of
// episode.StubModel and the sandbox fakes. The live ops return fixed payloads; the five
// stub ops (ResolveDependencyVersions, ComputeTaint, GenerateHarness, BuildManifest,
// ResolveInventory) return Unsupported(). It performs no I/O, no subprocess, no
// network, so it backs the hermetic test suite and the pipeline seam tests.
//
// When Partial is true, the live ops flip their Partiality to declared-partial (keeping a
// reachable-but-partial payload) so L3's seam test can exercise the CandidatePair.Partial
// = true mapping.
type StubPlugin struct {
	// Partial flips the live ops to declared-partial results.
	Partial bool
}

var _ LanguagePlugin = StubPlugin{}

// Canned stub symbols. Symbol is comparable and == compares ALL fields, so each logical symbol
// is minted ONCE here and reused across every canned result (index, graph, ingress, reach). That
// keeps the same logical symbol byte-identical wherever it appears — the map-key/set/== identity
// the graph consumers rely on — instead of re-spelling it per call site and silently diverging.
var (
	stubSymMain = Symbol{Kind: SymbolKindFunction, Package: "example.com/stub", Name: "main", DisplayName: "example.com/stub.main", SCIP: "scip:stub#main"}
	stubSymFoo  = Symbol{Kind: SymbolKindFunction, Package: "example.com/stub", Name: "Foo", DisplayName: "example.com/stub.Foo", SCIP: "scip:stub#Foo"}
	stubSymVuln = Symbol{Kind: SymbolKindFunction, Package: "example.com/dep", Name: "Vulnerable", DisplayName: "example.com/dep.Vulnerable", SCIP: "scip:vuln#Vulnerable"}
)

// stubLivePartiality returns the partiality the live ops should carry given the variant.
func (p StubPlugin) stubLivePartiality() Partiality {
	if p.Partial {
		return Partial(PartialReasonDynamicDispatch)
	}
	return Complete()
}

// Language returns "go" — StubPlugin always identifies as the Go plugin.
func (StubPlugin) Language() string { return "go" }

// IndexSymbols returns one canned Symbol. Live op — see StubPlugin: the result is a
// fixed fixture, not a real index, and embedding StubPlugin to override only some
// methods leaves this one fabricating evidence.
func (p StubPlugin) IndexSymbols(_ context.Context, _ IndexSymbolsRequest) (SymbolIndexResult, error) {
	return SymbolIndexResult{
		Partiality: p.stubLivePartiality(),
		Symbols:    []Symbol{stubSymFoo},
	}, nil
}

// ResolveDependencySymbols returns one canned resolved Symbol. Live op — see
// StubPlugin: the result is a fixed fixture, not a real resolution, and embedding
// StubPlugin to override only some methods leaves this one fabricating evidence.
func (p StubPlugin) ResolveDependencySymbols(_ context.Context, _ ResolveSymbolsRequest) (SymbolResolutionResult, error) {
	return SymbolResolutionResult{
		Partiality: p.stubLivePartiality(),
		Resolved:   []Symbol{stubSymVuln},
	}, nil
}

// CallGraph returns one canned two-edge graph. Live op — see StubPlugin: the result
// is a fixed fixture, not a real call graph, and embedding StubPlugin to override
// only some methods leaves this one fabricating evidence.
func (p StubPlugin) CallGraph(_ context.Context, _ CallGraphRequest) (CallGraphResult, error) {
	return CallGraphResult{
		Partiality: p.stubLivePartiality(),
		Algorithm:  "vta",
		Edges: []CallEdge{
			{Caller: stubSymMain, Callee: stubSymFoo},
			{Caller: stubSymFoo, Callee: stubSymVuln},
		},
		Roots: []Symbol{stubSymMain},
	}, nil
}

// FindIngresses returns one canned "main" ingress. Live op — see StubPlugin: the
// result is a fixed fixture, not a real scan, and embedding StubPlugin to override
// only some methods leaves this one fabricating evidence.
func (p StubPlugin) FindIngresses(_ context.Context, _ FindIngressesRequest) (IngressResult, error) {
	return IngressResult{
		Partiality: p.stubLivePartiality(),
		Ingresses: []Ingress{
			{Kind: "main", Symbol: stubSymMain, Selector: ""},
		},
	}, nil
}

// Reachability returns one canned ingress-to-sink path. Live op — see StubPlugin:
// the result is a fixed fixture, not a real reachability analysis, and embedding
// StubPlugin to override only some methods leaves this one fabricating evidence.
func (p StubPlugin) Reachability(_ context.Context, _ ReachabilityRequest) (ReachabilityResult, error) {
	return ReachabilityResult{
		Partiality: p.stubLivePartiality(),
		Paths: []ReachPath{
			{
				Sink:    stubSymVuln,
				Ingress: stubSymMain,
				Trace:   []Symbol{stubSymMain, stubSymFoo, stubSymVuln},
			},
		},
	}, nil
}

// ResolveDependencyVersions always returns Unsupported.
func (StubPlugin) ResolveDependencyVersions(_ context.Context, _ ResolveVersionsRequest) (DependencyVersionResult, error) {
	return DependencyVersionResult{Partiality: Unsupported()}, nil
}

// ComputeTaint always returns Unsupported.
func (StubPlugin) ComputeTaint(_ context.Context, _ ComputeTaintRequest) (TaintResult, error) {
	return TaintResult{Partiality: Unsupported()}, nil
}

// GenerateHarness always returns Unsupported.
func (StubPlugin) GenerateHarness(_ context.Context, _ GenerateHarnessRequest) (HarnessResult, error) {
	return HarnessResult{Partiality: Unsupported()}, nil
}

// BuildManifest always returns Unsupported.
func (StubPlugin) BuildManifest(_ context.Context, _ BuildManifestRequest) (BuildManifestResult, error) {
	return BuildManifestResult{Partiality: Unsupported()}, nil
}

// ResolveInventory always returns Unsupported. It returns an
// honestly-partial inventory (Complete=false, PartialReasonUnsupported), NOT an empty-but-successful
// one — a zero-node Complete() inventory would read downstream as "this build has no dependencies".
func (StubPlugin) ResolveInventory(_ context.Context, _ ResolveInventoryRequest) (DependencyInventory, error) {
	return DependencyInventory{Partiality: Unsupported()}, nil
}

// CapabilityManifest is honest absence: the stub publishes no manifest, so it returns
// capability.Manifest{Supported:false} — never a Supported:true manifest with empty axes.
func (StubPlugin) CapabilityManifest(_ context.Context, _ CapabilityManifestRequest) (capability.Manifest, error) {
	return capability.Manifest{Supported: false}, nil
}
