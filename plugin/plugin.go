// Package plugin defines the LanguagePlugin contract: the interface a
// language-specific evidence producer implements, the value types it exchanges with
// the pipeline, the first-class Partiality declaration (inv.5), and an in-memory
// StubPlugin used by hermetic tests.
//
// This package is import-light by design: tegrond (internal/pipeline) imports it, and
// it MUST NOT import internal/plugin/goanalysis (which links the heavy analysis
// libraries). That import boundary is the inv.8 mechanism — analysis code lives only in
// the cmd/tegron-plugin-go subprocess binary, never in-process in the daemon.
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

	// --- LIVE in Phase 1 (Go) ---

	// IndexSymbols emits SCIP-qualified symbol ids stable across app + dependencies.
	IndexSymbols(ctx context.Context, req IndexSymbolsRequest) (SymbolIndexResult, error)

	// ResolveDependencySymbols maps an advisory's vulnerable symbol(s) to concrete symbols
	// in this codebase. The advisory identifiers are GIVEN (inv.7) — the plugin never
	// originates them.
	ResolveDependencySymbols(ctx context.Context, req ResolveSymbolsRequest) (SymbolResolutionResult, error)

	// ResolveDependencyVersions reads the codebase's declared dependency versions
	// (pom.xml / build.gradle for Java; Phase-1 Go: Unsupported) for the given advisory
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

	// --- CONTRACT-PRESENT STUBS in Phase 1 (return declared partiality, Unsupported) ---

	// ComputeTaint computes source→sink taint flows. Phase-1 Go: Unsupported.
	ComputeTaint(ctx context.Context, req ComputeTaintRequest) (TaintResult, error)

	// GenerateHarness scaffolds a fuzz/unit/integration harness. Phase-1 Go: Unsupported.
	GenerateHarness(ctx context.Context, req GenerateHarnessRequest) (HarnessResult, error)

	// BuildManifest produces enough to build and run the app under test. Phase-1 Go: Unsupported.
	BuildManifest(ctx context.Context, req BuildManifestRequest) (BuildManifestResult, error)

	// ResolveInventory resolves the whole dependency graph for the buildable module (§4.1).
	// This cycle lands the operation; no plugin populates a real inventory yet — every plugin
	// without a resolver returns DependencyInventory{Partiality: Unsupported()} (honest absence,
	// never an empty-but-successful inventory).
	ResolveInventory(ctx context.Context, req ResolveInventoryRequest) (DependencyInventory, error)

	// CapabilityManifest returns the lane's static capability manifest — the up-front
	// declaration of what this analyzer supports (the compile-time complement to the per-run
	// Partiality). This cycle lands the operation only; no lane publishes content yet, so every
	// plugin returns capability.Manifest{Supported:false} (honest absence, never a Supported:true
	// manifest with empty axes). Content is authored per-lane in Phase-4.
	CapabilityManifest(ctx context.Context, req CapabilityManifestRequest) (capability.Manifest, error)
}

// Partiality declares whether an operation fully resolved its answer. A plugin that cannot
// (reflection, dynamic dispatch, cgo, tool failure) returns Complete=false with one or more
// machine-readable Reasons rather than a confident-looking incomplete result.
// It NEVER renders an unknown as "safe"/"not reachable" — the inv.5 boundary.
type Partiality struct {
	Complete bool     `json:"complete"`
	Reasons  []string `json:"reasons,omitempty"` // canonical reason codes; see PartialReason*
}

// Canonical partiality reason codes (machine-readable, stable strings).
const (
	PartialReasonReflection      = "reflection"         // calls via reflect.* invisible to static analysis
	PartialReasonDynamicDispatch = "dynamic_dispatch"   // interface dispatch not fully resolved
	PartialReasonCgo             = "cgo"                // native-code boundary (cgo) crossed
	PartialReasonUnsupported     = "unsupported_phase1" // operation is a Phase-1 contract stub
	PartialReasonToolFailure     = "tool_failure"       // a wrapped tool failed; surfaced, not retried (inv.4)
	PartialReasonNoIngress       = "no_known_ingress"   // reachable sink, no entry point found
	PartialReasonNoManifest      = "no_manifest"        // no lockfile/manifest to read installed versions from

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
)

// Complete is the constructor for a fully-resolved result.
func Complete() Partiality { return Partiality{Complete: true} }

// Partial constructs a declared-partial result with the given reason codes.
func Partial(reasons ...string) Partiality { return Partiality{Complete: false, Reasons: reasons} }

// Unsupported is the canonical Phase-1 contract-stub partiality.
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
}

// DependencyVersionResult reports the resolved declared version for the requested
// coordinate. Match is the dependency the plugin found for the request coordinate (with
// Resolved indicating whether its version is known); Found is false when no declaration of
// that coordinate exists in the build files at all.
type DependencyVersionResult struct {
	Partiality Partiality           `json:"partiality"`
	Found      bool                 `json:"found"` // a declaration of the request coordinate exists
	Match      ResolvedDependency   `json:"match"`
	All        []ResolvedDependency `json:"all,omitempty"` // every parsed declaration (evidence)
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
}

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

// DependencyInventory is the whole-graph resolver result (§4.1). This cycle lands the TYPE only;
// no plugin populates it (four+ plugins return Unsupported() — see §5). Nodes and Edges are
// emitted in explicit sorted order (see §7); no map is an iteration source on the encoding path.
type DependencyInventory struct {
	Partiality Partiality       `json:"partiality"` // graph-level declared partiality for unresolved conditions (§4.1 "declared partiality")
	Nodes      []DependencyNode `json:"nodes"`      // one per resolved package instance; sorted by Node.ID
	Edges      []DependencyEdge `json:"edges"`      // parent→child relationships; sorted by (Parent, Child)
}

// DependencyNode is one resolved package instance in the dependency graph.
type DependencyNode struct {
	ID         string               `json:"id"`         // stable package-instance key; DependencyEdge endpoints reference it. Distinct instances of the same PURL (different resolution scopes) get distinct IDs
	PURL       string               `json:"purl"`       // §4.1 normalized Package URL ("pkg:golang/github.com/x/y@v1.2.3")
	Version    string               `json:"version"`    // §4.1 exact resolved version
	Direct     bool                 `json:"direct"`     // §4.1 direct (true) vs transitive (false) relationship. NOT omitempty: false is load-bearing
	Membership DependencyMembership `json:"membership"` // §4.1 project/workspace/target membership
	Artifact   DependencyArtifact   `json:"artifact"`   // §4.1 selected artifact identity + integrity digest
	Provenance DependencyProvenance `json:"provenance"` // §4.1 manifest/lockfile/resolver/runtime-target provenance
	Partiality Partiality           `json:"partiality"` // §4.1 per-node declared partiality (unresolved condition on THIS node)
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
// source→sink flows toward. Phase-1 Go: Unsupported.
type ComputeTaintRequest struct {
	BuildDir string   `json:"build_dir"`
	Sinks    []string `json:"sinks,omitempty"` // resolved sink SCIP ids to trace toward
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
// reproducer harness for. Phase-1 Go: Unsupported.
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
// Phase-1 Go: Unsupported.
type BuildManifestRequest struct {
	BuildDir string `json:"build_dir"`
}

// RuntimeSpec is the ecosystem-neutral runtime descriptor (replaces GoVersion + ToolchainVersion).
type RuntimeSpec struct {
	Name      string `json:"name,omitempty"`      // runtime/language identity ("go", "node", "python", "dotnet")
	Version   string `json:"version,omitempty"`   // declared/minimum runtime version (replaces GoVersion; JS: node engine range — no longer overloaded onto a "go_version" field)
	Toolchain string `json:"toolchain,omitempty"` // exact toolchain pin when the manifest declares one (replaces ToolchainVersion); a stronger floor than Version
}

// ResolverSpec is the ecosystem-neutral resolver/build descriptor (replaces BuildCommand).
type ResolverSpec struct {
	Name    string `json:"name,omitempty"`    // resolver/build tool ("go", "npm", "maven", "gradle")
	Command string `json:"command,omitempty"` // neutral build invocation (replaces BuildCommand, e.g. "go build ./...")
}

// BuildManifestResult carries ecosystem-neutral build context (§4.6). Breaking change from the
// Go-named prior shape; four+ plugins still return Unsupported().
type BuildManifestResult struct {
	Partiality    Partiality   `json:"partiality"`
	Runtime       RuntimeSpec  `json:"runtime"`                 // §4.6 runtime
	Target        string       `json:"target,omitempty"`        // §4.6 target platform/architecture ("linux/amd64")
	Configuration string       `json:"configuration,omitempty"` // §4.6 build configuration/profile ("release", "Debug")
	ProjectRoot   string       `json:"project_root,omitempty"`  // §4.6 project root: module/package root identity (replaces Module)
	Resolver      ResolverSpec `json:"resolver"`                // §4.6 resolver
}

// StubPlugin implements LanguagePlugin with canned, in-memory results — the analog of
// episode.StubModel and the sandbox fakes. The live ops return fixed payloads; the three
// Phase-1 contract stubs return Unsupported(). It performs no I/O, no subprocess, no
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

// ResolveDependencyVersions is a Phase-1 contract stub: it always returns Unsupported.
func (StubPlugin) ResolveDependencyVersions(_ context.Context, _ ResolveVersionsRequest) (DependencyVersionResult, error) {
	return DependencyVersionResult{Partiality: Unsupported()}, nil
}

// ComputeTaint is a Phase-1 contract stub: it always returns Unsupported.
func (StubPlugin) ComputeTaint(_ context.Context, _ ComputeTaintRequest) (TaintResult, error) {
	return TaintResult{Partiality: Unsupported()}, nil
}

// GenerateHarness is a Phase-1 contract stub: it always returns Unsupported.
func (StubPlugin) GenerateHarness(_ context.Context, _ GenerateHarnessRequest) (HarnessResult, error) {
	return HarnessResult{Partiality: Unsupported()}, nil
}

// BuildManifest is a Phase-1 contract stub: it always returns Unsupported.
func (StubPlugin) BuildManifest(_ context.Context, _ BuildManifestRequest) (BuildManifestResult, error) {
	return BuildManifestResult{Partiality: Unsupported()}, nil
}

// ResolveInventory is a Phase-1 contract stub: it always returns Unsupported. It returns an
// honestly-partial inventory (Complete=false, PartialReasonUnsupported), NOT an empty-but-successful
// one — a zero-node Complete() inventory would read downstream as "this build has no dependencies".
func (StubPlugin) ResolveInventory(_ context.Context, _ ResolveInventoryRequest) (DependencyInventory, error) {
	return DependencyInventory{Partiality: Unsupported()}, nil
}

// CapabilityManifest is honest absence this cycle: no lane publishes a manifest yet, so it returns
// capability.Manifest{Supported:false} — never a Supported:true manifest with empty axes.
func (StubPlugin) CapabilityManifest(_ context.Context, _ CapabilityManifestRequest) (capability.Manifest, error) {
	return capability.Manifest{Supported: false}, nil
}
