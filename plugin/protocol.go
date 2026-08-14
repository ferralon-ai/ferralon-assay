package plugin

// Request is the one-shot subprocess request envelope. Op selects the operation; exactly
// one of the per-op request fields is populated, matching Op.
type Request struct {
	Protocol string `json:"protocol"` // = ProtocolVersion; client + subprocess must agree
	Op       string `json:"op"`       // OpIndexSymbols, OpReachability, ...

	IndexSymbols     *IndexSymbolsRequest     `json:"index_symbols,omitempty"`
	ResolveSymbols   *ResolveSymbolsRequest   `json:"resolve_symbols,omitempty"`
	ResolveVersions  *ResolveVersionsRequest  `json:"resolve_versions,omitempty"`
	CallGraph        *CallGraphRequest        `json:"call_graph,omitempty"`
	FindIngresses    *FindIngressesRequest    `json:"find_ingresses,omitempty"`
	Reachability     *ReachabilityRequest     `json:"reachability,omitempty"`
	ComputeTaint     *ComputeTaintRequest     `json:"compute_taint,omitempty"`
	GenerateHarness  *GenerateHarnessRequest  `json:"generate_harness,omitempty"`
	BuildManifest    *BuildManifestRequest    `json:"build_manifest,omitempty"`
	ResolveInventory *ResolveInventoryRequest `json:"resolve_inventory,omitempty"`
}

// Response is the one-shot subprocess response envelope. Exactly one payload field is set on
// success. Error is non-empty ONLY for a hard, non-partial failure (e.g. malformed request,
// build dir does not exist) — a partial-but-successful analysis sets the payload's Partiality
// instead. This distinguishes inv.4 hard errors from inv.5 declared partiality.
type Response struct {
	Protocol string `json:"protocol"`
	Error    string `json:"error,omitempty"`

	SymbolIndex      *SymbolIndexResult       `json:"symbol_index,omitempty"`
	SymbolResolution *SymbolResolutionResult  `json:"symbol_resolution,omitempty"`
	VersionResult    *DependencyVersionResult `json:"version_result,omitempty"`
	CallGraph        *CallGraphResult         `json:"call_graph,omitempty"`
	Ingress          *IngressResult           `json:"ingress,omitempty"`
	Reachability     *ReachabilityResult      `json:"reachability,omitempty"`
	Taint            *TaintResult             `json:"taint,omitempty"`
	Harness          *HarnessResult           `json:"harness,omitempty"`
	BuildManifest    *BuildManifestResult     `json:"build_manifest,omitempty"`
	Inventory        *DependencyInventory     `json:"inventory,omitempty"`
}

// ProtocolVersion is the wire-format version both client and subprocess must agree on.
// A mismatch is a hard error on both sides (inv.4) — fail fast, never best-effort decode.
const ProtocolVersion = "tegron.plugin.v1"

// Op* are the operation selectors carried in Request.Op, matching the LanguagePlugin op names.
const (
	OpIndexSymbols     = "index_symbols"
	OpResolveSymbols   = "resolve_symbols"
	OpResolveVersions  = "resolve_versions"
	OpCallGraph        = "call_graph"
	OpFindIngresses    = "find_ingresses"
	OpReachability     = "reachability"
	OpComputeTaint     = "compute_taint"
	OpGenerateHarness  = "generate_harness"
	OpBuildManifest    = "build_manifest"
	OpResolveInventory = "resolve_inventory"
)
