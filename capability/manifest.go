package capability

// Manifest is a language analyzer's capability declaration. Content is authored per-lane in
// Phase-4 (PLAN-4x0); this cycle every producer returns Manifest{Supported:false} (honest absence).
// All slices are emitted in explicit sorted order (no map is an iteration source on the encoding
// path) — the determinism rule the codebase already enforces for DependencyInventory.
type Manifest struct {
	Version           string   `json:"version"`                      // the lane's CONTENT version (what report cites); bumps when a planner adds support
	Language          string   `json:"language"`                     // lane tag, mirrors LanguagePlugin.Language() ("go","js",...)
	Supported         bool     `json:"supported"`                    // false = no manifest published yet (honest absence this cycle); NOT a plugin.Partiality
	Resolvers         []string `json:"resolvers,omitempty"`          // supported resolver/manifest formats (go.mod, package.json, pom.xml, ...)
	Runtimes          []string `json:"runtimes,omitempty"`           // supported runtime targets (go1.21, node18, ...)
	GraphSemantics    []string `json:"graph_semantics,omitempty"`    // supported call-graph semantics axes
	Frameworks        []string `json:"frameworks,omitempty"`         // frameworks recognized for ingress/idiom detection
	DynamicBoundaries []string `json:"dynamic_boundaries,omitempty"` // declared dynamic-analysis boundaries (reflection, cgo, dynamic_dispatch, ...)
	Analyzers         []string `json:"analyzers,omitempty"`          // analyzer identities/versions backing the axes
}
