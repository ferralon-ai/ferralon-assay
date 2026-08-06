package artifact

// CandidatePairSchemaVersion is the versioned schema identifier for the
// CandidatePair payload, following the verdict precedent ("tegron.<type>.v<N>").
const CandidatePairSchemaVersion = "tegron.candidate_pair.v1"

// CandidatePair is an (ingress, sink, path) triple linking an externally-reachable
// entry point to a vulnerable sink via a call path. The three legs map to the PoE
// evidence chain (sink = vulnerable symbol, path = call path/reachability,
// ingress = ingress map) and are carried by reference, never embedded.
type CandidatePair struct {
	SchemaVersion string `json:"schema_version"` // = CandidatePairSchemaVersion

	// Sink — the vulnerable symbol this pair targets (ref to a TypeVulnerableSymbol artifact).
	Sink Ref `json:"sink"`
	// Ingress — the entry point reaching the sink (ref to a TypeIngressMap artifact).
	// omitempty: a reachable-but-no-known-ingress pair is valid (declared partiality).
	Ingress *Ref `json:"ingress,omitempty"`
	// Path — the call path from ingress to sink (ref to a TypeReachability artifact).
	Path Ref `json:"path"`
	// Partial declares incomplete reachability rather than hiding it.
	Partial bool `json:"partial"`
}
