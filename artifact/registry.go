package artifact

// SchemaVersion strings follow the verdict precedent (verdict.SchemaVersion =
// "tegron.poe.v1"): "tegron.<type>.v<N>". Each payload-owning package SHOULD also
// export its own const; the Registry is the single source of truth the completeness
// test checks against.

// TypeMeta is the governance record for one artifact type: who produces it and
// the current shipped schema version of its payload.
type TypeMeta struct {
	Owner         string // producing stage name (matches Stage.Name())
	SchemaVersion string // current shipped payload version, e.g. "tegron.reachability.v1"
}

// Registry maps every artifact.Type this package declares to its owner + current schema
// version. Every declared Type MUST have exactly one entry, and exactly one producer owns
// each type (enforced by the completeness test).
//
// It governs the types this library produces, not every type that can be stored: Type is a
// plain string and Put never validates against the Registry, so a consumer may declare and
// store its own types with its own governance records. Lookup reporting ok=false therefore
// means "not one of ours", not "unknown to the system".
var registry = map[Type]TypeMeta{
	// This SchemaVersion is a cross-repo wire tag, matched by the advisory-source reader in
	// pipeline. It is "ferralon."-namespaced on purpose: this type is definitionally the
	// platform advisory feed, not an engine-internal shape. It is one of two designed
	// exceptions to the tegron.<type>.vN convention; see schemaVersionRe in registry_test.go.
	TypeNormalizedAdvisory: {Owner: "advisory_intake", SchemaVersion: "ferralon.normalized_advisory.v2"},
	TypeInventory:          {Owner: "codebase_inventory", SchemaVersion: "tegron.inventory.v1"},
	TypePublicPoC:          {Owner: "advisory_intake", SchemaVersion: "tegron.public_poc.v1"},
	TypeDisqualification:   {Owner: "disqualification_discovery", SchemaVersion: "tegron.disqualification.v1"},
	TypeDiscovery:          {Owner: "disqualification_discovery", SchemaVersion: "tegron.discovery.v1"},
	TypeVulnerableSymbol:   {Owner: "symbol_mapping", SchemaVersion: "tegron.vulnerable_symbol.v1"},
	TypeReachability:       {Owner: "reachability_ingress", SchemaVersion: "tegron.reachability.v1"},
	TypeIngressMap:         {Owner: "reachability_ingress", SchemaVersion: "tegron.ingress_map.v1"},
	TypeCandidatePair:      {Owner: "reachability_ingress", SchemaVersion: CandidatePairSchemaVersion},
	TypeTaint:              {Owner: "reachability_ingress", SchemaVersion: "tegron.taint.v1"},
	TypeHarness:            {Owner: "reachability_ingress", SchemaVersion: "tegron.harness.v1"},
	// TypePoE carries the verdict package's literal version. A test in the verdict package
	// asserts verdict.SchemaVersion == this value, catching drift without an artifact->verdict
	// import cycle (the dependency points inward).
	TypePoE: {Owner: "verdict_emission", SchemaVersion: "tegron.poe.v1"},
	// Deterministic exposure report: aggregates already-computed signals, emits no verdict.
	TypeExposureFootprint: {Owner: "exposure_footprint", SchemaVersion: ExposureFootprintSchemaVersion},
	// Standard projections — read-only views of a PoE. They are derived from the PoE at
	// emission time (or on demand via the API), not produced by a separate pipeline stage.
	TypeProjectionSARIF:       {Owner: "verdict_emission", SchemaVersion: "tegron.projection_sarif.v1"},
	TypeProjectionVEX:         {Owner: "verdict_emission", SchemaVersion: "tegron.projection_vex.v1"},
	TypeProjectionSSVC:        {Owner: "verdict_emission", SchemaVersion: "tegron.projection_ssvc.v1"},
	TypeProjectionRedactedPoE: {Owner: "verdict_emission", SchemaVersion: "tegron.projection_redacted_poe.v1"},
}

// Lookup returns the governance record for an artifact type. ok is false if the
// type has no Registry entry (which the completeness test forbids for known types).
func Lookup(t Type) (TypeMeta, bool) {
	m, ok := registry[t]
	return m, ok
}

// Types returns every artifact.Type that has a Registry entry, in no particular
// order. It lets callers (and the completeness test) enumerate the governed set.
func Types() []Type {
	ts := make([]Type, 0, len(registry))
	for t := range registry {
		ts = append(ts, t)
	}
	return ts
}
