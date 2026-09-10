package pipeline

// Thin EXPORTED accessors over the unexported PLAN-220 attribution predicates, added for
// PLAN-221's symbol-resolution-rate classifier (internal/eval/symbolresolution). They are pure
// pass-throughs — NO behaviour change to reportState / symbolBearing / ecosystemToken, whose
// bodies are untouched — so the metric's reason-classifier can live on the eval surface while the
// denominator predicates keep their single home here. This is the one place PLAN-221's diff
// legitimately leaves the pure-eval surface (accessor-only; justified in the PR body, field
// contract §7.1).

// ReportState is the exported accessor for reportState: the §3 report state for record r under
// attribution a (nil == absent == unreviewed).
func ReportState(r AdvisoryFacts, a *AdvisoryAttribution) string { return reportState(r, a) }

// SymbolBearing is the exported accessor for symbolBearing: the record carries >=1 vulnerable
// symbol (the D2 denominator predicate).
func SymbolBearing(r AdvisoryFacts) bool { return symbolBearing(r) }

// EcosystemToken is the exported accessor for ecosystemToken: the record's PURL ecosystem
// ("golang"/"maven"/… or "(none)") — the D1 denominator key and the classifier's lane gate.
func EcosystemToken(r AdvisoryFacts) string { return ecosystemToken(r) }

// StateAttributedReviewed is the exported mirror of the unexported stateAttributedReviewed — the
// D3 (reviewed-attributed-in-lane) target state. Aliases the single source of truth so the eval
// package can name the D3 inclusion state without duplicating the literal.
const StateAttributedReviewed = stateAttributedReviewed
