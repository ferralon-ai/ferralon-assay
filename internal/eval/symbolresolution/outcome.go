package symbolresolution

import (
	"fmt"

	"github.com/ferralon-ai/ferralon-assay/corpus"
)

// ResolutionOutcome is the per-(record × lane) resolution fact (C1). Exactly one of two shapes,
// discriminated by Resolved:
//
//	Resolved==true  → Symbol != nil, Reason == "".
//	Resolved==false → Symbol == nil, Reason ∈ the closed ResolutionReason set (never "").
//
// Enforced by Validate() (§2.1). There is no absent row: every record × in-scope lane yields one,
// so a record the pipeline never reached still produces an outcome carrying the reason that says
// so — byte-distinguishable from a resolved one.
type ResolutionOutcome struct {
	RecordID  string           `json:"record_id"`          // advisory vuln_id — the pipeline.AdvisoryTable / corpus key
	Lane      string           `json:"lane"`               // in-scope lane token, e.g. "go"
	Ecosystem string           `json:"ecosystem"`          // pipeline.EcosystemToken(r): "golang"/"maven"/… or "(none)"
	Category  corpus.Category  `json:"category,omitempty"` // from the BOUND corpus.Fixture; "" when no fixture is bound (kept visible, never dropped — §5)
	Resolved  bool             `json:"resolved"`           // discriminator
	Symbol    *ResolvedSymbol  `json:"symbol,omitempty"`   // set iff Resolved
	Reason    ResolutionReason `json:"reason,omitempty"`   // set iff !Resolved
}

// ResolvedSymbol names WHICH concrete symbol the resolver matched. It is a two-field projection
// of plugin.Symbol sufficient to identify the symbol, sourced from the signals CaseResult already
// surfaces (ResolvedSinkSCIP / ResolvedSinkDisplay) — so carrying it requires NO change to
// CaseResult or the resolver (C7 containment).
type ResolvedSymbol struct {
	SCIP        string `json:"scip"`         // plugin.Symbol.SCIP — the resolver's canonical id
	DisplayName string `json:"display_name"` // plugin.Symbol.DisplayName — human-readable identity
}

// Validate enforces the §2.1 XOR invariant: returns non-nil unless EXACTLY one shape holds —
//
//	(Resolved && Symbol != nil && Reason == "")  XOR  (!Resolved && Symbol == nil && Reason.Recognized())
//
// The two shapes can never both hold (Resolved differs), so the error case is "neither holds":
// a malformed outcome (e.g. resolved with no symbol, or unresolved with an empty/unknown reason).
// This is what makes a resolved outcome and a never-reached outcome byte-distinguishable (C1); an
// assertion that accepts both is measuring nothing.
func (o ResolutionOutcome) Validate() error {
	resolvedShape := o.Resolved && o.Symbol != nil && o.Reason == ""
	unresolvedShape := !o.Resolved && o.Symbol == nil && o.Reason.Recognized()
	if resolvedShape == unresolvedShape { // both false ⇒ malformed (both true is unreachable)
		return fmt.Errorf(
			"resolution outcome %s/%s: neither resolved nor unresolved shape holds (resolved=%v hasSymbol=%v reason=%q)",
			o.RecordID, o.Lane, o.Resolved, o.Symbol != nil, o.Reason)
	}
	return nil
}
