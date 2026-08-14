package pythonanalysis

// Selected-set requirements parsing (PLAN-170 E1–E3).
//
// This is the environment-AWARE requirements parser that feeds the forthcoming
// ResolveInventory path (E5). It differs in intent from ResolveDependencyVersions'
// parseRequirementsTxt, which is deliberately environment-BLIND: the advisory-matching path
// wants a coordinate's version regardless of the target environment (a sound
// over-approximation), so it strips markers and ignores extras. That path is retained
// unchanged. This path instead computes the SELECTED set for a declared descriptor —
// evaluating markers (E1), resolving extras against a declared selection (E2), and
// recording every otherwise-dropped line as a partial node (E3) — and returns lane-local
// pyReq records. E5 maps those onto plugin.DependencyInventory nodes.
//
// pyReq is intentionally a lane-local intermediate, not plugin.DependencyNode: the shared
// inventory assembly + reason-code/field wiring is L0-gated (onyx-q6) and lands in E5.

import "strings"

// pyReq is one parsed requirement line with the fields E1–E3 populate. It is the input E5
// projects onto plugin.DependencyNode.
type pyReq struct {
	Name     string // PyPI project name (may be "" for a source-only line, e.g. a bare URL)
	Version  string // exact resolved version; "" when unresolved
	Resolved bool   // an exact "==X.Y.Z" pin was found
	Source   string // manifest/resolver label, e.g. "requirements.txt"
	Marker   string // captured PEP 508 marker text ("" = none)

	Selected   bool     // marker true (or no marker) → in the selected set
	Unresolved bool     // marker referenced an unbound variable (§3.1 partial)
	Partial    []string // lane-local partiality reason codes (see partiality.go)

	// E2 extras: the extras group "[a,b]" declared on the requirement, and the subset the
	// declared Selection selects (in declared order — C7 determinism). SelectedExtras is the
	// provenance C2 requires: it records exactly which declared-selection entries produced the
	// inclusion, so a reader can tell an unselected extra was evaluated-and-excluded, not
	// missed. An unselected extra's subtree does not enter the selected set.
	Extras         []string
	SelectedExtras []string
}

// resolveRequirements parses a requirements file into the selected set for the declared
// environment env (variable→value) and extras selection. Each logical line becomes a pyReq
// whose Selected/Unresolved/Partial reflect its marker outcome; a marker-false requirement
// is returned as a node with Selected=false (an explicit, evaluated exclusion — NOT a silent
// drop), so a caller can distinguish "excluded because the marker said so" from "never
// parsed". env may be nil (then any marked line is unresolved).
func resolveRequirements(data []byte, env map[string]string, selection []string) []pyReq {
	var out []pyReq
	for _, raw := range joinContinuations(string(data)) {
		line := strings.TrimSpace(stripReqComment(raw))
		if line == "" {
			continue
		}

		marker := ""
		if i := strings.IndexByte(line, ';'); i >= 0 {
			marker = strings.TrimSpace(line[i+1:])
			line = strings.TrimSpace(line[:i])
		}

		name, version, resolved, extras := parseRequirementSpec(line)
		if name == "" {
			continue
		}

		r := pyReq{
			Name:           name,
			Version:        version,
			Resolved:       resolved,
			Source:         "requirements.txt",
			Marker:         marker,
			Extras:         extras,
			SelectedExtras: selectExtras(extras, selection),
		}
		applyMarker(&r, env, selection)
		out = append(out, r)
	}
	return out
}

// applyMarker evaluates r.Marker against the descriptor and sets the selection outcome.
// No marker → selected. Marker true → selected. Marker false → not selected (an evaluated
// exclusion). Unbound variable → unresolved with declared partiality naming the variable.
func applyMarker(r *pyReq, env map[string]string, selection []string) {
	if r.Marker == "" {
		r.Selected = true
		return
	}
	mr := evaluateMarker(r.Marker, env, selection)
	switch {
	case mr.unresolved:
		r.Unresolved = true
		r.Partial = append(r.Partial, envUnresolvedReason(mr.unboundVar))
	case mr.selected:
		r.Selected = true
	default:
		r.Selected = false // marker evaluated false: a resolved exclusion, not a drop
	}
}

// selectExtras returns, in declared order, the subset of a requirement's extras group that
// the declared Selection selects (PLAN-170 E2, C2). An extra not in the selection does not
// enter the selected set; the returned slice is the provenance of the inclusion. Extra names
// and selection entries are both PEP 503-normalized so matching is case/separator-insensitive.
// selection is used only for membership lookup — never iterated on an output path (C7).
func selectExtras(extras, selection []string) []string {
	if len(extras) == 0 || len(selection) == 0 {
		return nil
	}
	selSet := make(map[string]bool, len(selection))
	for _, s := range selection {
		if n := normalizePyCoordinate(s); n != "" {
			selSet[n] = true
		}
	}
	var out []string
	for _, e := range extras { // declared order preserved (C7)
		if selSet[normalizePyCoordinate(e)] {
			out = append(out, normalizePyCoordinate(e))
		}
	}
	return out
}

// envUnresolvedReason builds the partiality code for an unbound marker variable, appending
// the specific variable as a ":<var>" detail (architect-ruling item 2 convention). The
// bare code is used when the variable is unknown (malformed marker).
func envUnresolvedReason(unboundVar string) string {
	if unboundVar == "" {
		return reasonEnvUnresolvedPlaceholder
	}
	return reasonEnvUnresolvedPlaceholder + ":" + unboundVar
}
