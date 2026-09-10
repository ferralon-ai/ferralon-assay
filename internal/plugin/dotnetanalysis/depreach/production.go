package depreach

// production.go — the first-party BackingEdge production pass. It walks every method
// body of the first-party assembly (assembly/il.go walkIL, reused), resolves each IL
// call site through the CHA over the loaded set (assembly/chagraph.go ResolveDispatch,
// reused), and emits provenance-carrying BackingEdges: Producer/Origin/Confidence
// populated at production, the generated→source mapping (assembly/statemachine.go)
// applied for readability, and the ⚑SM declared partiality carried on any edge routed
// through a generated state machine.
//
// It performs NO verdict logic — that is the engine (engine.go) — and never inflates the
// frozen plugin.CallEdge: all provenance stays on BackingEdge, projected away by Compact().

import (
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// producer tags (the pass that emitted the edge).
const (
	producerCHA        = "cha"         // resolved (single/candidate/out-of-set-named) through the class hierarchy
	producerILCallsite = "il-callsite" // an unresolved site recorded straight from the IL walk (calli/jmp/open-world)
)

// ProduceBackingEdges walks the first-party assembly fp's method bodies and returns the
// BackingEdges for every IL call site, resolved against the CHA over the whole loaded set
// `all` (fp plus its dependency assemblies). Every returned edge carries a non-empty
// Producer and Origin and a valid Confidence; a state-machine-routed edge carries the
// declared partiality. No site is dropped: an unresolved/open-world site is emitted as a
// boundary edge, never omitted.
func ProduceBackingEdges(fp *assembly.Assembly, all []*assembly.Assembly) []BackingEdge {
	if fp == nil || fp.Failed {
		return nil
	}
	cha := assembly.NewCHA(all...)
	var out []BackingEdge
	for i := range fp.Types {
		td := &fp.Types[i]
		for _, m := range td.Methods {
			if m == nil || m.RVA == 0 {
				continue // abstract/native/runtime: no walkable body (a leaf, not a producer)
			}
			body, err := fp.MethodBody(m)
			if err != nil {
				continue
			}
			from, fromMap := symbolFor(fp, td, m)
			for _, edge := range body.Edges {
				origin := EdgeOrigin{Assembly: fp.Name, Method: m.Token, ILOffset: uint32(edge.Offset)}
				dr := cha.ResolveDispatch(fp, edge)

				if dr.State == assembly.DispatchBoundary || len(dr.Targets) == 0 {
					owner, name := calleeDisplay(fp, edge.Token)
					out = append(out, BackingEdge{
						From:          from,
						To:            boundarySymbol(owner, name),
						Kind:          edge.Kind,
						Producer:      producerILCallsite,
						Origin:        origin,
						Confidence:    ConfBoundary,
						Partial:       fromMap.Partial,
						PartialReason: fromMap.Reason,
					})
					continue
				}

				for _, tgt := range dr.Targets {
					be := BackingEdge{
						From:          from,
						Kind:          edge.Kind,
						Producer:      producerCHA,
						Origin:        origin,
						Partial:       fromMap.Partial,
						PartialReason: fromMap.Reason,
					}
					if tgt.Method == nil {
						// Named but out-of-set: a resolved-single/candidate whose body is not in
						// the loaded set. Confidence degrades to boundary (owner-out-of-set).
						be.To = boundarySymbol(tgt.OwnerDisplay, tgt.Name)
						be.Confidence = ConfBoundary
					} else {
						toSym, toMap := symbolFor(tgt.Asm, tgt.Type, tgt.Method)
						be.To = toSym
						be.Confidence = ConfResolved
						if dr.State == assembly.DispatchConservative {
							be.Confidence = ConfConservative
						}
						if toMap.Partial && !be.Partial {
							be.Partial = true
							be.PartialReason = toMap.Reason
						}
					}
					out = append(out, be)
				}
			}
		}
	}
	return out
}

// SymbolFor is the exported projector barrier-4b's Reachability op reuses to render a
// resolved path node (owner/type/method) as its source-level plugin.Symbol, with the
// generated→source (state-machine/lambda) mapping applied — so an emitted ReachPath trace
// reads as the source methods a developer wrote. It is a thin wrapper over the internal
// symbolFor (no logic change); the SourceMapping second return is dropped at this seam
// because the plugin op declares partiality from the engine's frontier hazards, not from
// per-edge ⚑SM (which rides on BackingEdge, the production artifact).
func SymbolFor(a *assembly.Assembly, td *assembly.TypeDef, m *assembly.MethodDef) plugin.Symbol {
	s, _ := symbolFor(a, td, m)
	return s
}

// symbolFor builds the lane-local plugin.Symbol identity for a method, applying the
// generated→source mapping so a generated MoveNext/lambda reads as the source method a
// developer wrote. The Symbol fields are the lane-local backing identity (the canonical
// SYMBOLS.md field spelling is PLAN-252's concern, not this cycle's); provenance and the
// declared partiality ride on the BackingEdge, never on the frozen public projection.
func symbolFor(a *assembly.Assembly, td *assembly.TypeDef, m *assembly.MethodDef) (plugin.Symbol, assembly.SourceMapping) {
	sm := a.MethodSourceMapping(td, m)
	kind := plugin.SymbolKindMethod
	if sm.SourceName == ".ctor" || sm.SourceName == ".cctor" {
		kind = plugin.SymbolKindConstructor
	}
	return plugin.Symbol{
		Kind:        kind,
		Package:     a.Name,
		Enclosing:   sm.SourceEnclosing,
		Name:        sm.SourceName,
		Generated:   sm.Generated,
		DisplayName: displayName(sm.SourceEnclosing, sm.SourceName),
	}, sm
}

// boundarySymbol builds the callee identity for a site whose target body is not in the
// loaded set (open-world / out-of-set / calli / jmp). It carries the named owner+method
// so the edge is recorded, never dropped; it is not marked generated (unobservable here).
func boundarySymbol(owner, name string) plugin.Symbol {
	return plugin.Symbol{
		Kind:        plugin.SymbolKindMethod,
		Enclosing:   owner,
		Name:        name,
		DisplayName: displayName(owner, name),
	}
}

func displayName(enclosing, name string) string {
	switch {
	case enclosing != "" && name != "":
		return enclosing + "." + name
	case name != "":
		return name
	default:
		return enclosing
	}
}

// calleeDisplay resolves a call operand token to its callee's (owner display, method
// name) for a boundary edge's identity — the same MethodDef/MemberRef/MethodSpec decode
// the engine uses, without minting an engine node.
func calleeDisplay(a *assembly.Assembly, tok assembly.Token) (owner, name string) {
	switch tok.Table() {
	case tblMethodDef:
		if m := a.MethodByRID(tok.RID()); m != nil {
			return "", m.Name
		}
	case tblMemberRef:
		if mr := a.MemberRef(tok.RID()); mr != nil {
			return mr.Type, mr.Name
		}
	case tblMethodSpec:
		if int(tok.RID()) < len(a.MethodSpecs) {
			return calleeDisplay(a, a.MethodSpecs[tok.RID()].Method)
		}
	}
	return "", ""
}
