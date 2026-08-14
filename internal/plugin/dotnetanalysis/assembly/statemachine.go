package assembly

// statemachine.go — the generated-code → source-method mapping (⚑SM).
//
// PLAN-051 SETTLED the rule and its doctrine (SYMBOLS.md §⚑SM): the decode
// `<Name>d__N` → source method `Name` (plus `<>c` display-class closures and
// `<Name>b__N_M` lambda bodies) is a NAME-MANGLING PATTERN, not a Roslyn query. This
// file is the single Go implementation of that settled rule; scip.go carries only the
// SCIP symbol-string construction and never decoded a mangle, so there was nothing to
// extract there — the rule lived as doctrine in SYMBOLS.md and is realized here once, so
// no second decoder can drift from the symbol layer.
//
// Declared partiality (C6): a path routed through a generated async/iterator state
// machine (its `MoveNext`) is DECLARED-PARTIAL — never silently collapsed, and we never
// invent an unobservable `<…>d__N` symbol. The state-machine type carries Generated=true;
// the source method it maps back to carries Generated=false.

import "strings"

// mangleKind classifies a compiler-mangled name.
type mangleKind int

const (
	mangleNone         mangleKind = iota
	mangleStateMachine            // <Name>d__N — async/iterator state-machine type
	mangleLambda                  // <Name>b__N_M — lambda body method
	mangleDisplayClass            // <>c / <>c__DisplayClassN — closure holder type
	mangleBackingField            // <Prop>k__BackingField — auto-property backing field
)

func (k mangleKind) String() string {
	switch k {
	case mangleStateMachine:
		return "statemachine"
	case mangleLambda:
		return "lambda"
	case mangleDisplayClass:
		return "displayclass"
	case mangleBackingField:
		return "backingfield"
	}
	return "none"
}

// decodeMangled parses a Roslyn compiler-mangled member/type name into (source name,
// kind, ok). The grammar is `<SOURCE>DISCRIMINATOR...`:
//
//	<FetchAsync>d__0        → ("FetchAsync",  statemachine)
//	<Run>b__0_0             → ("Run",         lambda)
//	<>c / <>c__DisplayClass → ("",            displayclass)
//	<Prop>k__BackingField   → ("Prop",        backingfield)
//
// A name that does not carry the mangle (a hand-written `MoveNext`, a user type named
// `Foo`, or a member whose name merely resembles one) returns ok=false — this is what
// keeps the mapping keyed on the observable mangle rather than a substring guess.
func decodeMangled(name string) (source string, kind mangleKind, ok bool) {
	if len(name) == 0 || name[0] != '<' {
		return "", mangleNone, false
	}
	gt := strings.IndexByte(name, '>')
	if gt < 0 {
		return "", mangleNone, false
	}
	inner := name[1:gt]
	rest := name[gt+1:]
	switch {
	case strings.HasPrefix(rest, "d__"):
		return inner, mangleStateMachine, true
	case strings.HasPrefix(rest, "b__"):
		return inner, mangleLambda, true
	case inner == "" && (rest == "c" || strings.HasPrefix(rest, "c__")):
		return "", mangleDisplayClass, true
	case strings.HasPrefix(rest, "k__BackingField"):
		return inner, mangleBackingField, true
	}
	return "", mangleNone, false
}

// DecodeGeneratedName decodes a compiler-mangled name to the SOURCE method name it
// belongs to, per the settled ⚑SM rule. ok is false for any name without the mangle.
// Exported so the production pass and its tests can assert the decode directly.
func DecodeGeneratedName(name string) (source string, ok bool) {
	s, kind, ok := decodeMangled(name)
	if !ok || kind == mangleDisplayClass {
		return "", ok && kind != mangleDisplayClass
	}
	return s, s != ""
}

// SourceMapping is the readability attribution of a (possibly compiler-generated) method
// back to the source method a developer wrote, carrying the ⚑SM DECLARED partiality any
// edge routed through a generated state machine inherits. For an ordinary method it is
// the identity mapping (Generated=false, Partial=false, SourceName/Enclosing = as-declared).
type SourceMapping struct {
	Generated       bool   // the method or its declaring type is compiler-generated
	StateMachine    bool   // attributed through a generated async/iterator state machine (MoveNext)
	Partial         bool   // ⚑SM declared partiality: an edge routed through this reads through a state machine
	SourceName      string // the source method name to attribute to (decoded, or as-declared)
	SourceEnclosing string // the source declaring type's display (the OUTER type for a nested state machine)
	Reason          string // why generated/partial, for provenance and the symbol layer
}

// MethodSourceMapping decides whether method m (declared in td) is compiler-generated
// and, if so, maps it to the source method a developer wrote — carrying the ⚑SM declared
// partiality for a state machine. It NEVER invents an unobservable `<…>d__N` symbol: when
// a generated element has no decodable source mangle, it keeps the observable name and
// flags Generated=true rather than fabricating a source identity.
func (a *Assembly) MethodSourceMapping(td *TypeDef, m *MethodDef) SourceMapping {
	sm := SourceMapping{SourceName: m.Name}
	if td != nil {
		sm.SourceEnclosing = typeDisplay(TypeRef{Namespace: td.Namespace, Name: td.Name})
	}

	// Declaring TYPE generated? (attribute OR mangle) — state machines & display classes.
	typeGen := false
	var typeInner string
	var typeKind mangleKind
	if td != nil {
		if a.isCompilerGenerated(td.Token) {
			typeGen = true
		}
		if src, kind, ok := decodeMangled(td.Name); ok {
			typeGen = true
			typeInner, typeKind = src, kind
		}
	}
	// METHOD itself generated? (attribute OR mangle) — lambda bodies, generated members.
	methodGen := false
	var methodInner string
	var methodKind mangleKind
	if a.isCompilerGenerated(m.Token) {
		methodGen = true
	}
	if src, kind, ok := decodeMangled(m.Name); ok {
		methodGen = true
		methodInner, methodKind = src, kind
	}

	if !typeGen && !methodGen {
		return sm // ordinary source method: identity mapping, Generated=false, not partial.
	}
	sm.Generated = true

	switch {
	case typeKind == mangleStateMachine:
		// async / iterator: MoveNext (and the SM's helper members) live inside <Name>d__N.
		// Map to the source method Name on the OUTER type; declare partiality for the
		// state-machine-routed edge — never a silent collapse (⚑SM / C6).
		sm.StateMachine = true
		sm.Partial = true
		sm.SourceName = typeInner
		if enc, ok := a.enclosingDisplay(td); ok {
			sm.SourceEnclosing = enc
		}
		sm.Generated = false // the mapped SOURCE method is not generated (SYMBOLS.md ⚑SM)
		sm.Reason = "⚑SM: edge routed through generated state machine " + td.Name + " (source-side declared-partial)"
	case methodKind == mangleLambda:
		// A lambda body maps to the source method that declared it (the outer type owns it).
		sm.SourceName = methodInner
		if enc, ok := a.enclosingDisplay(td); ok {
			sm.SourceEnclosing = enc
		}
		sm.Generated = false
		sm.Reason = "generated lambda body mapped to source method " + methodInner
	case typeKind == mangleDisplayClass:
		// The closure holder itself: no source METHOD to name — keep the observable
		// mangled identity, declared generated (do not invent a source symbol).
		sm.Reason = "generated display class (closure holder); kept observable"
	default:
		// Generated by attribute but no decodable source mangle: keep observable name.
		sm.Reason = "compiler-generated (attribute); no source-name mangle to decode"
	}
	return sm
}

// enclosingDisplay resolves the OUTER type that encloses a nested type via the
// NestedClass table, returning its "Namespace.Name" display. A generated state machine
// `<M>d__N` is nested in the type that declared the source method, so this recovers the
// developer-facing enclosing type. Returns ok=false when td is not a nested type.
func (a *Assembly) enclosingDisplay(td *TypeDef) (string, bool) {
	if td == nil {
		return "", false
	}
	for _, nc := range a.NestedTypes {
		if nc.Nested != td.Token {
			continue
		}
		encRID := nc.Enclosing.RID()
		for i := range a.Types {
			if a.Types[i].RID == encRID {
				return typeDisplay(TypeRef{Namespace: a.Types[i].Namespace, Name: a.Types[i].Name}), true
			}
		}
	}
	return "", false
}
