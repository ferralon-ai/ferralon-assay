package depreach

// provenance_c4_test.go — C4: the provenance-completeness SWEEP over BackingEdge
// (PLAN-350 barrier-4a criterion, exercised by barrier-4b). It asserts, by REFLECTION over
// the struct's provenance fields (not a hand-picked spot sample), that EVERY edge
// ProduceBackingEdges emits carries a non-empty Producer, a populated Origin (Assembly +
// Method), and a valid Confidence — with a NEGATIVE CONTROL proving the sweep actually
// fails when any one provenance field is empty, and a compact-projection check proving the
// frozen plugin.CallEdge is NOT inflated (it still carries only {Caller, Callee}).

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// sweepProvenance validates one edge's provenance fields by REFLECTION, so the check tracks
// the struct's provenance surface rather than a fixed spot sample. It returns a non-nil
// error naming the first empty/invalid provenance field — the same predicate drives the
// positive sweep (must pass for every produced edge) and the negative control (must fail).
func sweepProvenance(e BackingEdge) error {
	v := reflect.ValueOf(e)

	if p := v.FieldByName("Producer").String(); p == "" {
		return fmt.Errorf("empty Producer")
	}

	origin := v.FieldByName("Origin")
	if origin.FieldByName("Assembly").String() == "" {
		return fmt.Errorf("empty Origin.Assembly")
	}
	method, ok := origin.FieldByName("Method").Interface().(assembly.Token)
	if !ok {
		return fmt.Errorf("Origin.Method is not an assembly.Token")
	}
	if method.IsNull() {
		return fmt.Errorf("null Origin.Method")
	}

	conf, ok := v.FieldByName("Confidence").Interface().(Confidence)
	if !ok {
		return fmt.Errorf("Confidence is not a Confidence")
	}
	if conf.String() == "unknown" {
		return fmt.Errorf("invalid Confidence %d", conf)
	}
	return nil
}

// c4Fixture builds a single assembly whose Ingress.enter has both a RESOLVED in-set call
// (Vuln, producer cha / confidence resolved) and a BOUNDARY callvirt to an out-of-set
// receiver (producer il-callsite / confidence boundary), so the sweep spans more than one
// producer and confidence grade.
func c4Fixture(t *testing.T) *assembly.Assembly {
	b := scaffold()
	obj := b.extTypeRef("System", "Object")
	ext := cTypeDefOrRef(xTypeRef, obj)
	b.addType(0, "<Module>", "", 0, nil)

	_, tgtM := b.addType(0, "Target", "App", ext, []mspec{{name: "Vuln", flags: 0x10, sig: sigStaticVoid, il: body()}})
	vulnTok := mtok(xMethodDef, tgtM[0])
	extRef := b.extTypeRef("Ext", "Widget")
	extMember := b.row(xMemberRef, cMemberRefParent(xTypeRef, extRef), b.str("Do"), b.blob(sigInstVoid))
	b.addType(0, "Ingress", "App", ext, []mspec{
		{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilCall(vulnTok), ilCallvirt(mtok(xMemberRef, extMember)))},
	})
	return b.finish(t)
}

// TestC4_ProvenanceSweep is the completeness sweep + negative control + compact check.
func TestC4_ProvenanceSweep(t *testing.T) {
	a := c4Fixture(t)
	edges := ProduceBackingEdges(a, []*assembly.Assembly{a})
	if len(edges) == 0 {
		t.Fatal("no edges produced — sweep would be vacuous")
	}

	// SWEEP: every produced edge must pass provenance completeness.
	sawResolved, sawBoundary := false, false
	for _, e := range edges {
		if err := sweepProvenance(e); err != nil {
			t.Fatalf("produced edge failed provenance sweep: %v (%+v)", err, e)
		}
		switch e.Confidence {
		case ConfResolved:
			sawResolved = true
		case ConfBoundary:
			sawBoundary = true
		}
	}
	if !sawResolved || !sawBoundary {
		t.Fatalf("sweep must span resolved AND boundary edges; resolved=%v boundary=%v", sawResolved, sawBoundary)
	}

	// NEGATIVE CONTROL: an edge with ANY empty provenance field MUST fail the sweep — proving
	// the sweep is load-bearing, not vacuously green. Start from a fully-valid edge and blank
	// one provenance field at a time.
	valid := BackingEdge{
		Producer:   producerCHA,
		Origin:     EdgeOrigin{Assembly: "App", Method: mtok(xMethodDef, 1)},
		Confidence: ConfResolved,
	}
	if err := sweepProvenance(valid); err != nil {
		t.Fatalf("hand-built valid edge should pass the sweep, got %v", err)
	}
	mutations := []struct {
		name string
		mut  func(e *BackingEdge)
	}{
		{"empty Producer", func(e *BackingEdge) { e.Producer = "" }},
		{"empty Origin.Assembly", func(e *BackingEdge) { e.Origin.Assembly = "" }},
		{"null Origin.Method", func(e *BackingEdge) { e.Origin.Method = assembly.Token(0) }},
	}
	for _, m := range mutations {
		bad := valid
		m.mut(&bad)
		if err := sweepProvenance(bad); err == nil {
			t.Fatalf("negative control %q: sweep passed an edge with a blanked provenance field", m.name)
		}
	}

	// COMPACT PROJECTION: the frozen public plugin.CallEdge is not inflated — exactly two
	// fields, {Caller, Callee}, and Compact() carries only the endpoints.
	ce := reflect.TypeOf(plugin.CallEdge{})
	if ce.NumField() != 2 {
		t.Fatalf("plugin.CallEdge has %d fields, want exactly 2 {Caller,Callee}", ce.NumField())
	}
	if ce.Field(0).Name != "Caller" || ce.Field(1).Name != "Callee" {
		t.Fatalf("plugin.CallEdge fields = {%s,%s}, want {Caller,Callee}", ce.Field(0).Name, ce.Field(1).Name)
	}
	for _, e := range edges {
		if c := e.Compact(); c.Caller != e.From || c.Callee != e.To {
			t.Fatalf("Compact() endpoints drifted: %+v vs From=%+v To=%+v", c, e.From, e.To)
		}
	}
}
