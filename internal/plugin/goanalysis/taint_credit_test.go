// Hermetic goanalysis tests for which ingress a taint path credits (taint_ssa.go,
// taint.go): with several ingresses reaching one sink the credit must not depend on map
// iteration order. They build taintcreditmod in memory, as taint_flow_test.go does
// taintflowmod.
package goanalysis

import (
	"go/types"
	"slices"
	"testing"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// creditRuns is how many times a test repeats an analysis whose result once depended on
// map iteration order. Before the sort, fifty runs of runTaint split the credit between
// the three handlers every time (A/B/C 8/4/38, 6/6/38 and 4/6/40 in three tries).
const creditRuns = 50

// TestRunTaint_CreditIsDeterministic is the three-handlers-one-sink shape: every
// handler's taint reaches the sink through helper and helper2, and the sink is credited
// to handlerA on every run. handlerA is first by name, while handlerC is first in the
// source, so the order is the name order and not the position.
func TestRunTaint_CreditIsDeterministic(t *testing.T) {
	app := buildTaintModule(t, "tegron.test/taintcreditmod", "testdata/taintcreditmod/main.go")
	sp := &ssaProgram{prog: app.Prog}
	ingresses := map[string]*ssa.Function{}
	var ids []string
	for _, name := range []string{"handlerA", "handlerB", "handlerC"} {
		id := sp.scipFunc(app.Func(name))
		ingresses[id] = app.Func(name)
		ids = append(ids, id)
	}
	if got := sp.ingressOrder(ingresses); !slices.Equal(got, ids) {
		t.Fatalf("ingressOrder = %q, want %q (package path, then full name)", got, ids)
	}
	sink := sp.scipFunc(app.Func("sink"))

	credited := map[string]int{}
	for range creditRuns {
		paths, _ := runTaint(sp, ingresses, map[string]bool{sink: true})
		if len(paths) != 1 {
			t.Fatalf("paths = %+v, want one path to the sink", paths)
		}
		credited[paths[0].Ingress.SCIP]++
	}
	if credited[ids[0]] != creditRuns {
		t.Errorf("credit over %d runs = %v, want handlerA (%s) on every run", creditRuns, credited, ids[0])
	}
}

// TestResolveIngressFuncs_PrefersDeclaredFunc: Server.Handle and its synthetic
// (*Server).Handle wrapper share one SCIP id, and the id resolves to the declared method
// on every run, never to whichever the function map yielded last.
func TestResolveIngressFuncs_PrefersDeclaredFunc(t *testing.T) {
	app := buildTaintModule(t, "tegron.test/taintcreditmod", "testdata/taintcreditmod/main.go")
	sp := &ssaProgram{prog: app.Prog}
	declared := app.Prog.FuncValue(app.Pkg.Scope().Lookup("Server").Type().(*types.Named).Method(0))
	id := sp.scipFunc(declared)
	var sharing []string
	for fn := range ssautil.AllFunctions(app.Prog) {
		if fn != declared && fn.Blocks != nil && sp.scipFunc(fn) == id {
			sharing = append(sharing, fn.String())
		}
	}
	if len(sharing) == 0 {
		t.Fatalf("no other built function shares %s: the fixture no longer has the collision", id)
	}

	for range creditRuns {
		got := sp.resolveIngressFuncs([]plugin.Ingress{{Kind: "handler", Symbol: sym(id)}})
		if got[id] != declared {
			t.Fatalf("%s resolved to %v, want the declared %v (also sharing it: %q)", id, got[id], declared, sharing)
		}
	}
}
