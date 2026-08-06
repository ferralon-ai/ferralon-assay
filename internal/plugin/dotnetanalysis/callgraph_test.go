package dotnetanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func hasEdge(edges []plugin.CallEdge, caller, callee string) bool {
	for _, e := range edges {
		if e.Caller == caller && e.Callee == callee {
			return true
		}
	}
	return false
}

func hasReason(p plugin.Partiality, reason string) bool {
	for _, r := range p.Reasons {
		if r == reason {
			return true
		}
	}
	return false
}

// controllerApp is the canonical ASP.NET Core chain: a controller action (marked by an
// [HttpGet] attribute) calls a utility that calls the sink — Handle → Fetch → OpenConn.
// Every callee is unique by (name, arity) so the source-lexical resolver connects each edge.
const controllerApp = `
using Microsoft.AspNetCore.Mvc;

namespace Acme.Web
{
    [ApiController]
    [Route("api/[controller]")]
    public class FetchController : ControllerBase
    {
        [HttpGet]
        public string Handle(string target)
        {
            return Fetch(target);
        }

        private string Fetch(string target)
        {
            return OpenConn(target);
        }

        private string OpenConn(string url)
        {
            return url;
        }
    }
}
`

func TestCallGraph_ControllerChainEdgesResolve(t *testing.T) {
	dir := writeTree(t, map[string]string{"FetchController.cs": controllerApp})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	handle := funcSCIP("Acme.Web", []string{"FetchController"}, "Handle", 1)
	fetch := funcSCIP("Acme.Web", []string{"FetchController"}, "Fetch", 1)
	openConn := funcSCIP("Acme.Web", []string{"FetchController"}, "OpenConn", 1)

	for _, want := range [][2]string{{handle, fetch}, {fetch, openConn}} {
		if !hasEdge(res.Edges, want[0], want[1]) {
			t.Errorf("missing edge %s -> %s\nedges: %+v", want[0], want[1], res.Edges)
		}
	}
	// A lexical C# call graph is ALWAYS declared Partial (interface/virtual/DI dispatch).
	if res.Partiality.Complete {
		t.Error("C# call graph must never be Complete (structurally weak; dynamic dispatch)")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonDynamicDispatch) {
		t.Errorf("call graph must carry standing dynamic_dispatch reason; got %+v", res.Partiality)
	}
}

// The [HttpGet] controller action must be registered as a call-graph root so the reverse BFS
// can terminate at it even when nothing in the source invokes it.
func TestCallGraph_ControllerActionIsRoot(t *testing.T) {
	dir := writeTree(t, map[string]string{"FetchController.cs": controllerApp})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	handle := funcSCIP("Acme.Web", []string{"FetchController"}, "Handle", 1)
	found := false
	for _, r := range res.Roots {
		if r == handle {
			found = true
		}
	}
	if !found {
		t.Errorf("controller action Handle not registered as a call-graph root; roots=%v", res.Roots)
	}
}

// Control-flow keywords look like "word(" but must NOT become call edges; the real calls
// Cond()/Loop()/Pick() must.
func TestCallGraph_ControlFlowKeywordsAreNotEdges(t *testing.T) {
	src := `
namespace C
{
    public class Runner
    {
        public void Run()
        {
            if (Cond())
            {
                while (Loop())
                {
                    return;
                }
            }
            foreach (var x in Pick())
            {
            }
        }

        public bool Cond() { return true; }
        public bool Loop() { return false; }
        public int[] Pick() { return null; }
    }
}
`
	dir := writeTree(t, map[string]string{"c.cs": src})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	run := funcSCIP("C", []string{"Runner"}, "Run", 0)
	cond := funcSCIP("C", []string{"Runner"}, "Cond", 0)
	loop := funcSCIP("C", []string{"Runner"}, "Loop", 0)
	pick := funcSCIP("C", []string{"Runner"}, "Pick", 0)
	if !hasEdge(res.Edges, run, cond) || !hasEdge(res.Edges, run, loop) || !hasEdge(res.Edges, run, pick) {
		t.Errorf("expected Run->Cond, Run->Loop, Run->Pick edges; edges=%+v", res.Edges)
	}
	for _, e := range res.Edges {
		if e.Caller == "" || e.Callee == "" {
			t.Errorf("empty endpoint in edge %+v", e)
		}
	}
}

// A constructor call ("new ZipEntry(x)") resolves to the constructor declaration (indexed as
// a method under the type name), so an attacker path through construction is captured.
func TestCallGraph_ConstructorCallResolves(t *testing.T) {
	src := `
namespace Acme
{
    public class Factory
    {
        public Widget Build()
        {
            return new Widget(1);
        }
    }

    public class Widget
    {
        public Widget(int seed) { }
    }
}
`
	dir := writeTree(t, map[string]string{"f.cs": src})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	build := funcSCIP("Acme", []string{"Factory"}, "Build", 0)
	ctor := funcSCIP("Acme", []string{"Widget"}, "Widget", 1)
	if !hasEdge(res.Edges, build, ctor) {
		t.Errorf("expected Build -> Widget ctor edge; edges=%+v", res.Edges)
	}
}

// inv.5 honesty test: when a callee's (name, arity) matches MORE THAN ONE declared method
// (two classes each declare Process(1)), the resolver cannot soundly pick one, so it
// fabricates NO edge.
func TestCallGraph_AmbiguousCalleeDoesNotFabricateEdge(t *testing.T) {
	a := `
namespace A
{
    public class Entry
    {
        public void Go(int x) { Process(x); }
    }
}
`
	b := `
namespace B
{
    public class One { public void Process(int x) { Sink(); } public void Sink() { } }
}
`
	c := `
namespace C
{
    public class Two { public void Process(int x) { } }
}
`
	dir := writeTree(t, map[string]string{"a.cs": a, "b.cs": b, "c.cs": c})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if !hasReason(res.Partiality, plugin.PartialReasonDynamicDispatch) {
		t.Errorf("ambiguous callee must carry dynamic_dispatch reason, got %+v", res.Partiality)
	}
	entry := funcSCIP("A", []string{"Entry"}, "Go", 1)
	for _, e := range res.Edges {
		if e.Caller == entry {
			t.Errorf("ambiguous call fabricated an edge from entry: %+v", e)
		}
	}
}

func TestCallGraph_UnknownCalleeIsPartialNoEdge(t *testing.T) {
	src := `
namespace C
{
    public class Runner
    {
        public void Run() { ExternalLibraryCall(1, 2); }
    }
}
`
	dir := writeTree(t, map[string]string{"c.cs": src})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if res.Partiality.Complete {
		t.Error("unknown callee must declare partiality")
	}
	if len(res.Edges) != 0 {
		t.Errorf("unknown callee must not fabricate any edge; got %+v", res.Edges)
	}
}

func TestCallGraph_MissingBuildDirIsHardError(t *testing.T) {
	_, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: "testdata/does-not-exist"})
	if err == nil {
		t.Fatal("expected a hard error for a nonexistent build dir")
	}
}
