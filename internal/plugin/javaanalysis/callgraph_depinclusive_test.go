package javaanalysis

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// withFirstPartySource drops a minimal first-party .java file into build so
// CallGraph's loadProgram (which requires ≥1 source) runs — mirroring a real build
// that always has first-party code alongside its cached dependencies.
func withFirstPartySource(t *testing.T, build, rel, src string) {
	t.Helper()
	p := filepath.Join(build, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestCallGraph_DependencyInclusive_HasOpenedJarEdges proves PLAN-344 (d): once a
// declared dependency is cached and opened, CallGraph's edge set includes the
// dependency closure's own call edges (jvmref scheme), not just first-party source
// edges. This is the evidence the persisted graph carries that the dependency
// bytecode was actually parsed and searched — the signal analysisDidNotRun's
// empty-graph arm reads to tell a searched-negative (not_exploitable) apart from an
// analysis that never ran (undetermined).
func TestCallGraph_DependencyInclusive_HasOpenedJarEdges(t *testing.T) {
	build := buildNetkitFixture(t, false) // pom declares netkit + cached netkit-1.0.0.jar
	withFirstPartySource(t, build, "src/com/acme/app/App.java", `package com.acme.app;
public final class App {
    public static void main(String[] args) { System.out.println("ready"); }
}`)

	cg, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: build})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}

	// netkit's UrlFetcher.entry() calls fetch(): that dependency edge must appear.
	wantCaller := "jvmref com/evil/netkit/UrlFetcher#entry()V"
	wantCallee := "jvmref com/evil/netkit/UrlFetcher#fetch(Ljava/lang/String;)Ljava/lang/String;"
	var found bool
	for _, e := range cg.Edges {
		if e.Caller.SCIP == wantCaller && e.Callee.SCIP == wantCallee {
			found = true
		}
		// A dependency edge must never masquerade as a first-party source id.
		if strings.HasPrefix(e.Caller.SCIP, "jvmref ") != strings.HasPrefix(e.Callee.SCIP, "jvmref ") {
			t.Errorf("mixed-scheme edge (crossing must be a hazard, not a fabricated edge): %+v", e)
		}
	}
	if !found {
		t.Fatalf("dependency edge %q -> %q not in call graph; edges=%v", wantCaller, wantCallee, cg.Edges)
	}
	if len(cg.Edges) == 0 {
		t.Fatal("dependency-inclusive call graph must be non-empty when a JAR was opened")
	}
}

// TestReachability_FirstPartyDeadSink_WithOpenedDependency reproduces the SSRF-0002
// shape at the analyzer layer: a first-party sink present but dead (no ingress calls
// it; the program's only first-party entry does something else), in a build whose
// declared dependency IS cached and opened. It proves the real analyzer produces
// exactly the two inputs the not_exploitable verdict rests on — a call graph that is
// NON-EMPTY (the opened dependency closure supplies edges, even though the first-party
// code has no internal edges of its own) and NO reaching path to the sink. Before
// (d.2) the first-party-only graph was empty here and the honest verdict was forced to
// undetermined; the opened dependency is what turns the empty path set into a
// searched-negative.
func TestReachability_FirstPartyDeadSink_WithOpenedDependency(t *testing.T) {
	build := buildNetkitFixture(t, false) // pom declares netkit + cached netkit-1.0.0.jar
	withFirstPartySource(t, build, "src/com/acme/app/App.java", `package com.acme.app;
public final class App {
    public static void main(String[] args) { System.out.println("ready"); }
    public static int fetch(String target) { return target.length(); }
}`)

	cg, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: build})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if len(cg.Edges) == 0 {
		t.Fatal("SSRF-0002 shape: first-party has no internal edges, so the graph is non-empty ONLY via the opened dependency — got 0 edges")
	}

	sink := methodSCIP("com.acme.app", []string{"App"}, "fetch", 1)
	reach, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: build, Symbols: []string{sink}})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(reach.Paths) != 0 {
		t.Fatalf("dead first-party sink must have no reaching path, got %+v", reach.Paths)
	}
}

// TestCallGraph_NoDependencies_IsUnchanged is the insulation guard: a source-only
// build dir with no resolvable/cached dependencies contributes no dependency edges,
// so CallGraph is byte-for-byte what it was before the augmentation. This is why the
// dep-inclusive change carries zero blast radius for every existing first-party test
// (none cache a JAR) — and why a first-party verdict is never contaminated by the
// dependency machinery.
func TestCallGraph_NoDependencies_IsUnchanged(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"web/Only.java": `package com.example.web;
public class Only {
    static void a() { b(); }
    static void b() {}
}`,
	})

	cg, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	for _, e := range cg.Edges {
		if strings.HasPrefix(e.Caller.SCIP, "jvmref ") || strings.HasPrefix(e.Callee.SCIP, "jvmref ") {
			t.Errorf("no-dependency build must carry no jvmref (dependency) edges, got %+v", e)
		}
	}
}
