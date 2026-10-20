package kotlinanalysis

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// inventory_delegation_test.go — C6 (Kotlin ResolveInventory delegation). The dependency
// inventory is read from the build tool's resolved graph, which is JVM-generic, not
// Java-source-specific. The Kotlin lane MUST delegate to javaanalysis with no duplicated
// resolution logic; this test proves the two lanes return the byte-identical inventory over the
// same graph.

// TestResolveInventory_DelegatesToJavaAnalysis hands both lanes one graph with a transitive edge
// (app → top → leaf) and asserts kotlinanalysis.ResolveInventory == javaanalysis.ResolveInventory
// over it (C6): the Kotlin lane is a pure delegation.
func TestResolveInventory_DelegatesToJavaAnalysis(t *testing.T) {
	dir := t.TempDir()
	jar := filepath.Join(t.TempDir(), "x.jar")
	if err := os.WriteFile(jar, []byte("jar"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := graphModule(".", "app",
		graphDep{group: "org.top", artifact: "top", version: "1.0", jar: jar},
		graphDep{group: "org.leaf", artifact: "leaf", version: "2.0", jar: jar})
	m.Edges = []buildgraph.Edge{{From: m.Root, To: m.Nodes[1].ID}, {From: m.Nodes[1].ID, To: m.Nodes[2].ID}}
	graph := graphOption(t, m)

	req := plugin.ResolveInventoryRequest{BuildDir: dir}
	kotlinInv, kerr := ResolveInventory(context.Background(), req, graph)
	javaInv, jerr := javaanalysis.ResolveInventory(context.Background(), req, graph)
	if kerr != nil || jerr != nil {
		t.Fatalf("ResolveInventory errors: kotlin=%v java=%v", kerr, jerr)
	}
	// Non-vacuous: the graph actually yields nodes and the transitive edge.
	if len(javaInv.Nodes) < 2 || len(javaInv.Edges) < 1 || !javaInv.Partiality.Complete {
		t.Fatalf("fixture did not resolve as expected: %+v", javaInv)
	}
	if !reflect.DeepEqual(kotlinInv, javaInv) {
		t.Errorf("C6: kotlinanalysis.ResolveInventory must equal javaanalysis.ResolveInventory (pure delegation)\n kotlin=%+v\n java=%+v", kotlinInv, javaInv)
	}
}
