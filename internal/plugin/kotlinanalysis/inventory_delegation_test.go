package kotlinanalysis

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// inventory_delegation_test.go — C6 (Kotlin ResolveInventory delegation). Whole-graph dependency
// inventory is read from the build's resolved on-disk state (reactor POMs + a project-local .m2 POM
// cache), which is JVM-generic, not Java-source-specific. The Kotlin lane MUST delegate to
// javaanalysis with no duplicated resolution logic; this test proves the two lanes return the
// byte-identical inventory over the same JVM project, driven through the REAL resolver (no
// hand-built structs, no kotlinc/mvn/gradle/docker, no network — §3.3).

// TestResolveInventory_DelegatesToJavaAnalysis builds a small Maven project with a transitive edge
// resolved from a hermetic project-local .m2 cache, then asserts kotlinanalysis.ResolveInventory ==
// javaanalysis.ResolveInventory over it (C6): the Kotlin lane is a pure delegation.
func TestResolveInventory_DelegatesToJavaAnalysis(t *testing.T) {
	dir := t.TempDir()
	writeBuildFile(t, dir, "pom.xml", `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version></dependency></dependencies></project>`)

	// Hermetic project-local .m2 cache (newMavenCache prefers <buildDir>/.m2/repository over ~/.m2),
	// so resolution never depends on the ambient user cache: top → leaf, leaf childless.
	m2 := filepath.Join(dir, ".m2", "repository")
	writeCachePOM(t, m2, "org.top", "top", "1.0", `<project>
<groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version>
<dependencies><dependency><groupId>org.leaf</groupId><artifactId>leaf</artifactId><version>2.0</version></dependency></dependencies></project>`)
	writeCachePOM(t, m2, "org.leaf", "leaf", "2.0", `<project><groupId>org.leaf</groupId><artifactId>leaf</artifactId><version>2.0</version></project>`)

	req := plugin.ResolveInventoryRequest{BuildDir: dir}
	kotlinInv, kerr := ResolveInventory(context.Background(), req)
	javaInv, jerr := javaanalysis.ResolveInventory(context.Background(), req)
	if kerr != nil || jerr != nil {
		t.Fatalf("ResolveInventory errors: kotlin=%v java=%v", kerr, jerr)
	}
	// Non-vacuous: the fixture actually resolves a two-node graph with one edge.
	if len(javaInv.Nodes) != 2 || len(javaInv.Edges) != 1 {
		t.Fatalf("fixture did not resolve as expected: nodes=%d edges=%d", len(javaInv.Nodes), len(javaInv.Edges))
	}
	if !reflect.DeepEqual(kotlinInv, javaInv) {
		t.Errorf("C6: kotlinanalysis.ResolveInventory must equal javaanalysis.ResolveInventory (pure delegation)\n kotlin=%+v\n java=%+v", kotlinInv, javaInv)
	}
}

// writeCachePOM plants a POM under a project-local .m2 repository at the canonical Maven layout.
func writeCachePOM(t *testing.T, root, g, a, v, content string) {
	t.Helper()
	path := filepath.Join(root, pathFromGroup(g), a, v, a+"-"+v+".pom")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func pathFromGroup(g string) string {
	out := ""
	for _, part := range splitDots(g) {
		out = filepath.Join(out, part)
	}
	return out
}

func splitDots(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '.' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	return append(out, cur)
}
