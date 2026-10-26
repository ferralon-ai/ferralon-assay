package javaanalysis

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
)

// The bound for an unloaded JAR is everything the build resolved in each module that holds it,
// plus first-party code: the graph is the build's whole resolved closure, so no other code can
// sit behind the JAR's calls.
func TestBlindSpotTargets(t *testing.T) {
	dep := func(a, v string) graphDep {
		return graphDep{group: "org.t", artifact: a, version: v, jar: "/nonexistent/" + a + ".jar"}
	}
	graph := func(modules ...buildgraph.Module) *buildgraph.Graph { return &buildgraph.Graph{Modules: modules} }
	for _, tc := range []struct {
		name  string
		g     *buildgraph.Graph
		coord string
		want  []string
	}{
		{
			name:  "one module holds it",
			g:     graph(testModule(t, ".", "app", dep("a", "1"), dep("b", "2"))),
			coord: "org.t:a",
			want:  []string{"", "pkg:maven/org.t/a", "pkg:maven/org.t/b"},
		},
		{
			name: "modules that hold it are unioned, others left out",
			g: graph(
				testModule(t, "x", "x", dep("a", "1"), dep("b", "1")),
				testModule(t, "y", "y", dep("a", "2"), dep("c", "1")),
				testModule(t, "z", "z", dep("d", "1")),
			),
			coord: "org.t:a",
			want:  []string{"", "pkg:maven/org.t/a", "pkg:maven/org.t/b", "pkg:maven/org.t/c"},
		},
		{
			name:  "not in the graph",
			g:     graph(testModule(t, ".", "app", dep("a", "1"))),
			coord: "org.t:nope",
			want:  nil,
		},
		{
			// A module's own root is first-party source, not a dependency JAR.
			name:  "module root only",
			g:     graph(testModule(t, ".", "app", dep("a", "1"))),
			coord: "com.example:app",
			want:  nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := BlindSpotTargets(tc.g, tc.coord)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("targets = %q, want %q", got, tc.want)
			}
			// The callback edge: a bounded set without first-party code would let an unloaded
			// JAR's calls into the build's own objects go unseen.
			if got != nil && !slices.Contains(got, "") {
				t.Errorf("bounded targets omit first-party (\"\"): %q", got)
			}
			for _, g := range got {
				if strings.Contains(g, "@") {
					t.Errorf("target %q carries a version", g)
				}
			}
		})
	}
}
