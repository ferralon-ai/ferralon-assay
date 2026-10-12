package javaanalysis

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// closureFixture is a build whose first-party code depends directly on org.t:a and org.t:d.
// The inventory has a depending on org.t:b and org.t:j, though a's POM names only j (the
// inventory's edges count even where the POM chain does not show them); j's own POM declares
// an optional org.t:x, which Maven leaves out of the inventory. poms maps each artifact to its
// POM's dependency XML.
var closureFixture = struct {
	direct map[string]bool
	edges  map[string][]string
	poms   map[string]string
}{
	direct: map[string]bool{"a": true, "d": true},
	edges:  map[string][]string{"a": {"b", "j"}},
	poms: map[string]string{
		"a": `<dependency><groupId>org.t</groupId><artifactId>j</artifactId><version>1</version></dependency>`,
		"b": ``,
		"d": ``,
		"j": `<dependency><groupId>org.t</groupId><artifactId>x</artifactId><version>1</version><optional>true</optional></dependency>`,
	},
}

// buildClosureFixture writes the fixture's POMs into a fresh repository, leaving out the
// artifacts named in uncached, and returns the inventory and a cache over that repository.
func buildClosureFixture(t *testing.T, uncached ...string) (inventoryIndex, *mavenCache) {
	t.Helper()
	repo := t.TempDir()
	var inv plugin.DependencyInventory
	id := func(a string) string { return "|compile|pkg:maven/org.t/" + a + "@1" }
	for a, deps := range closureFixture.poms {
		inv.Nodes = append(inv.Nodes, plugin.DependencyNode{
			ID: id(a), PURL: "pkg:maven/org.t/" + a + "@1", Version: "1", Direct: closureFixture.direct[a],
			Provenance: plugin.DependencyProvenance{Resolver: "maven-effective"},
		})
		if slices.Contains(uncached, a) {
			continue
		}
		pom := `<project><modelVersion>4.0.0</modelVersion><groupId>org.t</groupId><artifactId>` + a +
			`</artifactId><version>1</version><dependencies>` + deps + `</dependencies></project>`
		p := filepath.Join(repo, pomRelPath("org.t", a, "1"))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(pom), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for parent, children := range closureFixture.edges {
		for _, c := range children {
			inv.Edges = append(inv.Edges, plugin.DependencyEdge{Parent: id(parent), Child: id(c)})
		}
	}
	return indexInventory(inv), newMavenCacheAt(repo)
}

// The bound for an unloaded JAR J is J, J's closure, "" and the closure of first-party code;
// anything that keeps one of those closures from being read in full leaves it unbounded.
func TestUnloadedJarTargets(t *testing.T) {
	full := []string{"", "pkg:maven/org.t/a", "pkg:maven/org.t/b", "pkg:maven/org.t/d", "pkg:maven/org.t/j", "pkg:maven/org.t/x"}
	for _, tc := range []struct {
		name     string
		jar      string
		uncached []string
		want     []string
	}{
		{name: "transitive jar, closure known", jar: "org.t:j", want: full},
		{name: "direct jar, closure known", jar: "org.t:d", want: full},
		{name: "jar metadata uncached", jar: "org.t:j", uncached: []string{"j"}, want: nil},
		{name: "first-party closure metadata uncached", jar: "org.t:j", uncached: []string{"d"}, want: nil},
		{name: "jar not in the inventory", jar: "org.t:nope", want: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ix, cache := buildClosureFixture(t, tc.uncached...)
			got := unloadedJarTargets(ix, cache, tc.jar)
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
