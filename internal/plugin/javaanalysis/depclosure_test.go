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
	return buildClosureFixtureWith(t, closureVariant{uncached: uncached})
}

// closureVariant alters the fixture: uncached artifacts get no POM, resolver overrides a node's
// Provenance.Resolver, and project replaces the XML between an artifact's <version>1</version>
// and </project> (parent, dependencies, properties).
type closureVariant struct {
	uncached []string
	resolver map[string]string
	project  map[string]string
}

func buildClosureFixtureWith(t *testing.T, v closureVariant) (inventoryIndex, *mavenCache) {
	t.Helper()
	uncached := v.uncached
	repo := t.TempDir()
	var inv plugin.DependencyInventory
	id := func(a string) string { return "|compile|pkg:maven/org.t/" + a + "@1" }
	for a, deps := range closureFixture.poms {
		inv.Nodes = append(inv.Nodes, plugin.DependencyNode{
			ID: id(a), PURL: "pkg:maven/org.t/" + a + "@1", Version: "1", Direct: closureFixture.direct[a],
			Provenance: plugin.DependencyProvenance{Resolver: "maven-effective"},
		})
		if r, ok := v.resolver[a]; ok {
			inv.Nodes[len(inv.Nodes)-1].Provenance.Resolver = r
		}
		if slices.Contains(uncached, a) {
			continue
		}
		body := `<dependencies>` + deps + `</dependencies>`
		if b, ok := v.project[a]; ok {
			body = b
		}
		pom := `<project><modelVersion>4.0.0</modelVersion><groupId>org.t</groupId><artifactId>` + a +
			`</artifactId><version>1</version>` + body + `</project>`
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
		resolver map[string]string
		project  map[string]string
		want     []string
	}{
		{name: "transitive jar, closure known", jar: "org.t:j", want: full},
		{name: "direct jar, closure known", jar: "org.t:d", want: full},
		{name: "jar metadata uncached", jar: "org.t:j", uncached: []string{"j"}, want: nil},
		{name: "first-party closure metadata uncached", jar: "org.t:j", uncached: []string{"d"}, want: nil},
		{name: "jar not in the inventory", jar: "org.t:nope", want: nil},
		// Gradle's variant-aware resolution can select dependencies the POMs don't declare, so a
		// Gradle-resolved node's closure isn't read from POMs even when they're cached.
		{name: "gradle-resolved node in the closure", jar: "org.t:j", resolver: map[string]string{"j": "gradle-lockfile"}, want: nil},
		// A parent can declare dependencies; a chain that stops early under-reads.
		{name: "parent pom missing", jar: "org.t:j", project: map[string]string{
			"j": `<parent><groupId>org.t</groupId><artifactId>gone</artifactId><version>1</version></parent>`,
		}, want: nil},
		{name: "uninterpolable coordinate", jar: "org.t:j", project: map[string]string{
			"j": `<dependencies><dependency><groupId>org.t</groupId><artifactId>${undefined}</artifactId><version>1</version></dependency></dependencies>`,
		}, want: nil},
		{name: "interpolated coordinate", jar: "org.t:j", project: map[string]string{
			"j": `<properties><x.name>x</x.name></properties><dependencies><dependency><groupId>${project.groupId}</groupId><artifactId>${x.name}</artifactId><version>1</version></dependency></dependencies>`,
		}, want: full},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ix, cache := buildClosureFixtureWith(t, closureVariant{uncached: tc.uncached, resolver: tc.resolver, project: tc.project})
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
