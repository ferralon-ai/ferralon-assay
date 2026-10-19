package javaanalysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// writeFile writes content to path under a temp tree, creating parents. Test helper.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeCachePOM plants a POM in a fixture m2 repo root at the canonical Maven layout.
func writeCachePOM(t *testing.T, root, g, a, v, content string) {
	t.Helper()
	writeFile(t, filepath.Join(root, pomRelPath(g, a, v)), content)
}

// nbsp is U+00A0, which Go's strings.TrimSpace strips and Java's String.trim keeps.
const nbsp = "\u00a0"

func findNode(t *testing.T, inv jsonInv, purl string) *invNode {
	t.Helper()
	for i := range inv.Nodes {
		if inv.Nodes[i].PURL == purl {
			return &inv.Nodes[i]
		}
	}
	return nil
}

type invNode struct {
	ID         string `json:"id"`
	PURL       string `json:"purl"`
	Version    string `json:"version"`
	Direct     bool   `json:"direct"`
	Membership struct {
		Project string `json:"project"`
		Target  string `json:"target"`
	} `json:"membership"`
	Partiality struct {
		Complete bool     `json:"complete"`
		Reasons  []string `json:"reasons"`
	} `json:"partiality"`
}

type invEdge struct {
	Parent string `json:"parent"`
	Child  string `json:"child"`
}

type jsonInv struct {
	Partiality struct {
		Complete bool     `json:"complete"`
		Reasons  []string `json:"reasons"`
	} `json:"partiality"`
	Nodes []invNode `json:"nodes"`
	Edges []invEdge `json:"edges"`
}

func toJSON(t *testing.T, v interface{}) jsonInv {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out jsonInv
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMaven_DirectLiteral(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>32.1.2-jre</version></dependency></dependencies></project>`)

	inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(t.TempDir()), nil))
	n := findNode(t, inv, "pkg:maven/com.google.guava/guava@32.1.2-jre")
	if n == nil {
		t.Fatalf("missing guava node; got %+v", inv.Nodes)
	}
	if n.Version != "32.1.2-jre" || !n.Direct {
		t.Errorf("guava should be direct/resolved; got %+v", n)
	}
	if n.Membership.Target != "compile" {
		t.Errorf("default scope should be compile; got %q", n.Membership.Target)
	}
}

func TestMaven_PropertyInterpolation(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<properties><guava.version>32.1.2-jre</guava.version></properties>
<dependencies><dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>${guava.version}</version></dependency></dependencies></project>`)

	inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(t.TempDir()), nil))
	if findNode(t, inv, "pkg:maven/com.google.guava/guava@32.1.2-jre") == nil {
		t.Fatalf("property should resolve to a literal; got %+v", inv.Nodes)
	}
}

func TestMaven_DependencyManagementSuppliesVersion(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencyManagement><dependencies><dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>32.1.2-jre</version></dependency></dependencies></dependencyManagement>
<dependencies><dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId></dependency></dependencies></project>`)

	inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(t.TempDir()), nil))
	if findNode(t, inv, "pkg:maven/com.google.guava/guava@32.1.2-jre") == nil {
		t.Fatalf("managed version should be applied; got %+v", inv.Nodes)
	}
}

func TestMaven_TransitiveEdgeFromCache(t *testing.T) {
	dir := t.TempDir()
	m2 := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version></dependency></dependencies></project>`)
	// top depends on leaf; leaf is a childless cached POM.
	writeCachePOM(t, m2, "org.top", "top", "1.0", `<project>
<groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version>
<dependencies><dependency><groupId>org.leaf</groupId><artifactId>leaf</artifactId><version>2.0</version></dependency></dependencies></project>`)
	writeCachePOM(t, m2, "org.leaf", "leaf", "2.0", `<project><groupId>org.leaf</groupId><artifactId>leaf</artifactId><version>2.0</version></project>`)

	inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil))
	top := findNode(t, inv, "pkg:maven/org.top/top@1.0")
	leaf := findNode(t, inv, "pkg:maven/org.leaf/leaf@2.0")
	if top == nil || leaf == nil {
		t.Fatalf("expected top+leaf nodes; got %+v", inv.Nodes)
	}
	if leaf.Direct {
		t.Error("leaf must be transitive (Direct=false)")
	}
	found := false
	for _, e := range inv.Edges {
		if e.Parent == top.ID && e.Child == leaf.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("expected edge top→leaf; got %+v", inv.Edges)
	}
	if !inv.Partiality.Complete {
		t.Errorf("fully-cached graph should be Complete; got %+v", inv.Partiality)
	}
}

func TestMaven_NearestWinsMediation(t *testing.T) {
	dir := t.TempDir()
	m2 := t.TempDir()
	// app → a(1.0) → shared(9.9);  app → shared(1.0) directly (nearest wins: 1.0).
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies>
<dependency><groupId>org.a</groupId><artifactId>a</artifactId><version>1.0</version></dependency>
<dependency><groupId>org.shared</groupId><artifactId>shared</artifactId><version>1.0</version></dependency>
</dependencies></project>`)
	writeCachePOM(t, m2, "org.a", "a", "1.0", `<project><groupId>org.a</groupId><artifactId>a</artifactId><version>1.0</version>
<dependencies><dependency><groupId>org.shared</groupId><artifactId>shared</artifactId><version>9.9</version></dependency></dependencies></project>`)
	writeCachePOM(t, m2, "org.shared", "shared", "1.0", `<project><groupId>org.shared</groupId><artifactId>shared</artifactId><version>1.0</version></project>`)

	inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil))
	if findNode(t, inv, "pkg:maven/org.shared/shared@1.0") == nil {
		t.Errorf("nearest (direct) shared@1.0 must win; got %+v", inv.Nodes)
	}
	if findNode(t, inv, "pkg:maven/org.shared/shared@9.9") != nil {
		t.Errorf("transitive shared@9.9 must lose mediation; got %+v", inv.Nodes)
	}
}

func TestMaven_UncachedSubtreeResidue(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.absent</groupId><artifactId>absent</artifactId><version>1.0</version></dependency></dependencies></project>`)

	inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(t.TempDir()), nil))
	n := findNode(t, inv, "pkg:maven/org.absent/absent@1.0")
	if n == nil {
		t.Fatalf("uncached dep must still be emitted; got %+v", inv.Nodes)
	}
	if !hasStr(n.Partiality.Reasons, reasonMavenUncachedSubtree) {
		t.Errorf("expected maven_uncached_subtree on node; got %+v", n.Partiality)
	}
	if inv.Partiality.Complete {
		t.Error("graph with an uncached subtree must not be Complete")
	}
}

func TestMaven_UnresolvedPropertyIsPresentButUnresolved(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.x</groupId><artifactId>x</artifactId><version>${env.UNKNOWN}</version></dependency></dependencies></project>`)

	inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(t.TempDir()), nil))
	n := findNode(t, inv, "pkg:maven/org.x/x@")
	if n == nil {
		t.Fatalf("unresolved dep must be present-but-unresolved, never dropped; got %+v", inv.Nodes)
	}
	if n.Version != "" {
		t.Errorf("unresolved version must stay empty, never guessed; got %q", n.Version)
	}
	if !hasStr(n.Partiality.Reasons, reasonPropertyUnresolved) {
		t.Errorf("expected property_unresolved; got %+v", n.Partiality)
	}
}

func TestMaven_Deterministic(t *testing.T) {
	dir := t.TempDir()
	m2 := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies>
<dependency><groupId>org.b</groupId><artifactId>b</artifactId><version>1.0</version></dependency>
<dependency><groupId>org.a</groupId><artifactId>a</artifactId><version>1.0</version></dependency>
</dependencies></project>`)
	writeCachePOM(t, m2, "org.a", "a", "1.0", `<project><groupId>org.a</groupId><artifactId>a</artifactId><version>1.0</version></project>`)
	writeCachePOM(t, m2, "org.b", "b", "1.0", `<project><groupId>org.b</groupId><artifactId>b</artifactId><version>1.0</version></project>`)

	var prev string
	for i := 0; i < 3; i++ {
		b, err := json.Marshal(resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil))
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && string(b) != prev {
			t.Fatalf("non-deterministic output across runs:\n%s\n%s", prev, b)
		}
		prev = string(b)
	}
}

func hasStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// A dependency declared with a classifier or a non-jar type names a different file than the
// main JAR. The node says so, and when such a declaration loses mediation to a plain one of
// the same GA, the winner says so too: the build may put both files on the classpath.
func TestMaven_ArtifactVariantIsMarked(t *testing.T) {
	for _, tc := range []struct {
		name, deps string
		variant    bool
	}{
		{"plain jar", `<dependency><groupId>io.netty</groupId><artifactId>netty-transport</artifactId><version>4.1.0</version></dependency>`, false},
		{"classifier", `<dependency><groupId>io.netty</groupId><artifactId>netty-transport</artifactId><version>4.1.0</version><classifier>linux-x86_64</classifier></dependency>`, true},
		{"test-jar type", `<dependency><groupId>io.netty</groupId><artifactId>netty-transport</artifactId><version>4.1.0</version><type>test-jar</type></dependency>`, true},
		{"JAR type, which Maven does not read as jar", `<dependency><groupId>io.netty</groupId><artifactId>netty-transport</artifactId><version>4.1.0</version><type>JAR</type></dependency>`, true},
		{"losing classifier declaration", `<dependency><groupId>io.netty</groupId><artifactId>netty-transport</artifactId><version>4.1.0</version></dependency>
<dependency><groupId>io.netty</groupId><artifactId>netty-transport</artifactId><version>4.1.0</version><classifier>linux-x86_64</classifier></dependency>`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies>`+tc.deps+`</dependencies></project>`)
			inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(t.TempDir()), nil))
			n := findNode(t, inv, "pkg:maven/io.netty/netty-transport@4.1.0")
			if n == nil {
				t.Fatalf("missing node; got %+v", inv.Nodes)
			}
			if got := slices.Contains(n.Partiality.Reasons, reasonMavenArtifactVariant); got != tc.variant {
				t.Errorf("variant reason on node = %v, want %v (%+v)", got, tc.variant, n.Partiality)
			}
		})
	}
}

// A transitive declaration of another file of an already-selected GA loses mediation but can
// still reach the classpath, so the winning node is marked.
func TestMaven_LosingTransitiveVariantMarksWinner(t *testing.T) {
	dir := t.TempDir()
	m2 := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies>
<dependency><groupId>io.netty</groupId><artifactId>netty-transport</artifactId><version>4.1.0</version></dependency>
<dependency><groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version></dependency>
</dependencies></project>`)
	writeCachePOM(t, m2, "org.top", "top", "1.0", `<project>
<groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version>
<dependencies><dependency><groupId>io.netty</groupId><artifactId>netty-transport</artifactId><version>4.1.0</version><classifier>linux-x86_64</classifier></dependency></dependencies></project>`)
	writeCachePOM(t, m2, "io.netty", "netty-transport", "4.1.0", `<project><groupId>io.netty</groupId><artifactId>netty-transport</artifactId><version>4.1.0</version></project>`)

	inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil))
	n := findNode(t, inv, "pkg:maven/io.netty/netty-transport@4.1.0")
	if n == nil || !slices.Contains(n.Partiality.Reasons, reasonMavenArtifactVariant) {
		t.Errorf("winner not marked: %+v", n)
	}
	// The package is in the inventory either way; a graph-level reason would block every
	// not_exploitable of the ecosystem for what is a byte-binding concern.
	if slices.Contains(inv.Partiality.Reasons, reasonMavenArtifactVariant) {
		t.Errorf("variant raised to a graph limit: %v", inv.Partiality.Reasons)
	}
}

// A dependency whose scope is none in Maven's scope table, a "test" padded with a no-break space
// among them, is on the graph but its subtree isn't modelled, so the inventory isn't Complete.
func TestMaven_UnmodelledScopeResidue(t *testing.T) {
	for _, tt := range []struct {
		name, scope string
		complete    bool
	}{
		{"test padded with a no-break space", nbsp + "test", false},
		{"a scope Maven doesn't name", "bogus", false},
		{"control, test", "test", true},
		{"control, runtime", "runtime", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir, m2 := t.TempDir(), t.TempDir()
			writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.x</groupId><artifactId>x</artifactId><version>1.0</version><scope>`+tt.scope+`</scope></dependency></dependencies></project>`)
			writeCachePOM(t, m2, "org.x", "x", "1.0", `<project><groupId>org.x</groupId><artifactId>x</artifactId><version>1.0</version>
<dependencies><dependency><groupId>org.y</groupId><artifactId>y</artifactId><version>1.0</version></dependency></dependencies></project>`)
			writeCachePOM(t, m2, "org.y", "y", "1.0", `<project><groupId>org.y</groupId><artifactId>y</artifactId><version>1.0</version></project>`)
			inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil))
			if findNode(t, inv, "pkg:maven/org.x/x@1.0") == nil {
				t.Fatalf("org.x must be on the graph; got %+v", inv.Nodes)
			}
			if inv.Partiality.Complete != tt.complete {
				t.Errorf("complete = %v, want %v; got %+v", inv.Partiality.Complete, tt.complete, inv.Partiality)
			}
			if got := hasStr(inv.Partiality.Reasons, reasonMavenUnmodelledScope); got == tt.complete {
				t.Errorf("maven_unmodelled_scope listed = %v; got %+v", got, inv.Partiality)
			}
		})
	}
}

// Maven compares scope names exactly (ScopeDependencySelector, DefaultModelBuilder's import
// test), so a transitive "Test" or "Provided" stays on the graph and an "Import" BOM is not
// imported. The reader must not fold case and call the inventory complete.
func TestMaven_ScopeIsCaseSensitive(t *testing.T) {
	for _, tc := range []struct {
		name, scope string
		kept        bool // org.t:t is on the graph
		complete    bool
	}{
		{"transitive Test", "Test", true, false},
		{"transitive Provided", "Provided", true, false},
		{"control, transitive test", "test", false, true},
		{"control, transitive provided", "provided", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, m2 := t.TempDir(), t.TempDir()
			writeFile(t, filepath.Join(dir, "pom.xml"), `<project><groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.x</groupId><artifactId>x</artifactId><version>1</version></dependency></dependencies></project>`)
			writeCachePOM(t, m2, "org.x", "x", "1", `<project><groupId>org.x</groupId><artifactId>x</artifactId><version>1</version>
<dependencies><dependency><groupId>org.t</groupId><artifactId>t</artifactId><version>1.0</version><scope>`+tc.scope+`</scope></dependency></dependencies></project>`)
			writeCachePOM(t, m2, "org.t", "t", "1.0", `<project><groupId>org.t</groupId><artifactId>t</artifactId><version>1.0</version></project>`)
			inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), map[string]string{}))
			n := findNode(t, inv, "pkg:maven/org.t/t@1.0")
			if (n != nil) != tc.kept {
				t.Fatalf("org.t:t on graph = %v, want %v; got %+v", n != nil, tc.kept, inv.Nodes)
			}
			if inv.Partiality.Complete != tc.complete {
				t.Errorf("complete = %v, want %v; got %+v", inv.Partiality.Complete, tc.complete, inv.Partiality)
			}
			if tc.kept && !hasStr(n.Partiality.Reasons, reasonMavenUnmodelledScope) {
				t.Errorf("org.t:t lacks %s; got %+v", reasonMavenUnmodelledScope, n.Partiality)
			}
		})
	}

	for _, tc := range []struct {
		name, scope string
		imported    bool
	}{
		{"Import BOM", "Import", false},
		{"control, import BOM", "import", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, m2 := t.TempDir(), t.TempDir()
			writeFile(t, filepath.Join(dir, "pom.xml"), `<project><groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencyManagement><dependencies><dependency><groupId>org.b</groupId><artifactId>bom</artifactId><version>1</version><type>pom</type><scope>`+tc.scope+`</scope></dependency></dependencies></dependencyManagement>
<dependencies><dependency><groupId>org.t</groupId><artifactId>t</artifactId></dependency></dependencies></project>`)
			writeCachePOM(t, m2, "org.b", "bom", "1", `<project><groupId>org.b</groupId><artifactId>bom</artifactId><version>1</version><packaging>pom</packaging>
<dependencyManagement><dependencies><dependency><groupId>org.t</groupId><artifactId>t</artifactId><version>2.0</version></dependency></dependencies></dependencyManagement></project>`)
			writeCachePOM(t, m2, "org.t", "t", "2.0", `<project><groupId>org.t</groupId><artifactId>t</artifactId><version>2.0</version></project>`)
			inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), map[string]string{}))
			if got := findNode(t, inv, "pkg:maven/org.t/t@2.0") != nil; got != tc.imported {
				t.Errorf("org.t:t@2.0 from the BOM = %v, want %v; got %+v", got, tc.imported, inv.Nodes)
			}
			if inv.Partiality.Complete != tc.imported {
				t.Errorf("complete = %v, want %v; got %+v", inv.Partiality.Complete, tc.imported, inv.Partiality)
			}
		})
	}
}
