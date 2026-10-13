package javaanalysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeGradleCachePOM plants a POM under a fixture modules-2/files-2.1 tree (with the content-hash
// dir Gradle uses).
func writeGradleCachePOM(t *testing.T, root, g, a, v, content string) {
	t.Helper()
	writeFile(t, filepath.Join(root, g, a, v, "deadbeef", a+"-"+v+".pom"), content)
}

func TestGradle_LockfileJoinEdges(t *testing.T) {
	dir := t.TempDir()
	cacheRoot := t.TempDir()
	writeFile(t, filepath.Join(dir, "build.gradle"), "dependencies {\n    implementation 'org.top:top:1.0'\n}\n")
	writeFile(t, filepath.Join(dir, "gradle.lockfile"), `# gradle lockfile
org.top:top:1.0=compileClasspath,runtimeClasspath
org.leaf:leaf:2.0=runtimeClasspath
empty=annotationProcessor`)
	writeGradleCachePOM(t, cacheRoot, "org.top", "top", "1.0", `<project><groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version>
<dependencies><dependency><groupId>org.leaf</groupId><artifactId>leaf</artifactId><version>2.0</version></dependency></dependencies></project>`)

	inv := toJSON(t, resolveGradle(dir, newGradleCache(cacheRoot)))
	top := findNode(t, inv, "pkg:maven/org.top/top@1.0")
	leaf := findNode(t, inv, "pkg:maven/org.leaf/leaf@2.0")
	if top == nil || leaf == nil {
		t.Fatalf("expected top+leaf locked nodes; got %+v", inv.Nodes)
	}
	if !top.Direct {
		t.Error("top is script-declared → Direct=true")
	}
	if leaf.Direct {
		t.Error("leaf is only locked, not declared → Direct=false")
	}
	found := false
	for _, e := range inv.Edges {
		if e.Parent == top.ID && e.Child == leaf.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("expected joined edge top→leaf; got %+v", inv.Edges)
	}
}

func TestGradle_NoLockfileIsHonestResidue(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "build.gradle"), "dependencies {\n    implementation 'org.top:top:1.0'\n}\n")

	inv := toJSON(t, resolveGradle(dir, newGradleCache(t.TempDir())))
	n := findNode(t, inv, "pkg:maven/org.top/top@1.0")
	if n == nil {
		t.Fatalf("declared-direct node must be present; got %+v", inv.Nodes)
	}
	if !n.Direct {
		t.Error("declared dep must be Direct")
	}
	if !hasStr(n.Partiality.Reasons, reasonGradleTransitive) {
		t.Errorf("no-lockfile node must carry gradle_transitive residue; got %+v", n.Partiality)
	}
	if inv.Partiality.Complete {
		t.Error("no-lockfile graph must not be Complete")
	}
}

func TestGradle_CatalogResolvesVersion(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "build.gradle"), "dependencies {\n    implementation 'com.google.guava:guava'\n}\n")
	writeFile(t, filepath.Join(dir, "gradle", "libs.versions.toml"), `[versions]
guava = "32.1.2-jre"
[libraries]
guava = { module = "com.google.guava:guava", version.ref = "guava" }`)

	inv := toJSON(t, resolveGradle(dir, newGradleCache(t.TempDir())))
	if findNode(t, inv, "pkg:maven/com.google.guava/guava@32.1.2-jre") == nil {
		t.Fatalf("catalog should resolve guava version; got %+v", inv.Nodes)
	}
}

func TestGradle_CacheMissResidue(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "build.gradle"), "dependencies {\n    implementation 'org.top:top:1.0'\n}\n")
	writeFile(t, filepath.Join(dir, "gradle.lockfile"), `org.top:top:1.0=runtimeClasspath`)

	inv := toJSON(t, resolveGradle(dir, newGradleCache(t.TempDir())))
	n := findNode(t, inv, "pkg:maven/org.top/top@1.0")
	if n == nil {
		t.Fatalf("locked node must be present; got %+v", inv.Nodes)
	}
	if !hasStr(n.Partiality.Reasons, reasonGradleUncached) {
		t.Errorf("cache-miss node must carry gradle_uncached; got %+v", n.Partiality)
	}
}

func TestGradle_Deterministic(t *testing.T) {
	dir := t.TempDir()
	cacheRoot := t.TempDir()
	writeFile(t, filepath.Join(dir, "gradle.lockfile"), `org.b:b:1.0=runtimeClasspath
org.a:a:1.0=runtimeClasspath`)
	writeGradleCachePOM(t, cacheRoot, "org.a", "a", "1.0", `<project><groupId>org.a</groupId><artifactId>a</artifactId><version>1.0</version></project>`)
	writeGradleCachePOM(t, cacheRoot, "org.b", "b", "1.0", `<project><groupId>org.b</groupId><artifactId>b</artifactId><version>1.0</version></project>`)

	var prev string
	for i := 0; i < 3; i++ {
		b, err := json.Marshal(resolveGradle(dir, newGradleCache(cacheRoot)))
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && string(b) != prev {
			t.Fatalf("non-deterministic gradle output:\n%s\n%s", prev, b)
		}
		prev = string(b)
	}
}

// A group:artifact locked at two versions keeps a node for each, and the declared edge reaches
// both: either copy can be the code that runs.
func TestGradle_LockfileKeepsEveryVersion(t *testing.T) {
	dir := t.TempDir()
	cacheRoot := t.TempDir()
	writeFile(t, filepath.Join(dir, "build.gradle"), "dependencies {\n    implementation 'org.top:top:1.0'\n}\n")
	writeFile(t, filepath.Join(dir, "gradle.lockfile"), `org.top:top:1.0=compileClasspath,runtimeClasspath
org.leaf:leaf:1.0=compileClasspath
org.leaf:leaf:2.0=runtimeClasspath`)
	writeGradleCachePOM(t, cacheRoot, "org.top", "top", "1.0", `<project><groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version>
<dependencies><dependency><groupId>org.leaf</groupId><artifactId>leaf</artifactId><version>1.0</version></dependency></dependencies></project>`)

	inv := toJSON(t, resolveGradle(dir, newGradleCache(cacheRoot)))
	top := findNode(t, inv, "pkg:maven/org.top/top@1.0")
	if top == nil {
		t.Fatalf("top missing; got %+v", inv.Nodes)
	}
	for _, purl := range []string{"pkg:maven/org.leaf/leaf@1.0", "pkg:maven/org.leaf/leaf@2.0"} {
		n := findNode(t, inv, purl)
		if n == nil {
			t.Errorf("locked %s dropped; got %+v", purl, inv.Nodes)
			continue
		}
		edge := false
		for _, e := range inv.Edges {
			if e.Parent == top.ID && e.Child == n.ID {
				edge = true
			}
		}
		if !edge {
			t.Errorf("no edge top -> %s; got %+v", purl, inv.Edges)
		}
	}
}

// A lock line that isn't a coordinate may lock one, so the node set isn't known in full.
func TestGradle_UnparsedLockLineIsReasoned(t *testing.T) {
	for _, tc := range []struct {
		name, lock string
		want       bool
	}{
		{"parsed", "# c\norg.top:top:1.0=runtimeClasspath\nempty=\n", false},
		{"no configurations", "org.top:top:1.0=runtimeClasspath\norg.x:x:3.0\n", true},
		{"two-part coordinate", "org.top:top:1.0=runtimeClasspath\norg.x:3.0=runtimeClasspath\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cacheRoot := t.TempDir()
			writeFile(t, filepath.Join(dir, "build.gradle"), "dependencies {\n    implementation 'org.top:top:1.0'\n}\n")
			writeFile(t, filepath.Join(dir, "gradle.lockfile"), tc.lock)
			writeGradleCachePOM(t, cacheRoot, "org.top", "top", "1.0", `<project><groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version></project>`)
			inv := toJSON(t, resolveGradle(dir, newGradleCache(cacheRoot)))
			if got := hasStr(inv.Partiality.Reasons, reasonGradleLockUnparsed); got != tc.want {
				t.Errorf("gradle_lockfile_unparsed = %v, want %v; partiality %+v", got, tc.want, inv.Partiality)
			}
			if tc.want && inv.Partiality.Complete {
				t.Error("graph with an unparsed lock line must not be Complete")
			}
		})
	}
}

// A lockfile that can't be read may lock anything.
func TestGradle_UnreadableLockfileIsReasoned(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-0 file")
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "build.gradle"), "dependencies {\n    implementation 'org.top:top:1.0'\n}\n")
	writeFile(t, filepath.Join(dir, "gradle.lockfile"), "org.top:top:1.0=runtimeClasspath\n")
	writeFile(t, filepath.Join(dir, "sub", "gradle.lockfile"), "org.x:x:1.0=runtimeClasspath\n")
	lock := filepath.Join(dir, "sub", "gradle.lockfile")
	if err := os.Chmod(lock, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(lock, 0o644) })
	inv := toJSON(t, resolveGradle(dir, newGradleCache(t.TempDir())))
	if !hasStr(inv.Partiality.Reasons, reasonGradleLockUnparsed) {
		t.Errorf("unreadable lockfile must give gradle_lockfile_unparsed; partiality %+v", inv.Partiality)
	}
}
