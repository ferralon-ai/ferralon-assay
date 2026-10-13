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
	writeFile(t, filepath.Join(dir, "sub", "build.gradle"), "")
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

// Only the lock state Gradle itself reads counts: gradle.lockfile in a project directory, or
// gradle/dependency-locks/<configuration>.lockfile under one. A *.lockfile in test resources,
// or a gradle.lockfile in a directory with no build script, is no lock of this build.
func TestGradle_LockReadOnlyWhereGradleKeepsIt(t *testing.T) {
	for _, tt := range []struct {
		name, path string
		read       bool
	}{
		{"root gradle.lockfile", "gradle.lockfile", true},
		{"root per-configuration lock", "gradle/dependency-locks/runtimeClasspath.lockfile", true},
		{"subproject gradle.lockfile", "sub/gradle.lockfile", true},
		{"stray *.lockfile in test resources", "src/test/resources/fixture.lockfile", false},
		{"stray gradle.lockfile in test resources", "src/test/resources/gradle.lockfile", false},
		{"per-configuration lock outside a project", "src/test/resources/gradle/dependency-locks/runtimeClasspath.lockfile", false},
		{"buildscript lock", "buildscript-gradle.lockfile", false},
		{"settings lock", "settings-gradle.lockfile", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "build.gradle"), "dependencies {\n    implementation 'org.top:top:1.0'\n}\n")
			writeFile(t, filepath.Join(dir, "sub", "build.gradle"), "")
			writeFile(t, filepath.Join(dir, filepath.FromSlash(tt.path)), "org.top:top:1.0=runtimeClasspath\norg.x:x:1.0=runtimeClasspath\n")
			_, files, haveLock, _ := readLockfiles(dir)
			if haveLock != tt.read {
				t.Errorf("lock read = %v (files %v), want %v", haveLock, files, tt.read)
			}
		})
	}

	// End to end: a dynamic declaration with only a stray lock is never pinned by it.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "build.gradle"), "dependencies {\n    implementation 'com.evil:netkit:1.+'\n}\n")
	writeFile(t, filepath.Join(dir, "src", "test", "resources", "fixture.lockfile"), "com.evil:netkit:1.0.0=runtimeClasspath\n")
	inv := toJSON(t, resolveGradle(dir, newGradleCache(t.TempDir())))
	if findNode(t, inv, mavenPURL("com.evil", "netkit", "1.0.0")) != nil || inv.Partiality.Complete {
		t.Errorf("a stray lock pinned netkit: %+v", inv)
	}
}

// The locked versions of a GA stand only when every declaration of it agrees with them. A
// literal declared version the lock does not hold, a coordinate the lock lacks, and (unless
// Gradle enforces every lock) a dynamic or version-less declaration leave the GA present but
// unresolved, so no single version's bytes are bound to it.
func TestGradle_LockMustAgreeWithDeclarations(t *testing.T) {
	const enforced = "dependencyLocking {\n    lockAllConfigurations()\n}\n"
	const lenient = "dependencyLocking {\n    lockAllConfigurations()\n    lockMode = LockMode.LENIENT\n}\n"
	netkit := mavenPURL("com.evil", "netkit", "1.0.0")
	for _, tt := range []struct {
		name, locking, decl string
		resolved            bool
	}{
		{"literal agrees", "", "'com.evil:netkit:1.0.0'", true},
		{"literal agrees, enforced", enforced, "'com.evil:netkit:1.0.0'", true},
		{"literal disagrees", "", "'com.evil:netkit:2.0.0'", false},
		{"literal disagrees, enforced", enforced, "'com.evil:netkit:2.0.0'", false},
		{"dynamic", "", "'com.evil:netkit:1.+'", false},
		{"dynamic, enforced", enforced, "'com.evil:netkit:1.+'", true},
		{"dynamic, lenient", lenient, "'com.evil:netkit:1.+'", false},
		{"interpolated", "", `"com.evil:netkit:${v}"`, false},
		{"interpolated, enforced", enforced, `"com.evil:netkit:${v}"`, true},
		{"version-less", "", "'com.evil:netkit'", false},
		{"version-less, enforced", enforced, "'com.evil:netkit'", true},
		{"enforcement only in a comment", "/* " + enforced + " */", "'com.evil:netkit'", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "build.gradle"), tt.locking+"dependencies {\n    implementation "+tt.decl+"\n}\n")
			writeFile(t, filepath.Join(dir, "gradle.lockfile"), "com.evil:netkit:1.0.0=compileClasspath,runtimeClasspath\nempty=\n")
			inv := toJSON(t, resolveGradle(dir, newGradleCache(t.TempDir())))
			if got := findNode(t, inv, netkit) != nil; got != tt.resolved {
				t.Errorf("netkit resolved at 1.0.0 = %v, want %v; nodes %+v", got, tt.resolved, inv.Nodes)
			}
			if tt.resolved {
				return
			}
			n := findNode(t, inv, mavenPURL("com.evil", "netkit", ""))
			if n == nil || n.Version != "" || !hasStr(n.Partiality.Reasons, reasonGradleLockUnconfirmed) {
				t.Errorf("want netkit present, unresolved, %s; got %+v", reasonGradleLockUnconfirmed, n)
			}
			if inv.Partiality.Complete || !hasStr(inv.Partiality.Reasons, reasonGradleLockUnconfirmed) {
				t.Errorf("graph must carry %s; got %+v", reasonGradleLockUnconfirmed, inv.Partiality)
			}
		})
	}

	t.Run("lock lacks a declared coordinate", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "build.gradle"), enforced+"dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n    implementation 'org.other:other:2.0'\n}\n")
		writeFile(t, filepath.Join(dir, "gradle.lockfile"), "com.evil:netkit:1.0.0=runtimeClasspath\n")
		inv := toJSON(t, resolveGradle(dir, newGradleCache(t.TempDir())))
		if findNode(t, inv, mavenPURL("org.other", "other", "2.0")) != nil {
			t.Error("a coordinate the lock lacks must not take the script's version")
		}
		n := findNode(t, inv, mavenPURL("org.other", "other", ""))
		if n == nil || !n.Direct || !hasStr(n.Partiality.Reasons, reasonGradleLockUnconfirmed) {
			t.Errorf("want org.other:other present, direct, unresolved; got %+v", n)
		}
		if inv.Partiality.Complete {
			t.Errorf("want partial; got %+v", inv.Partiality)
		}
	})
}

// Gradle keeps a lock per project, so each lock answers to the scripts that declare for its
// project: its own, and the root's for a subproject. Another project's script neither confirms
// nor stales it.
func TestGradle_LockCheckedPerProject(t *testing.T) {
	const lock = "com.evil:netkit:1.0.0=runtimeClasspath\norg.other:other:2.0=runtimeClasspath\n"
	netkit := mavenPURL("com.evil", "netkit", "1.0.0")
	for _, tt := range []struct {
		name     string
		files    map[string]string
		resolved bool
	}{
		{"a sibling's other version does not stale it", map[string]string{
			"a/build.gradle":    "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"a/gradle.lockfile": lock,
			"b/build.gradle":    "dependencies {\n    implementation 'com.evil:netkit:2.0.0'\n}\n",
		}, true},
		{"the root script declares for the subproject", map[string]string{
			"build.gradle":      "subprojects {\n    dependencies { implementation 'com.evil:netkit:2.0.0' }\n}\n",
			"a/build.gradle":    "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"a/gradle.lockfile": lock,
		}, false},
		{"the project's lock lacks what it declares", map[string]string{
			"a/build.gradle":    "dependencies {\n    implementation 'org.other:other:2.0'\n}\n",
			"a/gradle.lockfile": "org.other:other:2.0=runtimeClasspath\n",
			"b/build.gradle":    "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"b/gradle.lockfile": "empty=\n",
			"c/build.gradle":    "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"c/gradle.lockfile": "com.evil:netkit:1.0.0=runtimeClasspath\n",
		}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for rel, body := range tt.files {
				writeFile(t, filepath.Join(dir, filepath.FromSlash(rel)), body)
			}
			inv := toJSON(t, resolveGradle(dir, newGradleCache(t.TempDir())))
			if got := findNode(t, inv, netkit) != nil; got != tt.resolved {
				t.Errorf("netkit resolved at 1.0.0 = %v, want %v; nodes %+v", got, tt.resolved, inv.Nodes)
			}
		})
	}

	t.Run("an unreadable script confirms nothing", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a mode-000 file")
		}
		dir := t.TempDir()
		script := filepath.Join(dir, "a", "build.gradle")
		writeFile(t, script, "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n")
		writeFile(t, filepath.Join(dir, "a", "gradle.lockfile"), lock)
		if err := os.Chmod(script, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(script, 0o644) })
		inv := toJSON(t, resolveGradle(dir, newGradleCache(t.TempDir())))
		if findNode(t, inv, netkit) != nil {
			t.Errorf("netkit must not resolve when its project's script cannot be read; nodes %+v", inv.Nodes)
		}
	})
}
