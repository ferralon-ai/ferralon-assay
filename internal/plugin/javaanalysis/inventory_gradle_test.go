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

const gradleEnforced = "dependencyLocking {\n    lockAllConfigurations()\n}\n"

func TestGradle_LockfileJoinEdges(t *testing.T) {
	dir := t.TempDir()
	cacheRoot := t.TempDir()
	writeFile(t, filepath.Join(dir, "build.gradle"), gradleEnforced+"dependencies {\n    implementation 'org.top:top:1.0'\n}\n")
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
	writeFile(t, filepath.Join(dir, "build.gradle"), gradleEnforced+"dependencies {\n    implementation 'org.top:top:1.0'\n}\n")
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
	writeFile(t, filepath.Join(dir, "build.gradle"), gradleEnforced+"dependencies {\n    implementation 'org.top:top:1.0'\n}\n")
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
	writeFile(t, filepath.Join(dir, "settings.gradle"), "include 'sub'\n")
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
// gradle/dependency-locks/<configuration>.lockfile under one, where a project is root or one the
// settings script includes. A *.lockfile in test resources, or a gradle.lockfile in a directory
// the settings script does not include, is no lock of this build.
func TestGradle_LockReadOnlyWhereGradleKeepsIt(t *testing.T) {
	for _, tt := range []struct {
		name, path string
		read       bool
	}{
		{"root gradle.lockfile", "gradle.lockfile", true},
		{"root per-configuration lock", "gradle/dependency-locks/runtimeClasspath.lockfile", true},
		{"subproject gradle.lockfile", "sub/gradle.lockfile", true},
		{"lock in a directory the settings script does not include", "other/gradle.lockfile", false},
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
			writeFile(t, filepath.Join(dir, "other", "build.gradle"), "")
			writeFile(t, filepath.Join(dir, "settings.gradle"), "include 'sub'\n")
			writeFile(t, filepath.Join(dir, filepath.FromSlash(tt.path)), "org.top:top:1.0=runtimeClasspath\norg.x:x:1.0=runtimeClasspath\n")
			_, files, haveLock, _, _ := readLockfiles(dir)
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

// The locked versions of a GA stand only when the project's own top-level
// dependencyLocking { lockAllConfigurations() } enforces every lock and every declaration of the
// GA agrees with them. No locking statement, a literal declared version the lock does not hold, a
// coordinate the lock lacks, a version-less declaration, and an interpolated one (no SAFE
// statement) leave the GA present but unresolved, so no single version's bytes are bound to it.
func TestGradle_LockMustAgreeWithDeclarations(t *testing.T) {
	const enforced = "dependencyLocking {\n    lockAllConfigurations()\n}\n"
	const lenient = "dependencyLocking {\n    lockAllConfigurations()\n    lockMode = LockMode.LENIENT\n}\n"
	netkit := mavenPURL("com.evil", "netkit", "1.0.0")
	for _, tt := range []struct {
		name, locking, decl string
		resolved            bool
	}{
		{"literal agrees, no locking statement", "", "'com.evil:netkit:1.0.0'", false},
		{"literal agrees, enforced", enforced, "'com.evil:netkit:1.0.0'", true},
		{"literal disagrees", "", "'com.evil:netkit:2.0.0'", false},
		{"literal disagrees, enforced", enforced, "'com.evil:netkit:2.0.0'", false},
		{"dynamic", "", "'com.evil:netkit:1.+'", false},
		{"dynamic, enforced", enforced, "'com.evil:netkit:1.+'", true},
		{"dynamic, lenient", lenient, "'com.evil:netkit:1.+'", false},
		{"interpolated", "", `"com.evil:netkit:${v}"`, false},
		{"interpolated, enforced", enforced, `"com.evil:netkit:${v}"`, false},
		{"version-less", "", "'com.evil:netkit'", false},
		{"version-less, enforced", enforced, "'com.evil:netkit'", false},
		{"version-less under a platform, enforced", enforced, "platform('com.evil:bom:1.0')\n    implementation 'com.evil:netkit'", false},
		{"enforcement only in a comment", "/* " + enforced + " */", "'com.evil:netkit:1.+'", false},
		{"enforcement inside buildscript", "buildscript {\n" + enforced + "}\n", "'com.evil:netkit:1.+'", false},
		{"enforcement under if", "if (false) {\n" + enforced + "}\n", "'com.evil:netkit:1.+'", false},
		{"enforcement under a braceless if", "if (false)\n" + enforced, "'com.evil:netkit:1.+'", false},
		{"enforcement after else", "if (true) { }\nelse " + enforced, "'com.evil:netkit:1.+'", false},
		{"enforcement inside a call's closure", "afterEvaluate {\n" + enforced + "}\n", "'com.evil:netkit:1.+'", false},
		{"enforcement block holds more", "dependencyLocking {\n    lockAllConfigurations()\n    lockFile = file('x')\n}\n", "'com.evil:netkit:1.+'", false},
		{"enforcement with a second locking block", enforced + "dependencyLocking { unlockAllConfigurations() }\n", "'com.evil:netkit:1.+'", false},
		{"enforcement after a call statement", "java.toolchain.languageVersion = JavaLanguageVersion.of(17)\n" + enforced, "'com.evil:netkit:1.+'", true},
		{"enforcement after a string statement", "group = 'com.example'\n" + enforced, "'com.evil:netkit:1.+'", true},
		{"enforcement with a triple-quoted string", "def s = \"\"\"\n}\n\"\"\"\n" + enforced, "'com.evil:netkit:1.+'", false},
		{"enforcement only inside a triple-quoted string", "def s = \"\"\"\n" + enforced + "\"\"\"\n", "'com.evil:netkit:1.+'", false},
		{"enforcement after a statement inside a closure", "afterEvaluate {\n    group = 'x'\n" + enforced + "}\n", "'com.evil:netkit:1.+'", false},
		{"enforcement beside braces the reader can't balance", enforced + "def re = /\\{/\n", "'com.evil:netkit:1.+'", false},
		{"enforcement with a call chained on the block", "dependencyLocking { lockAllConfigurations() }.with { lockFile = file('x') }\n", "'com.evil:netkit:1.+'", false},
		{"enforcement with a lock mode named elsewhere", enforced + "ext.lockMode = 'STRICT'\n", "'com.evil:netkit:1.+'", false},
		{"enforcement with LENIENT named elsewhere", enforced + "ext.lockingMode = 'LENIENT'\n", "'com.evil:netkit:1.+'", false},
		{"enforcement in a script with an unterminated comment", enforced, "'com.evil:netkit:1.+'\n}\n/* unterminated", false},
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
// project: its own, and the root's for a subproject. The projects are root and those the settings
// script includes. Another project's script neither confirms nor stales a lock, but a project
// that locks nothing yet declares dependencies may resolve any of them at another version, and a
// lock in a directory the settings script does not include is no lock of this build.
func TestGradle_LockCheckedPerProject(t *testing.T) {
	const lock = "com.evil:netkit:1.0.0=runtimeClasspath\norg.other:other:2.0=runtimeClasspath\n"
	const enforced = "dependencyLocking {\n    lockAllConfigurations()\n}\n"
	netkit := mavenPURL("com.evil", "netkit", "1.0.0")
	for _, tt := range []struct {
		name     string
		files    map[string]string
		resolved bool
	}{
		{"a sibling's other version does not stale it", map[string]string{
			"settings.gradle":   "include 'a', 'b'\n",
			"a/build.gradle":    enforced + "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"a/gradle.lockfile": lock,
			"b/build.gradle":    enforced + "dependencies {\n    implementation 'com.evil:netkit:2.0.0'\n}\n",
			"b/gradle.lockfile": "com.evil:netkit:2.0.0=runtimeClasspath\n",
		}, true},
		{"the root script declares for the subproject", map[string]string{
			"settings.gradle":   "include 'a'\n",
			"build.gradle":      "subprojects {\n    dependencies { implementation 'com.evil:netkit:2.0.0' }\n}\n",
			"gradle.lockfile":   "com.evil:netkit:2.0.0=runtimeClasspath\n",
			"a/build.gradle":    enforced + "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"a/gradle.lockfile": lock,
		}, false},
		{"the project's lock lacks what it declares", map[string]string{
			"settings.gradle":   "include 'a', 'b', 'c'\n",
			"a/build.gradle":    enforced + "dependencies {\n    implementation 'org.other:other:2.0'\n}\n",
			"a/gradle.lockfile": "org.other:other:2.0=runtimeClasspath\n",
			"b/build.gradle":    enforced + "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"b/gradle.lockfile": "org.other:other:2.0=runtimeClasspath\n",
			"c/build.gradle":    enforced + "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"c/gradle.lockfile": "com.evil:netkit:1.0.0=runtimeClasspath\n",
		}, false},
		{"an included project without a lock declares another version", map[string]string{
			"settings.gradle":          "include 'app'\n",
			"build.gradle":             enforced + "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"gradle.lockfile":          lock,
			"app/build.gradle":         "dependencies {\n    implementation 'com.evil:netkit:2.0.0'\n}\n",
			"app/src/main/java/A.java": "class A {}\n",
		}, false},
		{"an included project without a lock declares something else", map[string]string{
			"settings.gradle":  "include 'app'\n",
			"build.gradle":     enforced + "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"gradle.lockfile":  lock,
			"app/build.gradle": "dependencies {\n    implementation 'org.pulls:netkit-2:1.0'\n}\n",
		}, false},
		{"an included project without a lock declares something, the root nothing", map[string]string{
			"settings.gradle":  "include 'app'\n",
			"build.gradle":     enforced + "group = 'com.example'\n",
			"gradle.lockfile":  lock,
			"app/build.gradle": "dependencies {\n    implementation 'org.pulls:netkit-2:1.0'\n}\n",
		}, false},
		{"a lock in a directory the settings script does not include", map[string]string{
			"settings.gradle":       "include 'app'\n",
			"app/build.gradle":      "dependencies {\n    implementation 'com.evil:netkit:2.0.0'\n}\n",
			"other/build.gradle":    "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"other/gradle.lockfile": lock,
		}, false},
		{"root enforcement is not the subproject's", map[string]string{
			"settings.gradle":     "include 'app'\n",
			"build.gradle":        enforced,
			"app/build.gradle":    "dependencies {\n    implementation 'com.evil:netkit:1.+'\n}\n",
			"app/gradle.lockfile": lock,
		}, false},
		{"root allprojects enforcement is not credited", map[string]string{
			"settings.gradle":     "include 'app'\n",
			"build.gradle":        "allprojects {\n" + enforced + "}\n",
			"app/build.gradle":    "dependencies {\n    implementation 'com.evil:netkit:1.+'\n}\n",
			"app/gradle.lockfile": lock,
		}, false},
		{"the subproject's own enforcement", map[string]string{
			"settings.gradle":     "include 'app'\n",
			"build.gradle":        enforced,
			"app/build.gradle":    enforced + "dependencies {\n    implementation 'com.evil:netkit:1.+'\n}\n",
			"app/gradle.lockfile": lock,
		}, true},
		{"the root's lenient mode overrides the subproject's own enforcement", map[string]string{
			"settings.gradle":     "include 'app'\n",
			"build.gradle":        "allprojects {\n    dependencyLocking { lockMode = LockMode.LENIENT }\n}\n",
			"app/build.gradle":    enforced + "dependencies {\n    implementation 'com.evil:netkit:1.+'\n}\n",
			"app/gradle.lockfile": lock,
		}, false},
		{"a nested project path, its intermediate project's script safe", map[string]string{
			"settings.gradle":           "include ':libs:core'\n",
			"libs/build.gradle":         "",
			"libs/core/build.gradle":    enforced + "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"libs/core/gradle.lockfile": lock,
		}, true},
		// R5-B1: include 'libs:core' creates :libs too, and Gradle evaluates its script.
		{"R5-B1 a nested project path whose intermediate project has no build script", map[string]string{
			"settings.gradle":           "include ':libs:core'\n",
			"libs/core/build.gradle":    enforced + "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"libs/core/gradle.lockfile": lock,
		}, false},
		{"R5-B1 an intermediate project's script turns locking off below it", map[string]string{
			"settings.gradle":     "include 'a:b'\n",
			"a/build.gradle":      "subprojects { configurations.all { resolutionStrategy.deactivateDependencyLocking() } }\n",
			"a/b/build.gradle":    enforced + "dependencies {\n    implementation 'com.evil:netkit:1.+'\n}\n",
			"a/b/gradle.lockfile": lock,
		}, false},
		{"an include path with an empty segment", map[string]string{
			"settings.gradle":     "include 'a::b'\n",
			"a/build.gradle":      "",
			"a/b/build.gradle":    enforced + "dependencies {\n    implementation 'com.evil:netkit:1.+'\n}\n",
			"a/b/gradle.lockfile": lock,
		}, false},
		{"R5-B1 control, every intermediate project's script safe", map[string]string{
			"settings.gradle":       "include 'a:b:c'\n",
			"a/build.gradle":        "group = 'x'\n",
			"a/b/build.gradle":      "",
			"a/b/c/build.gradle":    enforced + "dependencies {\n    implementation 'com.evil:netkit:1.+'\n}\n",
			"a/b/c/gradle.lockfile": lock,
		}, true},
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

	t.Run("a settings script not read in full confirms nothing", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "settings.gradle"), "rootProject.name = 'x'\nincludeFlat 'app'\n")
		writeFile(t, filepath.Join(dir, "build.gradle"), enforced+"dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n")
		writeFile(t, filepath.Join(dir, "gradle.lockfile"), lock)
		inv := toJSON(t, resolveGradle(dir, newGradleCache(t.TempDir())))
		if findNode(t, inv, netkit) != nil {
			t.Errorf("netkit must not resolve when the project set is unknown; nodes %+v", inv.Nodes)
		}
	})

	t.Run("an unreadable script confirms nothing", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a mode-000 file")
		}
		dir := t.TempDir()
		script := filepath.Join(dir, "a", "build.gradle")
		writeFile(t, filepath.Join(dir, "settings.gradle"), "include 'a'\n")
		writeFile(t, script, enforced+"dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n")
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

// A gradle/dependency-locks that can't be ruled absent counts as present. No whole build
// isolates this: a gradle directory that can't be searched also hides the wrapper properties,
// which fails the build's own check first. So it is pinned on gradleLegacyLocks itself.
func TestGradleLegacyLocks_UnreadIsPresent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	if gradleLegacyLocks(dir) {
		t.Fatal("control: no gradle directory, want false")
	}
	gradle := filepath.Join(dir, "gradle")
	if err := os.Mkdir(gradle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(gradle, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(gradle, 0o755) })
	if !gradleLegacyLocks(dir) {
		t.Error("gradleLegacyLocks = false under an unsearchable gradle directory, want true")
	}
}

// R5-B2: Gradle's default lock mode constrains only a configuration that has lock state, so a
// lock confirms the runtime graph only when it pins runtimeClasspath: an entry for it, or STRICT
// mode (which fails a configuration with no lock state) with no "empty=" line naming it.
func TestGradle_LockPinsRuntimeClasspath(t *testing.T) {
	const enforced = "dependencyLocking {\n    lockAllConfigurations()\n}\n"
	const strict = "dependencyLocking {\n    lockAllConfigurations()\n    lockMode = LockMode.STRICT\n}\n"
	const dynamic = "dependencies {\n    implementation 'com.evil:netkit:1.+'\n}\n"
	netkit := mavenPURL("com.evil", "netkit", "1.0.0")
	for _, tt := range []struct {
		name, script, buildFile, lock string
		resolved                      bool
		legacy                        map[string]string // files under gradle/dependency-locks
	}{
		{"entries for runtimeClasspath", enforced + dynamic, "build.gradle", "com.evil:netkit:1.0.0=runtimeClasspath\n", true, nil},
		{"default mode, no runtimeClasspath entries", enforced + dynamic, "build.gradle", "com.evil:netkit:1.0.0=compileClasspath\n", false, nil},
		{"L1 default mode, compileClasspath entries and a bare empty= line", enforced + dynamic, "build.gradle", "com.evil:netkit:1.0.0=compileClasspath\nempty=\n", false, nil},
		{"default mode, empty= names runtimeClasspath", enforced + dynamic, "build.gradle", "com.evil:netkit:1.0.0=compileClasspath\nempty=runtimeClasspath\n", false, nil},
		{"L1b a literal declaration, both locked for compileClasspath only",
			enforced + "dependencies {\n    implementation 'org.pulls:it:1.0'\n}\n", "build.gradle",
			"com.evil:netkit:1.0.0=compileClasspath\norg.pulls:it:1.0=compileClasspath\n", false, nil},
		{"STRICT, no empty= line", strict + dynamic, "build.gradle", "com.evil:netkit:1.0.0=compileClasspath\n", true, nil},
		{"STRICT, empty= names runtimeClasspath", strict + dynamic, "build.gradle", "com.evil:netkit:1.0.0=compileClasspath\nempty=runtimeClasspath\n", false, nil},
		{"STRICT, empty= names another configuration", strict + dynamic, "build.gradle", "com.evil:netkit:1.0.0=compileClasspath\nempty=testRuntimeClasspath\n", true, nil},
		{"STRICT set with set(), kts", "dependencyLocking {\n    lockMode.set(LockMode.STRICT)\n    lockAllConfigurations()\n}\ndependencies {\n    implementation(\"com.evil:netkit:1.+\")\n}\n", "build.gradle.kts", "com.evil:netkit:1.0.0=compileClasspath\n", true, nil},
		{"STRICT beside a second lock mode", "dependencyLocking {\n    lockAllConfigurations()\n    lockMode = LockMode.STRICT\n    lockMode = LockMode.LENIENT\n}\n" + dynamic, "build.gradle", "com.evil:netkit:1.0.0=compileClasspath\n", false, nil},
		// R6-B2: for a configuration gradle.lockfile has no state for, Gradle reads the legacy
		// gradle/dependency-locks/<configuration>.lockfile, so STRICT silence there pins
		// runtimeClasspath to a version this reader never takes.
		{"LG STRICT, a legacy runtimeClasspath lock at another version, a range declared",
			strict + "dependencies {\n    implementation 'com.evil:netkit:[1.0,3.0)'\n}\n", "build.gradle", "com.evil:netkit:1.0.0=compileClasspath\n", false,
			map[string]string{"runtimeClasspath.lockfile": "com.evil:netkit:2.0.0\n"}},
		{"LA STRICT, a legacy runtimeClasspath lock at another version, 1.+ declared", strict + dynamic, "build.gradle", "com.evil:netkit:1.0.0=compileClasspath\n", false,
			map[string]string{"runtimeClasspath.lockfile": "com.evil:netkit:2.0.0\n"}},
		{"STRICT, a legacy lock for another configuration only", strict + dynamic, "build.gradle", "com.evil:netkit:1.0.0=compileClasspath\n", false,
			map[string]string{"testRuntimeClasspath.lockfile": "com.evil:netkit:1.0.0\n"}},
		// R7-B1: which of the two lock states Gradle binds isn't decided here, so a legacy
		// directory unpins even a configuration gradle.lockfile holds entries for.
		{"R7-B1 entries for runtimeClasspath beside a legacy runtimeClasspath lock at another version", enforced + dynamic, "build.gradle", "com.evil:netkit:1.0.0=runtimeClasspath\n", false,
			map[string]string{"runtimeClasspath.lockfile": "com.evil:netkit:2.0.0\n"}},
		{"R7-B1 STRICT, entries for runtimeClasspath beside a legacy runtimeClasspath lock", strict + dynamic, "build.gradle", "com.evil:netkit:1.0.0=runtimeClasspath\n", false,
			map[string]string{"runtimeClasspath.lockfile": "com.evil:netkit:2.0.0\n"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, tt.buildFile), tt.script)
			for name, body := range tt.legacy {
				writeFile(t, filepath.Join(dir, "gradle", "dependency-locks", name), body)
			}
			writeFile(t, filepath.Join(dir, "gradle.lockfile"), tt.lock)
			inv := toJSON(t, resolveGradle(dir, newGradleCache(t.TempDir())))
			if got := findNode(t, inv, netkit) != nil; got != tt.resolved {
				t.Errorf("netkit resolved at 1.0.0 = %v, want %v; nodes %+v", got, tt.resolved, inv.Nodes)
			}
			if !tt.resolved && inv.Partiality.Complete {
				t.Errorf("want partial; got %+v", inv.Partiality)
			}
			if !tt.resolved && findNode(t, inv, mavenPURL("com.evil", "netkit", "")) == nil {
				t.Errorf("netkit not found unversioned; nodes %+v", inv.Nodes)
			}
		})
	}
}

// The SAFE set's own dependencyLocking check rejects a second lock mode before this reader runs,
// so the reader's rejection is pinned here directly.
func TestGradleLockingBody(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		ok, strict bool
	}{
		{"lockAllConfigurations alone", "\n    lockAllConfigurations()\n", true, false},
		{"with STRICT", "lockAllConfigurations()\nlockMode = LockMode.STRICT", true, true},
		{"with STRICT set(), on one line", "lockMode.set(LockMode.STRICT); lockAllConfigurations()", true, true},
		{"STRICT beside LENIENT", "lockAllConfigurations()\nlockMode = LockMode.STRICT\nlockMode = LockMode.LENIENT", false, false},
		{"LENIENT alone", "lockAllConfigurations()\nlockMode = LockMode.LENIENT", false, false},
		{"lockAllConfigurations twice", "lockAllConfigurations()\nlockAllConfigurations()", false, false},
		{"STRICT without lockAllConfigurations", "lockMode = LockMode.STRICT", false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if ok, strict := gradleLockingBody(tt.body); ok != tt.ok || strict != tt.strict {
				t.Errorf("gradleLockingBody = (%v, %v), want (%v, %v)", ok, strict, tt.ok, tt.strict)
			}
		})
	}
}
