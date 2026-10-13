package javaanalysis

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// mavenNode is one inventory node the Maven resolver would emit for coord at version in scope.
func mavenNode(coord, version, scope string) plugin.DependencyNode {
	g, a, _ := splitCoordinate(coord)
	return plugin.DependencyNode{
		ID:         "|" + scope + "|" + mavenPURL(g, a, version),
		PURL:       mavenPURL(g, a, version),
		Version:    version,
		Membership: plugin.DependencyMembership{Target: scope},
		Provenance: plugin.DependencyProvenance{Resolver: "maven-effective"},
	}
}

func gradleNode(coord, version, resolver string) plugin.DependencyNode {
	g, a, _ := splitCoordinate(coord)
	return plugin.DependencyNode{
		ID:         "|compileClasspath|" + mavenPURL(g, a, version),
		PURL:       mavenPURL(g, a, version),
		Version:    version,
		Membership: plugin.DependencyMembership{Target: "compileClasspath"},
		Provenance: plugin.DependencyProvenance{Resolver: resolver},
	}
}

// The search loads one version per package, taken from the classpath the application runs
// with, and names every package it cannot pick a version for instead of guessing.
func TestSelectRuntimeGAVs(t *testing.T) {
	const jd = "com.fasterxml.jackson.core:jackson-databind"
	for _, tc := range []struct {
		name     string
		nodes    []plugin.DependencyNode
		locks    []GradleLockEntry
		reactor  map[string]bool
		wantLoad []gav
		wantMiss []selectionMiss
	}{
		{
			name:     "test-only version left out, compile version loaded",
			nodes:    []plugin.DependencyNode{mavenNode(jd, "2.9.8", "test"), mavenNode(jd, "2.9.9", "compile")},
			wantLoad: []gav{{jd, "2.9.9"}},
		},
		{
			name:  "test-only package not loaded",
			nodes: []plugin.DependencyNode{mavenNode(jd, "2.9.8", "test")},
		},
		{
			name:     "provided and runtime are on the running classpath",
			nodes:    []plugin.DependencyNode{mavenNode("javax.servlet:servlet-api", "2.5", "provided"), mavenNode(jd, "2.9.9", "runtime")},
			wantLoad: []gav{{jd, "2.9.9"}, {"javax.servlet:servlet-api", "2.5"}},
		},
		{
			name:     "two runtime versions are a named miss",
			nodes:    []plugin.DependencyNode{mavenNode(jd, "2.9.8", "compile"), mavenNode(jd, "2.9.9", "runtime")},
			wantMiss: []selectionMiss{{jd, reasonDependencyVersionAmbiguous, jd + ": runtime versions 2.9.8, 2.9.9"}},
		},
		{
			name:     "unresolved version is a named miss",
			nodes:    []plugin.DependencyNode{mavenNode(jd, "", "compile")},
			wantMiss: []selectionMiss{{jd, reasonNoDependencyArtifact, jd + ": no resolved version"}},
		},
		{
			name:     "unresolved copy beside a resolved one is still a miss",
			nodes:    []plugin.DependencyNode{mavenNode(jd, "", "compile"), mavenNode(jd, "2.9.9", "runtime")},
			wantMiss: []selectionMiss{{jd, reasonNoDependencyArtifact, jd + ": no resolved version"}},
		},
		{
			name:  "gradle kapt version left out, runtimeClasspath version loaded",
			nodes: []plugin.DependencyNode{gradleNode(jd, "2.9.8", "gradle-lockfile")},
			locks: []GradleLockEntry{
				{Group: "com.fasterxml.jackson.core", Artifact: "jackson-databind", Version: "2.9.8", Configs: []string{"annotationProcessor", "kapt", "testRuntimeClasspath"}},
				{Group: "com.fasterxml.jackson.core", Artifact: "jackson-databind", Version: "2.9.9", Configs: []string{"compileClasspath", "runtimeClasspath"}},
			},
			wantLoad: []gav{{jd, "2.9.9"}},
		},
		{
			name:  "gradle compileClasspath-only package not loaded",
			nodes: []plugin.DependencyNode{gradleNode(jd, "2.9.9", "gradle-lockfile")},
			locks: []GradleLockEntry{{Group: "com.fasterxml.jackson.core", Artifact: "jackson-databind", Version: "2.9.9", Configs: []string{"compileClasspath"}}},
		},
		{
			name:  "gradle two runtimeClasspath versions are a named miss",
			nodes: []plugin.DependencyNode{gradleNode(jd, "2.9.8", "gradle-lockfile")},
			locks: []GradleLockEntry{
				{Group: "com.fasterxml.jackson.core", Artifact: "jackson-databind", Version: "2.9.8", Configs: []string{"runtimeClasspath"}},
				{Group: "com.fasterxml.jackson.core", Artifact: "jackson-databind", Version: "2.9.9", Configs: []string{"runtimeClasspath"}},
			},
			wantMiss: []selectionMiss{{jd, reasonDependencyVersionAmbiguous, jd + ": runtime versions 2.9.8, 2.9.9"}},
		},
		{
			name:     "gradle without a lockfile is a named miss",
			nodes:    []plugin.DependencyNode{gradleNode(jd, "2.9.9", "gradle-script")},
			wantMiss: []selectionMiss{{jd, reasonNoDependencyArtifact, jd + ": no lockfile pins its configuration or version"}},
		},
		{
			name:    "reactor module is first-party output",
			nodes:   []plugin.DependencyNode{mavenNode("com.acme:lib", "1.0.0", "compile")},
			reactor: map[string]bool{"com.acme:lib": true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ix := indexInventory(plugin.DependencyInventory{Nodes: tc.nodes})
			got := selectRuntimeGAVs(ix, tc.reactor, tc.locks)
			if !reflect.DeepEqual(got.load, tc.wantLoad) {
				t.Errorf("load = %v, want %v", got.load, tc.wantLoad)
			}
			if !reflect.DeepEqual(got.miss, tc.wantMiss) {
				t.Errorf("miss = %+v, want %+v", got.miss, tc.wantMiss)
			}
		})
	}
}

// A dependency only the tests use is not loaded, so a main calling into it meets an
// unloaded class (a hazard), never a path through test-only code.
func TestBytecodeReach_TestScopedDependencyIsNotLoaded(t *testing.T) {
	build := t.TempDir()
	a := &appFixture{t: t, build: build}
	writeFileT(t, filepath.Join(build, "pom.xml"), `<project><modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId><artifactId>app</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency><groupId>com.evil</groupId><artifactId>netkit</artifactId><version>1.0.0</version><scope>test</scope></dependency>
  </dependencies>
</project>`)
	b := &cpb{}
	jar := emitClassX(b, "com/evil/netkit/UrlFetcher", "java/lang/Object", 0x0021, []xmethod{{"fetch", fetchDesc, accPublic, ret}})
	writeJar(t, filepath.Join(build, ".m2", "repository", "com", "evil", "netkit", "1.0.0", "netkit-1.0.0.jar"), "com/evil/netkit/UrlFetcher.class", jar)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(callFetch))

	res := a.reach(netkitSinkID)
	if len(res.Paths) != 0 || len(res.Searched) != 0 {
		t.Fatalf("test-scoped JAR was loaded: Paths %v Searched %v", res.Paths, res.Searched)
	}
	if !hasReason(res.Partiality, plugin.PartialReasonReachabilityUndetermined) {
		t.Errorf("missing reachability_undetermined: %+v", res.Partiality)
	}
}

// A dependency with no resolved version is a scoped miss, mirrored run-wide.
func TestBytecodeReach_UnresolvedVersionIsScopedAndRunWide(t *testing.T) {
	a := newApp(t, `<dependency><groupId>com.dep</groupId><artifactId>nover</artifactId></dependency>`, false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(justReturn))

	res := a.reach(netkitSinkID)
	if !hasScoped(res.Partiality, reasonNoDependencyArtifact, "pkg:maven/com.dep/nover") {
		t.Fatalf("missing scoped no_dependency_artifact for the unversioned dependency: %+v", res.Partiality.Scoped)
	}
	if !hasReason(res.Partiality, reasonNoDependencyArtifact) || res.Partiality.Complete {
		t.Errorf("scoped reason not mirrored run-wide: %+v", res.Partiality)
	}
}

// Two caches holding different bytes for one JAR: neither copy is searched, and the miss
// names the package.
func TestBytecodeReach_DifferingCachedCopiesAreNotLoaded(t *testing.T) {
	a := newApp(t, "", false)
	b := &cpb{}
	other := emitClassX(b, "com/evil/netkit/UrlFetcher", "java/lang/Object", 0x0021, []xmethod{{"fetch", fetchDesc, accPublic, ret}, {"other", "()V", accPublic, ret}})
	writeJar(t, filepath.Join(a.build, ".gradle", "caches", "modules-2", "files-2.1", "com.evil", "netkit", "1.0.0", "0a1b2c", "netkit-1.0.0.jar"), "com/evil/netkit/UrlFetcher.class", other)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(callFetch))

	res := a.reach(netkitSinkID)
	if len(res.Paths) != 0 || len(res.Searched) != 0 {
		t.Fatalf("a differing copy was searched: Paths %v Searched %v", res.Paths, res.Searched)
	}
	found := false
	for _, s := range res.Partiality.Scoped {
		if s.Reason == reasonNoDependencyArtifact && s.Package == netkitPURL && s.Path == "com.evil:netkit:1.0.0: cached copies differ" {
			found = true
		}
	}
	if !found {
		t.Errorf("missing scoped no_dependency_artifact naming the differing copies: %+v", res.Partiality.Scoped)
	}
}
