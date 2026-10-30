package javaanalysis

import (
	"context"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func buildManifest(t *testing.T, dir, lang string, opts ...Option) plugin.BuildManifestResult {
	t.Helper()
	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir}, lang, opts...)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	return res
}

// manifestGraph is a graph resolved by tool on a JDK at jvm, holding a module at each path.
func manifestGraph(t *testing.T, tool, jvm string, paths ...string) Option {
	t.Helper()
	g := buildgraph.Graph{Schema: buildgraph.Schema, Tool: buildgraph.Tool{Name: tool, Version: "test"}, JVM: buildgraph.JVM{Version: jvm}}
	for _, p := range paths {
		name := "app"
		if p != "." {
			name = p
		}
		g.Modules = append(g.Modules, testModule(t, p, name))
	}
	return writeGraph(t, g)
}

// The irreducible residue every JVM manifest must declare (Target/Configuration always;
// toolchain_unpinned unless the graph names the JDK). The tests assert these are named, never
// silently dropped, and never Complete over them (inv.5).
func assertHonestResidue(t *testing.T, res plugin.BuildManifestResult, wantToolchainUnpinned bool) {
	t.Helper()
	if res.Partiality.Complete {
		t.Errorf("JVM manifest must never be Complete (portable Target + no static Configuration): %+v", res.Partiality)
	}
	if runtimeOf(res).Target != "" {
		t.Errorf("Target must be empty (portable bytecode), got %q", runtimeOf(res).Target)
	}
	if res.Configuration != "" {
		t.Errorf("Configuration must be empty (no static profile), got %q", res.Configuration)
	}
	if !hasReason(res.Partiality, reasonTargetNotApplicable) {
		t.Errorf("missing declared reason %q in %v", reasonTargetNotApplicable, res.Partiality.Reasons)
	}
	if !hasReason(res.Partiality, reasonNoBuildConfiguration) {
		t.Errorf("missing declared reason %q in %v", reasonNoBuildConfiguration, res.Partiality.Reasons)
	}
	if got := hasReason(res.Partiality, reasonToolchainUnpinned); got != wantToolchainUnpinned {
		t.Errorf("toolchain_unpinned reason = %v, want %v (reasons %v)", got, wantToolchainUnpinned, res.Partiality.Reasons)
	}
}

// The runtime is the JDK the build tool ran on: exact, ambient, its feature release the version.
func TestBuildManifest_MavenEmitBar(t *testing.T) {
	dir := writeTree(t, map[string]string{})
	res := buildManifest(t, dir, "java", manifestGraph(t, "maven", "17.0.9", "."))

	if res.ProjectRoot != "com.example:app" {
		t.Errorf("ProjectRoot = %q, want com.example:app", res.ProjectRoot)
	}
	rt := runtimeOf(res)
	if rt.Name != "java" || rt.Version != "17" || rt.Toolchain != "17.0.9" || rt.Source != plugin.RuntimeSourceAmbient {
		t.Errorf("Runtime = %+v, want java 17, toolchain 17.0.9, ambient", rt)
	}
	if resolverOf(res).Name != "maven" || resolverOf(res).Command != "mvn -o -DskipTests package" {
		t.Errorf("Resolver = %+v, want maven / offline package", resolverOf(res))
	}
	assertHonestResidue(t, res, false)
	if hasReason(res.Partiality, reasonNoRuntimeVersion) {
		t.Errorf("must not declare no_runtime_version when a version resolved: %v", res.Partiality.Reasons)
	}
}

func TestBuildManifest_GradleEmitBar(t *testing.T) {
	dir := writeTree(t, map[string]string{})
	res := buildManifest(t, dir, "java", manifestGraph(t, "gradle", "21.0.4", "."))
	if runtimeOf(res).Version != "21" {
		t.Errorf("Runtime.Version = %q, want 21", runtimeOf(res).Version)
	}
	if resolverOf(res).Name != "gradle" || resolverOf(res).Command != "gradle --offline assemble" {
		t.Errorf("Resolver = %+v, want gradle / offline assemble", resolverOf(res))
	}
	assertHonestResidue(t, res, false)
}

func TestJavaMajor(t *testing.T) {
	for in, want := range map[string]string{"1.8.0_402": "8", "21.0.4": "21", "17": "17", "11.0.2+9": "11", "25-ea": "25"} {
		if got := javaMajor(in); got != want {
			t.Errorf("javaMajor(%q) = %q, want %q", in, got, want)
		}
	}
}

// A graph that does not name its JDK leaves the version empty, never guessed.
func TestBuildManifest_NoRuntimeVersion(t *testing.T) {
	dir := writeTree(t, map[string]string{})
	res := buildManifest(t, dir, "java", manifestGraph(t, "maven", "", "."))
	if runtimeOf(res).Version != "" || runtimeOf(res).Toolchain != "" {
		t.Errorf("Runtime = %+v, want no version or toolchain (never guessed)", runtimeOf(res))
	}
	if !hasReason(res.Partiality, reasonNoRuntimeVersion) {
		t.Errorf("missing no_runtime_version reason: %v", res.Partiality.Reasons)
	}
	assertHonestResidue(t, res, true)
}

func TestBuildManifest_MultiModule(t *testing.T) {
	dir := writeTree(t, map[string]string{})
	res := buildManifest(t, dir, "java", manifestGraph(t, "maven", "21.0.4", ".", "mod-a", "mod-b"))
	if res.ProjectRoot != "com.example:app" {
		t.Errorf("ProjectRoot = %q, want com.example:app (root module)", res.ProjectRoot)
	}
	if !hasReason(res.Partiality, reasonMultiModule) || !hasReason(res.Partiality, reasonMultiModule+": 3 module(s): ., mod-a, mod-b") {
		t.Errorf("missing multi_module_project reason naming the modules: %v", res.Partiality.Reasons)
	}
}

// A classpath copy is the project it belongs to, not another module.
func TestBuildManifest_ClasspathCopy(t *testing.T) {
	dir := writeTree(t, map[string]string{})
	app := testModule(t, ".", "app")
	g := buildgraph.Graph{Schema: buildgraph.Schema, Tool: buildgraph.Tool{Name: "gradle", Version: "test"}, JVM: buildgraph.JVM{Version: "21.0.4"},
		Modules: []buildgraph.Module{app, classpathCopy(t, app, "testRuntimeClasspath")}}
	res := buildManifest(t, dir, "java", writeGraph(t, g))
	if res.ProjectRoot != "com.example:app" {
		t.Errorf("ProjectRoot = %q, want com.example:app", res.ProjectRoot)
	}
	if hasReason(res.Partiality, reasonMultiModule) {
		t.Errorf("a classpath copy counted as a module: %v", res.Partiality.Reasons)
	}
}

func TestBuildManifest_NoGraph(t *testing.T) {
	dir := writeTree(t, map[string]string{"pom.xml": "<project><artifactId>a</artifactId></project>"})
	res := buildManifest(t, dir, "java")
	if !hasReason(res.Partiality, PartialReasonBuildGraphAbsent) {
		t.Errorf("missing %s reason: %v", PartialReasonBuildGraphAbsent, res.Partiality.Reasons)
	}
	if res.ProjectRoot != "." || len(res.Resolvers) != 0 || runtimeOf(res).Version != "" {
		t.Errorf("want nothing read off the checkout, got %+v", res)
	}
	assertHonestResidue(t, res, true)
}

func TestBuildManifest_MissingBuildDirIsHardError(t *testing.T) {
	_, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: "/nonexistent/path/xyz"}, "java")
	if err == nil {
		t.Fatal("missing build dir must be a hard error (inv.4)")
	}
}

// Delegation parity: kotlin == java for the same graph (Runtime.Name aside).
func TestBuildManifest_KotlinDelegationParity(t *testing.T) {
	graph := manifestGraph(t, "gradle", "21.0.4", ".")
	jres := buildManifest(t, writeTree(t, map[string]string{}), "java", graph)
	kres := buildManifest(t, writeTree(t, map[string]string{}), "kotlin", graph)

	if runtimeOf(jres).Name != "java" || runtimeOf(kres).Name != "kotlin" {
		t.Fatalf("Runtime.Name should differ per lane: java=%q kotlin=%q", runtimeOf(jres).Name, runtimeOf(kres).Name)
	}
	// Everything except Runtime.Name must be identical.
	jres.Runtimes[0].Name, kres.Runtimes[0].Name = "", ""
	if !equalManifest(jres, kres) {
		t.Errorf("kotlin delegation must equal java (Runtime.Name aside):\n java   = %+v\n kotlin = %+v", jres, kres)
	}
}

func equalManifest(a, b plugin.BuildManifestResult) bool {
	return slices.Equal(a.Runtimes, b.Runtimes) && a.Configuration == b.Configuration &&
		a.ProjectRoot == b.ProjectRoot && slices.Equal(a.Resolvers, b.Resolvers) &&
		a.Partiality.Complete == b.Partiality.Complete && slices.Equal(a.Partiality.Reasons, b.Partiality.Reasons)
}

// runtimeOf and resolverOf return the manifest's sole runtime/resolver, or the zero value when
// there is not exactly one.
func runtimeOf(res plugin.BuildManifestResult) plugin.RuntimeSpec {
	rt, _ := res.PrimaryRuntime()
	return rt
}

func resolverOf(res plugin.BuildManifestResult) plugin.ResolverSpec {
	rs, _ := res.PrimaryResolver()
	return rs
}
