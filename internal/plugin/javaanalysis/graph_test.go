package javaanalysis

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// The version answer is every copy the build resolved: resolved only when the copies agree,
// complete only when nothing beside the graph's own build can resolve another. Under the same
// condition the answer is exhaustive, so a coordinate absent from the graph is not a dependency.
func TestResolveDependencyVersions_FromGraph(t *testing.T) {
	const widget = "com.example.lib:widget"
	dep := func(v, scope string) graphDep {
		return graphDep{group: "com.example.lib", artifact: "widget", version: v, scope: scope}
	}
	// reactor is a module app depending on its reactor sibling core, which a graph lists as a
	// file-less node with the sibling's root ID.
	reactor := func(t *testing.T) []buildgraph.Module {
		app := testModule(t, "app", "app")
		core := testModule(t, "core", "core")
		app.Nodes = append(app.Nodes, buildgraph.Node{ID: core.Root, Group: "com.example", Artifact: "core", Version: "1", Type: "jar", Scope: "compile"})
		app.Edges = append(app.Edges, buildgraph.Edge{From: app.Root, To: core.Root})
		return []buildgraph.Module{app, core}
	}
	for _, tc := range []struct {
		name         string
		tool         string
		coordinate   string                                 // "" ⇒ widget
		files        map[string]string                      // written into the checkout
		copies       [][]graphDep                           // one per module
		modules      func(t *testing.T) []buildgraph.Module // in place of copies
		cpCopy       []graphDep                             // the first module's integrationTestRuntimeClasspath copy
		unlisted     []string                               // on the first module
		noGraph      bool
		wantFound    bool
		wantVersion  string // "" ⇒ unresolved
		wantVersions []string
		wantComplete bool
		wantReason   string
		// notExhaustive withholds Exhaustive and MatchesComplete on a complete graph.
		notExhaustive bool
	}{
		{name: "one copy", tool: "maven", copies: [][]graphDep{{dep("1.3.9", "")}},
			wantFound: true, wantVersion: "1.3.9", wantVersions: []string{"1.3.9"}, wantComplete: true},
		{name: "modules agree", tool: "maven", copies: [][]graphDep{{dep("1.4.0", "")}, {dep("1.4.0", "runtime")}},
			wantFound: true, wantVersion: "1.4.0", wantVersions: []string{"1.4.0", "1.4.0"}, wantComplete: true},
		{name: "modules disagree", tool: "gradle", copies: [][]graphDep{{dep("1.4.0", "")}, {dep("1.3.9", "")}},
			wantFound: true, wantVersions: []string{"1.4.0", "1.3.9"}, wantComplete: true},
		{name: "a test-scope copy counts", tool: "maven", copies: [][]graphDep{{dep("1.4.0", "")}, {dep("1.3.9", "test")}},
			wantFound: true, wantVersions: []string{"1.4.0", "1.3.9"}, wantComplete: true},
		{name: "classifiers disagree in one module", tool: "maven",
			copies:    [][]graphDep{{dep("2.0", ""), {group: "com.example.lib", artifact: "widget", version: "1.0", scope: "test", classifier: "tests"}}},
			wantFound: true, wantVersions: []string{"2.0", "1.0"}, wantComplete: true},
		{name: "classifiers agree in one module", tool: "maven",
			copies:    [][]graphDep{{dep("2.0", ""), {group: "com.example.lib", artifact: "widget", version: "2.0", scope: "test", classifier: "tests"}}},
			wantFound: true, wantVersion: "2.0", wantVersions: []string{"2.0"}, wantComplete: true},
		// Gradle resolves each classpath on its own: an affected version only a test classpath
		// resolves is still in the build, so an advisory below 1.5 must not be ruled out by 2.0.
		{name: "a classpath copy disagrees", tool: "gradle", copies: [][]graphDep{{dep("2.0", "runtime")}}, cpCopy: []graphDep{dep("1.2", "test")},
			wantFound: true, wantVersions: []string{"2.0", "1.2"}, wantComplete: true},
		{name: "not in the graph", tool: "maven", copies: [][]graphDep{{}}, wantComplete: false},
		{name: "a gradle build beside a maven graph", tool: "maven", files: map[string]string{"svc/build.gradle": "dependencies {}\n"},
			copies: [][]graphDep{{dep("1.4.0", "")}}, wantFound: true, wantVersion: "1.4.0", wantVersions: []string{"1.4.0"}, wantReason: PartialReasonOtherToolBuild},
		{name: "a pom beside a gradle graph", tool: "gradle", files: map[string]string{"pom.xml": "<project/>"},
			copies: [][]graphDep{{dep("1.4.0", "")}}, wantFound: true, wantVersion: "1.4.0", wantVersions: []string{"1.4.0"}, wantReason: PartialReasonOtherToolBuild},
		{name: "not in the graph beside a gradle build", tool: "maven", files: map[string]string{"svc/build.gradle": "dependencies {}\n"},
			copies: [][]graphDep{{}}, wantReason: PartialReasonOtherToolBuild},
		{name: "no graph", noGraph: true, wantFound: true, wantReason: PartialReasonBuildGraphAbsent},
		// A coordinate the build is, not one it resolves: first-party, never a known absence.
		{name: "a reactor sibling", tool: "maven", coordinate: "com.example:core", modules: reactor, notExhaustive: true},
		{name: "the project's own coordinate", tool: "gradle", coordinate: "com.example:a", copies: [][]graphDep{{dep("1.4.0", "")}}, notExhaustive: true},
		{name: "the project's own coordinate in another case", tool: "gradle", coordinate: " Com.Example:A ", copies: [][]graphDep{{dep("1.4.0", "")}}, notExhaustive: true},
		{name: "another case", tool: "maven", coordinate: "Com.Example.Lib:Widget", copies: [][]graphDep{{dep("1.3.9", "")}},
			wantFound: true, wantVersion: "1.3.9", wantVersions: []string{"1.3.9"}, wantComplete: true},
		// A configuration that is no classpath, such as an agent a distribution copies in.
		{name: "a gradle extra-config dep is found", tool: "gradle", copies: [][]graphDep{{dep("1.4.0", buildgraph.ScopeOther)}},
			wantFound: true, wantVersion: "1.4.0", wantVersions: []string{"1.4.0"}, wantComplete: true},
		// The build installs something the graph does not list: neither absence nor the copies
		// are known.
		{name: "a withheld maven build", tool: "maven", copies: [][]graphDep{{}}, unlisted: []string{"maven-dependency-plugin execution copy-agent"}, notExhaustive: true},
		{name: "found in a withheld maven build", tool: "maven", copies: [][]graphDep{{dep("1.4.0", "")}}, unlisted: []string{"maven-dependency-plugin execution copy-agent"},
			wantFound: true, wantVersion: "1.4.0", wantVersions: []string{"1.4.0"}, notExhaustive: true},
		{name: "a gradle configuration that did not resolve", tool: "gradle", copies: [][]graphDep{{}}, unlisted: []string{"gradle configuration drivers"}, notExhaustive: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for rel, content := range tc.files {
				writeFile(t, filepath.Join(dir, filepath.FromSlash(rel)), content)
			}
			var opts []Option
			if !tc.noGraph {
				var ms []buildgraph.Module
				for i, deps := range tc.copies {
					ms = append(ms, testModule(t, string(rune('a'+i)), string(rune('a'+i)), deps...))
				}
				if tc.modules != nil {
					ms = tc.modules(t)
				}
				ms[0].Unlisted = tc.unlisted
				if tc.cpCopy != nil {
					ms = append(ms, classpathCopy(t, ms[0], "integrationTestRuntimeClasspath", tc.cpCopy...))
				}
				opts = append(opts, graphOption(t, tc.tool, ms...))
			}
			coordinate := tc.coordinate
			if coordinate == "" {
				coordinate = widget
			}
			res, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: dir, Coordinate: coordinate}, opts...)
			if err != nil {
				t.Fatal(err)
			}
			if res.Found != tc.wantFound || res.Match.Resolved != (tc.wantVersion != "") || res.Match.Version != tc.wantVersion {
				t.Errorf("Found %v, Match %+v; want found %v at %q", res.Found, res.Match, tc.wantFound, tc.wantVersion)
			}
			var versions []string
			for _, m := range res.Matches {
				versions = append(versions, m.Version)
			}
			if !reflect.DeepEqual(versions, tc.wantVersions) {
				t.Errorf("Matches = %v, want %v", versions, tc.wantVersions)
			}
			if want := tc.wantReason == "" && !tc.notExhaustive; tc.wantFound && res.MatchesComplete != want {
				t.Errorf("MatchesComplete = %v, want %v", res.MatchesComplete, want)
			}
			if tc.wantReason == "" != res.Partiality.Complete || (tc.wantReason != "" && !hasStr(res.Partiality.Reasons, tc.wantReason)) {
				t.Errorf("Partiality = %+v, want reason %q", res.Partiality, tc.wantReason)
			}
			if want := tc.wantReason == "" && !tc.notExhaustive; res.Exhaustive != want {
				t.Errorf("Exhaustive = %v, want %v", res.Exhaustive, want)
			}
		})
	}
}

// The inventory is the graph, one node per module per dependency, and carries the same coverage
// as the version answer.
func TestResolveInventory_FromGraph(t *testing.T) {
	gson := graphDep{group: "com.google.code.gson", artifact: "gson", version: "2.10.1"}
	for _, tc := range []struct {
		name       string
		files      map[string]string
		noGraph    bool
		wantNodes  int
		wantReason string
	}{
		{name: "graph", wantNodes: 2},
		{name: "a gradle build beside it", files: map[string]string{"build.gradle.kts": ""}, wantNodes: 2, wantReason: PartialReasonOtherToolBuild},
		{name: "no graph", noGraph: true, wantReason: PartialReasonBuildGraphAbsent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for rel, content := range tc.files {
				writeFile(t, filepath.Join(dir, rel), content)
			}
			var opts []Option
			if !tc.noGraph {
				opts = append(opts, graphOption(t, "maven", testModule(t, "a", "a", gson), testModule(t, "b", "b", gson)))
			}
			inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir}, opts...)
			if err != nil {
				t.Fatal(err)
			}
			if len(inv.Nodes) != tc.wantNodes {
				t.Errorf("nodes = %d, want %d", len(inv.Nodes), tc.wantNodes)
			}
			if tc.wantReason == "" != inv.Partiality.Complete || (tc.wantReason != "" && !hasStr(inv.Partiality.Reasons, tc.wantReason)) {
				t.Errorf("Partiality = %+v, want reason %q", inv.Partiality, tc.wantReason)
			}
		})
	}
}

// A named graph that does not decode is an error, never an absent graph.
func TestCheckBuildGraph(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "graph.json")
	if err := os.WriteFile(bad, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckBuildGraph(WithBuildGraph(bad)); err == nil {
		t.Error("CheckBuildGraph accepted a graph that does not decode")
	}
	if err := CheckBuildGraph(graphOption(t, "maven", testModule(t, ".", "app"))); err != nil {
		t.Errorf("CheckBuildGraph rejected a decodable graph: %v", err)
	}
	if err := CheckBuildGraph(WithBuildGraph("")); err != nil {
		t.Errorf("CheckBuildGraph without a graph: %v", err)
	}
}

// A checkout the other-tool walk cannot finish may hold the other build, so it counts as one.
func TestOtherToolBuild_UnreadableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-000 directory")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if !OtherToolBuild(&buildgraph.Graph{Tool: buildgraph.Tool{Name: "maven"}}, dir) {
		t.Error("OtherToolBuild = false for a checkout the walk could not read")
	}
}

// TestListsEveryInstall pins what an absence rests on: a graph its producer marked Complete, no
// unlisted install, and no archive in the checkout the graph does not hold.
func TestListsEveryInstall(t *testing.T) {
	jar := filepath.Join(t.TempDir(), "lib-1.jar")
	lib := graphDep{group: "com.example", artifact: "lib", version: "1", jar: jar}
	for _, tc := range []struct {
		name     string
		edit     func(g *buildgraph.Graph)
		files    map[string]string
		absent   bool
		coord    string
		wantRoot bool
	}{
		{name: "complete", absent: true},
		{name: "producer withheld Complete", edit: func(g *buildgraph.Graph) { g.Complete = false; g.Incomplete = []string{"task :fetch"} }},
		{name: "unlisted install", edit: func(g *buildgraph.Graph) { g.Modules[0].Unlisted = []string{"gradle configuration agent"} }},
		{name: "checked-in archive", files: map[string]string{"libs/agent.jar": "x"}},
		{name: "wrapper jar only", files: map[string]string{"gradle/wrapper/gradle-wrapper.jar": "x"}, absent: true},
		{name: "advisory on a module's alias", coord: "com.example:app-core", edit: func(g *buildgraph.Graph) { g.Modules[0].Aliases = []string{"com.example:app-core"} }, wantRoot: true},
		{name: "advisory on a coordinate an alias prefixes", coord: "com.example:app-core-extras", edit: func(g *buildgraph.Graph) { g.Modules[0].Aliases = []string{"com.example:app-core"} }, absent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for rel, body := range tc.files {
				p := filepath.Join(dir, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			g := &buildgraph.Graph{Tool: buildgraph.Tool{Name: "gradle"}, Complete: true, Modules: []buildgraph.Module{testModule(t, ".", "app", lib)}}
			if tc.edit != nil {
				tc.edit(g)
			}
			coord := tc.coord
			if coord == "" {
				coord = "com.evil:netkit"
			}
			if got := AbsentFromBuild(g, dir, coord); got != tc.absent {
				t.Errorf("AbsentFromBuild = %v, want %v", got, tc.absent)
			}
			res := graphVersions(g, coord, false, listsEveryInstall(g, dir))
			if want := tc.absent && !tc.wantRoot; res.Exhaustive != want {
				t.Errorf("Exhaustive = %v, want %v", res.Exhaustive, want)
			}
			if got := isRootCoordinate(g, coord); got != tc.wantRoot {
				t.Errorf("isRootCoordinate = %v, want %v", got, tc.wantRoot)
			}
		})
	}
}

// TestGraphInventoryUnlistedIsPartial: an inventory omitting what a module installs unlisted
// says so.
func TestGraphInventoryUnlistedIsPartial(t *testing.T) {
	m := testModule(t, ".", "app")
	m.Unlisted = []string{"maven-dependency-plugin execution copy-agent"}
	inv := graphInventory(&buildgraph.Graph{Modules: []buildgraph.Module{m}}, false)
	if inv.Partiality.Complete || len(inv.Partiality.Reasons) != 1 || inv.Partiality.Reasons[0] != PartialReasonUnlistedInstall {
		t.Fatalf("partiality = %+v, want %s", inv.Partiality, PartialReasonUnlistedInstall)
	}
}
