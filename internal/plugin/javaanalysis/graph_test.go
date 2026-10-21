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
// complete only when nothing beside the graph's own build can resolve another.
func TestResolveDependencyVersions_FromGraph(t *testing.T) {
	const widget = "com.example.lib:widget"
	dep := func(v, scope string) graphDep {
		return graphDep{group: "com.example.lib", artifact: "widget", version: v, scope: scope}
	}
	for _, tc := range []struct {
		name         string
		tool         string
		files        map[string]string // written into the checkout
		copies       [][]graphDep      // one per module
		cpCopy       []graphDep        // the first module's integrationTestRuntimeClasspath copy
		noGraph      bool
		wantFound    bool
		wantVersion  string // "" ⇒ unresolved
		wantVersions []string
		wantComplete bool
		wantReason   string
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
		{name: "no graph", noGraph: true, wantFound: true, wantReason: PartialReasonBuildGraphAbsent},
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
				if tc.cpCopy != nil {
					ms = append(ms, classpathCopy(t, ms[0], "integrationTestRuntimeClasspath", tc.cpCopy...))
				}
				opts = append(opts, graphOption(t, tc.tool, ms...))
			}
			res, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: dir, Coordinate: widget}, opts...)
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
			if tc.wantFound && res.MatchesComplete != (tc.wantReason == "") {
				t.Errorf("MatchesComplete = %v, want %v", res.MatchesComplete, tc.wantReason == "")
			}
			if tc.wantReason == "" != res.Partiality.Complete || (tc.wantReason != "" && !hasStr(res.Partiality.Reasons, tc.wantReason)) {
				t.Errorf("Partiality = %+v, want reason %q", res.Partiality, tc.wantReason)
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
