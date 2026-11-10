package javaanalysis

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// unionOption writes one graph per tool, each holding that tool's modules, and returns the option
// handing the plugin their list, as a scan of a root with both a POM and a Gradle build does.
func unionOption(t *testing.T, byTool map[string][]buildgraph.Module) Option {
	t.Helper()
	tools := make([]string, 0, len(byTool))
	for tool := range byTool {
		tools = append(tools, tool)
	}
	sort.Strings(tools)
	var files []string
	for _, tool := range tools {
		b, err := json.Marshal(buildgraph.Graph{
			Schema:   buildgraph.Schema,
			Tool:     buildgraph.Tool{Name: tool, Version: "test"},
			JVM:      buildgraph.JVM{Version: "21.0.4"},
			Modules:  byTool[tool],
			Complete: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(t.TempDir(), "graph.json")
		if err := os.WriteFile(file, b, 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	return WithBuildGraph(strings.Join(files, string(os.PathListSeparator)))
}

// With both builds resolved, a coordinate's copies are every version either tool resolved, each
// attributed to its tool; a version is ruled out only when every copy is.
func TestResolveDependencyVersions_Union(t *testing.T) {
	widget := func(v string) graphDep {
		return graphDep{group: "com.example.lib", artifact: "widget", version: v}
	}
	for _, tc := range []struct {
		name         string
		maven        string
		gradle       string
		wantVersion  string
		wantVersions []string
		wantSources  []string
	}{
		{name: "tools agree", maven: "1.4.0", gradle: "1.4.0", wantVersion: "1.4.0", wantVersions: []string{"1.4.0", "1.4.0"}, wantSources: []string{"gradle", "maven"}},
		{name: "tools disagree", maven: "1.4.0", gradle: "1.3.9", wantVersions: []string{"1.3.9", "1.4.0"}, wantSources: []string{"gradle", "maven"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "pom.xml"), "<project/>")
			writeFile(t, filepath.Join(dir, "build.gradle"), "")
			opt := unionOption(t, map[string][]buildgraph.Module{
				"maven":  {testModule(t, ".", "app", widget(tc.maven))},
				"gradle": {testModule(t, ".", "app", widget(tc.gradle))},
			})
			res, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: dir, Coordinate: "com.example.lib:widget"}, opt)
			if err != nil {
				t.Fatal(err)
			}
			var versions, sources []string
			for _, m := range res.Matches {
				versions, sources = append(versions, m.Version), append(sources, m.Source)
			}
			if !res.Found || res.Match.Version != tc.wantVersion || !reflect.DeepEqual(versions, tc.wantVersions) || !reflect.DeepEqual(sources, tc.wantSources) {
				t.Errorf("Match %q, Matches %v from %v; want %q, %v from %v", res.Match.Version, versions, sources, tc.wantVersion, tc.wantVersions, tc.wantSources)
			}
			// Both builds are listed, so neither stands beside the graph unresolved.
			if !res.Partiality.Complete || !res.Exhaustive {
				t.Errorf("Partiality %+v, Exhaustive %v; want complete and exhaustive", res.Partiality, res.Exhaustive)
			}
		})
	}
}

// A union covers both tools' build files; one graph covers only its own tool's.
func TestOtherToolBuild_Union(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), "<project/>")
	writeFile(t, filepath.Join(dir, "build.gradle"), "")
	maven := &buildgraph.Graph{Tool: buildgraph.Tool{Name: "maven"}, Modules: []buildgraph.Module{{ID: "m", Path: "."}}}
	gradle := &buildgraph.Graph{Tool: buildgraph.Tool{Name: "gradle"}, Modules: []buildgraph.Module{{ID: "g", Path: "."}}}
	if !OtherToolBuild(maven, dir) || !OtherToolBuild(gradle, dir) {
		t.Fatal("a single tool's graph covers the other tool's build")
	}
	if OtherToolBuild(buildgraph.Union(maven, gradle), dir) {
		t.Error("OtherToolBuild = true for the union of both tools' graphs")
	}
}

// One JAR each tool fetched into its own cache is loaded once; the inventory keeps each tool's
// nodes apart; the two builds' root modules are one module with code, not two.
func TestUnionReads(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "src", "main", "java", "A.java"), "class A {}")
	m2 := filepath.Join(t.TempDir(), "gson-2.10.1.jar")
	gcache := filepath.Join(t.TempDir(), "gson-2.10.1.jar")
	writeFile(t, m2, "jar bytes")
	writeFile(t, gcache, "jar bytes")
	gson := func(jar string) graphDep {
		return graphDep{group: "com.google.code.gson", artifact: "gson", version: "2.10.1", jar: jar}
	}
	opt := unionOption(t, map[string][]buildgraph.Module{
		"maven":  {testModule(t, ".", "app", gson(m2))},
		"gradle": {testModule(t, ".", "app", gson(gcache))},
	})
	g := BuildGraph(opt)
	if g == nil {
		t.Fatal("union graph did not load")
	}
	if load, miss := RuntimeSelection(g); len(load) != 1 || len(miss) != 0 {
		t.Errorf("RuntimeSelection = %v, %v; want one JAR", load, miss)
	}
	if jars := graphJars(g); len(jars) != 1 {
		t.Errorf("graphJars = %v, want one JAR", jars)
	}
	if jars := CoordinateJars(g, "com.google.code.gson:gson", ""); len(jars) != 1 {
		t.Errorf("CoordinateJars = %v, want one JAR", jars)
	}
	if multi, why := multipleModules(g, dir); multi {
		t.Errorf("multipleModules = true (%s), want one module with code", why)
	}
	inv := graphInventory(g, false)
	ids := map[string]string{}
	for _, n := range inv.Nodes {
		ids[n.ID] = n.Provenance.Resolver
	}
	if len(ids) != 2 || ids["maven:.|compile|pkg:maven/com.google.code.gson/gson@2.10.1"] != "maven" || ids["gradle:.|compile|pkg:maven/com.google.code.gson/gson@2.10.1"] != "gradle" {
		t.Errorf("inventory nodes = %v, want one per tool", ids)
	}
	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir}, "java", opt)
	if err != nil {
		t.Fatal(err)
	}
	var resolvers []string
	for _, r := range res.Resolvers {
		resolvers = append(resolvers, r.Name)
	}
	if !reflect.DeepEqual(resolvers, []string{"gradle", "maven"}) || res.ProjectRoot != "com.example:app" {
		t.Errorf("resolvers %v, project root %q; want both tools and the root module's own ID", resolvers, res.ProjectRoot)
	}
}

// A graph path that names one file is that file, even when the path holds a list separator.
func TestDecodeGraphs_SingleFileWithSeparator(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a"+string(os.PathListSeparator)+"b")
	file := filepath.Join(dir, "graph.json")
	b, _ := json.Marshal(buildgraph.Graph{Schema: buildgraph.Schema, Tool: buildgraph.Tool{Name: "maven"}})
	writeFile(t, file, string(b))
	g, err := decodeGraphs(file)
	if err != nil || g.Tool.Name != "maven" {
		t.Fatalf("decodeGraphs = %v, %v", g, err)
	}
}
