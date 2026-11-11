package javaanalysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
)

// dualGraph is the option handing the plugin one graph per build tool, each listing its tool's
// module whole, as a checkout with both a POM and a Gradle build resolves.
func dualGraph(t *testing.T, byTool map[string][]buildgraph.Module) Option {
	t.Helper()
	var files []string
	for _, tool := range []string{"gradle", "maven"} {
		mods, ok := byTool[tool]
		if !ok {
			continue
		}
		for i := range mods {
			mods[i].JDKToolchainsKnown = true
		}
		b, err := json.Marshal(buildgraph.Graph{
			Schema:     buildgraph.Schema,
			Tool:       buildgraph.Tool{Name: tool, Version: "test"},
			JVM:        buildgraph.JVM{Version: "21.0.4"},
			Conditions: buildgraph.Conditions{JDK: "21.0.4"},
			Subject:    buildgraph.Subject{Outputs: []string{".m2/repository", "target", "build"}},
			Modules:    mods,
			Complete:   true,
		})
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(t.TempDir(), tool+".json")
		if err := os.WriteFile(file, b, 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	return WithBuildGraph(strings.Join(files, string(os.PathListSeparator)))
}

// Each build tool's graph is its own unit: a path any tool's versions give is a path, and a sink
// is searched clean only when every tool's versions are. Two versions inside one tool's graph
// stay ambiguous.
func TestDualBuild_PerToolUnits(t *testing.T) {
	type tool struct {
		versions []string // netkit versions the tool's graph resolves
	}
	cases := map[string]struct {
		maven, gradle tool
		reaching      string // the version whose Api.safe calls the sink, "" for none
		wantPath      bool
		wantSearched  bool
		wantAmbiguous bool
	}{
		"vulnerable in maven, clean in gradle": {maven: tool{[]string{"1.0.0"}}, gradle: tool{[]string{"2.0.0"}}, reaching: "1.0.0", wantPath: true},
		"clean in maven, vulnerable in gradle": {maven: tool{[]string{"2.0.0"}}, gradle: tool{[]string{"1.0.0"}}, reaching: "1.0.0", wantPath: true},
		"both clean":                           {maven: tool{[]string{"1.0.0"}}, gradle: tool{[]string{"2.0.0"}}, wantSearched: true},
		"both reach":                           {maven: tool{[]string{"1.0.0"}}, gradle: tool{[]string{"1.0.0"}}, reaching: "1.0.0", wantPath: true},
		"two versions inside one tool":         {maven: tool{[]string{"1.0.0", "2.0.0"}}, gradle: tool{[]string{"2.0.0"}}, wantAmbiguous: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a := newApp(t, "", false)
			a.source("src/main/java/com/acme/App.java", appSource)
			a.class("target/classes", "com/acme/App", mainCalling(callStatic("com/evil/netkit/Api", "safe")))
			jars := map[string]string{}
			for _, v := range append(append([]string{}, c.maven.versions...), c.gradle.versions...) {
				if _, ok := jars[v]; !ok {
					jars[v] = a.writeNetkitAt(v, v == c.reaching)
				}
			}
			deps := func(tl tool) []graphDep {
				var out []graphDep
				for _, v := range tl.versions {
					out = append(out, graphDep{group: "com.evil", artifact: "netkit", version: v, jar: jars[v]})
				}
				return out
			}
			a.graph = dualGraph(t, map[string][]buildgraph.Module{
				"maven":  {testModule(t, ".", "app", deps(c.maven)...)},
				"gradle": {testModule(t, ".", "app", deps(c.gradle)...)},
			})

			res := a.reach(netkitSinkID)
			if got := len(res.Paths) > 0; got != c.wantPath {
				t.Errorf("paths = %+v, want a path %v", res.Paths, c.wantPath)
			}
			if got := len(res.Searched) == 1; got != c.wantSearched {
				t.Errorf("Searched = %v, want searched %v (partiality %+v)", res.Searched, c.wantSearched, res.Partiality)
			}
			if got := hasScoped(res.Partiality, reasonDependencyVersionAmbiguous, mavenPURLNoVersion("com.evil:netkit")); got != c.wantAmbiguous {
				t.Errorf("version-ambiguous scoped reason = %v, want %v (partiality %+v)", got, c.wantAmbiguous, res.Partiality)
			}
		})
	}
}

// A dual-tool checkout plans one whole-tool unit per tool, and refuses when a tool's own graph
// holds more than one module with code.
func TestReactorUnits_ByTool(t *testing.T) {
	cases := map[string]struct {
		modules map[string][]buildgraph.Module
		extra   func(a *appFixture)
		units   string
		refused bool
	}{
		"one module per tool": {
			modules: map[string][]buildgraph.Module{"maven": {{}}, "gradle": {{}}},
			units:   "gradle maven",
		},
		"two code modules in one tool": {
			modules: map[string][]buildgraph.Module{"maven": {{}, {}}, "gradle": {{}}},
			extra:   func(a *appFixture) { a.source("lib/src/main/java/com/acme/Lib.java", "package com.acme; class Lib {}") },
			refused: true,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a := newApp(t, "", false)
			a.source("src/main/java/com/acme/App.java", appSource)
			a.class("target/classes", "com/acme/App", mainCalling(justReturn))
			if c.extra != nil {
				c.extra(a)
			}
			byTool := map[string][]buildgraph.Module{}
			for tl, ms := range c.modules {
				for i := range ms {
					path := "."
					if i > 0 {
						path = "lib"
					}
					byTool[tl] = append(byTool[tl], testModule(t, path, "m"+strings.Repeat("x", i)))
				}
			}
			plan, multi, why := reactorUnits(a.build, dualGraph(t, byTool))
			if multi != c.refused {
				t.Fatalf("refused = %v (%q), want %v", multi, why, c.refused)
			}
			var ids []string
			if plan != nil {
				for _, u := range plan.units {
					ids = append(ids, u.id)
				}
			}
			if got := strings.Join(ids, " "); got != c.units {
				t.Errorf("units = %q, want %q", got, c.units)
			}
		})
	}
}
