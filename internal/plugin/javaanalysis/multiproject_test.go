package javaanalysis

import (
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
)

// Only modules with code of their own count: an aggregator or a BOM module beside one module
// with code is a single project.
func TestMultipleModules(t *testing.T) {
	for _, tc := range []struct {
		name    string
		modules []string // module paths
		copyOf  int      // 1 + the index of the module given a classpath copy, or 0
		src     []string // module paths holding a src directory
		multi   bool
		why     string
	}{
		{name: "one module", modules: []string{"."}, src: []string{"."}},
		{name: "aggregator root plus one module", modules: []string{".", "app"}, src: []string{"app"}},
		{name: "two modules with code", modules: []string{".", "api", "core"}, src: []string{"api", "core"}, multi: true, why: "build graph modules api, core"},
		{name: "root and a module with code", modules: []string{".", "app"}, src: []string{".", "app"}, multi: true, why: "build graph modules ., app"},
		{name: "no module with code", modules: []string{".", "bom"}},
		{name: "a classpath copy is not a second module", modules: []string{"."}, src: []string{"."}, copyOf: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			g := &buildgraph.Graph{Schema: buildgraph.Schema}
			for i, p := range tc.modules {
				g.Modules = append(g.Modules, testModule(t, p, string(rune('a'+i))))
			}
			if tc.copyOf > 0 {
				g.Modules = append(g.Modules, classpathCopy(t, g.Modules[tc.copyOf-1], "testRuntimeClasspath"))
			}
			for _, p := range tc.src {
				writeFile(t, filepath.Join(dir, filepath.FromSlash(p), "src", "A.java"), "class A {}")
			}
			multi, why := multipleModules(g, dir)
			if multi != tc.multi || why != tc.why {
				t.Errorf("multipleModules = %v, %q; want %v, %q", multi, why, tc.multi, tc.why)
			}
		})
	}
}
