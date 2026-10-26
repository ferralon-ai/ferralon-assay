package goanalysis

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// writeModule lays out a module (example.com/m) from name → contents.
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files["go.mod"] = "module example.com/m\n\ngo 1.22\n"
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// cgoScope is what a partiality says about cgo: whether it is a run-wide reason, and the targets
// of its scoped limits (nil when it has none).
func cgoScope(t *testing.T, p plugin.Partiality) (runWide bool, targets []string) {
	t.Helper()
	for _, s := range p.Scoped {
		if s.Reason != plugin.PartialReasonCgo {
			continue
		}
		if s.Targets == nil {
			t.Fatalf("scoped cgo limit with no targets is unbounded and must be a run-wide reason: %+v", s)
		}
		if !slices.Contains(s.Targets, s.Package) {
			t.Errorf("targets %v omit the limit's own package %q", s.Targets, s.Package)
		}
		if targets != nil && !reflect.DeepEqual(targets, s.Targets) {
			t.Errorf("scoped cgo limits disagree on targets: %v vs %v", targets, s.Targets)
		}
		targets = s.Targets
	}
	return slices.Contains(p.Reasons, plugin.PartialReasonCgo), targets
}

// TestLoadProgram_CgoDisabledBuildDeclaresDroppedCgo: with cgo off, a cgo file vanishes from the
// build with no runtime/cgo left to trip the call-graph detector, so the load itself must say so.
// The dropped file is Go code no analysis reads, so it may call anything it can reach; the limit
// is bounded to the build's modules, the standard library and the dropped file's imports, and
// unbounded when one of those imports is a package the build never loaded.
func TestLoadProgram_CgoDisabledBuildDeclaresDroppedCgo(t *testing.T) {
	t.Setenv("CGO_ENABLED", "0")
	const pure = "//go:build !cgo\n\npackage m\n\nfunc Run() {}\n"
	const cgo = "//go:build cgo\n\npackage m\n\n// void run(void) {}\nimport \"C\"\n\nfunc Run() { C.run() }\n"
	const cgoStdlib = "//go:build cgo\n\npackage m\n\n// void run(void) {}\nimport \"C\"\nimport \"encoding/json\"\n\nfunc Run() { C.run(); json.Valid(nil) }\n"
	const cgoUnloaded = "//go:build cgo\n\npackage m\n\n// void run(void) {}\nimport \"C\"\nimport \"example.org/absent\"\n\nfunc Run() { C.run(); absent.Do() }\n"
	const ignored = "//go:build ignore\n\npackage m\n\nimport \"C\"\n"
	const prodCgo = "//go:build cgo && prod\n\npackage m\n\n// void run2(void) {}\nimport \"C\"\n\nfunc Run2() { C.run2() }\n"
	cases := []struct {
		name        string
		files       map[string]string
		goflags     string
		wantRunWide bool
		wantTargets []string
	}{
		{"cgo variant dropped", map[string]string{"run.go": pure, "run_cgo.go": cgo}, "", false, []string{"", stdlibPURL}},
		{"dropped variant imports an unloaded standard-library package", map[string]string{"run.go": pure, "run_cgo.go": cgoStdlib}, "", false, []string{"", stdlibPURL}},
		{"dropped variant imports a package the build never loaded", map[string]string{"run.go": pure, "run_cgo.go": cgoUnloaded}, "", true, nil},
		{"cgo file excluded by a tag, not by cgo", map[string]string{"run.go": pure, "gen.go": ignored}, "", false, nil},
		{"no cgo at all", map[string]string{"run.go": pure}, "", false, nil},
		{"tagged cgo file, tag not set", map[string]string{"run.go": pure, "prod_cgo.go": prodCgo}, "", false, nil},
		{"tagged cgo file, tag set in GOFLAGS", map[string]string{"run.go": pure, "prod_cgo.go": prodCgo}, "-tags=prod", false, []string{"", stdlibPURL}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GOFLAGS", tc.goflags)
			res, err := LoadProgram(context.Background(), writeModule(t, tc.files))
			if err != nil {
				t.Fatal(err)
			}
			runWide, targets := cgoScope(t, res.Partiality)
			if runWide != tc.wantRunWide || !reflect.DeepEqual(targets, tc.wantTargets) {
				t.Errorf("cgo run-wide = %v targets = %v, want %v %v (partiality %+v)", runWide, targets, tc.wantRunWide, tc.wantTargets, res.Partiality)
			}
			if (runWide || targets != nil) == res.Partiality.Complete {
				t.Errorf("complete = %v with cgo declared = %v", res.Partiality.Complete, runWide || targets != nil)
			}
		})
	}
}

// TestCallGraph_UnboundedDroppedCgoStaysRunWide: a dropped cgo file importing a package the build
// never loaded could reach anything, so the call graph keeps cgo as a run-wide reason.
func TestCallGraph_UnboundedDroppedCgoStaysRunWide(t *testing.T) {
	t.Setenv("CGO_ENABLED", "0")
	const main = "package main\n\nimport \"example.com/m/c\"\n\nfunc main() { c.Run() }\n"
	const pure = "//go:build !cgo\n\npackage c\n\nfunc Run() {}\n"
	const cgo = "//go:build cgo\n\npackage c\n\n// void run(void) {}\nimport \"C\"\nimport \"example.org/absent\"\n\nfunc Run() { C.run(); absent.Do() }\n"
	dir := writeModule(t, map[string]string{"main.go": main, "c/run.go": pure, "c/run_cgo.go": cgo})
	cg, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if runWide, targets := cgoScope(t, cg.Partiality); !runWide || targets != nil {
		t.Errorf("cgo run-wide = %v targets = %v, want run-wide only (partiality %+v)", runWide, targets, cg.Partiality)
	}
}

// TestCallGraph_CompiledCgoIsScoped: a cgo build trips the call-graph detector. With no way for C
// to call back into Go, the hidden code is C code in the cgo module, so the limit targets that
// module alone; an //export opens a path back into Go, and the limit then targets the whole build.
func TestCallGraph_CompiledCgoIsScoped(t *testing.T) {
	t.Setenv("CGO_ENABLED", "1")
	cc, err := exec.Command("go", "env", "CC").Output()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath(strings.Fields(string(cc) + " cc")[0]); err != nil {
		t.Skip("no C compiler")
	}
	const main = "package main\n\nimport \"example.com/m/c\"\n\nfunc main() { c.Run() }\n"
	const noExport = "package c\n\n// int add(int a, int b) { return a + b; }\nimport \"C\"\n\nfunc Run() { C.add(1, 2) }\n"
	const export = "package c\n\n// int add(int a, int b) { return a + b; }\nimport \"C\"\n\n//export Hook\nfunc Hook() {}\n\nfunc Run() { C.add(1, 2) }\n"
	cases := []struct {
		name        string
		cgo         string
		wantTargets []string
	}{
		{"C cannot call back", noExport, []string{""}},
		{"an exported function lets C call back", export, []string{"", stdlibPURL}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeModule(t, map[string]string{"main.go": main, "c/c.go": tc.cgo})
			cg, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			runWide, targets := cgoScope(t, cg.Partiality)
			if runWide || !reflect.DeepEqual(targets, tc.wantTargets) {
				t.Errorf("cgo run-wide = %v targets = %v, want scoped to %v (partiality %+v)", runWide, targets, tc.wantTargets, cg.Partiality)
			}
			if cg.Partiality.Complete {
				t.Error("a graph with a scoped limit must not be complete")
			}
		})
	}
}

// TestCallGraph_StandardLibraryCgoIsNoLimit: the standard library's plugin package compiles with
// cgo, but its C only calls dlopen, so importing it holds no cgo limit; whether the program loads
// a plugin is the call graph's plugin_load, declared only when plugin.Open is reached.
func TestCallGraph_StandardLibraryCgoIsNoLimit(t *testing.T) {
	t.Setenv("CGO_ENABLED", "1")
	cc, err := exec.Command("go", "env", "CC").Output()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath(strings.Fields(string(cc) + " cc")[0]); err != nil {
		t.Skip("no C compiler")
	}
	const head = "package main\n\nimport \"plugin\"\n\nvar _ = plugin.Open\n\n"
	cases := []struct {
		name string
		main string
		want []string
	}{
		{"plugin imported, Open never reached", "func main() {}\n", nil},
		{"plugin.Open reached", "func main() { _, _ = plugin.Open(\"x.so\") }\n", []string{plugin.PartialReasonPluginLoad}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeModule(t, map[string]string{"main.go": head + tc.main})
			cg, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			if runWide, targets := cgoScope(t, cg.Partiality); runWide || targets != nil {
				t.Errorf("cgo run-wide = %v targets = %v, want no cgo limit (partiality %+v)", runWide, targets, cg.Partiality)
			}
			if !reflect.DeepEqual(cg.Partiality.Reasons, tc.want) {
				t.Errorf("reasons = %v, want %v", cg.Partiality.Reasons, tc.want)
			}
		})
	}
}

// TestReconcile_CarriesScopedLimits: a call graph whose only incompleteness is a scoped limit has
// stated its cause, so reconcile carries the limit and does not add reachability_undetermined;
// a reason added afterwards keeps it too.
func TestReconcile_CarriesScopedLimits(t *testing.T) {
	scoped := []plugin.ScopedReason{{Reason: plugin.PartialReasonCgo, Package: "pkg:golang/example.com/c", Targets: []string{"pkg:golang/example.com/c"}}}
	cg := plugin.CallGraphResult{Partiality: plugin.Partiality{Scoped: scoped}}
	part := reconcile(nil, cg, false)
	if part.Complete || len(part.Reasons) != 0 || !reflect.DeepEqual(part.Scoped, scoped) {
		t.Fatalf("reconcile = %+v, want incomplete with only the scoped limit", part)
	}
	part = withReason(part, plugin.PartialReasonAdvisoryUnknownToAnalyzer)
	if !reflect.DeepEqual(part.Scoped, scoped) || !hasReason(part.Reasons, plugin.PartialReasonAdvisoryUnknownToAnalyzer) {
		t.Fatalf("withReason = %+v, want the reason added and the scoped limit kept", part)
	}
}
