package goanalysis

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestCgoLimits drives cgoLimits over hand-built package graphs, for the shapes a test build cannot
// produce here: SWIG (no swig on the host), an unreadable file, a dependency module's cgo, and the
// standard library's plugin package.
func TestCgoLimits(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	plain := write("plain.go", "package c\n\n// int add(int a, int b) { return a + b; }\nimport \"C\"\n\nfunc Run() { C.add(1, 2) }\n")
	broken := write("broken.go", "package c\n\nimport \"C\"\n\nfunc {\n")
	missing := filepath.Join(dir, "missing_cgo.go")

	const dep = "pkg:golang/example.com/dep"
	every := []string{"", dep, stdlibPURL}
	runtimeCgo := &packages.Package{PkgPath: "runtime/cgo"}
	graph := func(cgoPkg *packages.Package) []*packages.Package {
		main := &packages.Package{PkgPath: "example.com/app", Module: &packages.Module{Path: "example.com/app", Main: true},
			Imports: map[string]*packages.Package{cgoPkg.PkgPath: cgoPkg}}
		return []*packages.Package{main}
	}
	depPkg := func(goFiles, otherFiles, ignored []string, compiled bool) *packages.Package {
		p := &packages.Package{PkgPath: "example.com/dep/c", Module: &packages.Module{Path: "example.com/dep"},
			GoFiles: goFiles, OtherFiles: otherFiles, IgnoredFiles: ignored, Imports: map[string]*packages.Package{}}
		if compiled {
			p.Imports["runtime/cgo"] = runtimeCgo
		}
		return p
	}
	stdPlugin := func(compiled bool) *packages.Package {
		p := &packages.Package{PkgPath: "plugin", Imports: map[string]*packages.Package{}}
		if compiled {
			p.Imports["runtime/cgo"] = runtimeCgo
		}
		return p
	}
	cases := []struct {
		name        string
		pkgs        []*packages.Package
		wantBounded bool
		wantPackage string
		wantTargets []string
	}{
		{"a dependency module's cgo, C cannot call back", graph(depPkg([]string{plain}, nil, nil, true)), true, dep, []string{dep}},
		{"a prebuilt object lets C call back", graph(depPkg([]string{plain}, []string{filepath.Join(dir, "blob.syso")}, nil, true)), true, dep, every},
		{"a SWIG interface lets C call back", graph(depPkg([]string{plain}, []string{filepath.Join(dir, "api.swig")}, nil, true)), true, dep, every},
		{"a cgo file that does not parse may export", graph(depPkg([]string{broken}, nil, nil, true)), true, dep, every},
		{"a dropped file that cannot be read bounds nothing", graph(depPkg(nil, nil, []string{missing}, false)), false, "", nil},
		{"the compiled plugin package bounds nothing", graph(stdPlugin(true)), false, "", nil},
		{"the plugin package without cgo is no cgo boundary", graph(stdPlugin(false)), true, "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scoped, _, bounded := cgoLimits(tc.pkgs, nil)
			if bounded != tc.wantBounded {
				t.Fatalf("bounded = %v, want %v (scoped %+v)", bounded, tc.wantBounded, scoped)
			}
			var want []plugin.ScopedReason
			if tc.wantTargets != nil {
				want = []plugin.ScopedReason{{Reason: plugin.PartialReasonCgo, Package: tc.wantPackage, Path: "example.com/dep/c", Targets: tc.wantTargets}}
			}
			if !reflect.DeepEqual(scoped, want) {
				t.Errorf("scoped = %+v, want %+v", scoped, want)
			}
		})
	}
}
