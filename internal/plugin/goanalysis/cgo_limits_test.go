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
// standard library's own cgo packages.
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
	exported := write("exported.go", "package c\n\nimport \"C\"\n\n//export Hook\nfunc Hook() {}\n")
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
	std := func(path string, goFiles []string) *packages.Package {
		return &packages.Package{PkgPath: path, GoFiles: goFiles, Imports: map[string]*packages.Package{"runtime/cgo": runtimeCgo}}
	}
	with := func(pkgs []*packages.Package, more ...*packages.Package) []*packages.Package {
		for _, p := range more {
			pkgs[0].Imports[p.PkgPath] = p
		}
		return pkgs
	}
	limit := func(pkg, path string, targets ...string) []plugin.ScopedReason {
		return []plugin.ScopedReason{{Reason: plugin.PartialReasonCgo, Package: pkg, Path: path, Targets: targets}}
	}
	cases := []struct {
		name        string
		pkgs        []*packages.Package
		wantBounded bool
		want        []plugin.ScopedReason
	}{
		{"a dependency module's cgo, C cannot call back", graph(depPkg([]string{plain}, nil, nil, true)), true, limit(dep, "example.com/dep/c", dep)},
		{"a prebuilt object lets C call back", graph(depPkg([]string{plain}, []string{filepath.Join(dir, "blob.syso")}, nil, true)), true, limit(dep, "example.com/dep/c", every...)},
		{"a SWIG interface lets C call back", graph(depPkg([]string{plain}, []string{filepath.Join(dir, "api.swig")}, nil, true)), true, limit(dep, "example.com/dep/c", every...)},
		{"a cgo file that does not parse may export", graph(depPkg([]string{broken}, nil, nil, true)), true, limit(dep, "example.com/dep/c", every...)},
		{"a dropped file's limit names the standard library", graph(depPkg(nil, nil, []string{plain}, false)), true, limit(dep, "example.com/dep/c", "", dep, stdlibPURL)},
		{"a dropped file that cannot be read bounds nothing", graph(depPkg(nil, nil, []string{missing}, false)), false, nil},
		{"the compiled plugin package is no cgo module", graph(std("plugin", []string{plain})), true, nil},
		{"the standard library's own cgo is no cgo module", with(graph(depPkg([]string{plain}, nil, nil, true)), std("net", []string{plain})), true, limit(dep, "example.com/dep/c", dep)},
		{"standard-library cgo that exports is", graph(std("net", []string{exported})), true, limit(stdlibPURL, "net", "", stdlibPURL)},
		{"a package outside any module is no standard library", graph(std("example.com/gopath/c", []string{plain})), true, limit(stdlibPURL, "example.com/gopath/c", stdlibPURL)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scoped, _, bounded := cgoLimits(tc.pkgs, nil)
			if bounded != tc.wantBounded {
				t.Fatalf("bounded = %v, want %v (scoped %+v)", bounded, tc.wantBounded, scoped)
			}
			if !reflect.DeepEqual(scoped, tc.want) {
				t.Errorf("scoped = %+v, want %+v", scoped, tc.want)
			}
		})
	}
}
