package goanalysis

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/tools/go/packages"
)

const (
	cbLib  = "pkg:golang/example.com/cgolib"
	cbLibA = "pkg:golang/example.com/liba"
	cbLibB = "pkg:golang/example.com/libb"
)

// writeCbTree lays out the modules of a build: app (the module under analysis), cgolib (the cgo
// package, importing liba), liba, libb. files maps "module/path" to contents; the go.mod files are
// written here, app requiring all three libraries.
func writeCbTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	files["app/go.mod"] = "module example.com/app\n\ngo 1.22\n\n" +
		"require (\n\texample.com/cgolib v0.0.0\n\texample.com/liba v0.0.0\n\texample.com/libb v0.0.0\n)\n\n" +
		"replace (\n\texample.com/cgolib => ../cgolib\n\texample.com/liba => ../liba\n\texample.com/libb => ../libb\n)\n"
	files["cgolib/go.mod"] = "module example.com/cgolib\n\ngo 1.22\n\nrequire example.com/liba v0.0.0\n\nreplace example.com/liba => ../liba\n"
	files["liba/go.mod"] = "module example.com/liba\n\ngo 1.22\n"
	files["libb/go.mod"] = "module example.com/libb\n\ngo 1.22\n"
	files["liba/a.go"] = "package liba\n\nfunc Do() {}\n"
	files["libb/b.go"] = "package libb\n\nfunc Do() {}\n"
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(root, "app")
}

const (
	// cbCompiled is a cgo package that exports to C and calls liba. Its API takes a function value
	// (RegisterFunc, RegisterHook, the Hook field) and database/sql's own value types (Exec).
	cbCompiled = "package cgolib\n\n// #include <stdint.h>\nimport \"C\"\n\nimport (\n\t\"database/sql/driver\"\n\n\t\"example.com/liba\"\n)\n\n" +
		"type Conn struct{ Hook func() }\n\n" +
		"func (c *Conn) RegisterFunc(name string, impl any) error { liba.Do(); return nil }\n" +
		"func (c *Conn) RegisterHook(f func()) { liba.Do() }\n" +
		"func (c *Conn) Exec(q string, args []driver.Value) error { return nil }\n" +
		"func (c *Conn) Close() error { return nil }\n" +
		"func Register(name string, f func()) {}\n"
	cbExport = "package cgolib\n\nimport \"C\"\n\n//export Hook\nfunc Hook() {}\n"
	// cbPure and cbDropped are the same package with cgo off and on: the build drops cbDropped.
	cbPure    = "//go:build !cgo\n\npackage cgolib\n\nimport \"database/sql/driver\"\n\ntype Conn struct{ Hook func() }\n\nfunc (c *Conn) RegisterFunc(name string, impl any) error { return nil }\nfunc (c *Conn) Exec(q string, args []driver.Value) error { return nil }\nfunc (c *Conn) Close() error { return nil }\n"
	cbDropped = "//go:build cgo\n\npackage cgolib\n\n// #include <stdint.h>\nimport \"C\"\n\nimport (\n\t\"database/sql/driver\"\n\n\t\"example.com/liba\"\n)\n\n" +
		"type Conn struct{ Hook func() }\n\nfunc (c *Conn) RegisterFunc(name string, impl any) error { liba.Do(); return nil }\n" +
		"func (c *Conn) Exec(q string, args []driver.Value) error { return nil }\nfunc (c *Conn) Close() error { return nil }\n" +
		"func (c *Conn) Backup(dest string) error { return nil }\n//export Hook\nfunc Hook() {}\n"
)

func appMain(body string) string {
	return "package main\n\nimport (\n\t\"database/sql/driver\"\n\n\t\"example.com/cgolib\"\n\t\"example.com/libb\"\n)\n\nvar _ driver.Value\n\nfunc main() {\n\tlibb.Do()\n\tc := &cgolib.Conn{}\n\t_ = c\n" + body + "}\n"
}

// TestLoadProgram_CgoCallbackBound: C reaches only the cgo package and what it imports when no code
// outside it hands the package a function or interface value.
func TestLoadProgram_CgoCallbackBound(t *testing.T) {
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("no C compiler")
	}
	every := []string{"", cbLib, cbLibA, cbLibB, stdlibPURL}
	bounded := []string{cbLib, cbLibA, stdlibPURL}
	cases := []struct {
		name        string
		files       map[string]string
		cgoEnabled  string
		wantTargets []string
	}{
		{"no call taking a callback", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/main.go": appMain("\tc.Close()\n\tc.Exec(\"q\", nil)\n")}, "1", bounded},
		{"a function-valued parameter", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/main.go": appMain("\tc.RegisterHook(func() {})\n")}, "1", every},
		{"an interface-valued parameter", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/main.go": appMain("\tc.RegisterFunc(\"f\", func() {})\n")}, "1", every},
		{"a package function with a function parameter", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/main.go": appMain("\tcgolib.Register(\"f\", nil)\n")}, "1", every},
		{"a function value taken, never called", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/main.go": appMain("\tf := cgolib.Register\n\t_ = f\n")}, "1", every},
		{"a method value taken, never called", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/main.go": appMain("\tf := c.RegisterFunc\n\t_ = f\n")}, "1", every},
		{"a function-typed field set", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/main.go": appMain("\t_ = cgolib.Conn{Hook: func() {}}\n")}, "1", every},
		{"a call through a wrapper embedding the type", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport,
			"app/wrap/w.go": "package wrap\n\nimport \"example.com/cgolib\"\n\ntype W struct{ *cgolib.Conn }\n",
			"app/main.go":   "package main\n\nimport (\n\t\"example.com/app/wrap\"\n\t\"example.com/cgolib\"\n\t\"example.com/libb\"\n)\n\nfunc main() {\n\tlibb.Do()\n\t(&wrap.W{&cgolib.Conn{}}).RegisterFunc(\"f\", nil)\n}\n"}, "1", every},
		{"an interface re-declaring an API method", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport,
			"app/main.go": appMain("\tvar r interface{ RegisterFunc(string, any) error } = c\n\t_ = r\n")}, "1", every},
		{"a reflective call by name", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/main.go": appMain("\t_ = \"RegisterFunc\"\n")}, "1", every},
		{"a driver that installs its own value converter", map[string]string{"cgolib/c.go": cbCompiled + "\nfunc (c *Conn) CheckNamedValue(nv *driver.NamedValue) error { return nil }\n", "cgolib/hook.go": cbExport, "app/main.go": appMain("\tc.Close()\n")}, "1", every},
		{"a package importing the cgo package that does not type-check", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/main.go": appMain("\tc.Close()\n\t_ = undefinedName\n")}, "1", every},
		{"cgo off, a left-out file importing the cgo package", map[string]string{"cgolib/pure.go": cbPure, "cgolib/dropped.go": cbDropped, "app/main.go": appMain("\tc.Close()\n\tlibaUse()\n"),
			"app/a.go":     "package main\n\nimport \"example.com/liba\"\n\nfunc libaUse() { liba.Do() }\n",
			"app/extra.go": "//go:build cgo\n\npackage main\n\nimport \"example.com/cgolib\"\n\nfunc init() { _ = cgolib.Conn{} }\n"}, "0", every},
		{"cgo off, the dropped file's import closure is a target", map[string]string{"cgolib/pure.go": cbPure, "cgolib/dropped.go": cbDropped, "app/main.go": appMain("\tc.Close()\n\tlibaUse()\n"),
			"app/a.go": "package main\n\nimport \"example.com/liba\"\n\nfunc libaUse() { liba.Do() }\n"}, "0", bounded},
		{"cgo off, a call only the dropped file declares", map[string]string{"cgolib/pure.go": cbPure, "cgolib/dropped.go": cbDropped, "app/main.go": appMain("\tc.Close()\n\tc.Backup(\"d\")\n\tlibaUse()\n"),
			"app/a.go": "package main\n\nimport \"example.com/liba\"\n\nfunc libaUse() { liba.Do() }\n"}, "0", every},
		{"cgo off, a callback-taking call on the pure variant", map[string]string{"cgolib/pure.go": cbPure, "cgolib/dropped.go": cbDropped, "app/main.go": appMain("\tc.RegisterFunc(\"f\", nil)\n\tlibaUse()\n"),
			"app/a.go": "package main\n\nimport \"example.com/liba\"\n\nfunc libaUse() { liba.Do() }\n"}, "0", every},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CGO_ENABLED", tc.cgoEnabled)
			t.Setenv("GOFLAGS", "-mod=mod")
			t.Setenv("GOPROXY", "off")
			res, err := LoadProgram(context.Background(), writeCbTree(t, tc.files))
			if err != nil {
				t.Fatal(err)
			}
			var targets []string
			for _, s := range res.cgo {
				targets = s.Targets
			}
			if !res.cgoBounded || !reflect.DeepEqual(targets, tc.wantTargets) {
				t.Errorf("cgo bounded = %v targets = %v, want %v (partiality %+v)", res.cgoBounded, targets, tc.wantTargets, res.Partiality)
			}
		})
	}
}

// TestCgoLimits_CallbackBoundFailsClosedWithoutTypes: a cgo package that exports, with no type
// information to read its API from, keeps every module as the target.
func TestCgoLimits_CallbackBoundFailsClosedWithoutTypes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exported.go")
	if err := os.WriteFile(path, []byte("package c\n\nimport \"C\"\n\n//export Hook\nfunc Hook() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := &packages.Package{PkgPath: "example.com/other/x", Module: &packages.Module{Path: "example.com/other"}, Imports: map[string]*packages.Package{}}
	cgo := &packages.Package{PkgPath: "example.com/dep/c", Module: &packages.Module{Path: "example.com/dep"}, GoFiles: []string{path},
		Imports: map[string]*packages.Package{"runtime/cgo": {PkgPath: "runtime/cgo"}}}
	app := &packages.Package{PkgPath: "example.com/app", Module: &packages.Module{Path: "example.com/app", Main: true},
		Imports: map[string]*packages.Package{cgo.PkgPath: cgo, other.PkgPath: other}}
	scoped, _, bounded := cgoLimits([]*packages.Package{app}, nil)
	want := []string{"", "pkg:golang/example.com/dep", "pkg:golang/example.com/other", stdlibPURL}
	if !bounded || len(scoped) != 1 || !reflect.DeepEqual(scoped[0].Targets, want) {
		t.Errorf("scoped = %+v bounded = %v, want targets %v", scoped, bounded, want)
	}
}
