package goanalysis

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
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
	if files["libb/b.go"] == "" {
		files["libb/b.go"] = "package libb\n\nfunc Do() {}\n"
	}
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
		"func Register(name string, f func()) {}\n" +
		"type Handler interface{ Serve() }\n\n" +
		"func Mount(h Handler) {}\n" +
		"func MountAll(hs ...Handler) {}\n" +
		"func MountBoth(a, b Handler) {}\n" +
		"func MountAny[T Handler](h T) {}\n"
	// cbSecond makes libb a second cgo package that exports to C.
	cbSecond = "package libb\n\n// #include <stdint.h>\nimport \"C\"\n\n//export libbHook\nfunc libbHook() {}\n\nfunc Do() {}\n"
	// cbFS is a first-party package, not main, declaring types the build hands the cgo package.
	cbFS = "package fsys\n\ntype FS struct{ Root string }\n\nfunc (f *FS) Serve() {}\nfunc (f FS) Stat() {}\nfunc (f *FS) hidden() {}\n\n" +
		"type Hooked struct{ Hook func() }\n\nfunc (h *Hooked) Serve() {}\n\n" +
		"type Wrapped struct{ Inner interface{ Serve() } }\n\nfunc (w *Wrapped) Serve() {}\n\n" +
		"type Promoting struct{ Server }\n\ntype Server interface{ Serve() }\n\n" +
		"type Generic[T any] struct{ V T }\n\nfunc (g *Generic[T]) Serve() {}\n\n" +
		"type Fn func()\n\nfunc (f Fn) Serve() {}\n\n" +
		"func Pair() (*FS, *FS) { return nil, nil }\n"
	// cbReflecting makes the cgo package one that reflects.
	cbReflecting = "package cgolib\n\nimport \"reflect\"\n\nvar _ = reflect.TypeOf\n"
	cbExport     = "package cgolib\n\nimport \"C\"\n\n//export Hook\nfunc Hook() {}\n"
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

// handing is appMain for a build whose main also imports the first-party fsys package.
func handing(body string) string {
	return "package main\n\nimport (\n\t\"unsafe\"\n\n\t\"example.com/app/fsys\"\n\t\"example.com/cgolib\"\n\t\"example.com/libb\"\n)\n\nvar (\n\t_ unsafe.Pointer\n\t_ fsys.FS\n)\n\nfunc main() {\n\tlibb.Do()\n\tc := &cgolib.Conn{}\n\t_ = c\n" + body + "}\n"
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
		wantHanded  []string
	}{
		{"no call taking a callback", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/main.go": appMain("\tc.Close()\n\tc.Exec(\"q\", nil)\n")}, "1", bounded, nil},
		{"a function-valued parameter", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/main.go": appMain("\tc.RegisterHook(func() {})\n")}, "1", every, nil},
		{"an interface-valued parameter", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/main.go": appMain("\tc.RegisterFunc(\"f\", func() {})\n")}, "1", every, nil},
		{"a package function with a function parameter", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/main.go": appMain("\tcgolib.Register(\"f\", nil)\n")}, "1", every, nil},
		{"a function value taken, never called", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/main.go": appMain("\tf := cgolib.Register\n\t_ = f\n")}, "1", every, nil},
		{"a method value taken, never called", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/main.go": appMain("\tf := c.RegisterFunc\n\t_ = f\n")}, "1", every, nil},
		{"a function-typed field set", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/main.go": appMain("\t_ = cgolib.Conn{Hook: func() {}}\n")}, "1", every, nil},
		{"a call through a wrapper embedding the type", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport,
			"app/wrap/w.go": "package wrap\n\nimport \"example.com/cgolib\"\n\ntype W struct{ *cgolib.Conn }\n",
			"app/main.go":   "package main\n\nimport (\n\t\"example.com/app/wrap\"\n\t\"example.com/cgolib\"\n\t\"example.com/libb\"\n)\n\nfunc main() {\n\tlibb.Do()\n\t(&wrap.W{&cgolib.Conn{}}).RegisterFunc(\"f\", func() {})\n}\n"}, "1", every, nil},
		{"an interface re-declaring an API method", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport,
			"app/main.go": appMain("\tvar r interface{ RegisterFunc(string, any) error } = c\n\t_ = r\n")}, "1", every, nil},
		{"a reflective call by name", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/main.go": appMain("\t_ = \"RegisterFunc\"\n")}, "1", every, nil},
		{"a driver that installs its own value converter", map[string]string{"cgolib/c.go": cbCompiled + "\nfunc (c *Conn) CheckNamedValue(nv *driver.NamedValue) error { return nil }\n", "cgolib/hook.go": cbExport, "app/main.go": appMain("\tc.Close()\n")}, "1", every, nil},
		{"a package importing the cgo package that does not type-check", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/main.go": appMain("\tc.Close()\n\t_ = undefinedName\n")}, "1", every, nil},
		{"cgo off, a left-out file importing the cgo package", map[string]string{"cgolib/pure.go": cbPure, "cgolib/dropped.go": cbDropped, "app/main.go": appMain("\tc.Close()\n\tlibaUse()\n"),
			"app/a.go":     "package main\n\nimport \"example.com/liba\"\n\nfunc libaUse() { liba.Do() }\n",
			"app/extra.go": "//go:build cgo\n\npackage main\n\nimport \"example.com/cgolib\"\n\nfunc init() { _ = cgolib.Conn{} }\n"}, "0", every, nil},
		{"cgo off, the dropped file's import closure is a target", map[string]string{"cgolib/pure.go": cbPure, "cgolib/dropped.go": cbDropped, "app/main.go": appMain("\tc.Close()\n\tlibaUse()\n"),
			"app/a.go": "package main\n\nimport \"example.com/liba\"\n\nfunc libaUse() { liba.Do() }\n"}, "0", bounded, nil},
		{"cgo off, a call only the dropped file declares", map[string]string{"cgolib/pure.go": cbPure, "cgolib/dropped.go": cbDropped, "app/main.go": appMain("\tc.Close()\n\tc.Backup(\"d\")\n\tlibaUse()\n"),
			"app/a.go": "package main\n\nimport \"example.com/liba\"\n\nfunc libaUse() { liba.Do() }\n"}, "0", every, nil},
		{"cgo off, a callback-taking call on the pure variant", map[string]string{"cgolib/pure.go": cbPure, "cgolib/dropped.go": cbDropped, "app/main.go": appMain("\tc.RegisterFunc(\"f\", func() {})\n\tlibaUse()\n"),
			"app/a.go": "package main\n\nimport \"example.com/liba\"\n\nfunc libaUse() { liba.Do() }\n"}, "0", every, nil},
		{"nil passed where the package takes an interface", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "app/main.go": handing("\tc.RegisterFunc(\"f\", nil)\n\tcgolib.Mount(nil)\n")}, "1", bounded, nil},
		{"a basic value passed where the package takes an interface", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "app/main.go": handing("\tc.RegisterFunc(\"f\", 1)\n")}, "1", bounded, nil},
		{"an unsafe pointer passed where the package takes an interface", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "app/main.go": handing("\tc.RegisterFunc(\"f\", unsafe.Pointer(&fsys.FS{}))\n")}, "1", every, nil},
		{"a value of a searched type handed over", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "app/main.go": handing("\tcgolib.Mount(&fsys.FS{})\n")}, "1", bounded, []string{"example.com/app/fsys.FS"}},
		{"a value of a searched type handed over as any, by value", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "app/main.go": handing("\tc.RegisterFunc(\"f\", fsys.FS{})\n")}, "1", bounded, []string{"example.com/app/fsys.FS"}},
		{"values handed to a variadic parameter", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "app/main.go": handing("\tcgolib.MountAll(&fsys.FS{}, &fsys.Hooked{})\n")}, "1", bounded, []string{"example.com/app/fsys.FS", "example.com/app/fsys.Hooked"}},
		{"a slice spread over a variadic parameter", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "app/main.go": handing("\tcgolib.MountAll([]cgolib.Handler{&fsys.FS{}}...)\n")}, "1", every, nil},
		{"a call's results spread over the parameters", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "app/main.go": handing("\tcgolib.MountBoth(fsys.Pair())\n")}, "1", every, nil},
		{"a searched type handed over beside a function value", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "app/main.go": handing("\tcgolib.Mount(&fsys.FS{})\n\tc.RegisterHook(func() {})\n")}, "1", every, nil},
		{"a value handed over under an interface type", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "app/main.go": handing("\tvar h cgolib.Handler = &fsys.FS{}\n\tcgolib.Mount(h)\n")}, "1", every, nil},
		{"a value of a main package's type handed over", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "app/main.go": handing("\tcgolib.Mount(&local{})\n") + "\ntype local struct{}\n\nfunc (l *local) Serve() {}\n"}, "1", every, nil},
		{"a value of a dependency's type handed over", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "libb/b.go": "package libb\n\nfunc Do() {}\n\ntype T struct{}\n\nfunc (t *T) Serve() {}\n", "app/main.go": appMain("\tcgolib.Mount(&libb.T{})\n")}, "1", every, nil},
		{"a value of a type declared in a function handed over", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "app/fsys/g.go": "package fsys\n\nimport \"example.com/cgolib\"\n\nfunc Start() {\n\ttype inner struct{ *FS }\n\tcgolib.Mount(inner{})\n}\n", "app/main.go": handing("\tfsys.Start()\n")}, "1", every, nil},
		{"a value of a generic type handed over", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "app/main.go": handing("\tcgolib.Mount(&fsys.Generic[int]{})\n")}, "1", every, nil},
		{"a value handed to a generic function", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "app/main.go": handing("\tcgolib.MountAny(&fsys.FS{})\n")}, "1", every, nil},
		{"a value handed over under a searched interface type", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "app/main.go": handing("\tvar h fsys.Server = &fsys.FS{}\n\tcgolib.Mount(h)\n")}, "1", every, nil},
		{"a value promoting an embedded interface's methods handed over", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "app/main.go": handing("\tcgolib.Mount(fsys.Promoting{})\n")}, "1", every, nil},
		{"a value of a named function type handed over", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "app/main.go": handing("\tcgolib.Mount(fsys.Fn(nil))\n")}, "1", every, nil},
		{"a value of an unnamed struct type handed over", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "app/main.go": handing("\tcgolib.Mount(struct{ *fsys.FS }{})\n")}, "1", every, nil},
		{"a value holding a function, the cgo package not reflecting", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "app/main.go": handing("\tcgolib.Mount(&fsys.Hooked{})\n\tcgolib.Mount(&fsys.Wrapped{})\n")}, "1", bounded, []string{"example.com/app/fsys.Hooked", "example.com/app/fsys.Wrapped"}},
		{"a value holding a function, the cgo package reflecting", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "cgolib/r.go": cbReflecting, "app/main.go": handing("\tcgolib.Mount(&fsys.Hooked{})\n")}, "1", every, nil},
		{"a value holding no function, the cgo package reflecting", map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "cgolib/r.go": cbReflecting, "app/main.go": handing("\tcgolib.Mount(&fsys.FS{})\n")}, "1", bounded, []string{"example.com/app/fsys.FS"}},
		{"cgo off, a value of a searched type handed to the pure variant", map[string]string{"cgolib/pure.go": cbPure + "\nfunc Mount(h interface{ Serve() }) {}\n", "cgolib/dropped.go": cbDropped, "app/fsys/f.go": cbFS, "app/main.go": handing("\tcgolib.Mount(&fsys.Hooked{})\n\tlibaUse()\n"), "app/a.go": "package main\n\nimport \"example.com/liba\"\n\nfunc libaUse() { liba.Do() }\n"}, "0", bounded, []string{"example.com/app/fsys.Hooked"}},
		{"cgo off, a value holding a function, a dropped file reflecting", map[string]string{"cgolib/pure.go": cbPure + "\nfunc Mount(h interface{ Serve() }) {}\n", "cgolib/dropped.go": cbDropped, "cgolib/refl.go": "//go:build cgo\n\npackage cgolib\n\nimport \"C\"\n\nimport \"reflect\"\n\nvar _ = reflect.TypeOf\n", "app/fsys/f.go": cbFS, "app/main.go": handing("\tcgolib.Mount(&fsys.Hooked{})\n\tlibaUse()\n"), "app/a.go": "package main\n\nimport \"example.com/liba\"\n\nfunc libaUse() { liba.Do() }\n"}, "0", every, nil},
		{"cgo off, a member whose parameter type does not check", map[string]string{"cgolib/pure.go": cbPure + "\nfunc Broken(x missing) {}\n", "cgolib/dropped.go": cbDropped, "app/main.go": appMain("\tc.Close()\n\tcgolib.Broken(nil)\n\tlibaUse()\n"), "app/a.go": "package main\n\nimport \"example.com/liba\"\n\nfunc libaUse() { liba.Do() }\n"}, "0", every, nil},
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
			var handed []string
			for _, h := range res.cgoHanded {
				handed = append(handed, handedName(h))
			}
			if !reflect.DeepEqual(handed, tc.wantHanded) {
				t.Errorf("handed = %v, want %v", handed, tc.wantHanded)
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
	scoped, _, _, bounded := cgoLimits([]*packages.Package{app}, nil)
	want := []string{"", "pkg:golang/example.com/dep", "pkg:golang/example.com/other", stdlibPURL}
	if !bounded || len(scoped) != 1 || !reflect.DeepEqual(scoped[0].Targets, want) {
		t.Errorf("scoped = %+v bounded = %v, want targets %v", scoped, bounded, want)
	}
}

// TestCallGraph_HandedValueMethodsAreRoots: C calls the exported methods of a value handed to a cgo
// package, so they are roots of the call graph, and the limit's Path states the narrowing.
func TestCallGraph_HandedValueMethodsAreRoots(t *testing.T) {
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("no C compiler")
	}
	const methods = "example.com/app/fsys/FS#"
	cases := []struct {
		name      string
		body      string
		libb      string
		wantRoots []string
		wantPaths []string
	}{
		{"a value handed over", "\tcgolib.Mount(&fsys.FS{})\n", "", []string{methods + "Serve().", methods + "Stat()."}, []string{
			"no call in this build hands example.com/cgolib a Go function or interface value other than example.com/app/fsys.FS, so its C code can reach only 3 modules and the methods of example.com/app/fsys.FS"}},
		{"nothing handed over", "\tc.Close()\n", "", nil, []string{
			"no call in this build hands example.com/cgolib a Go function or interface value, so its C code can reach only 3 modules"}},
		{"a function value handed over", "\tc.RegisterHook(func() {})\n", "", nil, []string{"example.com/cgolib"}},
		{"two cgo packages, a value handed to one", "\tcgolib.Mount(&fsys.FS{})\n", cbSecond, []string{methods + "Serve().", methods + "Stat()."}, []string{
			"no call in this build hands example.com/cgolib a Go function or interface value other than example.com/app/fsys.FS, so its C code can reach only 4 modules and the methods of example.com/app/fsys.FS",
			"no call in this build hands example.com/libb a Go function or interface value, so its C code can reach only 4 modules"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CGO_ENABLED", "1")
			t.Setenv("GOFLAGS", "-mod=mod")
			t.Setenv("GOPROXY", "off")
			dir := writeCbTree(t, map[string]string{"cgolib/c.go": cbCompiled, "cgolib/hook.go": cbExport, "app/fsys/f.go": cbFS, "libb/b.go": tc.libb, "app/main.go": handing(tc.body)})
			res, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			cg, err := callGraphDeclaring(res, "vta", declaredRunWide)
			if err != nil {
				t.Fatal(err)
			}
			var roots []string
			for _, r := range cg.Roots {
				if i := strings.Index(r.SCIP, methods); i >= 0 {
					roots = append(roots, r.SCIP[i:])
				}
			}
			if !reflect.DeepEqual(roots, tc.wantRoots) {
				t.Errorf("method roots = %v, want %v (all roots %v)", roots, tc.wantRoots, cg.Roots)
			}
			var paths []string
			for _, s := range cg.Partiality.Scoped {
				if s.Reason == "cgo" {
					paths = append(paths, s.Path)
				}
			}
			if !reflect.DeepEqual(paths, tc.wantPaths) {
				t.Errorf("cgo limit paths = %q, want %q", paths, tc.wantPaths)
			}
		})
	}
}
