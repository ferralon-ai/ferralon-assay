package goanalysis

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/gob"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/tools/go/packages"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// lofResult is what one refutation of module meets in the left-out gate: whether it is withheld,
// and the engine's facts for each left-out file, by its path relative to the tree.
type lofResult struct {
	withheld bool
	engine   *lofEngine
	facts    map[string]*lofFacts
}

// lofRun loads dir as the build, under the load's own toolchain unless unknown is set, and puts a
// refutation of module, whose vulnerable symbols are symbols, through withholdForLeftOutFiles.
// prepare, when set, runs between the load and the gate.
func lofRun(t *testing.T, dir, module string, symbols map[string][]string, unknown bool, prepare func(*LoadResult)) lofResult {
	t.Helper()
	load, err := LoadProgram(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	load.buildGoVersion = load.goVersion
	release := load.buildRelease()
	if release == nil {
		t.Fatalf("no build release for %q", load.goVersion)
	}
	if unknown {
		release = nil
	}
	if prepare != nil {
		prepare(load)
	}
	env := append(os.Environ(), "GOWORK=off")
	var vulnerable []string
	for p := range symbols {
		vulnerable = append(vulnerable, p)
	}
	refuted := plugin.ReachabilityResult{
		Partiality: plugin.Complete(),
		Refutation: &plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/" + module},
	}
	scanned := vulnScan{imports: map[string][]string{module: vulnerable}, symbols: symbols}
	res := withholdForLeftOutFiles(context.Background(), refuted, scanned, load.Packages, release, dir, env)
	withheld := res.Refutation == nil
	if declared := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonExcludedFiles); declared != withheld {
		t.Errorf("excluded_files declared = %v, withheld = %v (partiality %+v)", declared, withheld, res.Partiality)
	}
	e := loadLofEngine(context.Background(), load.Packages, release, dir, env)
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	facts := map[string]*lofFacts{}
	for path := range e.Facts {
		f, _ := e.file(path)
		real, err := filepath.EvalSymlinks(path)
		if err != nil {
			real = path
		}
		if rel, err := filepath.Rel(root, real); err == nil && !strings.HasPrefix(rel, "..") {
			path = filepath.ToSlash(rel)
		}
		facts[path] = f
	}
	return lofResult{withheld: withheld, engine: e, facts: facts}
}

// TestLeftOutEngine_Constructs: each way code the build left out can run code of a module, and each
// thing its declaration closure cannot follow. The module example.com/v holds the vulnerable package
// example.com/v/vuln; a file built only under the lofalt tag is left out.
func TestLeftOutEngine_Constructs(t *testing.T) {
	base := map[string]string{
		// The go directive binds the toolchain (directivesBindToolchain): goDirectiveFloor is 22.
		"go.mod":    "module example.com/m\n\ngo 1.22.0\n\nrequire example.com/v v0.0.0\n\nreplace example.com/v => ./_v\n",
		"main.go":   "package main\n\nimport \"example.com/v/vuln\"\n\nfunc main() { vuln.Safe() }\n",
		"_v/go.mod": "module example.com/v\n\ngo 1.22\n",
		"_v/vuln/vuln.go": "package vuln\n\nfunc Bad() {}\n\nfunc Safe() {}\n\nfunc Variadic(xs ...int) {}\n\n" +
			"type T struct{}\n\nfunc (T) Bad() {}\n\nfunc (T) Safe() {}\n\ntype U struct{}\n\nfunc (U) Safe() {}\n\n" +
			"type P struct{}\n\nfunc (*P) Bad() {}\n",
		// lib is loaded, and nothing the build runs calls it.
		"lib/lib.go": "package lib\n\nimport \"example.com/v/vuln\"\n\n" +
			"func Make() interface{ Bad() } { return vuln.T{} }\n\n" +
			"func MakeSafe() interface{ Safe() } { return vuln.U{} }\n\n" +
			"func Apply(f func()) { f() }\n\n" +
			"type W struct{ vuln.T }\n\ntype Y struct{}\n",
	}
	off := func(body string) string { return "//go:build lofalt\n\n" + body }
	x := func(imports, body string) map[string]string {
		return map[string]string{"x.go": off("package main\n\nimport (\n" + imports + "\n)\n\n" + body)}
	}
	// hook takes the symbol's address in loaded code.
	hook := map[string]string{"lib/hook.go": "package lib\n\nimport \"example.com/v/vuln\"\n\nvar Hook func()\n\nfunc Install() { Hook = vuln.Bad }\n"}
	vulnOnly := "\t\"example.com/v/vuln\""
	// newT makes a T where the left-out file names only the function.
	newT := map[string]string{"_v/vuln/new.go": "package vuln\n\nfunc NewT() *T { return &T{} }\n"}
	// um is a package the build does not load, whose method calls the symbol.
	um := map[string]string{"_v/um/um.go": "package um\n\nimport \"example.com/v/vuln\"\n\ntype T struct{}\n\nfunc (*T) Run() { vuln.Bad() }\n\nfunc Nop() {}\n"}
	libOnly := "\t\"example.com/m/lib\""
	bad := map[string][]string{"example.com/v/vuln": {"Bad", "T.Bad", "P.Bad", "Variadic"}}
	badFunc := map[string][]string{"example.com/v/vuln": {"Bad"}}
	cases := []struct {
		name     string
		files    map[string]string
		symbols  map[string][]string // bad when nil
		withheld bool
		item     string // the fail-closed item x.go's closure raises, when set
		unknown  bool   // the build's toolchain is not established
	}{
		{"nothing left out", nil, nil, false, "", false},
		// direct call / func ref
		{"a left-out init calls the symbol", x(vulnOnly, "func init() { vuln.Bad() }\n"), nil, true, "", false},
		{"a left-out init calls another function of the vulnerable package", x(vulnOnly, "func init() { vuln.Safe() }\n"), nil, false, "", false},
		{"a left-out init takes the symbol's value", x(vulnOnly, "var f = vuln.Bad\n"), nil, true, "", false},
		{"a package documentation file calls the symbol", map[string]string{
			"doc.go": "package documentation\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Bad() }\n",
		}, nil, false, "", false},
		{"a left-out file not named _test.go with a _test clause calls the symbol", map[string]string{
			"x.go": off("package main_test\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Bad() }\n"),
		}, nil, true, "", false},
		{"no loaded package imports the vulnerable one and a left-out file of a directory holding only _test clauses calls the symbol", map[string]string{
			"main.go":    "package main\n\nfunc main() {}\n",
			"lib/lib.go": "package lib\n",
			"ext/x.go":   off("package ext_test\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Bad() }\n"),
		}, nil, true, "", false},
		{"the vulnerable package is not loaded and a left-out file calls the symbol", map[string]string{
			"main.go": "package main\n\nfunc main() {}\n",
			"x.go":    off("package main\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Bad() }\n"),
		}, nil, true, "", false},
		{"the vulnerable package is not loaded and a left-out file calls only another function", map[string]string{
			"main.go": "package main\n\nfunc main() {}\n",
			"x.go":    off("package main\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Safe() }\n"),
		}, nil, false, "", false},
		// method call x.m(), by name
		{"a left-out init calls the symbol's method name on a value loaded code made", x(libOnly, "func init() { lib.Make().Bad() }\n"), nil, true, "", false},
		{"a left-out init calls another method name on a value loaded code made", x(libOnly, "func init() { lib.MakeSafe().Safe() }\n"), nil, false, "", false},
		{"a left-out init hands the symbol's type to a method of a value loaded code made", merge(x("\t\"example.com/m/lib\"\n\t\"example.com/v/vuln\"", "func init() { lib.MakeTaker().Take(vuln.T{}) }\n"), map[string]string{
			"lib/take.go": "package lib\n\ntype taker struct{}\n\nfunc (taker) Take(v any) { v.(interface{ Bad() }).Bad() }\n\nfunc MakeTaker() interface{ Take(any) } { return taker{} }\n",
		}), nil, true, "", false},
		// interface dispatch: a type whose method set holds the symbol
		{"a left-out init names a type whose method set holds the symbol", x(vulnOnly, "func init() { var v vuln.T; _ = v }\n"), nil, true, "", false},
		{"a left-out init names a type whose method set does not", x(vulnOnly, "func init() { var v vuln.U; _ = v }\n"), nil, false, "", false},
		// embedding: promoted methods, and a variant's change to a loaded type's method set
		{"a left-out init calls the symbol promoted through an embedded field", x(vulnOnly, "type w struct{ vuln.T }\n\nfunc init() { var v w; v.Bad() }\n"), nil, true, "", false},
		{"a left-out file adds a method to a loaded type that embeds the symbol's type", map[string]string{
			"lib/w_alt.go": off("package lib\n\nfunc (W) Extra() {}\n"),
		}, nil, true, "", false},
		{"a left-out file adds a method to a loaded type whose method set holds no symbol", map[string]string{
			"lib/y_alt.go": off("package lib\n\nfunc (Y) Extra() {}\n"),
		}, nil, false, "", false},
		// method values / func values
		{"a left-out init calls a loaded function value while the symbol's address is taken", merge(x(libOnly, "func init() { lib.Install(); lib.Hook() }\n"), hook), nil, true, "", false},
		{"a left-out init installs the hook and never calls a function value", merge(x(libOnly, "func init() { lib.Install() }\n"), hook), badFunc, false, "", false},
		{"a left-out init routes a function value into loaded code while the symbol is a method", x(libOnly, "func init() { lib.Apply(func() {}) }\n"), nil, true, "", false},
		{"a left-out init routes a function value into loaded code, the symbol a function no one takes", x(libOnly, "func init() { lib.Apply(func() {}) }\n"), badFunc, false, "", false},
		// init / var initializers
		{"a left-out variable's initializer calls the symbol", x(vulnOnly, "var v = f()\n\nfunc f() int { vuln.Bad(); return 0 }\n"), nil, true, "", false},
		{"a left-out file's function nothing calls calls the symbol", x(vulnOnly, "func unused() { vuln.Bad() }\n"), nil, true, "", false},
		// generics
		{"left-out generic code calls the symbol through a constraint", x(vulnOnly, "func call[X interface{ Bad() }](x X) { x.Bad() }\n\nfunc init() { call(vuln.T{}) }\n"), nil, true, "", false},
		{"left-out generic code with a receiver type parameter", x("", "type box[E any] struct{ e E }\n\nfunc (b box[E]) get() E { return b.e }\n\nfunc init() { _ = box[int]{}.get() }\n"), nil, false, "", false},
		// dot imports, aliases, shadowing
		{"a left-out init calls the symbol through a dot-import", x("\t. \"example.com/v/vuln\"", "func init() { Bad() }\n"), nil, true, "", false},
		{"a left-out init calls the symbol through an alias", x(vulnOnly, "type a = vuln.T\n\nfunc init() { var v a; v.Bad() }\n"), nil, true, "", false},
		{"a left-out init's locals shadow nothing it cannot resolve", x(vulnOnly, "func init() { Bad := vuln.Safe; Bad() }\n"), nil, false, "", false},
		{"a left-out init calls a variadic symbol with no arguments", x(vulnOnly, "func init() { vuln.Variadic() }\n"), nil, true, "", false},
		// linkname
		{"a left-out function pulls the symbol by linkname", x("\t_ \"unsafe\"\n\t_ \"example.com/v/vuln\"",
			"//go:linkname pulled example.com/v/vuln.Bad\nfunc pulled()\n\nfunc init() { pulled() }\n"), nil, true, "", false},
		{"a left-out function pulls by linkname a symbol nothing declares", x("\t_ \"unsafe\"\n\t_ \"example.com/v/vuln\"",
			"//go:linkname pulled example.com/v/vuln.Nowhere\nfunc pulled()\n\nfunc init() { pulled() }\n"), nil, true, lofLinkname, false},
		// The linker takes the dynamic import only when no Go code or assembly defines the symbol.
		{"a left-out file links by linkname a C symbol it imports", x("\t_ \"unsafe\"\n\t\"example.com/v/vuln\"",
			"//go:cgo_import_dynamic libc_puts puts \"libc.so\"\n\n//go:linkname libc_puts libc_puts\nvar libc_puts byte\n\nfunc init() { vuln.Safe() }\n"), nil, true, lofLinkname, false},
		{"a left-out file links by linkname a bare symbol nothing imports", x("\t_ \"unsafe\"\n\t\"example.com/v/vuln\"",
			"//go:linkname libc_puts libc_puts\nvar libc_puts byte\n\nfunc init() { vuln.Safe() }\n"), nil, true, lofLinkname, false},
		// asm
		{"a left-out bodyless function's assembly calls the symbol", merge(x(vulnOnly, "func asm()\n\nfunc init() { asm(); _ = vuln.Safe }\n"), map[string]string{
			"x_lofalt.s": "//go:build lofalt\n\n#include \"textflag.h\"\n\nTEXT ·asm(SB),NOSPLIT,$0\n\tCALL example.com∕v∕vuln·Bad(SB)\n\tRET\n",
		}), nil, true, "", false},
		{"a left-out bodyless function has no body anywhere", x(vulnOnly, "func asm()\n\nfunc init() { asm(); vuln.Safe() }\n"), nil, true, lofBodyless, false},
		{"left-out assembly references a symbol nothing declares", merge(x(vulnOnly, "func asm()\n\nfunc init() { asm(); vuln.Safe() }\n"), map[string]string{
			"x_lofalt.s": "//go:build lofalt\n\nTEXT ·asm(SB),0,$0\n\tCALL example.com∕v∕vuln·Nowhere(SB)\n\tRET\n",
		}), nil, true, lofAsmSymbol, false},
		// cgo
		{"a left-out cgo file's exported function calls the symbol", x("\t\"C\"\n\t\"example.com/v/vuln\"", "//export Exported\nfunc Exported() { vuln.Bad() }\n"), nil, true, "", false},
		{"a left-out cgo file calls C and another function", x("\t\"C\"\n\t\"example.com/v/vuln\"", "func init() { C.puts(nil); vuln.Safe() }\n"), nil, false, "", false},
		// reflection
		{"a left-out init calls MethodByName", x("\t\"reflect\"\n\t\"example.com/m/lib\"", "func init() { reflect.ValueOf(lib.MakeSafe()).MethodByName(\"Bad\").Call(nil) }\n"), nil, true, "", false},
		{"a left-out init calls MethodByName on a value loaded code made, never importing reflect", merge(x(libOnly, "func init() { lib.Reflected(lib.MakeSafe()).MethodByName(\"Bad\").Call(nil) }\n"), map[string]string{
			"lib/refl.go": "package lib\n\nimport \"reflect\"\n\nfunc Reflected(x any) reflect.Value { return reflect.ValueOf(x) }\n",
		}), nil, true, "", false},
		// a value routed into loaded code that calls through it, other than as an argument
		{"a left-out init stores the symbol's type in a loaded struct's field that loaded code calls", merge(x(vulnOnly+"\n"+libOnly, "func init() { lib.Box{X: vuln.NewT()}.Run() }\n"), newT, map[string]string{
			"lib/box.go": "package lib\n\ntype Box struct{ X interface{ Bad() } }\n\nfunc (b Box) Run() { b.X.Bad() }\n",
		}), nil, true, "", false},
		{"a left-out init stores the symbol's type in a loaded variable that loaded code calls", merge(x(vulnOnly+"\n"+libOnly, "func init() { lib.Current = vuln.NewT(); lib.Fire() }\n"), newT, map[string]string{
			"lib/current.go": "package lib\n\nvar Current interface{ Bad() }\n\nfunc Fire() { Current.Bad() }\n",
		}), nil, true, "", false},
		// what an unloaded package the file enters roots: its //export functions and initializers
		{"a left-out file enters an unloaded cgo package whose exported function calls the symbol", merge(x("\t_ \"example.com/v/cg\"", ""), map[string]string{
			"_v/cg/cg.go": "package cg\n\nimport \"C\"\n\nimport \"example.com/v/vuln\"\n\n//export Exported\nfunc Exported() { vuln.Bad() }\n",
		}), nil, true, "", false},
		{"a left-out file enters an unloaded package whose variable initializer calls the symbol", merge(x("\t_ \"example.com/v/initv\"", ""), map[string]string{
			"_v/initv/initv.go": "package initv\n\nimport \"example.com/v/vuln\"\n\nvar v = f()\n\nfunc f() int { vuln.Bad(); return 0 }\n",
		}), nil, true, "", false},
		// fail-closed items
		{"a left-out file does not parse", x(vulnOnly, "func init() {\n"), nil, true, lofParseError, false},
		{"a left-out file imports a path nothing provides", x("\t\"example.org/nowhere\"", "func init() { nowhere.Call() }\n"), nil, true, lofUnresolvedImport, false},
		{"a left-out init calls a name the vulnerable package does not declare", x(vulnOnly, "func init() { vuln.Nowhere() }\n"), nil, true, lofUnresolvedName, false},
		// build constraints the build's toolchain fixes
		{"a left-out file for gccgo calls the symbol", map[string]string{
			"x.go": "//go:build gccgo\n\npackage main\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Bad() }\n",
		}, nil, false, "", false},
		{"a left-out file for every compiler but gc calls the symbol", map[string]string{
			"x.go": "//go:build !gc\n\npackage main\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Bad() }\n",
		}, nil, false, "", false},
		{"a left-out file for another OS calls the symbol", map[string]string{
			"x_plan9.go": "package main\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Bad() }\n",
		}, nil, true, "", false},
		{"toolchain unknown: a file for releases before the go directive's", map[string]string{
			"x.go": "//go:build !go1.22\n\npackage main\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Bad() }\n",
		}, nil, false, "", true},
		{"toolchain unknown: a file for releases before one after the go directive's", map[string]string{
			"x.go": "//go:build !go1.23\n\npackage main\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Bad() }\n",
		}, nil, true, "", true},
		// A go directive without a patch release does not bind the toolchain, so it fixes no release tag.
		{"toolchain unknown: a file for releases before a go directive that does not bind the toolchain", map[string]string{
			"go.mod": "module example.com/m\n\ngo 1.22\n\nrequire example.com/v v0.0.0\n\nreplace example.com/v => ./_v\n",
			"x.go":   "//go:build !go1.22\n\npackage main\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Bad() }\n",
		}, nil, true, "", true},
		{"a left-out file for no compiler but gc under more tags than are judged", map[string]string{
			"x.go": "//go:build !gc && t1 && t2 && t3 && t4 && t5 && t6 && t7 && t8 && t9 && t10 && t11 && t12 && t13 && t14 && t15 && t16\n\n" +
				"package main\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Bad() }\n",
		}, nil, true, "", false},
		{"a left-out file whose constraint no build satisfies", map[string]string{
			"x.go": "//go:build gc && !gc\n\npackage main\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Bad() }\n",
		}, nil, true, "", false},
		{"a left-out function pulls the symbol's pointer method by linkname", x("\t_ \"unsafe\"\n\t_ \"example.com/v/vuln\"",
			"//go:linkname pulled example.com/v/vuln.(*P).Bad\nfunc pulled(*struct{})\n\nfunc init() { pulled(nil) }\n"), nil, true, "", false},
		{"a left-out function pulls by linkname a method of an unloaded package that calls the symbol", merge(x("\t_ \"unsafe\"\n\t_ \"example.com/v/um\"",
			"//go:linkname pulled example.com/v/um.(*T).Run\nfunc pulled(*struct{})\n\nfunc init() { pulled(nil) }\n"), um), badFunc, true, "", false},
		{"a left-out file holds a malformed linkname directive", x("\t_ \"unsafe\"\n"+vulnOnly,
			"//go:linkname local remote extra\nvar local byte\n\nfunc init() { vuln.Safe() }\n"), badFunc, true, lofLinkname, false},
		// a loaded method whose receiver can carry a func in, and a result whose methods return one
		{"a left-out function pulls by linkname a loaded method whose receiver takes a func", merge(x("\t_ \"unsafe\"\n"+vulnOnly,
			"//go:linkname pulled example.com/m/lib.H.Do\nfunc pulled()\n\nfunc init() { pulled(); vuln.Safe() }\n"), map[string]string{
			"lib/h.go": "package lib\n\ntype H func(func())\n\nfunc (h H) Do() {}\n",
		}), nil, true, "", false},
		{"a left-out init calls a loaded function whose interface result returns a func that takes one", merge(x(libOnly+"\n"+vulnOnly,
			"func init() { _ = lib.Make2(); vuln.Safe() }\n"), map[string]string{
			"lib/i2.go": "package lib\n\ntype I2 interface{ Get() func(func()) }\n\nfunc Make2() I2 { return nil }\n",
		}), nil, true, "", false},
		// dot imports resolve through the imported package
		{"a left-out init calls another function through a dot-import", x("\t. \"example.com/v/vuln\"", "func init() { Safe() }\n"), badFunc, false, "", false},
		// what the file enters: a package nothing provides, one that does not parse, and an unloaded package's imports
		{"a left-out file blank-imports a path nothing provides", x("\t_ \"example.org/nowhere\"\n"+vulnOnly, "func init() { vuln.Safe() }\n"), badFunc, true, lofUnresolvedImport, false},
		{"a left-out file enters an unloaded package one of whose files does not parse", merge(x("\t_ \"example.com/v/pe\"\n"+vulnOnly, "func init() { vuln.Safe() }\n"), map[string]string{
			"_v/pe/pe.go":     "package pe\n",
			"_v/pe/broken.go": "package pe\n\nfunc (\n",
		}), badFunc, true, lofParseError, false},
		{"a left-out file enters an unloaded package one of whose build constraints does not parse", merge(x("\t_ \"example.com/v/pc\"\n"+vulnOnly, "func init() { vuln.Safe() }\n"), map[string]string{
			"_v/pc/pc.go":  "package pc\n",
			"_v/pc/bad.go": "//go:build a\n//go:build b\n\npackage pc\n",
		}), badFunc, true, lofParseError, false},
		{"a left-out file enters an unloaded package one of whose assembly build constraints does not parse", merge(x("\t_ \"example.com/v/pa\"\n"+vulnOnly, "func init() { vuln.Safe() }\n"), map[string]string{
			"_v/pa/pa.go": "package pa\n",
			"_v/pa/pa.s":  "//go:build a\n//go:build b\n",
		}), badFunc, true, lofParseError, false},
		{"a left-out file enters an unloaded package whose file imports a package whose init calls the symbol", merge(x("\t_ \"example.com/v/um2\"", ""), map[string]string{
			"_v/um2/um2.go": "package um2\n\nimport _ \"example.com/v/w2\"\n",
			"_v/w2/w2.go":   "package w2\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Bad() }\n",
		}), badFunc, true, "", false},
		// methods of unloaded types: of a type the closure names, and by a name the closure calls
		{"a left-out init names an unloaded type whose method calls the symbol", merge(x("\t\"example.com/v/um\"", "func init() { var v um.T; _ = v }\n"), um), badFunc, true, "", false},
		{"a left-out init calls by name a method of an unloaded package it entered", merge(x("\t_ \"example.com/v/um\"",
			"type runner interface{ Run() }\n\nfunc init() { var v runner; v.Run() }\n"), um), badFunc, true, "", false},
		{"left-out assembly enters an unloaded package after the file called its method's name", merge(x(vulnOnly,
			"type runner interface{ Run() }\n\nfunc init() { var v runner; v.Run(); vuln.Safe() }\n\nfunc asm()\n"), um, map[string]string{
			"x_lofalt.s": "//go:build lofalt\n\nTEXT ·asm(SB),0,$0\n\tCALL example.com∕v∕um·Nop(SB)\n\tRET\n",
		}), badFunc, true, "", false},
		// dynamic calls and reflection, while the symbol's address is taken
		{"a left-out init calls a local function value while the symbol's address is taken", merge(x(libOnly,
			"func init() { lib.Install(); f := lib.Install; f() }\n"), hook), badFunc, true, "", false},
		{"a left-out init selects reflect's Call name while the symbol's address is taken", merge(x(libOnly,
			"type s struct{}\n\nfunc (s) Call() {}\n\nfunc init() { lib.Install(); var v s; _ = v.Call }\n"), hook), badFunc, true, "", false},
		{"left-out assembly calls a foreign symbol while the symbol's address is taken", merge(x(libOnly, "func asm()\n\nfunc init() { lib.Install(); asm() }\n"), hook, map[string]string{
			"x_lofalt.s": "//go:build lofalt\n\nTEXT ·asm(SB),0,$0\n\tCALL foreign(SB)\n\tRET\n",
		}), badFunc, true, "", false},
		{"left-out assembly calls through a register while the symbol's address is taken", merge(x(libOnly, "func asm()\n\nfunc init() { lib.Install(); asm() }\n"), hook, map[string]string{
			"x_lofalt.s": "//go:build lofalt\n\nTEXT ·asm(SB),0,$0\n\tCALL AX\n\tRET\n",
		}), badFunc, true, "", false},
		{"a left-out init reads a loaded variable while the symbol's address is taken", merge(x(libOnly, "func init() { lib.Install(); _ = lib.N }\n"), hook, map[string]string{
			"lib/n.go": "package lib\n\nvar N int\n",
		}), badFunc, true, "", false},
		{"a left-out init calls by name a loaded method that calls the symbol", merge(x("", "type runner interface{ Run() }\n\nfunc init() { var v runner; v.Run() }\n"), map[string]string{
			"lib/c.go": "package lib\n\nimport \"example.com/v/vuln\"\n\ntype C struct{}\n\nfunc (C) Run() { vuln.Bad() }\n",
		}), badFunc, true, "", false},
		// The receiver's type parameter shadows the type's name, so the closure never names the type.
		{"a left-out method on a loaded generic type whose method set holds the symbol", map[string]string{
			"lib/g.go":     "package lib\n\nimport \"example.com/v/vuln\"\n\ntype G[E any] struct{ vuln.T }\n",
			"lib/g_alt.go": off("package lib\n\nfunc (G[G]) Extra() {}\n"),
		}, nil, true, "", false},
		// The build's call x.m() reaches b.m in the class-hierarchy graph (b is boxed into sink) but
		// not in the type-propagation one, where only a flows into x.
		{"a left-out init names a type whose method only the class-hierarchy graph reaches", map[string]string{
			"main.go": "package main\n\nimport \"example.com/v/vuln\"\n\ntype i interface{ m() }\n\ntype a struct{}\n\nfunc (a) m() {}\n\ntype b struct{}\n\n" +
				"func (b) m() { vuln.Bad() }\n\nfunc run(x i) { x.m() }\n\nvar sink any = b{}\n\nfunc main() { vuln.Safe(); run(a{}) }\n",
			"x.go": off("package main\n\nfunc init() { var v b; _ = v }\n"),
		}, badFunc, true, "", false},
		// assembly bodies: of a function nothing calls, of a symbol only assembly declares, and file-local ones
		{"a left-out bodyless function nothing calls has assembly that calls the symbol", merge(x(vulnOnly, "func asm()\n\nfunc init() { vuln.Safe() }\n"), map[string]string{
			"x_lofalt.s": "//go:build lofalt\n\nTEXT ·asm(SB),0,$0\n\tCALL example.com∕v∕vuln·Bad(SB)\n\tRET\n",
		}), badFunc, true, "", false},
		{"left-out assembly calls an assembly-only symbol that calls the symbol", merge(x(vulnOnly, "func asm()\n\nfunc init() { vuln.Safe() }\n"), map[string]string{
			"x_lofalt.s": "//go:build lofalt\n\nTEXT ·asm(SB),0,$0\n\tCALL ·helper(SB)\n\tRET\n\nTEXT ·helper(SB),0,$0\n\tCALL example.com∕v∕vuln·Bad(SB)\n\tRET\n",
		}), badFunc, true, "", false},
		{"left-out assembly calls a file-local symbol that calls the symbol", merge(x(vulnOnly, "func asm()\n\nfunc init() { vuln.Safe() }\n"), map[string]string{
			"x_lofalt.s": "//go:build lofalt\n\nTEXT ·asm(SB),0,$0\n\tCALL helper<>(SB)\n\tRET\n\nTEXT helper<>(SB),0,$0\n\tCALL example.com∕v∕vuln·Bad(SB)\n\tRET\n",
		}), badFunc, true, "", false},
		{"left-out assembly calls a file-local symbol nothing declares", merge(x(vulnOnly, "func asm()\n\nfunc init() { vuln.Safe() }\n"), map[string]string{
			"x_lofalt.s": "//go:build lofalt\n\nTEXT ·asm(SB),0,$0\n\tCALL helper<>(SB)\n\tRET\n",
		}), badFunc, true, lofAsmSymbol, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			symbols := tc.symbols
			if symbols == nil {
				symbols = bad
			}
			dir := writeTree(t, merge(base, tc.files))
			got := lofRun(t, dir, "example.com/v", symbols, tc.unknown, nil)
			if got.withheld != tc.withheld {
				t.Fatalf("withheld = %v, want %v (facts %s)", got.withheld, tc.withheld, lofDescribe(got))
			}
			if tc.item != "" {
				if f := lofFileWith(got, tc.item); f == "" {
					t.Errorf("no left-out file fails closed on %s (facts %s)", tc.item, lofDescribe(got))
				}
			}
		})
	}
}

// TestLeftOutEngine_Uncompilable: a left-out file naming an identifier no variant of its package
// declares compiles in no build and is dropped, only when go/types confirms it on the file alone and
// nothing the check did not see could supply the name; otherwise the file fails closed.
func TestLeftOutEngine_Uncompilable(t *testing.T) {
	base := map[string]string{
		"go.mod":          "module example.com/m\n\ngo 1.22\n\nrequire example.com/v v0.0.0\n\nreplace example.com/v => ./_v\n",
		"main.go":         "package main\n\nimport \"example.com/v/vuln\"\n\nfunc main() { vuln.Safe() }\n",
		"_v/go.mod":       "module example.com/v\n\ngo 1.22\n",
		"_v/vuln/vuln.go": "package vuln\n\nfunc Bad() {}\n\nfunc Safe() {}\n",
		// x.go calls the symbol, and names helper, which no file the walk reads declares.
		"x.go": "//go:build lofalt\n\npackage main\n\nimport \"example.com/v/vuln\"\n\nfunc init() { helper(); vuln.Bad() }\n",
	}
	// In a cached row example.com/v is read from the module cache, outside the build's tree, and the
	// left-out file is y.go of the vulnerable package itself.
	cachedBase := map[string]string{
		"x.go":         "package main\n",
		"_v/vuln/y.go": "//go:build lofalt\n\npackage vuln\n\nfunc init() { helper(); Bad() }\n",
	}
	const cachedMod = "mc/example.com/v@v0.0.0/"
	relocate := func(files map[string]string) map[string]string {
		out := map[string]string{}
		for name, body := range files {
			if rest, ok := strings.CutPrefix(name, "_v/"); ok {
				out[cachedMod+rest] = body
			} else {
				out["m/"+name] = body
			}
		}
		out["m/go.mod"] = strings.Replace(out["m/go.mod"], "./_v", "../"+strings.TrimSuffix(cachedMod, "/"), 1)
		return out
	}
	bad := map[string][]string{"example.com/v/vuln": {"Bad"}}
	strs := map[string]string{
		"main.go": "package main\n\nimport (\n\t\"strings\"\n\n\t\"example.com/v/vuln\"\n)\n\nfunc main() { _ = strings.ToUpper(\"x\"); vuln.Safe() }\n",
	}
	cases := []struct {
		name     string
		files    map[string]string
		cached   bool   // example.com/v lies in the module cache
		unread   string // a file made unreadable after the load
		modcache string // GOMODCACHE for the engine, set after the load: "mc" for a cached row when unset
		withheld bool
		item     string
		dropped  string // the file dropped: x.go, or y.go in a cached row, when unset
	}{
		// Source outside the module cache and the toolchain may gain a file before it compiles.
		{"nothing declares the name in the main module", nil, false, "", "", true, lofUnresolvedName, ""},
		{"the package has a generated file", map[string]string{
			"gen.go": "// Code generated by hand. DO NOT EDIT.\n\npackage main\n",
		}, false, "", "", true, lofUnresolvedName, ""},
		{"the package has a go:generate directive", map[string]string{
			"gen.go": "package main\n\n//go:generate stringer -type=kind\n",
		}, false, "", "", true, lofUnresolvedName, ""},
		{"a module-cache package read from another cache", nil, true, "", "_elsewhere", true, lofUnresolvedName, ""},

		{"nothing declares the name in a module-cache package: the file never compiles", nil, true, "", "", false, "", ""},
		{"a module-cache package has a generated file", map[string]string{
			"_v/vuln/gen.go": "// Code generated by hand. DO NOT EDIT.\n\npackage vuln\n",
		}, true, "", "", false, "", ""},
		{"only a file for another compiler declares the name", map[string]string{
			"_v/vuln/helper_gccgo.go": "//go:build gccgo\n\npackage vuln\n\nfunc helper() {}\n",
		}, true, "", "", true, lofUnresolvedName, ""},
		{"only an ignored file declares the name", map[string]string{
			"_v/vuln/helper.go": "//go:build ignore\n\npackage vuln\n\nfunc helper() {}\n",
		}, true, "", "", true, lofUnresolvedName, ""},
		{"the package has a cgo file, which generates no such name", map[string]string{
			"_v/vuln/c.go": "//go:build lofalt\n\npackage vuln\n\nimport \"C\"\n",
		}, true, "", "", false, "", ""},
		{"the package has a cgo file and the name is one cgo could generate", map[string]string{
			"_v/vuln/c.go": "//go:build lofalt\n\npackage vuln\n\nimport \"C\"\n",
			"_v/vuln/y.go": "//go:build lofalt\n\npackage vuln\n\nfunc init() { _helper(); Bad() }\n",
		}, true, "", "", true, lofUnresolvedName, ""},
		{"only a file that never compiles declares the name", map[string]string{
			"_v/vuln/z.go": "//go:build lofalt\n\npackage vuln\n\nfunc helper() { nowhere() }\n",
		}, true, "", "", false, "", ""},
		{"the package has a SWIG interface", map[string]string{
			"_v/vuln/x.swig": "%module x\n",
		}, true, "", "", true, lofUnresolvedName, ""},
		{"a file of the package cannot be read", map[string]string{
			"_v/vuln/z.go": "//go:build lofalt\n\npackage vuln\n",
		}, true, "_v/vuln/z.go", "", true, lofUnresolvedName, ""},
		{"a file the build compiled cannot be read", map[string]string{
			"_v/vuln/w.go": "package vuln\n",
		}, true, "_v/vuln/w.go", "", true, lofUnresolvedName, ""},
		{"a file of the package has a build constraint that does not parse", map[string]string{
			"_v/vuln/z.go": "//go:build lofalt\n//go:build ignore\n\npackage vuln\n",
		}, true, "", "", true, lofUnresolvedName, ""},
		{"an ignored file of the package does not parse", map[string]string{
			"_v/vuln/z.go": "//go:build ignore\n\npackage vuln\n\nfunc (\n",
		}, true, "", "", true, lofUnresolvedName, ""},
		{"the file has another type error", map[string]string{
			"_v/vuln/y.go": "//go:build lofalt\n\npackage vuln\n\nfunc init() { helper(); var n int = \"s\"; _ = n; Bad() }\n",
		}, true, "", "", true, lofVariantTypecheck, ""},
		{"the file dot-imports a package", map[string]string{
			"_v/vuln/y.go": "//go:build lofalt\n\npackage vuln\n\nimport . \"strings\"\n\nfunc init() { helper(); _ = ToUpper; Bad() }\n",
		}, true, "", "", true, lofUnresolvedName, ""},
		// go/types never evaluates the arguments of a generic type it could not import, so it
		// reports nothing about helper.
		{"the name is an argument of a generic type from a package the build did not load", map[string]string{
			"_v/gen/gen.go": "package gen\n\ntype T[X any] struct{}\n",
			"_v/vuln/y.go":  "//go:build lofalt\n\npackage vuln\n\nimport \"example.com/v/gen\"\n\nvar _ gen.T[helper]\n\nfunc init() { Bad() }\n",
		}, true, "", "", true, lofVariantTypecheck, ""},

		// A qualified name the standard library does not declare, in any variant.
		{"a loaded standard-library package declares no such name", merge(strs, map[string]string{
			"x.go": "//go:build lofalt\n\npackage main\n\nimport (\n\t\"strings\"\n\n\t\"example.com/v/vuln\"\n)\n\nfunc init() { strings.NoSuchName(); vuln.Bad() }\n",
		}), false, "", "", false, "", ""},
		{"the standard-library name alone proves it, beside a bare name nothing declares", merge(strs, map[string]string{
			"x.go": "//go:build lofalt\n\npackage main\n\nimport (\n\t\"strings\"\n\n\t\"example.com/v/vuln\"\n)\n\nfunc init() { helper(); strings.NoSuchName(); vuln.Bad() }\n",
		}), false, "", "", false, "", ""},
		{"the standard-library name, and another type error", merge(strs, map[string]string{
			"x.go": "//go:build lofalt\n\npackage main\n\nimport (\n\t\"strings\"\n\n\t\"example.com/v/vuln\"\n)\n\nfunc init() { strings.NoSuchName(); var n int = \"s\"; _ = n; vuln.Bad() }\n",
		}), false, "", "", true, lofVariantTypecheck, ""},
		// The checker is given the build's sync: the embedded Mutex's Lock is no error of its own.
		{"the standard-library name, beside a use of another loaded package", merge(strs, map[string]string{
			"main.go": "package main\n\nimport (\n\t\"strings\"\n\t\"sync\"\n\n\t\"example.com/v/vuln\"\n)\n\nvar mu sync.Mutex\n\nfunc main() { mu.Lock(); _ = strings.ToUpper(\"x\"); vuln.Safe() }\n",
			"x.go":    "//go:build lofalt\n\npackage main\n\nimport (\n\t\"strings\"\n\t\"sync\"\n\n\t\"example.com/v/vuln\"\n)\n\ntype locked struct{ sync.Mutex }\n\nfunc init() { var l locked; l.Lock(); strings.NoSuchName(); vuln.Bad() }\n",
		}), false, "", "", false, "", ""},
		{"the standard-library name, beside an array length another file declares", merge(strs, map[string]string{
			"size.go": "package main\n\nconst size = 4\n",
			"x.go":    "//go:build lofalt\n\npackage main\n\nimport (\n\t\"strings\"\n\n\t\"example.com/v/vuln\"\n)\n\nvar buf [size]byte\n\nfunc init() { _ = buf; strings.NoSuchName(); vuln.Bad() }\n",
		}), false, "", "", false, "", ""},
		// The receiver's type parameter shadows the import: the file compiles.
		{"a receiver's type parameter is named for an import and selects a method of its constraint", merge(strs, map[string]string{
			"x.go": "//go:build lofalt\n\npackage main\n\nimport (\n\t\"strings\"\n\n\t\"example.com/v/vuln\"\n)\n\n" +
				"type namer interface{ NoSuchName() }\n\ntype r[T namer] struct{}\n\nfunc (r[strings]) m() { _ = strings.NoSuchName }\n\n" +
				"func init() { _ = strings.ToUpper; vuln.Bad() }\n",
		}), false, "", "", true, lofVariantTypecheck, ""},
		{"a standard-library package the build did not load", map[string]string{
			"x.go": "//go:build lofalt\n\npackage main\n\nimport (\n\t\"go/doc/comment\"\n\n\t\"example.com/v/vuln\"\n)\n\nfunc init() { comment.NoSuchName(); vuln.Bad() }\n",
		}, false, "", "", true, lofUnresolvedName, ""},
		{"a standard-library name cgo could generate", merge(strs, map[string]string{
			"x.go": "//go:build lofalt\n\npackage main\n\nimport (\n\t\"strings\"\n\n\t\"example.com/v/vuln\"\n)\n\nfunc init() { strings._NoSuchName(); vuln.Bad() }\n",
		}), false, "", "", true, lofUnresolvedName, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := merge(base, tc.files)
			if tc.cached {
				tree = relocate(merge(merge(base, cachedBase), tc.files))
			}
			root := writeTree(t, tree)
			dir, modcache := root, tc.modcache
			if tc.cached {
				dir = filepath.Join(root, "m")
				if modcache == "" {
					modcache = "mc"
				}
			}
			var prepares []func(*LoadResult)
			if tc.unread != "" {
				path := filepath.Join(dir, tc.unread)
				if rest, ok := strings.CutPrefix(tc.unread, "_v/"); ok && tc.cached {
					path = filepath.Join(root, cachedMod, rest)
				}
				prepares = append(prepares, func(*LoadResult) {
					if err := os.Chmod(path, 0); err != nil {
						t.Fatal(err)
					}
				})
				t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
			}
			if modcache != "" {
				prepares = append(prepares, func(*LoadResult) { t.Setenv("GOMODCACHE", filepath.Join(root, modcache)) })
			}
			got := lofRun(t, dir, "example.com/v", bad, false, func(l *LoadResult) {
				for _, p := range prepares {
					p(l)
				}
			})
			if got.withheld != tc.withheld {
				t.Fatalf("withheld = %v, want %v (facts %s)", got.withheld, tc.withheld, lofDescribe(got))
			}
			if tc.item != "" && lofFileWith(got, tc.item) == "" {
				t.Errorf("no left-out file fails closed on %s (facts %s)", tc.item, lofDescribe(got))
			}
			if tc.item == "" {
				want := tc.dropped
				switch {
				case want != "":
				case tc.cached:
					want = "vuln/y.go"
				default:
					want = "x.go"
				}
				var f *lofFacts
				for path, ff := range got.facts {
					if path == want || tc.cached && strings.HasSuffix(filepath.ToSlash(path), "/"+cachedMod+want) {
						f = ff
					}
				}
				if f == nil || !f.Dropped {
					t.Errorf("%s not dropped (facts %s)", want, lofDescribe(got))
				}
			}
		})
	}
}

// TestLeftOutEngine_LoadedValues: a left-out file hands its own value to loaded code through a value
// loaded code made, which loaded code the build runs (lib.Fire) later calls the symbol through.
func TestLeftOutEngine_LoadedValues(t *testing.T) {
	base := map[string]string{
		"go.mod":          "module example.com/m\n\ngo 1.22.0\n\nrequire example.com/v v0.0.0\n\nreplace example.com/v => ./_v\n",
		"main.go":         "package main\n\nimport (\n\t\"example.com/m/lib\"\n\t\"example.com/v/vuln\"\n)\n\nfunc main() { vuln.Safe(); lib.Fire() }\n",
		"_v/go.mod":       "module example.com/v\n\ngo 1.22\n",
		"_v/vuln/vuln.go": "package vuln\n\nfunc Safe() {}\n\ntype T struct{}\n\nfunc NewT() *T { return &T{} }\n\nfunc (*T) Bad() {}\n",
		"lib/lib.go": "package lib\n\nimport \"unsafe\"\n\ntype I interface{ Bad() }\n\nvar hook I\n\n" +
			"func Fire() {\n\tif hook != nil {\n\t\thook.Bad()\n\t}\n\tif box.X != nil {\n\t\tbox.X.Bad()\n\t}\n}\n\n" +
			"type Reg struct{ n int }\n\nfunc (Reg) Register(h I) { hook = h }\n\nfunc (Reg) Len() int { return 0 }\n\nfunc Default() *Reg { return &Reg{} }\n\n" +
			"type setter struct{ n int }\n\nfunc (setter) Set(v any) { hook, _ = v.(I) }\n\nfunc Any() any { return setter{} }\n\n" +
			"func AnyF() any { return func(v any) { hook, _ = v.(I) } }\n\n" +
			"func H() func() func(I) { return func() func(I) { return func(i I) { hook = i } } }\n\n" +
			"type Box struct{ X I }\n\nvar box = &Box{}\n\ntype Getter interface{ Box() *Box }\n\ntype g struct{ n int }\n\nfunc (g) Box() *Box { return box }\n\nfunc Get() Getter { return g{} }\n\n" +
			"func (Reg) AnyM() any { return func(v any) { hook, _ = v.(I) } }\n\nfunc (Reg) Thunk() func() any { return func() any { return func(v any) { hook, _ = v.(I) } } }\n\n" +
			"var ch = make(chan any, 1)\n\nfunc (Reg) AnyC() any { return ch }\n\nvar R Reg\n\nfunc Ptr(p unsafe.Pointer) { hook = *(*I)(p) }\n\n" +
			"type Taker interface{ Take(I) }\n\ntype Next interface{ Next() Taker }\n\ntype tk struct{ n int }\n\nfunc (tk) Take(i I) { hook = i }\n\nfunc (tk) Next() Taker { return tk{} }\n\nfunc Chain() Next { return tk{} }\n",
	}
	cases := []struct {
		name     string
		body     string
		withheld bool
	}{
		{"a method of a loaded type a loaded function returns", "func init() { lib.Default().Register(vuln.NewT()) }\n", true},
		{"a method of a loaded type the file names", "func init() { var r lib.Reg; r.Register(vuln.NewT()) }\n", true},
		{"a method of an any asserted to a file-local interface", "func init() { lib.Any().(interface{ Set(any) }).Set(vuln.NewT()) }\n", true},
		{"an any asserted to a func type", "func init() { lib.AnyF().(func(any))(vuln.NewT()) }\n", true},
		{"a func a returned func returns", "func init() { lib.H()()(vuln.NewT()) }\n", true},
		{"a field of what an interface's method returns", "func init() { lib.Get().Box().X = vuln.NewT() }\n", true},
		{"a method of what an interface's method returns", "func init() { lib.Chain().Next().Take(vuln.NewT()) }\n", true},
		{"an any a loaded method returns asserted to a func type", "func init() { lib.Default().AnyM().(func(any))(vuln.NewT()) }\n", true},
		{"an any a loaded method returns asserted to a channel", "func init() { lib.Default().AnyC().(chan any) <- vuln.NewT() }\n", true},
		{"a loaded method of a loaded variable", "func init() { lib.R.AnyM().(func(any))(vuln.NewT()) }\n", true},
		{"an any a loaded method's func result returns", "func init() { lib.Default().Thunk()().(func(any))(vuln.NewT()) }\n", true},
		{"a type switch on an any a loaded method returns", "func init() {\n\tswitch f := lib.Default().AnyM().(type) {\n\tcase func(any):\n\t\tf(vuln.NewT())\n\t}\n}\n", true},
		{"an unsafe.Pointer a loaded function takes", "func init() {\n\tvar i interface{ Bad() } = vuln.NewT()\n\tlib.Ptr(unsafe.Pointer(&i))\n}\n", true},
		{"a method no loaded type takes a value through", "func init() { _ = lib.Default().Len(); vuln.Safe() }\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			imp := ""
			if strings.Contains(tc.body, "unsafe.") {
				imp = "\t\"unsafe\"\n"
			}
			x := "//go:build lofalt\n\npackage main\n\nimport (\n\t\"example.com/m/lib\"\n\t\"example.com/v/vuln\"\n" + imp + ")\n\n" + tc.body
			dir := writeTree(t, merge(base, map[string]string{"x.go": x}))
			got := lofRun(t, dir, "example.com/v", map[string][]string{"example.com/v/vuln": {"T.Bad"}}, false, nil)
			if got.withheld != tc.withheld {
				t.Errorf("withheld = %v, want %v (facts %s)", got.withheld, tc.withheld, lofDescribe(got))
			}
		})
	}
}

// TestLofFixedSource: only the toolchain's source and a module-cache module version are fixed.
func TestLofEngineEncoding(t *testing.T) {
	e := &lofEngine{
		Strs:    []string{"", "p", "p\x00F", "M", "héllo"},
		Nodes:   []lofNode{{Pkg: 1, Name: 2, Sym: 2, M1: -1, M2: -1, F0: true}, {Pkg: 1, Name: 3, Sym: 4, M1: 3, M2: -1, Addr: true, FT: true, Synth: true}},
		In0:     [][]int32{{1}, nil},
		InT:     [][]int32{{1, 0}},
		Decls:   [][4]int32{{1, 2, 2, -1}, {1, 4, 4, 3}},
		FailStd: lofUnknownToolchain,
		Facts:   map[string][]byte{"x.go": {1, 2, 3}},
	}
	b, err := e.encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeLofEngine(b)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Strs, e.Strs) || !slices.Equal(got.Nodes, e.Nodes) || !slices.Equal(got.Decls, e.Decls) ||
		got.Fail != e.Fail || got.FailStd != e.FailStd || !slices.Equal(got.Facts["x.go"], e.Facts["x.go"]) || len(got.Facts) != 1 {
		t.Fatalf("decoded %+v, want %+v", got, e)
	}
	for _, in := range [][2][][]int32{{got.In0, e.In0}, {got.InT, e.InT}} {
		if !slices.EqualFunc(in[0], in[1], func(a, b []int32) bool { return slices.Equal(a, b) }) {
			t.Fatalf("callers %v, want %v", in[0], in[1])
		}
	}

	// A truncated or overlong graph is an error, never a panic or a partial engine.
	var w lofWire
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&w); err != nil {
		t.Fatal(err)
	}
	graph := w.Graph
	for _, g := range [][]byte{graph[:len(graph)-1], graph[:len(graph)/2], graph[:3], append(slices.Clone(graph), 0)} {
		w.Graph = g
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(w); err != nil {
			t.Fatal(err)
		}
		if _, err := decodeLofEngine(buf.Bytes()); err == nil {
			t.Fatalf("graph of %d bytes (of %d) decoded", len(g), len(graph))
		}
	}
}

func TestLofFixedSource(t *testing.T) {
	w := &lofWorld{buildDir: "/work/m", goroot: "/go", modcache: "/cache/mod"}
	for _, tc := range []struct {
		dir  string
		want bool
	}{
		{"/go/src/strings", true},
		{"/go/pkg/tool", false},
		{"/cache/mod/example.com/v@v1.0.0/vuln", true},
		{"/cache/mod/example.com/v@v1.0.0", true},
		{"/cache/mod/example.com/v/vuln", false},
		{"/cache/mod/cache/download/example.com/v/@v", false},
		{"/cache/mod", false},
		{"/elsewhere/example.com/v@v1.0.0", false},
		{"/work/m", false},
		{"/work/m/vuln", false},
	} {
		if got := w.fixedSource(tc.dir); got != tc.want {
			t.Errorf("fixedSource(%q) = %v, want %v", tc.dir, got, tc.want)
		}
	}
	// A build tree inside the module cache is never fixed.
	w = &lofWorld{buildDir: "/cache/mod/example.com/m@v1.0.0", modcache: "/cache/mod"}
	for _, dir := range []string{"/cache/mod/example.com/m@v1.0.0", "/cache/mod/example.com/m@v1.0.0/x"} {
		if w.fixedSource(dir) {
			t.Errorf("fixedSource(%q) = true inside the build tree", dir)
		}
	}
	if (&lofWorld{goroot: "/go"}).fixedSource("/go/src/strings") {
		t.Error("fixedSource is true with no build tree")
	}
}

// TestLeftOutEngine_FailClosed: what the engine cannot bound, build or establish withholds.
func TestLeftOutEngine_FailClosed(t *testing.T) {
	tree := map[string]string{
		"go.mod":          "module example.com/m\n\ngo 1.22\n\nrequire example.com/v v0.0.0\n\nreplace example.com/v => ./_v\n",
		"main.go":         "package main\n\nimport \"example.com/v/vuln\"\n\nfunc main() { vuln.Safe() }\n",
		"_v/go.mod":       "module example.com/v\n\ngo 1.22\n",
		"_v/vuln/vuln.go": "package vuln\n\nfunc Bad() {}\n\nfunc Safe() {}\n",
		"x.go":            "//go:build lofalt\n\npackage main\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Safe() }\n",
	}
	bad := map[string][]string{"example.com/v/vuln": {"Bad"}}

	t.Run("within budget the file releases", func(t *testing.T) {
		if got := lofRun(t, writeTree(t, tree), "example.com/v", bad, false, nil); got.withheld {
			t.Fatalf("withheld, want released (facts %s)", lofDescribe(got))
		}
	})
	t.Run("over the declaration budget", func(t *testing.T) {
		saved := lofBudgetDecls
		lofBudgetDecls = 0
		t.Cleanup(func() { lofBudgetDecls = saved })
		got := lofRun(t, writeTree(t, tree), "example.com/v", bad, false, nil)
		if !got.withheld || lofFileWith(got, lofBudget) == "" {
			t.Fatalf("withheld = %v, want withheld on %s (facts %s)", got.withheld, lofBudget, lofDescribe(got))
		}
	})
	t.Run("past the time budget", func(t *testing.T) {
		saved := lofBudgetTime
		lofBudgetTime = 0
		t.Cleanup(func() { lofBudgetTime = saved })
		got := lofRun(t, writeTree(t, tree), "example.com/v", bad, false, nil)
		if !got.withheld || lofFileWith(got, lofBudget) == "" {
			t.Fatalf("withheld = %v, want withheld on %s (facts %s)", got.withheld, lofBudget, lofDescribe(got))
		}
	})
	t.Run("an unreadable file of an unloaded package", func(t *testing.T) {
		dir := writeTree(t, merge(tree, map[string]string{
			"go.mod":      "module example.com/m\n\ngo 1.22\n\nrequire (\n\texample.com/v v0.0.0\n\texample.com/dep v0.0.0\n)\n\nreplace (\n\texample.com/v => ./_v\n\texample.com/dep => ./_dep\n)\n",
			"_dep/go.mod": "module example.com/dep\n\ngo 1.22\n",
			"_dep/d/d.go": "package d\n\nfunc Call() {}\n",
			"x.go":        "//go:build lofalt\n\npackage main\n\nimport \"example.com/dep/d\"\n\nfunc init() { d.Call() }\n",
		}))
		blocked := filepath.Join(dir, "_dep", "d", "d.go")
		t.Cleanup(func() { _ = os.Chmod(blocked, 0o644) })
		got := lofRun(t, dir, "example.com/v", bad, false, func(*LoadResult) {
			if err := os.Chmod(blocked, 0); err != nil {
				t.Fatal(err)
			}
		})
		if !got.withheld || lofFileWith(got, lofMissingSource) == "" {
			t.Fatalf("withheld = %v, want withheld on %s (facts %s)", got.withheld, lofMissingSource, lofDescribe(got))
		}
	})
	t.Run("the scan is cancelled", func(t *testing.T) {
		dir := writeTree(t, tree)
		load, err := LoadProgram(context.Background(), dir)
		if err != nil {
			t.Fatal(err)
		}
		load.buildGoVersion = load.goVersion
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		e := loadLofEngine(ctx, load.Packages, load.buildRelease(), dir, append(os.Environ(), "GOWORK=off"))
		got := lofResult{engine: e, facts: map[string]*lofFacts{}}
		for path := range e.Facts {
			got.facts[path], _ = e.file(path)
		}
		if f := lofFileWith(got, lofBudget); !strings.HasSuffix(f, "/x.go") {
			t.Fatalf("x.go does not fail closed on %s (facts %s)", lofBudget, lofDescribe(got))
		}
	})

	// A left-out file's closure fails closed on the file itself: unreadable, or its build constraint
	// or package clause does not parse. The file is rewritten after the load.
	for _, tc := range []struct{ name, item, src string }{
		{"the left-out file cannot be read", lofMissingSource, ""},
		{"the left-out file's build constraint does not parse", lofParseError, "//go:build lofalt\n//go:build other\n\npackage main\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Safe() }\n"},
		{"the left-out file's package clause does not parse", lofParseError, "//go:build lofalt\n\npackage\n\nimport \"example.com/v/vuln\"\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, tree)
			path := filepath.Join(dir, "x.go")
			t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
			got := lofRun(t, dir, "example.com/v", bad, false, func(*LoadResult) {
				var err error
				if tc.src == "" {
					err = os.Chmod(path, 0)
				} else {
					err = os.WriteFile(path, []byte(tc.src), 0o644)
				}
				if err != nil {
					t.Fatal(err)
				}
			})
			if !got.withheld || lofFileWith(got, tc.item) == "" {
				t.Fatalf("withheld = %v, want withheld on %s (facts %s)", got.withheld, tc.item, lofDescribe(got))
			}
		})
	}

	// noX is the tree without x.go.
	noX := func(files map[string]string) map[string]string {
		out := merge(tree, files)
		delete(out, "x.go")
		return out
	}
	// dep is a module the build does not load, whose package d x.go enters; x.go calls only vuln.Safe.
	dep := func(imp, body string) map[string]string {
		return merge(tree, map[string]string{
			"go.mod":      "module example.com/m\n\ngo 1.22\n\nrequire (\n\texample.com/v v0.0.0\n\texample.com/dep v0.0.0\n)\n\nreplace (\n\texample.com/v => ./_v\n\texample.com/dep => ./_dep\n)\n",
			"_dep/go.mod": "module example.com/dep\n\ngo 1.22\n",
			"_dep/d/d.go": "package d\n\nfunc Call() {}\n",
			"_dep/d/e.go": "package d\n",
			"_dep/d/d.s":  "// d has assembly.\n",
			"x.go":        "//go:build lofalt\n\npackage main\n\nimport (\n\t" + imp + "\n\t\"example.com/v/vuln\"\n)\n\nfunc init() { " + body + "vuln.Safe() }\n",
		})
	}
	for _, tc := range []struct {
		name, imp, body, blocked string
		mode                     os.FileMode
	}{
		{"the loaded package the file calls cannot be listed", `_ "example.com/dep/d"`, "", "_v/vuln", 0o311},
		{"another file of an unloaded package the file calls cannot be read", `"example.com/dep/d"`, "d.Call(); ", "_dep/d/e.go", 0},
		{"an assembly file of an unloaded package the file enters cannot be read", `_ "example.com/dep/d"`, "", "_dep/d/d.s", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, dep(tc.imp, tc.body))
			blocked := filepath.Join(dir, tc.blocked)
			t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })
			got := lofRun(t, dir, "example.com/v", bad, false, func(*LoadResult) {
				if err := os.Chmod(blocked, tc.mode); err != nil {
					t.Fatal(err)
				}
			})
			if !got.withheld || lofFileWith(got, lofMissingSource) == "" {
				t.Fatalf("withheld = %v, want withheld on %s (facts %s)", got.withheld, lofMissingSource, lofDescribe(got))
			}
		})
	}
	// unlinked leaves the vulnerable package unloaded: x.go enters u, an unloaded package of the
	// vulnerable module that is not one of the symbol's, so only the walk of what x.go links decides.
	unlinked := merge(tree, map[string]string{
		"main.go":   "package main\n\nfunc main() {}\n",
		"_v/u/u.go": "package u\n",
		"x.go":      "//go:build lofalt\n\npackage main\n\nimport _ \"example.com/v/u\"\n",
	})
	for _, tc := range []struct {
		name, item string
		files      map[string]string
		blocked    map[string]os.FileMode
	}{
		// Here the left-out file is in loaded package d of another module, outside the main module's
		// tree, which the gate walks whole; x.go at the root imports nothing and is not kept.
		{"the left-out file's directory cannot be listed and the vulnerable package is not loaded", lofMissingSource, map[string]string{
			"go.mod":      "module example.com/m\n\ngo 1.22\n\nrequire (\n\texample.com/v v0.0.0\n\texample.com/dep v0.0.0\n)\n\nreplace (\n\texample.com/v => ./_v\n\texample.com/dep => ./_dep\n)\n",
			"_dep/go.mod": "module example.com/dep\n\ngo 1.22\n",
			"_dep/d/d.go": "package d\n\nfunc F() {}\n",
			"_dep/d/x.go": "//go:build lofalt\n\npackage d\n\nimport _ \"example.com/v/u\"\n",
			"main.go":     "package main\n\nimport \"example.com/dep/d\"\n\nfunc main() { d.F() }\n",
			"x.go":        "//go:build lofalt\n\npackage main\n",
		}, map[string]os.FileMode{"_dep/d": 0o311, "_v/u/u.go": 0}},
		{"a file of an unloaded package the file enters cannot be read and the vulnerable package is not loaded", lofMissingSource, nil,
			map[string]os.FileMode{"_v/u/u.go": 0}},
		{"a build constraint of an unloaded package the file enters does not parse and the vulnerable package is not loaded", lofParseError,
			map[string]string{"_v/u/bad.go": "//go:build a\n//go:build b\n\npackage u\n"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, merge(unlinked, tc.files))
			t.Cleanup(func() {
				for p := range tc.blocked {
					_ = os.Chmod(filepath.Join(dir, p), 0o755)
				}
			})
			got := lofRun(t, dir, "example.com/v", bad, false, func(*LoadResult) {
				for p, mode := range tc.blocked {
					if err := os.Chmod(filepath.Join(dir, p), mode); err != nil {
						t.Fatal(err)
					}
				}
			})
			if !got.withheld || lofFileWith(got, tc.item) == "" {
				t.Fatalf("withheld = %v, want withheld on %s (facts %s)", got.withheld, tc.item, lofDescribe(got))
			}
		})
	}
	t.Run("the vulnerable package is not loaded and a file that cannot link it fails closed", func(t *testing.T) {
		// The module graph cannot be read, so the gate keeps x.go; x.go names a function u does not
		// declare, and still links only u, which reaches nothing of the symbol's package.
		dir := writeTree(t, merge(unlinked, map[string]string{
			"go.mod":      "module example.com/m\n\ngo 1.22\n\nrequire (\n\texample.com/v v0.0.0\n\texample.com/dep v0.0.0\n)\n\nreplace (\n\texample.com/v => ./_v\n\texample.com/dep => ./_dep\n)\n",
			"_dep/go.mod": "module example.com/dep\n\ngo 1.22\n",
			"_dep/d/d.go": "package d\n",
			"x.go":        "//go:build lofalt\n\npackage main\n\nimport \"example.com/v/u\"\n\nfunc init() { u.Missing() }\n",
		}))
		blocked := filepath.Join(dir, "_dep", "go.mod")
		t.Cleanup(func() { _ = os.Chmod(blocked, 0o644) })
		got := lofRun(t, dir, "example.com/v", bad, false, func(*LoadResult) {
			if err := os.Chmod(blocked, 0); err != nil {
				t.Fatal(err)
			}
		})
		if got.withheld || lofFileWith(got, lofUnresolvedName) == "" {
			t.Fatalf("withheld = %v, want released despite %s (facts %s)", got.withheld, lofUnresolvedName, lofDescribe(got))
		}
	})
	t.Run("the left-out file's package directory cannot be listed", func(t *testing.T) {
		// y.go of the loaded vulnerable package is left out; its directory stays searchable, so y.go
		// itself reads.
		dir := writeTree(t, noX(map[string]string{
			"_v/vuln/y.go": "//go:build lofalt\n\npackage vuln\n\nfunc init() { Safe() }\n",
		}))
		vdir := filepath.Join(dir, "_v", "vuln")
		t.Cleanup(func() { _ = os.Chmod(vdir, 0o755) })
		got := lofRun(t, dir, "example.com/v", bad, false, func(*LoadResult) {
			if err := os.Chmod(vdir, 0o311); err != nil {
				t.Fatal(err)
			}
		})
		if !got.withheld || lofFileWith(got, lofMissingSource) == "" {
			t.Fatalf("withheld = %v, want withheld on %s (facts %s)", got.withheld, lofMissingSource, lofDescribe(got))
		}
	})

	// The walk stops at the budget with a standard-library name nothing declares still open: the
	// file is withheld on the budget, never dropped as uncompilable on a walk it did not finish.
	strs := "package main\n\nimport (\n\t\"strings\"\n\n\t\"example.com/v/vuln\"\n)\n\nfunc main() { _ = strings.ToUpper(\"x\"); vuln.Safe() }\n"
	budget := func(t *testing.T, decls int) {
		saved := lofBudgetDecls
		lofBudgetDecls = decls
		t.Cleanup(func() { lofBudgetDecls = saved })
	}
	t.Run("the budget stops the file's walk with a name still open", func(t *testing.T) {
		budget(t, 1)
		dir := writeTree(t, merge(tree, map[string]string{
			"main.go": strs,
			"x.go":    "//go:build lofalt\n\npackage main\n\nimport (\n\t\"strings\"\n\n\t\"example.com/v/vuln\"\n)\n\nfunc init() { strings.NoSuchName(); vuln.Bad() }\n\nfunc other() {}\n",
		}))
		got := lofRun(t, dir, "example.com/v", bad, false, nil)
		if !got.withheld || lofFileWith(got, lofBudget) == "" {
			t.Fatalf("withheld = %v, want withheld on %s (facts %s)", got.withheld, lofBudget, lofDescribe(got))
		}
	})
	t.Run("the budget stops the walk of the package's roots with a name still open", func(t *testing.T) {
		// tool is a directory of the main module the build does not load: a.go's package roots are
		// its two initializers, and the walk of them, which the file's walk continues, stops.
		budget(t, 1)
		dir := writeTree(t, noX(map[string]string{
			"main.go":   strs,
			"tool/a.go": "//go:build lofalt\n\npackage tool\n\nimport (\n\t\"strings\"\n\n\t\"example.com/v/vuln\"\n)\n\nfunc init() { strings.NoSuchName() }\n\nfunc init() { vuln.Safe() }\n",
		}))
		got := lofRun(t, dir, "example.com/v", bad, false, nil)
		if !got.withheld || lofFileWith(got, lofBudget) == "" {
			t.Fatalf("withheld = %v, want withheld on %s (facts %s)", got.withheld, lofBudget, lofDescribe(got))
		}
	})

	// The walk of a package's roots, which each of its left-out files continues, is rebuilt for
	// another package and once a file is dropped.
	t.Run("a dropped file's imports leave the package roots' walk", func(t *testing.T) {
		// tool/a.go calls u.Helper. u.go, one variant of it, names a standard-library name nothing
		// declares, and imports w2, whose initializer calls the symbol; u.go is dropped, and with it
		// w2's initializer from the walk of tool's roots.
		dir := writeTree(t, noX(map[string]string{
			"main.go":         strs,
			"tool/a.go":       "//go:build lofalt\n\npackage tool\n\nimport \"example.com/v/u\"\n\nfunc run() { u.Helper() }\n",
			"_v/u/u.go":       "//go:build lofalt\n\npackage u\n\nimport (\n\t\"strings\"\n\n\t_ \"example.com/v/w2\"\n)\n\nfunc Helper() { strings.NoSuchName() }\n",
			"_v/u/u_other.go": "//go:build !lofalt\n\npackage u\n\nfunc Helper() {}\n",
			"_v/w2/w2.go":     "package w2\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Bad() }\n",
		}))
		got := lofRun(t, dir, "example.com/v", bad, false, nil)
		if got.withheld {
			t.Fatalf("withheld, want released (facts %s)", lofDescribe(got))
		}
	})
	t.Run("each package's left-out files continue that package's roots", func(t *testing.T) {
		// a and b are directories of the main module the build does not load; a's initializer calls
		// the symbol, and b's file reaches nothing of it.
		dir := writeTree(t, noX(map[string]string{
			"a/a.go": "//go:build lofalt\n\npackage a\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Bad() }\n",
			"b/b.go": "//go:build lofalt\n\npackage b\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Safe() }\n",
		}))
		got := lofRun(t, dir, "example.com/v", bad, false, nil)
		reaches := func(path string) bool {
			f := got.facts[path]
			if f == nil {
				t.Fatalf("the engine holds no %s (facts %s)", path, lofDescribe(got))
			}
			return slices.ContainsFunc(f.Funcs, func(id int32) bool { return got.engine.Strs[id] == symKey("example.com/v/vuln", "Bad") })
		}
		if !reaches("a/a.go") || reaches("b/b.go") {
			t.Fatalf("a/a.go reaches Bad = %v, b/b.go = %v; want true, false (facts %s)", reaches("a/a.go"), reaches("b/b.go"), lofDescribe(got))
		}
	})
	t.Run("the call graphs cannot be built", func(t *testing.T) {
		got := lofRun(t, writeTree(t, tree), "example.com/v", bad, false, func(load *LoadResult) {
			// A package with syntax but no type information for it: SSA cannot build it.
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "broken.go", "package broken\n\nfunc F() { F() }\n", 0)
			if err != nil {
				t.Fatal(err)
			}
			load.Packages = append(load.Packages, &packages.Package{
				ID: "broken", PkgPath: "example.com/m/broken", Name: "broken", Fset: fset,
				Types: types.NewPackage("example.com/m/broken", "broken"), Syntax: []*ast.File{f},
			})
		})
		if !got.withheld || got.engine.Fail != lofGraphError {
			t.Fatalf("withheld = %v, engine failure %q, want withheld on %s", got.withheld, got.engine.Fail, lofGraphError)
		}
	})
}

// TestLeftOutEngine_StandardLibrary: against a standard-library refutation the engine judges the
// toolchain's own left-out files, and only the release the build runs on.
func TestLeftOutEngine_StandardLibrary(t *testing.T) {
	// The scan is for linux/amd64: crypto/x509's darwin files are left out.
	t.Setenv("GOOS", "linux")
	t.Setenv("GOARCH", "amd64")
	t.Setenv("CGO_ENABLED", "0")
	useStd := func(imp, use string) map[string]string {
		return map[string]string{
			"go.mod":  "module example.com/m\n\ngo 1.22\n",
			"main.go": "package main\n\nimport \"" + imp + "\"\n\nfunc main() { " + use + " }\n",
		}
	}
	verify := useStd("crypto/x509", "_, _ = (&x509.Certificate{}).Verify(x509.VerifyOptions{})")
	// The build loads strings and not container/list, the vulnerable package.
	stringsMain := useStd("strings", "_ = strings.ToUpper(\"x\")")
	list := map[string][]string{"container/list": {"New"}}
	cases := []struct {
		name     string
		tree     map[string]string
		symbols  map[string][]string
		unknown  bool
		goflags  string // GOFLAGS for the engine, set after the load
		withheld bool
		failStd  string
		counts   string // a standard-library file, by its path below GOROOT/src, that must still count
	}{
		// Only root_darwin.go's systemVerify reaches the macOS policy call; Verify reaches systemVerify.
		// The file's closure fails closed on the toolchain's own linknames, so it counts.
		{"Verify is reached and only darwin's systemVerify reaches the symbol", verify,
			map[string][]string{"crypto/x509/internal/macos": {"SecPolicyCreateSSL"}}, false, "", true, "", "crypto/x509/root_darwin.go"},
		{"a left-out standard-library file cannot link the vulnerable package", useStd("strings", "_ = strings.ToUpper(\"x\")"),
			map[string][]string{"net/http": {"Get"}}, false, "", false, "", ""},
		{"the toolchain the build runs on is unknown", useStd("os", "_, _ = os.Open(\"x\")"),
			map[string][]string{"os": {"Root.Open"}}, true, "", true, lofUnknownToolchain, ""},
		{"the build reads the standard library through an overlay", useStd("os", "_, _ = os.Open(\"x\")"),
			map[string][]string{"os": {"Root.Open"}}, false, "-overlay=overlay.json", true, lofGorootMismatch, ""},
		// A left-out file that links the vulnerable package names a standard-library symbol nothing declares.
		{"a left-out file pulls by linkname a standard-library symbol nothing declares", merge(stringsMain, map[string]string{
			"x.go": "//go:build lofalt\n\npackage main\n\nimport (\n\t_ \"container/list\"\n\t_ \"unsafe\"\n)\n\n//go:linkname pulled strings.NoSuchName\nfunc pulled()\n\nfunc init() { pulled() }\n",
		}), list, false, "", true, "", ""},
		{"left-out assembly calls a standard-library symbol nothing declares", merge(stringsMain, map[string]string{
			"x.go":       "//go:build lofalt\n\npackage main\n\nimport _ \"container/list\"\n\nfunc asm()\n\nfunc init() { asm() }\n",
			"x_lofalt.s": "//go:build lofalt\n\nTEXT ·asm(SB),0,$0\n\tCALL strings·NoSuchName(SB)\n\tRET\n",
		}), list, false, "", true, "", ""},
		{"the toolchain is unknown and a left-out file links the vulnerable package without naming a symbol", merge(stringsMain, map[string]string{
			"x.go": "//go:build lofalt\n\npackage main\n\nimport _ \"container/list\"\n",
		}), list, true, "", true, lofUnknownToolchain, ""},
		{"a left-out file links the vulnerable package and names only declared symbols", merge(stringsMain, map[string]string{
			"x.go": "//go:build lofalt\n\npackage main\n\nimport (\n\t_ \"container/list\"\n\t_ \"unsafe\"\n)\n\n//go:linkname pulled strings.ToUpper\nfunc pulled(string) string\n\nfunc init() { pulled(\"x\") }\n",
		}), list, false, "", false, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var prepare func(*LoadResult)
			if tc.goflags != "" {
				prepare = func(*LoadResult) { t.Setenv("GOFLAGS", tc.goflags) }
			}
			got := lofRun(t, writeTree(t, tc.tree), "stdlib", tc.symbols, tc.unknown, prepare)
			if got.withheld != tc.withheld {
				t.Fatalf("withheld = %v, want %v (facts %s)", got.withheld, tc.withheld, lofDescribe(got))
			}
			if got.engine.FailStd != tc.failStd {
				t.Errorf("standard-library failure = %q, want %q", got.engine.FailStd, tc.failStd)
			}
			if tc.counts != "" {
				found := false
				for path, f := range got.facts {
					if strings.HasSuffix(filepath.ToSlash(path), "/src/"+tc.counts) {
						found = true
						if f.Excluded || f.Dropped || len(f.FC)+len(f.FCStd) == 0 && !f.Novel {
							t.Errorf("%s no longer counts: %+v", tc.counts, *f)
						}
					}
				}
				if !found {
					t.Errorf("the engine holds no %s", tc.counts)
				}
			}
		})
	}
	// The go command's GOROOT, set after the load, is not the release's own standard library.
	for _, tc := range []struct {
		name, version, failStd string
		absent                 bool
	}{
		{"the go command cannot report its GOROOT", "", lofUnknownToolchain, true},
		{"the GOROOT holds no VERSION file", "", lofUnknownToolchain, false},
		{"the GOROOT is another release's", "go1.20\n", lofGorootMismatch, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := lofRun(t, writeTree(t, useStd("os", "_, _ = os.Open(\"x\")")), "stdlib", map[string][]string{"os": {"Root.Open"}}, false, func(*LoadResult) {
				root := t.TempDir()
				switch {
				case tc.absent:
					root = filepath.Join(root, "absent")
				case tc.version != "":
					if err := os.WriteFile(filepath.Join(root, "VERSION"), []byte(tc.version), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				t.Setenv("GOROOT", root)
			})
			if !got.withheld || got.engine.FailStd != tc.failStd {
				t.Fatalf("withheld = %v, standard-library failure = %q, want withheld on %q (facts %s)", got.withheld, got.engine.FailStd, tc.failStd, lofDescribe(got))
			}
		})
	}
}

// lofFileWith returns a left-out file whose closure, or link walk, fails closed on item.
func lofFileWith(r lofResult, item string) string {
	for path, f := range r.facts {
		if slices.Contains(f.FC, item) || slices.Contains(f.FCStd, item) || slices.Contains(f.LinkFC, item) {
			return path
		}
	}
	return ""
}

// lofDescribe renders the engine's facts for a failure message.
func lofDescribe(r lofResult) string {
	var b strings.Builder
	if r.engine.Fail != "" {
		b.WriteString("engine failed: " + r.engine.Fail + "; ")
	}
	for path, f := range r.facts {
		b.WriteString(path + ": ")
		b.WriteString(strings.Join(f.FC, ","))
		if f.Dropped {
			b.WriteString(" dropped")
		} else if f.Excluded {
			b.WriteString(" excluded")
		}
		if f.Novel {
			b.WriteString(" novel")
		}
		b.WriteString("; ")
	}
	return b.String()
}

// TestLofStdAbsent: a standard-library name is proved absent only from the toolchain's own source,
// read whole, every build constraint included.
func TestLofStdAbsent(t *testing.T) {
	goroot := writeTree(t, map[string]string{
		"src/p/p.go":        "package p\n\nfunc Here() {}\n",
		"src/p/p_other.go":  "//go:build ignore\n\npackage p\n\nfunc Ignored() {}\n",
		"src/p/p_test.go":   "package p\n\nfunc InTest() {}\n",
		"src/bad/bad.go":    "package bad\n\nfunc (\n",
		"elsewhere/q/q.go":  "package q\n",
		"src/vendor/v/v.go": "package v\n",
	})
	w := &lofWorld{goroot: goroot, stdNames: map[string]map[string]bool{}}
	std := func(dir string) *lofPkg { return &lofPkg{std: true, dir: filepath.Join(goroot, dir)} }
	cases := []struct {
		name string
		p    *lofPkg
		id   string
		want bool
	}{
		{"declared nowhere", std("src/p"), "Nowhere", true},
		{"declared", std("src/p"), "Here", false},
		{"declared only under the ignore tag", std("src/p"), "Ignored", false},
		{"declared only in a test file", std("src/p"), "InTest", true},
		{"a name cgo could generate", std("src/p"), "_Nowhere", false},
		{"a file of the package does not parse", std("src/bad"), "Nowhere", false},
		{"the package's directory cannot be read", std("src/gone"), "Nowhere", false},
		{"the directory is outside the toolchain's source", std("elsewhere/q"), "Nowhere", false},
		{"the package is not the standard library's", &lofPkg{dir: filepath.Join(goroot, "src/p")}, "Nowhere", false},
		{"a vendored standard-library package", std("src/vendor/v"), "Nowhere", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := w.stdAbsent(tc.p, tc.id); got != tc.want {
				t.Errorf("stdAbsent(%s) = %v, want %v", tc.id, got, tc.want)
			}
		})
	}
	t.Run("no toolchain source", func(t *testing.T) {
		w := &lofWorld{stdNames: map[string]map[string]bool{}}
		if w.stdAbsent(std("src/p"), "Nowhere") {
			t.Error("proved absent with no GOROOT")
		}
	})
}

// TestLofUnder: what lies below a root.
func TestLofUnder(t *testing.T) {
	for _, tc := range []struct {
		path, root string
		want       bool
	}{
		{"/a/b/c", "/a/b", true},
		{"/a/b", "/a/b", false},
		{"/a/bc", "/a/b", false},
		{"/a", "/a/b", false},
		{"/a/b/../c", "/a/b", false},
	} {
		if got := lofUnder(tc.path, tc.root); got != tc.want {
			t.Errorf("lofUnder(%q, %q) = %v, want %v", tc.path, tc.root, got, tc.want)
		}
	}
}

// TestLeftOutEngine_AsmLinkDefiners: a bare symbol left-out assembly references and its own package
// does not define binds, in some link, to whatever defines that name anywhere in the link: a Go
// declaration a //go:linkname pushes to it or an //export function, followed; Go assembly, whose
// body is followed; a .syso object, or a definer the index cannot see, which fails closed. lib's
// file y_alt.go, left out and built under another tag, is the only importer of the packages holding
// definers, so x.go's closure never enters them.
func TestLeftOutEngine_AsmLinkDefiners(t *testing.T) {
	base := map[string]string{
		"go.mod":          "module example.com/m\n\ngo 1.22.0\n\nrequire example.com/v v0.0.0\n\nreplace example.com/v => ./_v\n",
		"main.go":         "package main\n\nimport \"example.com/v/vuln\"\n\nfunc main() { vuln.Safe() }\n",
		"_v/go.mod":       "module example.com/v\n\ngo 1.22\n",
		"_v/vuln/vuln.go": "package vuln\n\nfunc Bad() {}\n\nfunc Safe() {}\n",
		"lib/lib.go":      "package lib\n",
		"x.go":            "//go:build lofalt\n\npackage main\n\nfunc asm()\n\nfunc init() { asm() }\n",
		"x_lofalt.s":      "//go:build lofalt\n\nTEXT ·asm(SB),0,$0\n\tCALL target(SB)\n\tRET\n",
	}
	// importer links pkg into some build through a file the build leaves out.
	importer := func(pkg string) map[string]string {
		return map[string]string{"lib/y_alt.go": "//go:build lofother\n\npackage lib\n\nimport _ \"example.com/v/" + pkg + "\"\n"}
	}
	sy := func(obj []byte) map[string]string {
		return merge(importer("sy"), map[string]string{"_v/sy/sy.go": "package sy\n", "_v/sy/sy.syso": string(obj)})
	}
	bad := symKey("example.com/v/vuln", "Bad")
	cases := []struct {
		name     string
		files    map[string]string
		reach    string // a loaded function x.go's closure reaches, when set
		sink     bool   // x.go's closure reaches a loaded variable holding a func
		item     string // what x.go's closure fails closed on, when set
		withheld bool
	}{
		{"nothing defines the symbol: foreign code", nil, "", false, "", false},
		{"a loaded //go:linkname push of a function with a body", map[string]string{
			"lib/def.go": "package lib\n\nimport (\n\t_ \"unsafe\"\n\n\t\"example.com/v/vuln\"\n)\n\n//go:linkname impl target\nfunc impl() { vuln.Bad() }\n",
		}, symKey("example.com/m/lib", "impl"), false, "", true},
		{"a loaded //go:linkname push of an initialized variable", map[string]string{
			"lib/def.go": "package lib\n\nimport (\n\t_ \"unsafe\"\n\n\t\"example.com/v/vuln\"\n)\n\n//go:linkname impl target\nvar impl = vuln.Bad\n",
		}, "", true, "", true},
		{"a loaded //go:linkname push of an uninitialized variable", map[string]string{
			"lib/def.go": "package lib\n\nimport (\n\t_ \"unsafe\"\n\n\t\"example.com/v/vuln\"\n)\n\n//go:linkname impl target\nvar impl func()\n\nfunc init() { impl = vuln.Bad }\n",
		}, "", true, "", true},
		{"an uninitialized variable an unloaded package pushes", merge(importer("def"), map[string]string{
			"_v/def/def.go": "package def\n\nimport (\n\t_ \"unsafe\"\n\n\t\"example.com/v/vuln\"\n)\n\n//go:linkname v target\nvar v func()\n\nfunc init() { v = vuln.Bad }\n",
		}), bad, false, lofLinkname, true},
		{"a //go:linkname push of a bodyless function defines nothing", map[string]string{
			"lib/def.go": "package lib\n\nimport (\n\t_ \"unsafe\"\n\n\t\"example.com/v/vuln\"\n)\n\n//go:linkname impl target\nfunc impl()\n\nfunc F() { vuln.Bad() }\n",
		}, "", false, "", false},
		{"an //export function of an unloaded cgo package", merge(importer("exp"), map[string]string{
			"_v/exp/exp.go": "package exp\n\nimport \"C\"\n\nimport \"example.com/v/vuln\"\n\n//export target\nfunc target() { vuln.Bad() }\n",
		}), bad, false, "", true},
		{"an //export comment outside a cgo file defines nothing", merge(importer("exp"), map[string]string{
			"_v/exp/exp.go": "package exp\n\nimport \"example.com/v/vuln\"\n\n//export target\nfunc target() { vuln.Bad() }\n",
		}), "", false, "", false},
		{"Go assembly data of an unloaded package links it", merge(importer("def"), map[string]string{
			"_v/def/def.go": "package def\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Bad() }\n",
			"_v/def/def.s":  "GLOBL target(SB),8,$8\n",
		}), bad, false, "", true},
		{"Go assembly of an unloaded package", merge(importer("def"), map[string]string{
			"_v/def/def.go": "package def\n",
			"_v/def/def.s":  "TEXT target(SB),0,$0\n\tCALL example.com∕v∕vuln·Bad(SB)\n\tRET\n",
		}), bad, false, "", true},
		{"a macro of an included header may produce it", merge(importer("mac"), map[string]string{
			"_v/mac/mac.go": "package mac\n",
			"_v/mac/mk.h":   "#define MK(n) TEXT n(SB),0,$0; RET\n",
			"_v/mac/mac.s":  "#include \"mk.h\"\n\nMK(target)\n",
		}), "", false, lofAsmSymbol, true},
		{"an included header that does not resolve may define anything", merge(importer("mac"), map[string]string{
			"_v/mac/mac.go": "package mac\n",
			"_v/mac/mac.s":  "#include \"missing.h\"\n",
		}), "", false, lofAsmSymbol, true},
		{"a .syso object defines it", sy(lofELFObject("target")), "", false, lofAsmSymbol, true},
		{"a .syso object defines it with a leading underscore", sy(lofELFObject("_target")), "", false, lofAsmSymbol, true},
		{"a .syso object defines other names", sy(lofELFObject("other")), "", false, "", false},
		{"a .syso object of unknown format", sy([]byte("not an object")), "", false, lofAsmSymbol, true},
		{"an import some build links does not resolve", importer("nowhere"), "", false, lofAsmSymbol, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, merge(base, tc.files))
			got := lofRun(t, dir, "example.com/v", map[string][]string{"example.com/v/vuln": {"Bad"}}, false, nil)
			f := got.facts["x.go"]
			if f == nil {
				t.Fatalf("the engine holds no x.go (facts %s)", lofDescribe(got))
			}
			if !f.Dyn {
				t.Errorf("x.go: no dynamic call; a build without the definer binds the symbol to foreign code")
			}
			var fc []string
			if tc.item != "" {
				fc = []string{tc.item}
			}
			if !slices.Equal(f.FC, fc) {
				t.Errorf("x.go fails closed on %v, want %v", f.FC, fc)
			}
			reached := slices.ContainsFunc(f.Funcs, func(id int32) bool { return got.engine.Strs[id] == tc.reach })
			if tc.reach != "" && !reached {
				t.Errorf("x.go does not reach %s", tc.reach)
			}
			for _, k := range []string{bad, symKey("example.com/m/lib", "impl"), symKey("example.com/v/exp", "target")} {
				if tc.reach != k && slices.ContainsFunc(f.Funcs, func(id int32) bool { return got.engine.Strs[id] == k }) {
					t.Errorf("x.go reaches %s", k)
				}
			}
			if f.Sink != tc.sink {
				t.Errorf("x.go sink = %v, want %v", f.Sink, tc.sink)
			}
			if got.withheld != tc.withheld {
				t.Errorf("withheld = %v, want %v (facts %s)", got.withheld, tc.withheld, lofDescribe(got))
			}
		})
	}
}

// TestLeftOutEngine_AsmFuncdataPlaceholder: go_args_stackmap and no_pointers_stackmap, which the
// assembler renames as FUNCDATA's symbol operand, are dropped only from the refs the toolchain's own
// funcdata.h ($GOROOT/src/runtime or $GOROOT/pkg/include) gives a standard-library package's
// assembly. Anywhere else, module code included, either name follows its definers, here an unloaded
// package's header that mentions it. A standard-library row lays the module out under a stand-in
// GOROOT and marks its package standard.
func TestLeftOutEngine_AsmFuncdataPlaceholder(t *testing.T) {
	base := map[string]string{
		"go.mod":          "module example.com/m\n\ngo 1.22.0\n\nrequire example.com/v v0.0.0\n\nreplace example.com/v => ./_v\n",
		"main.go":         "package main\n\nimport \"example.com/v/vuln\"\n\nfunc main() { vuln.Safe() }\n",
		"_v/go.mod":       "module example.com/v\n\ngo 1.22\n",
		"_v/vuln/vuln.go": "package vuln\n\nfunc Bad() {}\n\nfunc Safe() {}\n",
		"lib/lib.go":      "package lib\n",
		"lib/y_alt.go":    "//go:build lofother\n\npackage lib\n\nimport _ \"example.com/v/fd\"\n",
		"_v/fd/fd.go":     "package fd\n",
		"_v/fd/fd.h":      "#define GO_ARGS FUNCDATA $0, go_args_stackmap(SB)\n#define NO_LOCAL_POINTERS FUNCDATA $1, no_pointers_stackmap(SB)\n",
		"_v/fd/fd.s":      "#include \"fd.h\"\n",
		"x.go":            "//go:build lofalt\n\npackage main\n\nfunc asm()\n\nfunc init() { asm() }\n",
	}
	funcdataH := map[string]string{"funcdata.h": base["_v/fd/fd.h"]}
	body := func(pre, stmt string) map[string]string {
		return map[string]string{"x_lofalt.s": "//go:build lofalt\n\n" + pre + "TEXT ·asm(SB),0,$0\n\t" + stmt + "\n\tRET\n"}
	}
	type row struct {
		name  string
		root  string // the module's directory under a stand-in GOROOT; "" runs it as an ordinary module
		std   bool   // the package at root is the standard library's
		files map[string]string
		held  bool   // x.go's closure fails closed on the symbol
		gap   string // why the row's verdict is released, a gap the exclusion did not open
	}
	var cases []row
	for _, c := range []struct{ name, macro, slot string }{
		{"go_args_stackmap", "GO_ARGS", "0"},
		{"no_pointers_stackmap", "NO_LOCAL_POINTERS", "1"},
	} {
		n := c.name + "(SB)"
		use := merge(funcdataH, body("#include \"funcdata.h\"\n\n", c.macro))
		cases = append(cases, []row{
			{c.name + ": std, the toolchain's runtime/funcdata.h", "src/runtime", true, use, false, ""},
			{c.name + ": std, the toolchain's pkg/include/funcdata.h", "pkg/include", true, use, false, ""},
			{c.name + ": std, a funcdata.h elsewhere in GOROOT", "src/rt", true, use, true, ""},
			{c.name + ": a module at the toolchain's funcdata.h", "src/runtime", false, use, true, ""},
			{c.name + ": std, a CALL beside the toolchain's funcdata.h", "src/runtime", true, merge(funcdataH, body("#include \"funcdata.h\"\n\n", "CALL "+n)), true, ""},
			{c.name + ": std, a FUNCDATA macro of the file", "src/runtime", true, body("#define "+c.macro+" FUNCDATA $"+c.slot+", "+n+"\n\n", c.macro), true, ""},
			{c.name + ": a module's own funcdata.h", "", false, use, true, ""},
			{c.name + ": a module's FUNCDATA macro as CALL, then the toolchain's funcdata.h", "", false, body("#define FUNCDATA CALL\n#include \"funcdata.h\"\n\n", c.macro), true, ""},
			{c.name + ": a module's FUNCDATA macro as MOVQ, then the toolchain's funcdata.h", "", false, body("#define FUNCDATA MOVQ\n#include \"funcdata.h\"\n\n", c.macro), true, ""},
			{c.name + ": std, ../runtime/funcdata.h within GOROOT", "src/fd", true,
				merge(body("#include \"../runtime/funcdata.h\"\n\n", c.macro), map[string]string{"../runtime/funcdata.h": base["_v/fd/fd.h"]}), false, ""},
			{c.name + ": std, the toolchain's funcdata.h found in $GOROOT/pkg/include", "src/fd", true,
				merge(body("#include \"funcdata.h\"\n\n", c.macro), map[string]string{"../../pkg/include/funcdata.h": base["_v/fd/fd.h"]}), false, ""},
			{c.name + ": a module CALL commented FUNCDATA", "", false, body("", "CALL "+n+" /* FUNCDATA */"), true, ""},
			{c.name + ": a module header CALL macro commented FUNCDATA", "", false, merge(body("#include \"fd.h\"\n\n", "M"), map[string]string{"fd.h": "#define M CALL " + n + " // FUNCDATA\n"}), true, ""},
			{c.name + ": a module FUNCDATA defined as a CALL", "", false, body("#define FUNCDATA CALL\n\n", "FUNCDATA "+n), true, ""},
			{c.name + ": a module comment opened on an earlier line", "", false, body("", "MOVQ AX, BX\n/*\nFUNCDATA $"+c.slot+", /* */ CALL "+n), true, ""},
			{c.name + ": a module macro parameter named FUNCDATA", "", false, body("#define M(FUNCDATA) FUNCDATA $"+c.slot+", "+n+"\n\n", "M(MOVQ)"), true, ""},
			{c.name + ": a module CALL beside a comment-glued operand", "", false, body("", "FUNCDATA $"+c.slot+", /**/"+n+"; CALL "+n), true, ""},
			{c.name + ": a module FUNCDATA defined by an out-of-directory header", "", false, merge(body("#include \"h/fd.h\"\n\n", "FUNCDATA $"+c.slot+", "+n), map[string]string{"h/fd.h": "#define FUNCDATA MOVQ\n"}), true, ""},
			{c.name + ": a module macro of the name", "", false, body("#define "+c.name+" ·evil\n\n", "FUNCDATA $"+c.slot+", "+n), true, ""},
		}...)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.gap != "" {
				t.Skip("pre-existing gap: " + tc.gap)
			}
			var fc, fcStd []string
			if tc.root == "" {
				got := lofRun(t, writeTree(t, merge(base, tc.files)), "example.com/v", map[string][]string{"example.com/v/vuln": {"Bad"}}, false, nil)
				f := got.facts["x.go"]
				if f == nil {
					t.Fatalf("the engine holds no x.go (facts %s)", lofDescribe(got))
				}
				if got.withheld != tc.held {
					t.Errorf("withheld = %v, want %v (facts %s)", got.withheld, tc.held, lofDescribe(got))
				}
				fc, fcStd = f.FC, f.FCStd
			} else {
				fc, fcStd = lofStdRootClosure(t, tc.root, tc.std, merge(base, tc.files))
			}
			var want []string
			if tc.held {
				want = []string{lofAsmSymbol}
			}
			if !slices.Equal(fc, want) || len(fcStd) > 0 {
				t.Errorf("x.go fails closed on %v (standard library %v), want %v", fc, fcStd, want)
			}
		})
	}
}

// TestLeftOutEngine_AsmInclude: a header a left-out file's assembly includes is found as cmd/asm finds
// it, from the package's directory within its module, then in $GOROOT/pkg/include, and its macros'
// references are followed like the file's own. An include found nowhere, or only by leaving the
// module, fails the file's bodies closed; the go command's generated go_asm.h does not. The module
// sits one directory below the tree, beside a header outside it.
func TestLeftOutEngine_AsmInclude(t *testing.T) {
	base := map[string]string{
		"m/go.mod":          "module example.com/m\n\ngo 1.22.0\n\nrequire example.com/v v0.0.0\n\nreplace example.com/v => ./_v\n",
		"m/main.go":         "package main\n\nimport \"example.com/v/vuln\"\n\nfunc main() { vuln.Safe() }\n",
		"m/_v/go.mod":       "module example.com/v\n\ngo 1.22\n",
		"m/_v/vuln/vuln.go": "package vuln\n\nfunc Bad() {}\n\nfunc Safe() {}\n",
		"m/_v/def/def.go":   "package def\n",
		"m/lib/lib.go":      "package lib\n",
		"m/lib/y_alt.go":    "//go:build lofother\n\npackage lib\n\nimport _ \"example.com/v/def\"\n",
		"m/app/app.go":      "package app\n\nimport _ \"example.com/v/vuln\"\n",
		"m/app/x.go":        "//go:build lofalt\n\npackage app\n\nfunc asm()\n\nfunc init() { asm() }\n",
		"outside.h":         "#define NOTHING 1\n",
	}
	bad := symKey("example.com/v/vuln", "Bad")
	asm := func(pre, stmt string) map[string]string {
		return map[string]string{"m/app/x_lofalt.s": "//go:build lofalt\n\n" + pre + "TEXT ·asm(SB),0,$0\n\t" + stmt + "\n\tRET\n"}
	}
	definer := map[string]string{"m/_v/def/def.s": "TEXT ext(SB),0,$0\n\tCALL example.com∕v∕vuln·Bad(SB)\n\tRET\n"}
	mention := map[string]string{"m/_v/def/def.h": "#define EXT ext\n", "m/_v/def/def.s": "#include \"def.h\"\n"}
	header := map[string]string{"m/include/x.h": "#define M CALL ext(SB)\n"}
	cases := []struct {
		name  string
		files map[string]string
		reach bool   // x.go's closure reaches Bad
		item  string // what x.go's closure fails closed on, when set: a header's mention of ext is an opaque definer of it
	}{
		{"a module ../include header's macro, to a definer", merge(asm("#include \"../include/x.h\"\n\n", "M"), header, definer), true, lofAsmSymbol},
		{"a module ../include header's macro, no definer", merge(asm("#include \"../include/x.h\"\n\n", "M"), header), false, lofAsmSymbol},
		{"a header the included header includes from the package's directory", merge(asm("#include \"../include/n.h\"\n\n", "M"), definer, map[string]string{
			"m/include/n.h": "#include \"../include/n.h\"\n#include \"y.h\"\n", "m/app/y.h": "#define M CALL ext(SB)\n"}), true, lofAsmSymbol},
		{"an include found nowhere", asm("#include \"missing.h\"\n\n", "NOP"), false, lofAsmSymbol},
		{"an include with no closing quote", asm("#include \"missing.h\n\n", "NOP"), false, lofAsmSymbol},
		{"an include in a comment", asm("/* #include \"missing.h\" */\n// #include \"missing.h\"\n\n", "NOP"), false, ""},
		{"an include on a line of a block comment", asm("/*\n#include \"missing.h\"\n*/\n\n", "NOP"), false, ""},
		{"an include leaving the module", asm("#include \"../../outside.h\"\n\n", "NOP"), false, lofAsmSymbol},
		{"an absolute include leaving the module", nil, false, lofAsmSymbol},
		{"the generated go_asm.h", asm("#include \"go_asm.h\"\n\n", "NOP"), false, ""},
		{"a go_asm.h of the package's directory shadows the generated one", merge(asm("#include \"go_asm.h\"\n\n", "M"), mention,
			map[string]string{"m/app/go_asm.h": "#define M CALL ext(SB)\n"}), false, lofAsmSymbol},
		{"textflag.h from $GOROOT/pkg/include", asm("#include \"textflag.h\"\n\n", "NOP"), false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, merge(base, tc.files))
			if tc.files == nil {
				out := filepath.Join(dir, "outside.h")
				if err := os.WriteFile(filepath.Join(dir, "m", "app", "x_lofalt.s"), []byte("//go:build lofalt\n\n#include \""+out+"\"\n\nTEXT ·asm(SB),0,$0\n\tRET\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got := lofRun(t, filepath.Join(dir, "m"), "example.com/v", map[string][]string{"example.com/v/vuln": {"Bad"}}, false, nil)
			f := got.facts["app/x.go"]
			if f == nil {
				t.Fatalf("the engine holds no app/x.go (facts %s)", lofDescribe(got))
			}
			var fc []string
			if tc.item != "" {
				fc = []string{tc.item}
			}
			if !slices.Equal(f.FC, fc) || len(f.FCStd) > 0 {
				t.Errorf("x.go fails closed on %v (standard library %v), want %v", f.FC, f.FCStd, fc)
			}
			if reached := slices.ContainsFunc(f.Funcs, func(id int32) bool { return got.engine.Strs[id] == bad }); reached != tc.reach {
				t.Errorf("x.go reaches Bad = %v, want %v", reached, tc.reach)
			}
			if want := tc.reach || tc.item != ""; got.withheld != want {
				t.Errorf("withheld = %v, want %v (facts %s)", got.withheld, want, lofDescribe(got))
			}
		})
	}
}

// TestLofParseAsmFuncdataNoGoroot: with no toolchain root known, no header is the toolchain's
// funcdata.h, even one at the path a root of "." would give it.
func TestLofParseAsmFuncdataNoGoroot(t *testing.T) {
	t.Chdir(writeTree(t, map[string]string{"src/runtime/funcdata.h": "#define GO_ARGS FUNCDATA $0, go_args_stackmap(SB)\n"}))
	for _, tc := range []struct {
		goroot string
		kept   bool
	}{{"", true}, {".", false}} {
		p := &lofPkg{path: "runtime", dir: filepath.Join("src", "runtime"), root: ".", std: true, asmText: map[string][]*lofAsm{}, asmData: map[string]bool{}}
		parseAsm(p, filepath.Join("src", "runtime", "a.s"), []byte("#include \"funcdata.h\"\nTEXT ·f(SB),0,$0\n\tGO_ARGS\n\tRET\n"), tc.goroot)
		bodies := p.asmText["runtime.f"]
		if len(bodies) != 1 {
			t.Fatalf("goroot %q: bodies of runtime.f = %d, want 1", tc.goroot, len(bodies))
		}
		if kept := slices.Contains(bodies[0].refs, "go_args_stackmap"); kept != tc.kept {
			t.Errorf("goroot %q: go_args_stackmap kept = %v, want %v (refs %v)", tc.goroot, kept, tc.kept, bodies[0].refs)
		}
	}
}

// lofStdRootClosure lays files out as module example.com/m at root under a stand-in GOROOT, marks
// the package standard when std, and returns what x.go's closure fails closed on, and fails closed on
// for the standard library.
func lofStdRootClosure(t *testing.T, root string, std bool, files map[string]string) ([]string, []string) {
	t.Helper()
	tree := map[string]string{}
	for name, body := range files {
		tree[root+"/"+name] = body
	}
	goroot, err := filepath.EvalSymlinks(writeTree(t, tree))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(goroot, root)
	ctx := context.Background()
	load, err := LoadProgram(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	load.buildGoVersion = load.goVersion
	release := load.buildRelease()
	floor := goDirectiveFloor(load.Packages)
	excluded := func(x constraint.Expr) bool { return ignored(x) || toolchainExcluded(x, release, floor) }
	w := newLofWorld(ctx, load.Packages, dir, append(os.Environ(), "GOWORK=off"), excluded, goroot, time.Now().Add(time.Minute))
	w.dirs["example.com/m"], w.names["example.com/m"], w.std["example.com/m"] = dir, "main", std
	cl := w.closure(filepath.Join(dir, "x.go"), "example.com/m")
	return cl.fc, cl.fcStd
}

// TestLeftOutEngine_AsmLinkOwnDefiner: a bare symbol x.go's own assembly defines still follows every
// other definer of it in the link, and a build that links no definition binds it to foreign code. The
// link may keep another package's DUPOK definition over a non-DUPOK one in either load order, and the
// own definition may sit in a file another build leaves out.
func TestLeftOutEngine_AsmLinkOwnDefiner(t *testing.T) {
	base := map[string]string{
		"go.mod":          "module example.com/m\n\ngo 1.22.0\n\nrequire example.com/v v0.0.0\n\nreplace example.com/v => ./_v\n",
		"main.go":         "package main\n\nimport \"example.com/v/vuln\"\n\nfunc main() { vuln.Safe() }\n",
		"_v/go.mod":       "module example.com/v\n\ngo 1.22\n",
		"_v/vuln/vuln.go": "package vuln\n\nfunc Bad() {}\n\nfunc Safe() {}\n",
		"lib/lib.go":      "package lib\n",
		"lib/y_alt.go":    "//go:build lofother\n\npackage lib\n\nimport _ \"example.com/v/def\"\n",
		"x.go":            "//go:build lofalt\n\npackage main\n\nfunc asm()\n\nfunc init() { asm() }\n",
	}
	loadedDef := "package main\n\nimport (\n\t_ \"example.com/v/def\"\n\t\"example.com/v/vuln\"\n)\n\nfunc main() { vuln.Safe() }\n"
	// The other definer: a body calling Bad, data whose package's init calls Bad, or a variable
	// holding Bad.
	text := func(flags string) map[string]string {
		return map[string]string{"_v/def/def.go": "package def\n", "_v/def/def.s": "TEXT target(SB)," + flags + "$0\n\tCALL example.com∕v∕vuln·Bad(SB)\n\tRET\n"}
	}
	asmData := map[string]string{
		"_v/def/def.go": "package def\n\nimport \"example.com/v/vuln\"\n\nfunc init() { vuln.Bad() }\n",
		"_v/def/def.s":  "DATA target+0(SB)/8, $2\nGLOBL target(SB),2,$8\n",
	}
	goVar := map[string]string{"_v/def/def.go": "package def\n\nimport (\n\t_ \"unsafe\"\n\n\t\"example.com/v/vuln\"\n)\n\n//go:linkname v target\nvar v = vuln.Bad\n"}
	ownText := func(flags string) map[string]string {
		return map[string]string{"x_lofalt.s": "//go:build lofalt\n\nTEXT target(SB)," + flags + "$0\n\tRET\n\nTEXT ·asm(SB),0,$0\n\tCALL target(SB)\n\tRET\n"}
	}
	ownData := func(def string) map[string]string {
		return map[string]string{"x_lofalt.s": "//go:build lofalt\n\n" + def + "\nTEXT ·asm(SB),0,$0\n\tMOVQ target(SB), AX\n\tRET\n"}
	}
	none := map[string]string{"_v/def/def.go": "package def\n"}
	callOnly := map[string]string{"x_lofalt.s": "//go:build lofalt\n\nTEXT ·asm(SB),0,$0\n\tCALL target(SB)\n\tRET\n"}
	cases := []struct {
		name  string
		files map[string]string
		reach bool   // x.go's closure reaches vuln.Bad
		sink  bool   // x.go's closure reaches a loaded variable holding a func
		item  string // what x.go's closure fails closed on, when set: entering an unloaded package
		// that pushes a //go:linkname fails closed at the dot-less linkname arm
	}{
		{"own TEXT, no other definer", merge(none, ownText("NOSPLIT,")), false, false, ""},
		{"own DUPOK TEXT, another package's DUPOK TEXT", merge(text("2,"), ownText("2,")), true, false, ""},
		{"own DUPOK TEXT, a loaded package's DUPOK TEXT", merge(text("2,"), ownText("NOSPLIT|DUPOK,"), map[string]string{"main.go": loadedDef}), true, false, ""},
		{"own NOSPLIT TEXT, another package's DUPOK TEXT", merge(text("2,"), ownText("NOSPLIT,")), true, false, ""},
		{"own NOSPLIT TEXT, a loaded package's DUPOK TEXT", merge(text("2,"), ownText("NOSPLIT,"), map[string]string{"main.go": loadedDef}), true, false, ""},
		{"own TEXT with no flags, another package's DUPOK TEXT", merge(text("2,"), ownText("")), true, false, ""},
		{"own DUPOK TEXT, another package's non-DUPOK TEXT", merge(text(""), ownText("DUPOK,")), true, false, ""},
		{"own unfilled GLOBL, another package's variable", merge(goVar, ownData("GLOBL target(SB),8,$8\n")), true, false, lofLinkname},
		{"own unfilled GLOBL, a loaded package's variable", merge(goVar, ownData("GLOBL target(SB),8,$8\n"), map[string]string{"main.go": loadedDef}), false, true, ""},
		{"own filled GLOBL, another package's DUPOK data", merge(asmData, ownData("DATA target+0(SB)/8, $1\nGLOBL target(SB),8,$8\n")), true, false, ""},
		{"own GLOBL filled only in a disjoint build, another package's variable", merge(goVar, ownData("GLOBL target(SB),8,$8\n"), map[string]string{
			"d_nolofalt.s": "//go:build !lofalt\n\nDATA target+0(SB)/8, $0\n",
		}), true, false, lofLinkname},
		{"own TEXT only in a disjoint build, no other definer", merge(none, callOnly, map[string]string{
			"t_nolofalt.s": "//go:build !lofalt\n\nTEXT target(SB),0,$0\n\tRET\n",
		}), false, false, ""},
		{"own TEXT only in a disjoint build, another package's TEXT", merge(text(""), callOnly, map[string]string{
			"t_nolofalt.s": "//go:build !lofalt\n\nTEXT target(SB),0,$0\n\tRET\n",
		}), true, false, ""},
	}
	bad := symKey("example.com/v/vuln", "Bad")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := lofRun(t, writeTree(t, merge(base, tc.files)), "example.com/v", map[string][]string{"example.com/v/vuln": {"Bad"}}, false, nil)
			f := got.facts["x.go"]
			if f == nil {
				t.Fatalf("the engine holds no x.go (facts %s)", lofDescribe(got))
			}
			if !f.Dyn {
				t.Errorf("x.go: no dynamic call; a build linking no definition binds the symbol to foreign code")
			}
			var fc []string
			if tc.item != "" {
				fc = []string{tc.item}
			}
			if !slices.Equal(f.FC, fc) {
				t.Errorf("x.go fails closed on %v, want %v", f.FC, fc)
			}
			if reached := slices.ContainsFunc(f.Funcs, func(id int32) bool { return got.engine.Strs[id] == bad }); reached != tc.reach {
				t.Errorf("x.go reaches vuln.Bad = %v, want %v", reached, tc.reach)
			}
			if f.Sink != tc.sink {
				t.Errorf("x.go sink = %v, want %v", f.Sink, tc.sink)
			}
		})
	}
}

// TestLeftOutEngine_AsmLinkDefinerOrder: the definer of a bare symbol sits in a package no closure
// has parsed yet; whether another closure parsed it first changes nothing.
func TestLeftOutEngine_AsmLinkDefinerOrder(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"go.mod":          "module example.com/m\n\ngo 1.22.0\n\nrequire example.com/v v0.0.0\n\nreplace example.com/v => ./_v\n",
		"main.go":         "package main\n\nimport \"example.com/v/vuln\"\n\nfunc main() { vuln.Safe() }\n",
		"_v/go.mod":       "module example.com/v\n\ngo 1.22\n",
		"_v/vuln/vuln.go": "package vuln\n\nfunc Bad() {}\n\nfunc Safe() {}\n",
		"lib/lib.go":      "package lib\n",
		"lib/def.go":      "package lib\n\nimport (\n\t_ \"unsafe\"\n\n\t\"example.com/v/vuln\"\n)\n\n//go:linkname impl target\nfunc impl() { vuln.Bad() }\n",
		"lib/y_alt.go":    "//go:build lofother\n\npackage lib\n\nfunc init() {}\n",
		"x.go":            "//go:build lofalt\n\npackage main\n\nfunc asm()\n\nfunc init() { asm() }\n",
		"x_lofalt.s":      "//go:build lofalt\n\nTEXT ·asm(SB),0,$0\n\tCALL target(SB)\n\tRET\n",
	})
	ctx := context.Background()
	load, err := LoadProgram(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	load.buildGoVersion = load.goVersion
	release := load.buildRelease()
	env := append(os.Environ(), "GOWORK=off")
	floor := goDirectiveFloor(load.Packages)
	excluded := func(x constraint.Expr) bool { return ignored(x) || toolchainExcluded(x, release, floor) }
	goroot, item := lofToolchain(ctx, dir, env, release)
	if item != "" {
		t.Fatal(item)
	}
	cands := map[string]lofCandidate{}
	for _, c := range lofCandidates(load.Packages) {
		cands[filepath.Base(c.path)] = c
	}
	if _, ok := cands["y_alt.go"]; !ok {
		t.Fatalf("y_alt.go is no candidate: %v", cands)
	}
	// x reports what x.go's closure reaches and fails closed on after the closures of order.
	x := func(order ...string) (bool, []string) {
		w := newLofWorld(ctx, load.Packages, dir, env, excluded, goroot, time.Now().Add(time.Minute))
		var cl *lofClosure
		for _, name := range order {
			c := cands[name]
			cl = w.closure(c.path, c.pkg)
		}
		impl := false
		for fn := range cl.funcs {
			impl = impl || funcKey(fn) == symKey("example.com/m/lib", "impl")
		}
		return impl, cl.fc
	}
	for _, order := range [][]string{{"x.go"}, {"y_alt.go", "x.go"}} {
		if impl, fc := x(order...); !impl || len(fc) > 0 {
			t.Errorf("after %v: x.go reaches lib.impl = %v, fails closed on %v; want true, nothing", order, impl, fc)
		}
	}
}

// lofELFObject returns an ELF64 relocatable object whose text section defines each of names as a
// global function symbol.
func lofELFObject(names ...string) []byte {
	le := binary.LittleEndian
	strtab := []byte{0}
	syms := make([]byte, 24) // the null symbol
	for _, n := range names {
		s := make([]byte, 24)
		le.PutUint32(s[0:], uint32(len(strtab)))
		s[4] = 1<<4 | 2 // STB_GLOBAL, STT_FUNC
		le.PutUint16(s[6:], 1)
		syms = append(syms, s...)
		strtab = append(append(strtab, n...), 0)
	}
	shstrtab := []byte("\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00")
	text := []byte{0xc3}
	off := func(n int) int { return (n + 7) &^ 7 }
	textOff := 64
	symOff := off(textOff + len(text))
	strOff := symOff + len(syms)
	shstrOff := strOff + len(strtab)
	shOff := off(shstrOff + len(shstrtab))
	out := make([]byte, shOff+5*64)
	copy(out, "\x7fELF\x02\x01\x01")
	le.PutUint16(out[16:], 1)  // ET_REL
	le.PutUint16(out[18:], 62) // EM_X86_64
	le.PutUint32(out[20:], 1)
	le.PutUint64(out[40:], uint64(shOff))
	le.PutUint16(out[52:], 64)
	le.PutUint16(out[58:], 64)
	le.PutUint16(out[60:], 5)
	le.PutUint16(out[62:], 4)
	copy(out[textOff:], text)
	copy(out[symOff:], syms)
	copy(out[strOff:], strtab)
	copy(out[shstrOff:], shstrtab)
	section := func(i int, name, typ uint32, flags uint64, offset, size int, link, info uint32, entsize uint64) {
		h := out[shOff+i*64:]
		le.PutUint32(h[0:], name)
		le.PutUint32(h[4:], typ)
		le.PutUint64(h[8:], flags)
		le.PutUint64(h[24:], uint64(offset))
		le.PutUint64(h[32:], uint64(size))
		le.PutUint32(h[40:], link)
		le.PutUint32(h[44:], info)
		le.PutUint64(h[48:], 1)
		le.PutUint64(h[56:], entsize)
	}
	section(1, 1, 1, 6, textOff, len(text), 0, 0, 0)       // .text: SHT_PROGBITS, alloc+exec
	section(2, 7, 2, 0, symOff, len(syms), 3, 1, 24)       // .symtab: SHT_SYMTAB, its strings in 3, locals end at 1
	section(3, 15, 3, 0, strOff, len(strtab), 0, 0, 0)     // .strtab
	section(4, 23, 3, 0, shstrOff, len(shstrtab), 0, 0, 0) // .shstrtab
	return out
}

// TestLeftOutEngine_AsmLinkDefinerStd: the race detector's runtime assembly references the race
// runtime's symbols bare, and the standard library's own .syso objects define them: a definer
// inside the toolchain fails closed for a standard-library refutation only, and one of a module
// for every refutation.
func TestLeftOutEngine_AsmLinkDefinerStd(t *testing.T) {
	base := map[string]string{
		"go.mod":     "module example.com/m\n\ngo 1.22.0\n",
		"main.go":    "package main\n\nfunc main() {}\n",
		"x.go":       "//go:build lofalt\n\npackage main\n\nfunc asm()\n\nfunc init() { asm() }\n",
		"x_lofalt.s": "//go:build lofalt\n\nTEXT ·asm(SB),0,$0\n\tCALL runtime·raceread(SB)\n\tRET\n",
	}
	for _, tc := range []struct {
		name    string
		files   map[string]string
		fc, std bool
	}{
		{"only the toolchain defines it", nil, false, true},
		{"a module's .syso object defines it too", map[string]string{
			"main.go":   "package main\n\nimport _ \"example.com/m/sy\"\n\nfunc main() {}\n",
			"sy/sy.go":  "package sy\n",
			"sy/a.syso": string(lofELFObject("__tsan_read")),
		}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := lofRun(t, writeTree(t, merge(base, tc.files)), "stdlib", map[string][]string{"strings": {"Index"}}, false, nil)
			f := got.facts["x.go"]
			if f == nil {
				t.Fatalf("the engine holds no x.go (facts %s)", lofDescribe(got))
			}
			if fc, std := slices.Contains(f.FC, lofAsmSymbol), slices.Contains(f.FCStd, lofAsmSymbol); fc != tc.fc || std != tc.std {
				t.Errorf("x.go fails closed on %s = %v, for the standard library = %v; want %v, %v", lofAsmSymbol, fc, std, tc.fc, tc.std)
			}
		})
	}
}
