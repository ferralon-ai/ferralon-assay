package goanalysis

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

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
		{"a left-out function pulls the symbol's pointer method by linkname", x("\t_ \"unsafe\"\n\t_ \"example.com/v/vuln\"",
			"//go:linkname pulled example.com/v/vuln.(*P).Bad\nfunc pulled(*struct{})\n\nfunc init() { pulled(nil) }\n"), nil, true, "", false},
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
		{"the file has another type error", map[string]string{
			"_v/vuln/y.go": "//go:build lofalt\n\npackage vuln\n\nfunc init() { helper(); var n int = \"s\"; _ = n; Bad() }\n",
		}, true, "", "", true, lofVariantTypecheck, ""},
		{"the file dot-imports a package", map[string]string{
			"_v/vuln/y.go": "//go:build lofalt\n\npackage vuln\n\nimport . \"strings\"\n\nfunc init() { helper(); _ = ToUpper; Bad() }\n",
		}, true, "", "", true, lofUnresolvedName, ""},

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
