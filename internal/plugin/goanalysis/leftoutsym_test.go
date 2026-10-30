package goanalysis

import (
	"context"
	"os"
	"runtime"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// lofVerdictFor loads dir as the build under the load's own release and asks leftOutReachesSymbols
// whether its left-out code may reach vulnerable.
func lofVerdictFor(t *testing.T, dir string, vulnerable map[string][]string, env []string) lofVerdict {
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
	_, _, base, err := wholeProgramOf(load)
	if err != nil {
		t.Fatal(err)
	}
	if base == nil {
		t.Fatal("no reached base")
	}
	if env == nil {
		env = append(os.Environ(), "GOWORK=off")
	}
	return leftOutReachesSymbols(context.Background(), load.Packages, vulnerable, base, *release, dir, env)
}

// TestLeftOutReachesSymbols_StandardLibrary: against the release's own standard library, a left-out
// file of a loaded standard package counts only when code it can run reaches a vulnerable symbol.
func TestLeftOutReachesSymbols_StandardLibrary(t *testing.T) {
	// otherVerify is a function only another platform's Certificate.systemVerify calls.
	otherVerify := map[string][]string{"crypto/x509": {"checkChainSSLServerPolicy"}}
	if runtime.GOOS != "darwin" {
		otherVerify = map[string][]string{"crypto/x509/internal/macos": {"SecPolicyCreateSSL"}}
	}
	useStd := func(imp, use string) string {
		return "package main\n\nimport \"" + imp + "\"\n\nfunc main() { " + use + " }\n"
	}
	cases := []struct {
		name       string
		main       string
		vulnerable map[string][]string
		withheld   bool
		reason     string // checked when set
	}{
		{"Verify is reached and only another platform's systemVerify reaches the symbol",
			useStd("crypto/x509", "_, _ = (&x509.Certificate{}).Verify(x509.VerifyOptions{})"), otherVerify, true, ""},
		{"only ParseCertificate is reached, and the boringcrypto build of a function it reaches imports C",
			useStd("crypto/x509", "_, _ = x509.ParseCertificate(nil)"), map[string][]string{"crypto/x509": {"Certificate.Verify"}}, true, lofCgo},
		{"only Open is reached and the symbol is Root.Open",
			useStd("os", "_, _ = os.Open(\"x\")"), map[string][]string{"os": {"Root.Open"}}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"go.mod": "module example.com/m\n\ngo 1.22\n", "main.go": tc.main})
			v := lofVerdictFor(t, dir, tc.vulnerable, nil)
			if v.Withhold != tc.withheld {
				t.Fatalf("withheld = %v, want %v (verdict %+v)", v.Withhold, tc.withheld, v)
			}
			if tc.reason != "" && v.Reason != tc.reason {
				t.Errorf("reason = %q, want %q (verdict %+v)", v.Reason, tc.reason, v)
			}
		})
	}
}

// TestLeftOutReachesSymbols_Constructs: each way code the build left out can run, and each thing the
// closure cannot follow, over a module whose vulnerable package is example.com/m/vuln. A file built
// under the lofalt tag is left out.
func TestLeftOutReachesSymbols_Constructs(t *testing.T) {
	base := map[string]string{
		"go.mod": "module example.com/m\n\ngo 1.22\n",
		"vuln/vuln.go": "package vuln\n\nfunc Bad() {}\n\nfunc Safe() {}\n\nfunc BadInt() int { return 0 }\n\n" +
			"type T struct{}\n\nfunc (T) Bad() {}\n\nfunc (T) Safe() {}\n\nfunc Variadic(xs ...int) {}\n",
		"hook/hook.go": "package hook\n\nfunc Hook() {}\n",
	}
	on := func(body string) string { return "//go:build !lofalt\n\n" + body }
	off := func(body string) string { return "//go:build lofalt\n\n" + body }
	mainWith := func(imports, body string) string {
		return "package main\n\nimport (\n" + imports + "\n)\n\nfunc main() {\n" + body + "\n}\n"
	}
	bad := map[string][]string{"example.com/m/vuln": {"Bad", "T.Bad", "Variadic"}}
	cases := []struct {
		name     string
		files    map[string]string
		withheld bool
		reason   string
	}{
		{"nothing left out", map[string]string{"main.go": mainWith(`"example.com/m/vuln"`, "vuln.Safe()")}, false, ""},
		{"another build's replacement of a reached function calls the symbol", map[string]string{
			"main.go":    "package main\n\nfunc main() { run() }\n",
			"run_on.go":  on("package main\n\nimport \"example.com/m/vuln\"\n\nfunc run() { vuln.Safe() }\n"),
			"run_off.go": off("package main\n\nimport \"example.com/m/vuln\"\n\nfunc run() { vuln.Bad() }\n"),
		}, true, lofReachesSymbol},
		{"another build's replacement of a reached function calls only other functions", map[string]string{
			"main.go":    "package main\n\nfunc main() { run() }\n",
			"run_on.go":  on("package main\n\nimport \"example.com/m/vuln\"\n\nfunc run() { vuln.Safe() }\n"),
			"run_off.go": off("package main\n\nimport \"example.com/m/vuln\"\n\nfunc run() { vuln.Safe(); vuln.BadInt() }\n"),
		}, false, ""},
		{"another build's replacement of an unreached function calls the symbol", map[string]string{
			"main.go":    "package main\n\nfunc main() {}\n",
			"run_on.go":  on("package main\n\nfunc run() {}\n"),
			"run_off.go": off("package main\n\nimport \"example.com/m/vuln\"\n\nfunc run() { vuln.Bad() }\n"),
		}, false, ""},
		{"another build's replacement of a reached method calls the symbol", map[string]string{
			"main.go":    "package main\n\ntype r struct{}\n\nfunc main() { r{}.run() }\n",
			"run_on.go":  on("package main\n\nfunc (r) run() {}\n"),
			"run_off.go": off("package main\n\nimport \"example.com/m/vuln\"\n\nfunc (r) run() { vuln.Bad() }\n"),
		}, true, lofReachesSymbol},
		{"a left-out init calls the symbol", map[string]string{
			"main.go": "package main\n\nfunc main() {}\n",
			"x.go":    off("package main\n\nimport \"example.com/m/vuln\"\n\nfunc init() { vuln.Bad() }\n"),
		}, true, lofReachesSymbol},
		{"a left-out variable's initializer calls the symbol", map[string]string{
			"main.go": "package main\n\nfunc main() {}\n",
			"x.go":    off("package main\n\nimport \"example.com/m/vuln\"\n\nvar x = f()\n\nfunc f() int { vuln.Bad(); return 0 }\n"),
		}, true, lofReachesSymbol},
		{"a package only left-out code imports has an init that calls the symbol", map[string]string{
			"go.mod":           "module example.com/m\n\ngo 1.22\n\nrequire example.com/initbad v0.0.0\n\nreplace example.com/initbad => ./_initbad\n",
			"main.go":          "package main\n\nfunc main() {}\n",
			"x.go":             off("package main\n\nimport _ \"example.com/initbad\"\n"),
			"_initbad/go.mod":  "module example.com/initbad\n\ngo 1.22\n",
			"_initbad/init.go": "package initbad\n\nimport \"example.com/m/vuln\"\n\nfunc init() { vuln.Bad() }\n",
		}, true, lofReachesSymbol},
		{"a left-out type reached code dispatches to calls the symbol", map[string]string{
			"main.go":  "package main\n\ntype I interface{ M() }\n\nfunc use(i I) { i.M() }\n\nfunc main() { use(mk()) }\n",
			"mk_on.go": on("package main\n\ntype onT struct{}\n\nfunc (onT) M() {}\n\nfunc mk() I { return onT{} }\n"),
			"mk_off.go": off("package main\n\nimport \"example.com/m/vuln\"\n\ntype offT struct{}\n\n" +
				"func (offT) M() { vuln.Bad() }\n\nfunc mk() I { return offT{} }\n"),
		}, true, lofReachesSymbol},
		{"left-out code calls a method value reached code passes it", map[string]string{
			"main.go":      mainWith(`"example.com/m/vuln"`, "apply(vuln.T{}.Bad)"),
			"apply_on.go":  on("package main\n\nfunc apply(f func()) {}\n"),
			"apply_off.go": off("package main\n\nfunc apply(f func()) { f() }\n"),
		}, true, lofReachesSymbol},
		{"left-out code calls a function literal reached code passes it", map[string]string{
			"main.go":      mainWith(`"example.com/m/vuln"`, "apply(func() { vuln.Bad() })"),
			"apply_on.go":  on("package main\n\nfunc apply(f func()) {}\n"),
			"apply_off.go": off("package main\n\nfunc apply(f func()) { f() }\n"),
		}, true, lofReachesSymbol},
		{"left-out code never calls the function value reached code passes it", map[string]string{
			"main.go":      mainWith(`"example.com/m/vuln"`, "apply(func() { vuln.Bad() })"),
			"apply_on.go":  on("package main\n\nfunc apply(f func()) {}\n"),
			"apply_off.go": off("package main\n\nfunc apply(f func()) { _ = f }\n"),
		}, false, ""},
		{"left-out generic code calls the symbol through a constraint", map[string]string{
			"main.go":     mainWith(`"example.com/m/vuln"`, "call(vuln.T{})"),
			"call_on.go":  on("package main\n\nfunc call[X interface{ Bad() }](x X) {}\n"),
			"call_off.go": off("package main\n\nfunc call[X interface{ Bad() }](x X) { x.Bad() }\n"),
		}, true, lofReachesSymbol},
		{"a left-out init calls the symbol promoted through an embedded field", map[string]string{
			"main.go": "package main\n\nfunc main() {}\n",
			"x.go":    off("package main\n\nimport \"example.com/m/vuln\"\n\ntype w struct{ vuln.T }\n\nfunc init() { var v w; v.Bad() }\n"),
		}, true, lofReachesSymbol},
		{"a left-out init calls the symbol through an alias", map[string]string{
			"main.go": "package main\n\nfunc main() {}\n",
			"x.go":    off("package main\n\nimport \"example.com/m/vuln\"\n\ntype a = vuln.T\n\nfunc init() { var v a; v.Bad() }\n"),
		}, true, lofReachesSymbol},
		{"a left-out init calls the symbol through a dot-import", map[string]string{
			"main.go": "package main\n\nfunc main() {}\n",
			"x.go":    off("package main\n\nimport . \"example.com/m/vuln\"\n\nfunc init() { Bad() }\n"),
		}, true, lofReachesSymbol},
		{"a left-out init calls a selection of another arity", map[string]string{
			"main.go": mainWith(`"example.com/m/vuln"`, "_ = vuln.T{}"),
			"x.go":    off("package main\n\ntype s struct{}\n\nfunc (s) Bad(int) {}\n\nfunc init() { var v s; v.Bad(1) }\n"),
		}, false, ""},
		{"a left-out init calls a variadic symbol with no arguments", map[string]string{
			"main.go": "package main\n\nfunc main() {}\n",
			"x.go":    off("package main\n\nimport \"example.com/m/vuln\"\n\nfunc init() { vuln.Variadic() }\n"),
		}, true, lofReachesSymbol},
		{"a left-out function pulls the symbol by linkname", map[string]string{
			"main.go": "package main\n\nfunc main() {}\n",
			"x.go": off("package main\n\nimport _ \"unsafe\"\n\n//go:linkname pulled example.com/m/vuln.Bad\nfunc pulled()\n\n" +
				"func init() { pulled() }\n"),
		}, true, lofReachesSymbol},
		{"a left-out function pushed by linkname calls the symbol", map[string]string{
			"main.go": mainWith(`"example.com/m/hook"`, "hook.Hook()"),
			"x.go": off("package main\n\nimport (\n\t_ \"unsafe\"\n\t\"example.com/m/vuln\"\n)\n\n" +
				"//go:linkname pushed example.com/m/hook.Pushed\nfunc pushed() { vuln.Bad() }\n"),
		}, true, lofReachesSymbol},
		{"a left-out bodyless function's assembly calls the symbol", map[string]string{
			"main.go":    "package main\n\nfunc main() {}\n",
			"x.go":       off("package main\n\nfunc asm()\n\nfunc init() { asm() }\n"),
			"x_lofalt.s": "//go:build lofalt\n\n#include \"textflag.h\"\n\nTEXT ·asm(SB),NOSPLIT,$0\n\tCALL example.com∕m∕vuln·Bad(SB)\n\tRET\n",
		}, true, lofReachesSymbol},
		{"a left-out bodyless function has no body anywhere", map[string]string{
			"main.go": "package main\n\nfunc main() {}\n",
			"x.go":    off("package main\n\nfunc asm()\n\nfunc init() { asm() }\n"),
		}, true, lofBodyless},
		{"left-out assembly references a symbol nothing declares", map[string]string{
			"main.go":    "package main\n\nfunc main() {}\n",
			"x.go":       off("package main\n\nfunc asm()\n\nfunc init() { asm() }\n"),
			"x_lofalt.s": "//go:build lofalt\n\nTEXT ·asm(SB),0,$0\n\tCALL example.com∕m∕vuln·Nowhere(SB)\n\tRET\n",
		}, true, lofAsmSymbol},
		{"a left-out cgo file", map[string]string{
			"main.go": "package main\n\nfunc main() {}\n",
			"x.go":    off("package main\n\nimport \"C\"\n\nfunc init() {}\n"),
		}, true, lofCgo},
		{"a left-out file does not parse", map[string]string{
			"main.go": "package main\n\nfunc main() {}\n",
			"x.go":    off("package main\n\nfunc init() {\n"),
		}, true, lofParseError},
		{"a left-out file imports a path nothing provides", map[string]string{
			"main.go": "package main\n\nfunc main() {}\n",
			"x.go":    off("package main\n\nimport _ \"example.org/nowhere\"\n"),
		}, true, lofUnresolvedImport},
		{"a left-out init calls MethodByName", map[string]string{
			"main.go": "package main\n\nfunc main() {}\n",
			"x.go":    off("package main\n\nimport \"reflect\"\n\nfunc init() { var v reflect.Value; v.MethodByName(\"Bad\") }\n"),
		}, true, lofReflectCall},
		{"a main-module package the load never listed calls the symbol", map[string]string{
			"main.go":      "package main\n\nfunc main() {}\n",
			"tool/tool.go": off("package main\n\nimport \"example.com/m/vuln\"\n\nfunc main() { vuln.Bad() }\n"),
		}, true, lofReachesSymbol},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, merge(base, tc.files))
			v := lofVerdictFor(t, dir, bad, nil)
			if v.Withhold != tc.withheld {
				t.Fatalf("withheld = %v, want %v (verdict %+v)", v.Withhold, tc.withheld, v)
			}
			if v.Reason != tc.reason {
				t.Errorf("reason = %q, want %q (verdict %+v)", v.Reason, tc.reason, v)
			}
		})
	}
}

// TestLeftOutReachesSymbols_Bounds: what the closure counts as vulnerable, how far it lets left-out
// code route back into the build, and when it gives up and withholds.
func TestLeftOutReachesSymbols_Bounds(t *testing.T) {
	base := map[string]string{
		"go.mod":       "module example.com/m\n\ngo 1.22\n",
		"vuln/vuln.go": "package vuln\n\nfunc Bad() {}\n\nfunc Safe() {}\n\ntype T struct{}\n\nfunc (T) Bad() {}\n",
	}
	// vuln.Safe is reached: govulncheck searches from every exported function of a loaded package.
	callsSafe := map[string]string{
		"main.go": "package main\n\nfunc main() {}\n",
		"x.go":    "//go:build lofalt\n\npackage main\n\nimport \"example.com/m/vuln\"\n\nfunc h() { vuln.Safe() }\n\nfunc init() { h() }\n",
	}
	// The build holds a dep.T, which an interface call it makes could dispatch to but never does; a
	// left-out file that names no package of dep's calls into the build.
	escapes := map[string]string{
		"go.mod":      "module example.com/m\n\ngo 1.22\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => ./_dep\n",
		"_dep/go.mod": "module example.com/dep\n\ngo 1.22\n",
		"_dep/dep.go": "package dep\n\ntype T struct{}\n\nfunc (T) Bad() {}\n\nfunc New() T { return T{} }\n",
		"main.go": "package main\n\nimport \"example.com/dep\"\n\ntype I interface{ Bad() }\n\ntype other struct{}\n\n" +
			"func (other) Bad() {}\n\nfunc call(i I) { i.Bad() }\n\nvar sink dep.T\n\nfunc main() { call(other{}); sink = dep.New() }\n",
		"x.go": "//go:build lofalt\n\npackage main\n\nfunc init() { call(other{}) }\n",
	}
	bad := map[string][]string{"example.com/m/vuln": {"Bad", "T.Bad"}}
	depBad := map[string][]string{"example.com/dep": {"T.Bad"}}
	cases := []struct {
		name       string
		files      map[string]string
		vulnerable map[string][]string
		env        []string
		budget     int
		mode       escapeMode
		withheld   bool
		reason     string
	}{
		{"a package the advisory lists no symbols for counts every function", callsSafe,
			map[string][]string{"example.com/m/vuln": nil}, nil, 0, escapeAllBase, true, lofReachesSymbol},
		{"a package the advisory lists symbols for counts only those", callsSafe, bad, nil, 0, escapeAllBase, false, ""},
		{"left-out code may reach any method the build's types have that its interface calls match", escapes,
			depBad, nil, 0, escapeAllBase, true, lofReachesSymbol},
		{"importers only: the left-out code names no package such a method belongs to", escapes,
			depBad, nil, 0, escapeImporters, false, ""},
		{"a file overlay may replace standard-library source", callsSafe, bad,
			append(os.Environ(), "GOWORK=off", "GOFLAGS=-overlay=/nonexistent.json"), 0, escapeAllBase, true, lofGorootMismatch},
		{"the closure outgrows its budget", callsSafe, bad, nil, 1, escapeAllBase, true, lofBudget},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.budget > 0 {
				defer func(n int) { lofBudgetDecls = n }(lofBudgetDecls)
				lofBudgetDecls = tc.budget
			}
			defer func(m escapeMode) { escapeBaseTypes = m }(escapeBaseTypes)
			escapeBaseTypes = tc.mode
			dir := writeTree(t, merge(base, tc.files))
			v := lofVerdictFor(t, dir, tc.vulnerable, tc.env)
			if v.Withhold != tc.withheld {
				t.Fatalf("withheld = %v, want %v (verdict %+v)", v.Withhold, tc.withheld, v)
			}
			if v.Reason != tc.reason {
				t.Errorf("reason = %q, want %q (verdict %+v)", v.Reason, tc.reason, v)
			}
		})
	}
}

// TestLeftOutReachesSymbols_UnknownToolchain: a release whose toolchain cannot be found withholds.
func TestLeftOutReachesSymbols_UnknownToolchain(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"go.mod":  "module example.com/m\n\ngo 1.22\n",
		"main.go": "package main\n\nfunc main() {}\n",
		"x.go":    "//go:build lofalt\n\npackage main\n\nfunc init() {}\n",
	})
	load, err := LoadProgram(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	load.buildGoVersion = load.goVersion
	_, _, base, err := wholeProgramOf(load)
	if err != nil {
		t.Fatal(err)
	}
	release := *load.buildRelease()
	release.patch = 999
	env := append(os.Environ(), "GOWORK=off", "GOPROXY=off")
	v := leftOutReachesSymbols(context.Background(), load.Packages, map[string][]string{"example.com/m/vuln": nil}, base, release, dir, env)
	if !v.Withhold || v.Reason != lofUnknownToolchain {
		t.Fatalf("verdict %+v, want withheld for %q", v, lofUnknownToolchain)
	}
}

// TestWithholdForLeftOutFiles_Routing: which refutations the symbol closure narrows. A module
// refutation, or one without what the build reaches, keeps the package-level rule.
func TestWithholdForLeftOutFiles_Routing(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"go.mod":       "module example.com/m\n\ngo 1.22\n",
		"vuln/vuln.go": "package vuln\n\nfunc Bad() {}\n\nfunc Safe() {}\n",
		"main.go":      "package main\n\nfunc main() {}\n",
		"x.go":         "//go:build lofalt\n\npackage main\n\nimport \"example.com/m/vuln\"\n\nfunc init() { vuln.Safe() }\n",
	})
	load, err := LoadProgram(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	load.buildGoVersion = load.goVersion
	_, _, reached, err := wholeProgramOf(load)
	if err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "GOWORK=off")
	scanned := vulnScan{
		imports: map[string][]string{"example.com/m": {"example.com/m/vuln"}},
		symbols: map[string][]string{"example.com/m/vuln": {"Bad"}},
	}
	if v := leftOutReachesSymbols(context.Background(), load.Packages, scanned.vulnerableSymbols("example.com/m"), reached, *load.buildRelease(), dir, env); v.Withhold {
		t.Fatalf("symbol closure withholds (%+v); the routing rows need it to release", v)
	}
	cases := []struct {
		name    string
		reached *reachedBase
	}{
		{"a module refutation", reached},
		{"a refutation without what the build reaches", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			refuted := plugin.ReachabilityResult{
				Partiality: plugin.Complete(),
				Refutation: &plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/example.com/m"},
			}
			res := withholdForLeftOutFiles(context.Background(), refuted, scanned, load.Packages, load.buildRelease(), tc.reached, dir, env)
			if res.Refutation != nil || !slices.Contains(res.Partiality.Reasons, plugin.PartialReasonExcludedFiles) {
				t.Fatalf("released (%+v); the package-level rule withholds", res.Partiality)
			}
		})
	}
}
