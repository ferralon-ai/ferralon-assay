// Hermetic goanalysis tests for the value-flow shapes taint must survive (taint_ssa.go):
// library calls with no SSA body, a store into a struct field, a type assertion and a
// map lookup, the stores through an element or nested field address that a variadic
// call, a slice literal or a nested struct makes, a store through a pointer field or a
// slice view, the append and copy builtins, the spread of a request's context, the
// sanitizer model that body-less forwarding brings into effect, and the places taint
// stops: where the chain of bases ends, and at a pointer a call writes through.
//
// They run runTaint over taintflowmod's main.go, type-checked and built in memory
// against the chimod net/http and chi stubs and two one-line stdlib stand-ins. As in a
// real load, only the fixture's own package gets SSA bodies; every dependency is
// body-less, exactly as real net/http is. Building in memory skips go/packages, whose
// load alone is over the per-test time limit.
package goanalysis

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"testing"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// taintFlowStdlib stands in for the stdlib functions taintflowmod calls, under their
// real import paths: the sanitizer model keys on the package path.
var taintFlowStdlib = []struct{ path, src string }{
	{"strconv", "package strconv\nfunc Atoi(s string) (int, error) { return 0, nil }"},
	{"strings", "package strings\nfunc TrimSpace(s string) string { return s }"},
	{"fmt", "package fmt\nfunc Sprintf(format string, a ...any) string { return format }"},
	{"encoding/json", "package json\nfunc Unmarshal(data []byte, v any) error { return nil }"},
}

// buildTaintModule type-checks a taint fixture's dependencies (the stand-ins, then the
// chimod stubs) and builds its main package, mainGo, under path: the only package with
// SSA bodies.
func buildTaintModule(t *testing.T, path, mainGo string) *ssa.Package {
	t.Helper()
	fset := token.NewFileSet()
	parse := func(name string, src any) *ast.File {
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		return f
	}
	checked := map[string]*types.Package{}
	conf := &types.Config{Importer: importerFunc(func(path string) (*types.Package, error) {
		if p, ok := checked[path]; ok {
			return p, nil
		}
		return nil, os.ErrNotExist
	})}
	check := func(path string, f *ast.File) {
		pkg, err := conf.Check(path, fset, []*ast.File{f}, nil)
		if err != nil {
			t.Fatalf("check %s: %v", path, err)
		}
		checked[path] = pkg
	}
	for _, s := range taintFlowStdlib {
		check(s.path, parse(s.path+".go", s.src))
	}
	check("tegron.test/nethttp", parse("testdata/chimod/nethttpstub/http.go", nil))
	check("github.com/go-chi/chi/v5", parse("testdata/chimod/chiv5stub/chi.go", nil))
	app, _, err := ssautil.BuildPackage(conf, fset, types.NewPackage(path, "main"),
		[]*ast.File{parse(mainGo, nil)}, ssa.SanityCheckFunctions)
	if err != nil {
		t.Fatalf("build %s: %v", path, err)
	}
	return app
}

// TestRunTaint_FlowShapes reads each shape's result off its own sink: tainted means a
// path from the flows handler's parameters, untainted means no path.
func TestRunTaint_FlowShapes(t *testing.T) {
	rows := []struct {
		shape, sink string
		tainted     bool
	}{
		// Body-less library calls forward taint from a tainted argument or receiver.
		{"r.Header.Get", "sinkHeaderGet", true},
		{"r.URL.Query().Get", "sinkQueryGet", true},
		{"r.FormValue", "sinkFormValue", true},
		{"chi.URLParam", "sinkURLParam", true},
		{"strings.TrimSpace (unmodeled transform)", "sinkTrimSpace", true},
		// ...except a modeled sanitizer.
		{"strconv.Atoi (sanitizer)", "sinkAtoi", false},
		{"store into a struct field", "sinkFieldStore", true},
		{"type assertion", "sinkTypeAssert", true},
		{"map lookup", "sinkLookup", true},
		// Controls.
		{"r.URL.Path", "sinkPath", true},
		{"r.URL.RawQuery", "sinkRawQuery", true},
		{"first-party ownID", "sinkOwnID", true},
		{"library call on a value not from the request", "sinkUntainted", false},
		// A store through an element or nested field address taints its base, so the
		// backing array a variadic call or a slice literal builds, and a sibling field,
		// read as tainted.
		{"variadic library call (fmt.Sprintf)", "sinkSprintf", true},
		{"variadic sink (exec.Command shape)", "sinkVariadic", true},
		{"slice literal", "sinkSliceLit", true},
		{"nested field, then its sibling", "sinkNestedSibling", true},
		{"variadic call on values not from the request", "sinkVariadicConst", false},
		// The chain of bases continues through a load of a field or element address
		// and through a slice view.
		{"store through a pointer field, read back", "sinkPointerField", true},
		{"store through a slice view, read through the array", "sinkSliceView", true},
		// The append and copy builtins carry taint from their arguments.
		{"append(args, x)", "sinkAppend", true},
		{"copy(dst, tainted)", "sinkCopy", true},
		{"append on values not from the request", "sinkAppendConst", false},
		{"copy from values not from the request", "sinkCopyConst", false},
		// Where taint stops: at a load of a global pointer, at a package-level struct
		// value (the chain reaches the global, but no read of a global observes it), and
		// at a pointer a closure captures.
		{"store through a global pointer, read back", "sinkGlobalPointer", false},
		{"store through a package-level struct value, read back", "sinkPackageStruct", false},
		{"store through a closure-captured pointer, read outside", "sinkClosureCapture", false},
		// ...and at a pointer a call writes through, read back after the call: a
		// body-less callee taints only its result, and a first-party callee's store
		// taints only its own parameter.
		{"json.Unmarshal(b, &v), v read back", "sinkOutArgLibrary", false},
		{"first-party fill(&v, x), v read back", "sinkOutArgOwn", false},
		// r.Context() taints ctx, and ctx taints the result of a first-party call that
		// takes it, though the result does not depend on it; a ctx passed to an
		// interface method, a call with no static callee, leaves the result clean.
		{"first-party lookup(ctx, const)", "sinkCtxOwn", true},
		{"interface method st.Get(ctx, const)", "sinkCtxIface", false},
	}
	app := buildTaintModule(t, "tegron.test/taintflowmod", "testdata/taintflowmod/main.go")
	sp := &ssaProgram{prog: app.Prog}
	ids := map[string]string{}
	sinks := map[string]bool{}
	for _, r := range rows {
		fn := app.Func(r.sink)
		if fn == nil {
			t.Fatalf("no func %s in taintflowmod", r.sink)
		}
		ids[r.sink] = sp.scipFunc(fn)
		sinks[ids[r.sink]] = true
	}
	paths, _ := runTaint(sp, map[string]*ssa.Function{"flows": app.Func("flows")}, sinks)
	hit := map[string]bool{}
	for _, p := range paths {
		hit[p.Sink.SCIP] = true
	}
	for _, r := range rows {
		if got := hit[ids[r.sink]]; got != r.tainted {
			t.Errorf("%s: tainted = %v, want %v", r.shape, got, r.tainted)
		}
	}
}
