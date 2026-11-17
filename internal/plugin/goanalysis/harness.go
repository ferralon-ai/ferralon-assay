package goanalysis

import (
	"context"
	"fmt"
	"go/token"
	"go/types"
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/tools/go/packages"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// sinkSymbol is the package+symbol decomposition of a sink SCIP id.
type sinkSymbol struct {
	pkgPath  string // import path of the sink's package
	pkgName  string // last path element (the default import identifier)
	receiver string // method receiver type name, empty for package-level funcs
	name     string // function/method name
}

// GenerateHarness emits a reproducer SKELETON (Go source text of a _test.go file)
// for the sink symbol, with a clearly-marked TODO for the attacker-controlled
// input. It does NOT trigger the vuln — it is a structural skeleton, declared as
// such (Skeleton=true, Partial).
//
// The skeleton compiles as emitted. With the request's BuildDir the sink's
// signature is resolved and the skeleton calls the sink; without one it names the
// sink and skips (see generateHarness).
//
// Partiality is declared, never overclaimed (inv.5): an unparseable sink SCIP, an
// unknown input shape, and the fact that this is a skeleton rather than a working
// exploit are all carried as Partial with a reason — never the retired
// unsupported_phase1 code, and never a confident "exploit" claim.
func GenerateHarness(ctx context.Context, req plugin.GenerateHarnessRequest) (plugin.HarnessResult, error) {
	ctx, err := withGoWork(ctx, req.GoWork)
	if err != nil {
		return plugin.HarnessResult{}, err
	}
	return generateHarness(ctx, req, req.BuildDir)
}

// generateHarness is GenerateHarness for a sink whose package loads from buildDir.
// With a buildDir the sink's signature is resolved and the skeleton calls the sink:
// each parameter gets its zero value, except that a string, []byte or io.Reader
// parameter is bound to the test's input. A sink the skeleton cannot name or
// supply (an unexported symbol, an internal package of another module, a generic
// sink, a parameter of an unexported type) is skipped with a TODO saying which.
// With no buildDir, or a package that does not load, the skeleton names the sink
// in its skip and neither imports nor references it.
func generateHarness(ctx context.Context, req plugin.GenerateHarnessRequest, buildDir string) (plugin.HarnessResult, error) {
	sym, ok := parseSinkSCIP(req.Sink)
	if !ok {
		return plugin.HarnessResult{
			Partiality: plugin.Partial(plugin.PartialReasonToolFailure),
			Skeleton:   true,
		}, nil
	}

	kind := req.Kind
	if kind == "" {
		kind = "unit"
	}

	var body harnessBody
	if buildDir != "" {
		body, ok = resolvedHarnessBody(ctx, buildDir, sym)
	}
	if buildDir == "" || !ok {
		body = unresolvedHarnessBody(sym)
	}
	src := renderHarness(sym, body, req.Ingress, kind)

	// The input shape is unknown (we cannot construct attacker-controlled values),
	// so the harness is a skeleton, not a working exploit: declared Partial.
	reasons := []string{plugin.PartialReasonDynamicDispatch}
	if kind != "unit" && kind != "fuzz" && kind != "integration" {
		reasons = append(reasons, plugin.PartialReasonToolFailure)
	}

	return plugin.HarnessResult{
		Partiality: plugin.Partial(reasons...),
		Source:     src,
		Skeleton:   true,
	}, nil
}

// parseSinkSCIP decomposes a SCIP id of the emitter's grammar
//
//	scip-go gomod <module> <version> <pkgPath>/<descriptor>
//
// where <descriptor> is "<name>()." for a func or "<recv>#<name>()." for a
// method. Anything not matching this shape is unparseable (ok=false).
func parseSinkSCIP(scip string) (sinkSymbol, bool) {
	fields := strings.Fields(scip)
	if len(fields) < 5 || fields[0] != "scip-go" || fields[1] != "gomod" {
		return sinkSymbol{}, false
	}
	desc := fields[4]
	slash := strings.LastIndex(desc, "/")
	if slash < 0 {
		return sinkSymbol{}, false
	}
	pkgPath := desc[:slash]
	tail := strings.TrimSuffix(desc[slash+1:], "().")
	if tail == "" || tail == desc[slash+1:] { // missing the "()." func/method suffix
		return sinkSymbol{}, false
	}

	sym := sinkSymbol{pkgPath: pkgPath, pkgName: path.Base(pkgPath)}
	if h := strings.IndexByte(tail, '#'); h >= 0 {
		sym.receiver = tail[:h]
		sym.name = tail[h+1:]
	} else {
		sym.name = tail
	}
	if sym.name == "" || sym.pkgPath == "" {
		return sinkSymbol{}, false
	}
	return sym, true
}

// sinkAlias is the identifier the skeleton imports the sink's package under. An
// explicit name, because the last path element is not the package name for a
// major-version suffix ("/v2") or a gopkg.in path ("yaml.v3").
const sinkAlias = "sink"

// harnessBody is what the test function of a skeleton does.
type harnessBody struct {
	// imports maps an import path to the identifier it is imported under.
	imports map[string]string
	// stmts are the statements before the skip or the call, one per line.
	stmts []string
	// call is the statement that calls the sink; empty when the skeleton skips.
	call string
	// skip is the reason the skeleton skips instead of calling the sink.
	skip string
	// usesInput reports whether stmts or call read the test's input, named "in".
	usesInput bool
}

// renderHarness produces the Go source skeleton: a fuzz target whose input is the
// fuzzer's, or a test whose input is a TODO.
func renderHarness(sym sinkSymbol, body harnessBody, ingress, kind string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "// Code generated by %s (harness skeleton). DO NOT EDIT.\n", plugin.BinaryName("go"))
	fmt.Fprintf(&b, "// This is a reproducer SKELETON for sink %s.%s — it does NOT supply\n", commentText(sym.pkgName), commentText(sym.name))
	fmt.Fprintf(&b, "// attacker-controlled input and does NOT prove exploitability.\n")
	fmt.Fprintf(&b, "// kind=%s", commentText(kind))
	if ingress != "" {
		fmt.Fprintf(&b, " ingress=%s", commentText(ingress))
	}
	b.WriteString("\npackage harness\n\nimport (\n\t\"testing\"\n")
	paths := make([]string, 0, len(body.imports))
	for p := range body.imports {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	if len(paths) > 0 {
		b.WriteString("\n")
	}
	for _, p := range paths {
		if alias := body.imports[p]; alias == path.Base(p) {
			fmt.Fprintf(&b, "\t%q\n", p)
		} else {
			fmt.Fprintf(&b, "\t%s %q\n", alias, p)
		}
	}
	b.WriteString(")\n\n")

	indent := "\t"
	switch kind {
	case "fuzz":
		indent = "\t\t"
		b.WriteString("func FuzzSink(f *testing.F) {\n")
		b.WriteString("\tf.Fuzz(func(t *testing.T, in string) {\n")
		b.WriteString("\t\t// TODO: shape the fuzz input into the attacker-controlled value the sink consumes.\n")
	default: // unit | integration
		b.WriteString("func TestSinkReachable(t *testing.T) {\n")
		if body.usesInput {
			b.WriteString("\tin := \"\" // TODO: the attacker-controlled input that triggers the vulnerability.\n")
		} else if body.skip == "" {
			b.WriteString("\t// TODO: replace the zero values with the attacker-controlled input that triggers the vulnerability.\n")
		}
	}
	for _, s := range body.stmts {
		fmt.Fprintf(&b, "%s%s\n", indent, s)
	}
	if body.skip != "" {
		fmt.Fprintf(&b, "%st.Skip(%q)\n", indent, "TODO: "+body.skip)
	} else {
		fmt.Fprintf(&b, "%s%s\n", indent, body.call)
	}
	if kind == "fuzz" {
		b.WriteString("\t})\n}\n")
	} else {
		b.WriteString("}\n")
	}
	return b.String()
}

// unresolvedHarnessBody is the body for a sink whose signature is not known: it
// skips, naming the sink in the reason. It neither imports nor references the
// sink, because whether a reference compiles (a generic function, an interface
// method, a main package, a symbol since removed) is itself unknown without the
// signature.
func unresolvedHarnessBody(sym sinkSymbol) harnessBody {
	name := sym.pkgPath + "." + sym.name
	if sym.receiver != "" {
		name = sym.pkgPath + "." + sym.receiver + "." + sym.name
	}
	why := unnameable(sym, "")
	if why == "" {
		why = "its signature was not resolved"
	}
	return harnessBody{skip: "call " + name + " with attacker-controlled input; " + why}
}

// unnameable says why a test outside the sink's package cannot name the sink, or
// "" when it can. mainModule is the module the skeleton is written into, whose
// own top-level internal packages it may import; "" when unknown.
func unnameable(sym sinkSymbol, mainModule string) string {
	if !token.IsIdentifier(sym.name) || (sym.receiver != "" && !token.IsIdentifier(sym.receiver)) {
		return "the sink is not a named function or method"
	}
	if !token.IsExported(sym.name) || (sym.receiver != "" && !token.IsExported(sym.receiver)) {
		return "the sink is unexported, so the test belongs in its package"
	}
	if !importableFrom(sym.pkgPath, mainModule) {
		return "the sink is in an internal or vendored package this test cannot import"
	}
	return ""
}

// commentText is s as it may stand in a line comment: a name read from a symbol id
// may hold a newline, a NUL or invalid UTF-8, none of which a Go source file allows
// there.
func commentText(s string) string {
	return strings.Map(func(r rune) rune {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			return '?'
		}
		return r
	}, s)
}

// importableFrom reports whether a test at the root of mainModule may import
// pkgPath: any package with no internal or vendor element, and an internal package
// only directly under that root.
func importableFrom(pkgPath, mainModule string) bool {
	elems := strings.Split(pkgPath, "/")
	for i, e := range elems {
		switch e {
		case "vendor":
			return false
		case "internal":
			return mainModule != "" && strings.Join(elems[:i], "/") == mainModule
		}
	}
	return true
}

// resolvedHarnessBody loads the sink's package from buildDir and returns the body
// that calls the sink. ok is false when the package or the symbol does not load.
func resolvedHarnessBody(ctx context.Context, buildDir string, sym sinkSymbol) (harnessBody, bool) {
	env, _, _ := programEnv(ctx, buildDir)
	pkgs, err := packages.Load(&packages.Config{
		Context: ctx,
		Dir:     buildDir,
		Env:     env,
		Mode:    packages.NeedName | packages.NeedTypes | packages.NeedModule,
	}, sym.pkgPath)
	if err != nil || len(pkgs) != 1 || pkgs[0].Types == nil {
		return harnessBody{}, false
	}
	pkg := pkgs[0]
	mainModule := ""
	if pkg.Module != nil && pkg.Module.Main {
		mainModule = pkg.Module.Path
	}
	if pkg.Name == "main" {
		return harnessBody{skip: "call the sink with attacker-controlled input; it is in a main package, which no test can import"}, true
	}
	if why := unnameable(sym, mainModule); why != "" {
		return harnessBody{skip: "call the sink with attacker-controlled input; " + why}, true
	}

	h := &harnessBuilder{mainModule: mainModule, imports: map[string]string{sym.pkgPath: sinkAlias}, names: map[string]bool{}}
	for _, reserved := range []string{sinkAlias, "testing", "t", "f", "in", "recv"} {
		h.names[reserved] = true
	}
	skip := func(why string) (harnessBody, bool) {
		return harnessBody{skip: "call the sink with attacker-controlled input; " + why}, true
	}

	var fn *types.Func
	callee := sinkAlias + "." + sym.name
	var stmts []string
	if sym.receiver == "" {
		fn, _ = pkg.Types.Scope().Lookup(sym.name).(*types.Func)
	} else {
		tn, _ := pkg.Types.Scope().Lookup(sym.receiver).(*types.TypeName)
		if tn == nil {
			return harnessBody{}, false
		}
		named, _ := types.Unalias(tn.Type()).(*types.Named)
		if named == nil {
			return harnessBody{skip: "call the sink with attacker-controlled input; its receiver is not a named type, so the test must construct it"}, true
		}
		if named.TypeParams().Len() > 0 && named.TypeArgs().Len() == 0 {
			return harnessBody{skip: "call the sink with attacker-controlled input; its receiver type is generic, so the test must choose its type arguments"}, true
		}
		if types.IsInterface(named) {
			return harnessBody{skip: "call the sink with attacker-controlled input; it is an interface method, so the test must choose an implementation"}, true
		}
		obj, _, _ := types.LookupFieldOrMethod(types.NewPointer(named), true, pkg.Types, sym.name)
		fn, _ = obj.(*types.Func)
		stmts = append(stmts, fmt.Sprintf("var recv %s.%s", sinkAlias, sym.receiver))
		callee = "recv." + sym.name
	}
	if fn == nil {
		return harnessBody{}, false
	}
	sig := fn.Type().(*types.Signature)
	if sig.TypeParams().Len() > 0 {
		return harnessBody{skip: "call the sink with attacker-controlled input; it is generic, so the test must choose its type arguments"}, true
	}

	var args []string
	usesInput := false
	params := sig.Params()
	for i := 0; i < params.Len(); i++ {
		t := params.At(i).Type()
		variadic := sig.Variadic() && i == params.Len()-1
		if variadic {
			t = t.(*types.Slice).Elem()
		}
		if arg, ok := h.inputArg(t); ok {
			usesInput = true
			args = append(args, arg)
			continue
		}
		if isNamed(t, "context", "Context") {
			args = append(args, h.importName("context", "context")+".Background()")
			continue
		}
		if !h.representable(t) {
			return skip(fmt.Sprintf("parameter %d has a type this test cannot name", i+1))
		}
		name := fmt.Sprintf("a%d", i)
		typ := types.TypeString(t, h.qualify)
		if variadic {
			stmts = append(stmts, fmt.Sprintf("var %s []%s", name, typ))
			args = append(args, name+"...")
		} else {
			stmts = append(stmts, fmt.Sprintf("var %s %s", name, typ))
			args = append(args, name)
		}
	}
	call := fmt.Sprintf("%s(%s)", callee, strings.Join(args, ", "))
	if n := sig.Results().Len(); n > 0 {
		call = strings.TrimSuffix(strings.Repeat("_, ", n), ", ") + " = " + call
	}
	return harnessBody{imports: h.imports, stmts: stmts, call: call, usesInput: usesInput}, true
}

// harnessBuilder names the types and packages a resolved skeleton refers to.
type harnessBuilder struct {
	mainModule string
	imports    map[string]string // import path -> identifier
	names      map[string]bool   // identifiers taken in the skeleton's file
}

// importName returns the identifier pkgPath is imported under, importing it under
// name, or name with a number appended when name is taken, the first time.
func (h *harnessBuilder) importName(pkgPath, name string) string {
	if alias, ok := h.imports[pkgPath]; ok {
		return alias
	}
	alias := name
	for n := 2; h.names[alias]; n++ {
		alias = fmt.Sprintf("%s%d", name, n)
	}
	h.names[alias] = true
	h.imports[pkgPath] = alias
	return alias
}

func (h *harnessBuilder) qualify(p *types.Package) string {
	return h.importName(p.Path(), p.Name())
}

// inputArg returns the expression that hands the test's input to a parameter of
// type t: a string, a []byte or an io.Reader.
func (h *harnessBuilder) inputArg(t types.Type) (string, bool) {
	switch u := t.(type) {
	case *types.Basic:
		if u.Kind() == types.String {
			return "in", true
		}
	case *types.Slice:
		if b, ok := u.Elem().(*types.Basic); ok && b.Kind() == types.Byte {
			return "[]byte(in)", true
		}
	}
	if isNamed(t, "io", "Reader") {
		return h.importName("strings", "strings") + ".NewReader(in)", true
	}
	return "", false
}

// representable reports whether a test at the root of the main module can write
// the type t: every named type in it is exported and importable, and it has no
// type parameter and no unexported struct field or interface method.
func (h *harnessBuilder) representable(t types.Type) bool {
	return h.representableIn(t, map[types.Type]bool{})
}

func (h *harnessBuilder) representableIn(t types.Type, seen map[types.Type]bool) bool {
	if seen[t] {
		return true
	}
	seen[t] = true
	named := func(obj *types.TypeName, args *types.TypeList) bool {
		if obj.Pkg() != nil && (!obj.Exported() || obj.Pkg().Name() == "main" || !importableFrom(obj.Pkg().Path(), h.mainModule)) {
			return false
		}
		for i := 0; i < args.Len(); i++ {
			if !h.representableIn(args.At(i), seen) {
				return false
			}
		}
		return true
	}
	switch u := t.(type) {
	case *types.Basic:
		return u.Kind() != types.UnsafePointer && u.Kind() != types.Invalid
	case *types.Alias:
		return named(u.Obj(), u.TypeArgs())
	case *types.Named:
		return named(u.Obj(), u.TypeArgs())
	case *types.Pointer:
		return h.representableIn(u.Elem(), seen)
	case *types.Slice:
		return h.representableIn(u.Elem(), seen)
	case *types.Array:
		return h.representableIn(u.Elem(), seen)
	case *types.Chan:
		return h.representableIn(u.Elem(), seen)
	case *types.Map:
		return h.representableIn(u.Key(), seen) && h.representableIn(u.Elem(), seen)
	case *types.Signature:
		if u.TypeParams().Len() > 0 {
			return false
		}
		for _, tuple := range []*types.Tuple{u.Params(), u.Results()} {
			for i := 0; i < tuple.Len(); i++ {
				if !h.representableIn(tuple.At(i).Type(), seen) {
					return false
				}
			}
		}
		return true
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if f := u.Field(i); !f.Exported() || !h.representableIn(f.Type(), seen) {
				return false
			}
		}
		return true
	case *types.Interface:
		if u.NumEmbeddeds() > 0 {
			return false
		}
		for i := 0; i < u.NumExplicitMethods(); i++ {
			if m := u.ExplicitMethod(i); !m.Exported() || !h.representableIn(m.Type(), seen) {
				return false
			}
		}
		return true
	}
	return false
}
