package dotnetanalysis

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// program is the whole-build parse: every file's call sites + ingress markers, plus the
// resolution index used to connect a lexical call site (and a minimal-API handler
// reference) to the concrete declared method it names.
type program struct {
	files       []fileParse
	readFailed  bool
	skipped     bool
	funcsByName map[string][]funcDecl
}

// fileParse holds one source file's call sites and ingress markers. The caller/handler SCIP
// ids are built from the identity fields carried on each marker, so no per-file module is
// needed (SCIP identity is keyed on the C# namespace, not the file path).
type fileParse struct {
	calls     []callSite
	ingresses []ingressMarker
}

// funcDecl is one declared method/constructor located by its namespace + enclosing-type
// chain + name + arity — enough to build its SCIP id, byte-identical to the id IndexSymbols
// emits for the same declaration, so a resolved sink, a call-graph node, and an ingress
// symbol share one identity space.
type funcDecl struct {
	namespace string
	enclosing []string
	name      string
	arity     int
}

func (d funcDecl) scip() string {
	return scipSymbol(d.namespace, d.enclosing, functionDescriptor(d.name, d.arity))
}

// funcSCIP builds the SCIP id for a method from its namespace, enclosing-type chain, name,
// and arity. It is byte-identical to the id IndexSymbols emits for the same declaration.
func funcSCIP(namespace string, enclosing []string, name string, arity int) string {
	return scipSymbol(namespace, enclosing, functionDescriptor(name, arity))
}

// resolveCallee maps a lexical call (leaf name + explicit-argument arity) to the SCIP id of
// the single declared method it names, or ("", false) when unresolvable. C# method calls
// carry no implicit receiver argument, so the call arity matches the declaration arity
// exactly. Zero matches (a library / BCL / imported method with no source declaration) or
// more than one (an overload set or a name the lexer cannot scope-resolve — interface/
// virtual dispatch) yields NO edge: the standing dynamic_dispatch partiality already
// covers this, and no edge is ever fabricated (inv.5).
func (p *program) resolveCallee(name string, callArity int) (string, bool) {
	seen := map[string]bool{}
	var matches []string
	for _, fd := range p.funcsByName[name] {
		if fd.arity == callArity {
			s := fd.scip()
			if !seen[s] {
				seen[s] = true
				matches = append(matches, s)
			}
		}
	}
	if len(matches) == 1 {
		return matches[0], true
	}
	return "", false
}

// resolveIngressSymbol resolves an ingress marker to the SCIP id of the handler method it
// names. A controller-action marker carries the method's full identity (namespace +
// enclosing + name + arity), so its id is built directly. A minimal-API marker carries a
// handler REFERENCE (arity == handlerRefArity): it is re-resolved against the program's
// declared methods of that name iff EXACTLY ONE method declares the name (a sound single
// resolution). An unresolved/ambiguous reference yields "" (no ingress — honest absence,
// never a fabricated node).
func (p *program) resolveIngressSymbol(in ingressMarker) string {
	if in.arity != handlerRefArity {
		return funcSCIP(in.namespace, in.enclosing, in.name, in.arity)
	}
	cands := p.funcsByName[in.name]
	if len(cands) != 1 {
		return ""
	}
	return cands[0].scip()
}

// loadProgram parses every C# file under buildDir into a whole-program view and builds the
// name → declaration resolution index. A missing/empty build dir is a hard error (inv.4),
// matching IndexSymbols; read failures and skipped constructs degrade partiality.
func loadProgram(buildDir string) (*program, error) {
	info, err := os.Stat(buildDir)
	if err != nil {
		return nil, fmt.Errorf("dotnetanalysis: stat build dir %q: %w", buildDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("dotnetanalysis: build dir %q is not a directory", buildDir)
	}
	paths, err := csharpFiles(buildDir)
	if err != nil {
		return nil, fmt.Errorf("dotnetanalysis: scan %q: %w", buildDir, err)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("dotnetanalysis: no .cs sources under %q", buildDir)
	}

	prog := &program{funcsByName: map[string][]funcDecl{}}
	for _, p := range paths {
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			prog.readFailed = true
			continue
		}
		clean := []rune(stripCSharp(string(data)))
		var skipped bool
		decls := parseDecls(clean, &skipped)
		if skipped {
			prog.skipped = true
		}
		calls, ingresses := parseCallsAndIngresses(clean)
		for _, d := range decls {
			if d.kind != kindFunc {
				continue
			}
			prog.funcsByName[d.name] = append(prog.funcsByName[d.name], funcDecl{
				namespace: d.namespace,
				enclosing: d.enclosing,
				name:      d.name,
				arity:     d.arity,
			})
		}
		prog.files = append(prog.files, fileParse{calls: calls, ingresses: ingresses})
	}
	return prog, nil
}

// CallGraph builds the source-level call graph for the C# module at req.BuildDir. It is a
// pure-Go, source-only lexical graph: caller and callee are both declared methods, and a
// call site is connected to its callee ONLY when the callee's (simple name, arity) resolves
// to EXACTLY ONE declared method in the program. When a callee is ambiguous (an overload
// set / a name the lexer cannot scope-resolve) or unknown (a library / imported method with
// no source declaration), NO edge is fabricated — the inv.5 honesty boundary.
//
// The graph is ALWAYS declared Partial(dynamic_dispatch): a lexical C# scanner categorically
// cannot resolve interface dispatch, virtual/override methods, dependency-injection wiring,
// or reflection (scope §5 R1 — these need scip-dotnet at Prove-tier, which Assess does not
// have), so it is structurally an under-approximation of the true call graph. Declaring
// partiality is the conservative direction (a missing edge is UNKNOWN, never a false
// not-affected). Read failures add tool_failure; skipped constructs add unsupported_phase1.
func CallGraph(_ context.Context, req plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	prog, err := loadProgram(req.BuildDir)
	if err != nil {
		return plugin.CallGraphResult{}, err
	}

	seen := map[plugin.CallEdge]bool{}
	var edges []plugin.CallEdge
	rootsSet := map[string]bool{}

	for _, f := range prog.files {
		for _, cs := range f.calls {
			callee, ok := prog.resolveCallee(cs.calleeName, cs.calleeArity)
			if !ok {
				continue
			}
			e := plugin.CallEdge{
				Caller: funcSCIP(cs.callerNamespace, cs.callerEnclosing, cs.callerName, cs.callerArity),
				Callee: callee,
			}
			if !seen[e] {
				seen[e] = true
				edges = append(edges, e)
			}
		}
		// Framework ingress handler methods are call-graph roots (static-reachability entry
		// points), so a reverse BFS can terminate at them even when no caller in the source
		// invokes them.
		for _, in := range f.ingresses {
			if sym := prog.resolveIngressSymbol(in); sym != "" {
				rootsSet[sym] = true
			}
		}
	}

	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Caller != edges[j].Caller {
			return edges[i].Caller < edges[j].Caller
		}
		return edges[i].Callee < edges[j].Callee
	})

	roots := make([]string, 0, len(rootsSet))
	for r := range rootsSet {
		roots = append(roots, r)
	}
	sort.Strings(roots)

	return plugin.CallGraphResult{
		Partiality: callGraphPartiality(prog),
		Algorithm:  "source-lexical",
		Edges:      edges,
		Roots:      roots,
	}, nil
}

// callGraphPartiality declares the call graph ALWAYS partial for C#: the lexical scanner
// categorically cannot resolve interface/virtual dispatch, DI wiring, or reflection, so
// dynamic_dispatch is a standing reason. Read failures and skipped constructs add their own
// machine-readable reasons.
func callGraphPartiality(prog *program) plugin.Partiality {
	reasons := []string{plugin.PartialReasonDynamicDispatch}
	if prog.readFailed {
		reasons = append(reasons, plugin.PartialReasonToolFailure)
	}
	if prog.skipped {
		reasons = append(reasons, plugin.PartialReasonUnsupported)
	}
	return plugin.Partial(reasons...)
}
