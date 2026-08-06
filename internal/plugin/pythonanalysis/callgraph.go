package pythonanalysis

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// program is the whole-build parse: every file's module + call sites + ingress markers,
// plus the resolution index used to connect a lexical call site to the concrete declared
// function it names.
type program struct {
	files      []fileParse
	readFailed bool
	skipped    bool
	// funcsByName maps a function's simple name → every declaration of that name (across
	// modules and classes). A callee resolves to exactly one declaration by name +
	// self/cls-tolerant arity; zero or multiple matches mean the lexical callee cannot be
	// soundly resolved to a single edge (inv.5: no fabricated edge).
	funcsByName map[string][]funcDecl
}

// resolveCallee maps a lexical call (leaf name + explicit-argument arity) to the SCIP id
// of the single declared function it names, or ("", false) when unresolvable. Arity match
// is self/cls-tolerant: a method call "obj.method(args)" carries one fewer explicit
// argument than the declaration "def method(self, args)", so a declaration of arity
// callArity OR callArity+1 matches. Zero matches (library/import/builtin) or more than one
// (an ambiguous name the lexer cannot scope-resolve) yields no edge.
func (p *program) resolveCallee(name string, callArity int) (string, bool) {
	seen := map[string]bool{}
	var matches []string
	for _, fd := range p.funcsByName[name] {
		if fd.arity == callArity || fd.arity == callArity+1 {
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

// funcDecl is one declared function located by its module + enclosing class chain + name
// + arity — enough to build its SCIP id (identical to the id IndexSymbols emits for the
// same declaration, so a resolved sink, a call-graph node, and an ingress symbol coincide).
type funcDecl struct {
	module    string
	enclosing []string
	name      string
	arity     int
}

func (d funcDecl) scip() string {
	return scipSymbol(d.module, d.enclosing, functionDescriptor(d.name, d.arity))
}

// fileParse pairs a parsed file's module with its call sites and ingress markers (needed
// to qualify callers/callees and ingress handlers into SCIP ids).
type fileParse struct {
	module    string
	calls     []callSite
	ingresses []ingressMarker
}

// funcSCIP builds the SCIP id for a function from its module, enclosing class chain, name,
// and arity. It is byte-identical to the id IndexSymbols emits for the same declaration,
// so a call-graph node, a resolved sink, and an ingress symbol share one identity space.
func funcSCIP(module string, enclosing []string, name string, arity int) string {
	return scipSymbol(module, enclosing, functionDescriptor(name, arity))
}

// loadProgram parses every Python file under buildDir into a whole-program view and builds
// the (name, arity) → SCIP resolution index. A missing/empty build dir is a hard error
// (inv.4), matching IndexSymbols; read failures and skipped constructs degrade partiality.
func loadProgram(buildDir string) (*program, error) {
	info, err := os.Stat(buildDir)
	if err != nil {
		return nil, fmt.Errorf("pythonanalysis: stat build dir %q: %w", buildDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("pythonanalysis: build dir %q is not a directory", buildDir)
	}
	paths, err := pythonFiles(buildDir)
	if err != nil {
		return nil, fmt.Errorf("pythonanalysis: scan %q: %w", buildDir, err)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("pythonanalysis: no .py sources under %q", buildDir)
	}

	prog := &program{funcsByName: map[string][]funcDecl{}}
	for _, p := range paths {
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			prog.readFailed = true
			continue
		}
		module := moduleOf(buildDir, p)
		clean := stripPython(string(data))
		lines := logicalLines(clean)

		decls := parseDecls(lines)
		calls, ingresses := parseCallsAndIngresses(lines)

		for _, d := range decls {
			if d.kind != kindFunc {
				continue
			}
			fd := funcDecl{module: module, enclosing: d.enclosing, name: d.name, arity: d.arity}
			prog.funcsByName[d.name] = append(prog.funcsByName[d.name], fd)
		}
		prog.files = append(prog.files, fileParse{module: module, calls: calls, ingresses: ingresses})
	}
	return prog, nil
}

// CallGraph builds the source-level call graph for the Python module at req.BuildDir. It
// is a pure-Go, source-only lexical graph: caller and callee are both declared functions,
// and a call site is connected to its callee ONLY when the callee's (simple name, arity)
// resolves to EXACTLY ONE declared function in the program. When a callee is ambiguous (a
// name declared by multiple functions the lexer cannot scope-resolve) or unknown (a
// library/imported/builtin function with no source declaration), NO edge is fabricated and
// the partiality carries dynamic_dispatch — the inv.5 honesty boundary.
//
// The graph is ALWAYS declared Partial(dynamic_dispatch): a lexical Python scanner cannot
// see dynamic dispatch, getattr, decorator-rewriting, or monkeypatched edges, so it is
// structurally an under-approximation of the true call graph. Declaring partiality is the
// conservative direction (a missing edge is UNKNOWN, never a false not-affected); the
// Python plugin therefore never claims a Complete call graph. Read failures add
// tool_failure; skipped constructs add unsupported_phase1.
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
				// 0 matches (library/import/builtin/unknown) or >1 (unresolvable name):
				// no sound single edge. The standing dynamic_dispatch partiality already
				// covers this; never fabricate (inv.5).
				continue
			}
			e := plugin.CallEdge{Caller: funcSCIP(f.module, cs.callerEnclosing, cs.callerName, cs.callerArity), Callee: callee}
			if !seen[e] {
				seen[e] = true
				edges = append(edges, e)
			}
		}
		// Framework ingress handler functions are call-graph roots (static-reachability
		// entry points), so a reverse BFS can terminate at them even when no caller in the
		// source invokes them.
		for _, in := range f.ingresses {
			rootsSet[funcSCIP(f.module, in.enclosing, in.name, in.arity)] = true
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

// callGraphPartiality declares the call graph ALWAYS partial for Python: the lexical
// scanner categorically cannot resolve dynamic dispatch / getattr / decorator-rewriting /
// monkeypatching, so dynamic_dispatch is a standing reason. Read failures and skipped
// constructs add their own machine-readable reasons.
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
