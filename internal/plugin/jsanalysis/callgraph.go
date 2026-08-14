package jsanalysis

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// program is the whole-build parse: every file's module + declarations + call sites
// + ingress markers, plus indexes used to resolve lexical call sites and ingress
// handler references to concrete declared functions.
type program struct {
	files      []fileParse
	readFailed bool
	skipped    bool
	// funcsByKey maps "name/arity" → the SCIP ids of every declared function with
	// that simple name and arity. A single entry resolves unambiguously; multiple
	// (or zero) entries mean the lexical callee cannot be soundly resolved.
	funcsByKey map[string][]string
	// funcsByName maps a function simple name → its declarations (any arity), used to
	// re-resolve an ingress handler REFERENCE (which carries no arity) to the single
	// declared handler function of that name.
	funcsByName map[string][]funcDecl
}

// funcDecl is one declared function located by its module + enclosing class chain +
// name + arity (enough to build its SCIP id).
type funcDecl struct {
	module    string
	enclosing []string
	name      string
	arity     int
}

func (d funcDecl) scip() string {
	return scipSymbol(d.module, d.enclosing, functionDescriptor(d.name, d.arity))
}

// fileParse pairs a parsed file with its module (needed to qualify call-site
// callers/callees and ingress handlers into SCIP ids).
type fileParse struct {
	module    string
	decls     []decl
	calls     []callSite
	ingresses []ingressMarker
}

// methodKey is the (simple name, arity) resolution key for a function.
func methodKey(name string, arity int) string {
	return fmt.Sprintf("%s/%d", name, arity)
}

// funcSCIP builds the SCIP id for a function given its module, enclosing class
// chain, name, and arity. It is identical to the id symbolsFromParse emits for the
// same declaration, so a resolved sink, a call-graph node, and an ingress symbol all
// coincide — the equality firstPartyReachPaths relies on.
func funcSCIP(module string, enclosing []string, name string, arity int) string {
	return scipSymbol(module, enclosing, functionDescriptor(name, arity))
}

// sym mints a plugin.Symbol from a SCIP id — the single string→Symbol construction
// point for the call graph / reachability / taint world. Every graph symbol (edge
// endpoint, root, ingress, sink, trace frame) is minted here so two references to the
// same SCIP id are byte-identical: that is the ==, map-key, and set identity the BFS
// and adjacency maps rely on, and an inconsistently-built Symbol silently breaks those
// lookups. DisplayName mirrors the SCIP id; the richer structured Symbol fields are
// deliberately left zero here — display/matching identity is owned by the
// index/resolver path (symbolsFromParse, jsSymbolForms), not the graph.
func sym(scip string) plugin.Symbol {
	return plugin.Symbol{SCIP: scip, DisplayName: scip}
}

// loadProgram parses every JS/TS file under buildDir into a whole-program view and
// builds the resolution indexes. A missing/empty build dir is a hard error (inv.4),
// matching IndexSymbols; read failures and skipped constructs degrade partiality.
func loadProgram(buildDir string) (*program, error) {
	info, err := os.Stat(buildDir)
	if err != nil {
		return nil, fmt.Errorf("jsanalysis: stat build dir %q: %w", buildDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("jsanalysis: build dir %q is not a directory", buildDir)
	}
	files, err := jsFiles(buildDir)
	if err != nil {
		return nil, fmt.Errorf("jsanalysis: scan %q: %w", buildDir, err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("jsanalysis: no .js/.ts/.jsx/.tsx sources under %q", buildDir)
	}

	prog := &program{
		funcsByKey:  map[string][]string{},
		funcsByName: map[string][]funcDecl{},
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			prog.readFailed = true
			continue
		}
		module := moduleOf(buildDir, f)
		pr := parseFile(module, string(data))
		if pr.skipped {
			prog.skipped = true
		}
		fp := fileParse{module: pr.module, decls: pr.decls, calls: pr.calls, ingresses: pr.ingresses}
		prog.files = append(prog.files, fp)
		for _, d := range pr.decls {
			if d.kind != kindFunc {
				continue
			}
			fd := funcDecl{module: pr.module, enclosing: d.enclosing, name: d.name, arity: d.arity}
			scip := fd.scip()
			prog.funcsByKey[methodKey(d.name, d.arity)] = append(prog.funcsByKey[methodKey(d.name, d.arity)], scip)
			prog.funcsByName[d.name] = append(prog.funcsByName[d.name], fd)
		}
	}
	return prog, nil
}

// resolveIngressSymbol resolves an ingress marker to the SCIP id of the handler
// function it names. A route/server ingress carries the handler REFERENCE name with
// a sentinel arity (handlerRefArity): it is re-resolved against the program's
// declared functions of that name iff EXACTLY ONE function declares the name (a
// sound single resolution). A default-export handler carries a concrete arity, so it
// resolves directly. An unresolved/ambiguous handler yields "" (no ingress symbol —
// honest absence, never a fabricated node).
func (p *program) resolveIngressSymbol(module string, in ingressMarker) string {
	if in.arity != handlerRefArity {
		return funcSCIP(module, in.enclosing, in.name, in.arity)
	}
	cands := p.funcsByName[in.name]
	if len(cands) != 1 {
		return ""
	}
	return cands[0].scip()
}

// CallGraph builds the source-level call graph for the JS/TS module at
// req.BuildDir. It is a pure-Go, source-only graph: caller and callee are both
// declared functions, and a call site is connected to its callee ONLY when the
// callee's (simple name, arity) resolves to exactly one declared function in the
// program. When a callee is ambiguous (a name declared by multiple functions it
// cannot disambiguate — e.g. prototype/dynamic dispatch) or unknown (a library/
// imported function with no source declaration), NO edge is fabricated and the
// result is declared partial with reason dynamic_dispatch — the inv.5 honesty
// boundary: an unresolved callee is never rendered as a (wrong) edge or as
// reachability.
func CallGraph(_ context.Context, req plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	prog, err := loadProgram(req.BuildDir)
	if err != nil {
		return plugin.CallGraphResult{}, err
	}

	seen := map[plugin.CallEdge]bool{}
	var edges []plugin.CallEdge
	rootsSet := map[string]bool{}
	unresolved := false

	for _, f := range prog.files {
		for _, cs := range f.calls {
			caller := sym(funcSCIP(f.module, cs.callerEnclosing, cs.callerName, cs.callerArity))
			candidates := prog.funcsByKey[methodKey(cs.calleeName, cs.calleeArity)]
			switch len(candidates) {
			case 1:
				e := plugin.CallEdge{Caller: caller, Callee: sym(candidates[0])}
				if !seen[e] {
					seen[e] = true
					edges = append(edges, e)
				}
			default:
				// 0 candidates (library/import/unknown) or >1 (unresolvable name):
				// no sound single edge. Declare partiality; never fabricate (inv.5).
				unresolved = true
			}
		}
		// Framework ingress handler functions are call-graph roots (program entry
		// points for static reachability), so the BFS can terminate at them even if no
		// caller within the source program invokes them. An ingress whose handler
		// reference does not resolve to a single declared function contributes no root.
		for _, in := range f.ingresses {
			if sym := prog.resolveIngressSymbol(f.module, in); sym != "" {
				rootsSet[sym] = true
			}
		}
	}

	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Caller.SCIP != edges[j].Caller.SCIP {
			return edges[i].Caller.SCIP < edges[j].Caller.SCIP
		}
		return edges[i].Callee.SCIP < edges[j].Callee.SCIP
	})

	// Roots dedupe on their SCIP id (the natural string key) and mint a Symbol per id,
	// so a root and the same function appearing as an edge endpoint are byte-identical.
	rootIDs := make([]string, 0, len(rootsSet))
	for r := range rootsSet {
		rootIDs = append(rootIDs, r)
	}
	sort.Strings(rootIDs)
	roots := make([]plugin.Symbol, 0, len(rootIDs))
	for _, r := range rootIDs {
		roots = append(roots, sym(r))
	}

	return plugin.CallGraphResult{
		Partiality: callGraphPartiality(prog, unresolved),
		Algorithm:  "source-lexical",
		Edges:      edges,
		Roots:      roots,
	}, nil
}

// callGraphPartiality declares the call graph's completeness. ANY unresolved callee,
// read failure, or skipped construct makes the graph declared-partial: the
// source-lexical graph never resolves prototype/dynamic dispatch or imported calls,
// so partiality is the honest norm for non-trivial JS/TS.
func callGraphPartiality(prog *program, unresolved bool) plugin.Partiality {
	var reasons []string
	if unresolved {
		reasons = append(reasons, plugin.PartialReasonDynamicDispatch)
	}
	if prog.readFailed {
		reasons = append(reasons, plugin.PartialReasonToolFailure)
	}
	if prog.skipped {
		reasons = append(reasons, plugin.PartialReasonUnsupported)
	}
	if len(reasons) == 0 {
		return plugin.Complete()
	}
	return plugin.Partial(reasons...)
}
