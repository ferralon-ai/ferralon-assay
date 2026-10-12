package cfamilycgx

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/cfamilyanalysis/compiledb"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// unresolvedProbes are three trees whose call into a dependency's vulnerable function cgx's
// graph cannot show: the function is defined in the dependency, not the tree, and is reached
// through a call the dependency makes, a macro alias, or a function-pointer table. Each graph is
// what cgx reports for its tree.
var unresolvedProbes = []struct {
	name     string
	src      string
	nodes    []node
	advisory []string
}{
	{
		name: "dependency_call",
		src: "#include <zlib.h>\n\nint main(void)\n{\n\tunsigned char dst[64];\n\tuLongf n = sizeof dst;\n" +
			"\treturn uncompress(dst, &n, (const Bytef *)\"\", 0);\n}\n",
		nodes:    []node{{FQN: "main", Kind: "function", File: "main.c", Line: 3}},
		advisory: []string{"inflate_fast", "inflate"},
	},
	{
		name: "macro_alias",
		src: "#include <zlib.h>\n#define DECOMP inflate\n\nint run(z_stream *s)\n{\n\treturn DECOMP(s, 0);\n}\n\n" +
			"int main(void)\n{\n\tz_stream s = {0};\n\treturn run(&s);\n}\n",
		nodes: []node{
			{FQN: "DECOMP", Kind: "macro", File: "main.c", Line: 2},
			{FQN: "run", Kind: "function", File: "main.c", Line: 4},
			{FQN: "main", Kind: "function", File: "main.c", Line: 9},
		},
		advisory: []string{"inflate"},
	},
	{
		name: "fn_ptr_table",
		src: "#include <zlib.h>\n\ntypedef int (*fn)(z_streamp, int);\nstatic fn table[] = { inflate };\n\n" +
			"int main(void)\n{\n\tz_stream s = {0};\n\treturn table[0](&s, 0);\n}\n",
		nodes: []node{
			{FQN: "fn", Kind: "type", File: "main.c", Line: 3},
			{FQN: "table", Kind: "constant", File: "main.c", Line: 4},
			{FQN: "main", Kind: "function", File: "main.c", Line: 6},
		},
		advisory: []string{"inflate"},
	},
}

// An advisory symbol the graph has no definition for is declared cgx_sink_unresolved, under the
// tool_failure base the gate reads as did-not-run, on resolve and on the path ops; quiet boundary
// codes may sit beside it but never stand in for it.
func TestLane_UnresolvedAdvisorySymbol_DeclaredLoud(t *testing.T) {
	ctx := context.Background()
	if !strings.HasPrefix(reasonSinkUnresolved, plugin.PartialReasonToolFailure+":") {
		t.Fatalf("%s is not under the loud %s base", reasonSinkUnresolved, plugin.PartialReasonToolFailure)
	}
	for _, p := range unresolvedProbes {
		t.Run(p.name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"main.c": p.src})
			l := newTestLane(t, Config{}, (&fakeOpener{g: &fakeGraph{nodes: p.nodes}}).open)

			res, err := l.ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{BuildDir: dir, AdvisorySymbols: p.advisory})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Resolved) != 0 || !hasReason(res.Partiality, reasonSinkUnresolved) {
				t.Errorf("resolve %v: %+v, want nothing resolved and %s", p.advisory, res, reasonSinkUnresolved)
			}
			if hasReason(res.Partiality, reasonUnparsed) {
				t.Errorf("resolve %v declares %s: no definition was lost", p.advisory, reasonUnparsed)
			}

			re, err := l.Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dir, Symbols: p.advisory})
			if err != nil {
				t.Fatal(err)
			}
			ta, err := l.ComputeTaint(ctx, plugin.ComputeTaintRequest{BuildDir: dir, Sinks: p.advisory})
			if err != nil {
				t.Fatal(err)
			}
			for op, part := range map[string]plugin.Partiality{"reachability": re.Partiality, "compute_taint": ta.Partiality} {
				if !hasReason(part, reasonSinkUnresolved) {
					t.Errorf("%s partiality %v lacks %s", op, part.Reasons, reasonSinkUnresolved)
				}
			}
		})
	}

	// The dependency call is also named as a link boundary, quietly, beside the loud code.
	p := unresolvedProbes[0]
	dir := writeTree(t, map[string]string{"main.c": p.src})
	l := newTestLane(t, Config{}, (&fakeOpener{g: &fakeGraph{nodes: p.nodes}}).open)
	res, err := l.ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{BuildDir: dir, AdvisorySymbols: p.advisory})
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(res.Partiality, reasonLinkPrefix+"uncompress") || !hasReason(res.Partiality, reasonSinkUnresolved) {
		t.Errorf("dependency call: %v, want %suncompress and %s", res.Partiality.Reasons, reasonLinkPrefix, reasonSinkUnresolved)
	}
}

// A definition lost in one file is declared even when another file defines a function of the
// same name that the graph does have (file-static helpers routinely share names).
func TestResidue_LostDefinitionKeyedByFile(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"a.c": "static int process(int x)\n{\n\treturn x;\n}\n",
		"b.c": "static int process(int x)\n{\n\treturn x + 1;\n}\n",
	})
	files := []string{"a.c", "b.c"}
	only := &graphView{nodes: map[string][]node{"process": {{FQN: "process", Kind: "function", File: "b.c", Line: 1}}}, kinds: map[string]bool{}}
	if reasons, unparsed := residue(dir, files, only); !unparsed["process"] || !reasons[reasonUnparsed] {
		t.Errorf("a.c's process lost, b.c's parsed: reasons %v, unparsed %v", reasons, unparsed)
	}
	both := &graphView{nodes: map[string][]node{"process": {
		{FQN: "process", Kind: "function", File: "a.c", Line: 1},
		{FQN: "process", Kind: "function", File: "b.c", Line: 1},
	}}, kinds: map[string]bool{}}
	if reasons, unparsed := residue(dir, files, both); len(unparsed) != 0 || reasons[reasonUnparsed] {
		t.Errorf("both parsed: reasons %v, unparsed %v", reasons, unparsed)
	}
}

// No graph op reads Complete: on a tree with a compilation database and nothing the residue
// scan finds, every op still declares the standing method limit, and only quiet method limits.
func TestLane_NoOpReadsComplete(t *testing.T) {
	ctx := context.Background()
	dir := writeTree(t, map[string]string{"main.c": "static int helper(void)\n{\n\treturn 0;\n}\n\nint main(void)\n{\n\treturn helper();\n}\n"})
	g := &fakeGraph{
		nodes: []node{{FQN: "main", Kind: "function", File: "main.c", Line: 6}, {FQN: "helper", Kind: "function", File: "main.c", Line: 1}},
		rows:  []edgeRow{{"main", "calls", "certain", "helper"}},
	}
	l := newTestLane(t, Config{}, (&fakeOpener{g: g}).open)
	withDB(l, &compiledb.DB{TUs: []compiledb.TU{{File: dir + "/main.c", Lang: compiledb.LangC}}})

	idx, err := l.IndexSymbols(ctx, plugin.IndexSymbolsRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	res, err := l.ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{BuildDir: dir, AdvisorySymbols: []string{"helper"}})
	if err != nil {
		t.Fatal(err)
	}
	cg, err := l.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	in, err := l.FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	re, err := l.Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{"helper"}})
	if err != nil {
		t.Fatal(err)
	}
	ta, err := l.ComputeTaint(ctx, plugin.ComputeTaintRequest{BuildDir: dir, Sinks: []string{"helper"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(cg.Edges) != 1 || len(res.Resolved) != 1 || len(re.Paths) != 1 {
		t.Fatalf("fixture did not analyze: %d edges, %d resolved, %d paths", len(cg.Edges), len(res.Resolved), len(re.Paths))
	}
	for op, p := range map[string]plugin.Partiality{
		"index_symbols": idx.Partiality, "resolve_symbols": res.Partiality, "call_graph": cg.Partiality,
		"find_ingresses": in.Partiality, "reachability": re.Partiality, "compute_taint": ta.Partiality,
	} {
		if p.Complete || len(p.Reasons) == 0 {
			t.Errorf("%s: %+v, want Partial with its residue named", op, p)
		}
		for _, r := range p.Reasons {
			if r != reasonMacro && r != plugin.PartialReasonDynamicDispatch {
				t.Errorf("%s: declares %s on a clean tree", op, r)
			}
		}
	}
	for op, p := range map[string]plugin.Partiality{"index_symbols": idx.Partiality, "call_graph": cg.Partiality, "find_ingresses": in.Partiality} {
		if !hasReason(p, reasonMacro) {
			t.Errorf("%s: %v, want the standing %s", op, p.Reasons, reasonMacro)
		}
	}
}
