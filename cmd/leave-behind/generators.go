// generators.go — one generator per live leave-behind. Each drives cgx over the
// already-built index, reshapes the output into an agent-consumable artifact that
// preserves the approximation envelope (or per-row confidence where cgx emits no
// envelope), and writes it into the bundle. Generators never launder a `possible`
// edge as fact and never report an empty result as "proven absent".
package main

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// dataFlowRowLimit bounds the DATA_FLOW provenance sweep; CQL var-length walks
// are depth/row-capped by default, so an explicit bound is stated, not implied.
const dataFlowRowLimit = 2000

// genResult reports what one generator emitted, for the manifest.
type genResult struct {
	files     []string
	itemCount int
	bytes     int
	note      string
}

// discoverPkgSymbols returns the non-test function/method/type symbols defined in
// pkg — the shared input to the Symbol Card and Blast-Radius generators. Value
// nodes (fqn with '#') and closures ('{func@') are excluded; they are not API.
func discoverPkgSymbols(ctx context.Context, c *cgxClient, pkg string) ([]searchRow, error) {
	rows, err := c.search(ctx, pkg+"::", "", 0)
	if err != nil {
		return nil, err
	}
	var out []searchRow
	seen := map[string]bool{}
	for _, r := range rows {
		if !strings.HasPrefix(r.Fqn, pkg+"::") {
			continue
		}
		if r.Kind != "function" && r.Kind != "method" && r.Kind != "type" {
			continue
		}
		if strings.Contains(r.Fqn, "#") || strings.Contains(r.Fqn, "{func@") {
			continue
		}
		if isTestSymbol(r) {
			continue
		}
		if seen[r.Fqn] {
			continue
		}
		seen[r.Fqn] = true
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fqn < out[j].Fqn })
	return out, nil
}

// --- 1. Repo Atlas & Hotspot Map -------------------------------------------

type pkgCount struct {
	Package     string `json:"package"`
	SymbolCount int    `json:"symbol_count"`
	ExampleFile string `json:"example_file"`
}

type atlasArtifact struct {
	artifactMeta
	Filter             string                  `json:"filter_applied"`
	Hotspots           map[string][]symbolRank `json:"hotspots"`
	FirstPartyPackages []pkgCount              `json:"first_party_packages"`
}

func genAtlas(ctx context.Context, c *cgxClient, b *bundle) (*genResult, error) {
	hot := map[string][]symbolRank{}
	const wantPerRank = 15
	for _, rank := range []string{"inbound", "outbound", "total"} {
		rows, err := c.symbols(ctx, rank, 300)
		if err != nil {
			return nil, err
		}
		var fp []symbolRank
		for _, r := range rows {
			if isFirstParty(r.File) {
				fp = append(fp, r)
			}
			if len(fp) >= wantPerRank {
				break
			}
		}
		hot[rank] = fp
	}

	all, err := c.searchAll(ctx, 0)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	example := map[string]string{}
	for _, r := range all {
		if !isFirstParty(r.File) {
			continue
		}
		pkg := r.Fqn
		if i := strings.Index(pkg, "::"); i >= 0 {
			pkg = pkg[:i]
		}
		counts[pkg]++
		if example[pkg] == "" {
			example[pkg] = r.File
		}
	}
	pkgs := make([]pkgCount, 0, len(counts))
	for p, n := range counts {
		pkgs = append(pkgs, pkgCount{Package: p, SymbolCount: n, ExampleFile: example[p]})
	}
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].SymbolCount != pkgs[j].SymbolCount {
			return pkgs[i].SymbolCount > pkgs[j].SymbolCount
		}
		return pkgs[i].Package < pkgs[j].Package
	})

	art := atlasArtifact{
		artifactMeta: artifactMeta{
			Kind:        "repo_atlas",
			Description: "First-party hub ranking (inbound/outbound/total) plus a per-package symbol inventory.",
			GeneratedBy: []string{
				strings.Join(c.argv("symbols", "--rank", "inbound", "--top", "300"), " "),
				strings.Join(c.argv("symbols", "--rank", "outbound", "--top", "300"), " "),
				strings.Join(c.argv("symbols", "--rank", "total", "--top", "300"), " "),
				strings.Join(c.argv("search", "--all", "--limit", "0"), " "),
			},
			Honesty: "`cgx symbols` carries no approximation envelope; each hub row instead " +
				"decomposes its edges by_confidence — read that, not the raw degree, as the certainty. " +
				"On this index nearly all call edges are `possible`. Package counts are first-party only " +
				"(vendor/ and corpus/testdata/ excluded).",
		},
		Filter:             "excluded vendor/ and corpus/testdata/",
		Hotspots:           hot,
		FirstPartyPackages: pkgs,
	}
	n, err := b.writeJSON(fileAtlas, art)
	if err != nil {
		return nil, err
	}
	return &genResult{files: []string{fileAtlas}, itemCount: len(pkgs), bytes: n}, nil
}

// --- 2. Symbol Cards --------------------------------------------------------

type symbolCard struct {
	artifactMeta
	Symbol *explainResult `json:"symbol"`
}

func genSymbolCards(ctx context.Context, c *cgxClient, b *bundle, pkg string, syms []searchRow) (*genResult, error) {
	res := &genResult{}
	for _, s := range syms {
		ex, err := c.explain(ctx, s.Fqn)
		if err != nil {
			return nil, err
		}
		card := symbolCard{
			artifactMeta: artifactMeta{
				Kind:        "symbol_card",
				Description: fmt.Sprintf("Orientation card for %s: definition, degree, and every incident edge.", s.Fqn),
				GeneratedBy: []string{strings.Join(c.argv("explain", s.Fqn), " ")},
				Honesty: "`explain` emits no top-level approximation envelope; confidence and condition " +
					"are per-edge on `symbol.edges[]`. Treat each edge at its own `confidence` " +
					"(certain/probable/possible), not as fact.",
			},
			Symbol: ex,
		}
		rel := filepath.Join(dirSymbols, pkg, cardName(pkg, s.Fqn))
		n, err := b.writeJSON(rel, card)
		if err != nil {
			return nil, err
		}
		res.files = append(res.files, rel)
		res.bytes += n
		res.itemCount++
	}
	res.note = fmt.Sprintf("package %q", pkg)
	return res, nil
}

// --- 3. Blast-Radius Cards --------------------------------------------------

type blastCard struct {
	artifactMeta
	Symbol        string      `json:"symbol"`
	Depth         int         `json:"depth"`
	Approximation any         `json:"approximation"`
	TotalCallers  int         `json:"total_callers"`
	DirectCallers int         `json:"direct_callers"`
	TestCallers   int         `json:"test_callers"`
	Callers       []forestRow `json:"callers"`
}

func genBlastRadius(ctx context.Context, c *cgxClient, b *bundle, pkg string, syms []searchRow, depth int) (*genResult, error) {
	res := &genResult{}
	for _, s := range syms {
		if s.Kind == "type" {
			continue // reverse-call closure is defined for callables
		}
		fr, err := c.callers(ctx, s.Fqn, depth)
		if err != nil {
			return nil, err
		}
		direct, tests := 0, 0
		for _, r := range fr.Results {
			if r.Depth == 1 {
				direct++
			}
			if strings.HasSuffix(r.File, "_test.go") {
				tests++
			}
		}
		card := blastCard{
			artifactMeta: artifactMeta{
				Kind:        "blast_radius",
				Description: fmt.Sprintf("Reverse-reachability closure (who breaks) for %s at depth %d.", s.Fqn, depth),
				GeneratedBy: []string{strings.Join(c.argv("callers", s.Fqn, "--depth", fmt.Sprintf("%d", depth)), " ")},
				Honesty: "Callers are labeled per-row (`confidence`, `condition`, `depth`). The top-level " +
					"`approximation` envelope is cgx's verbatim disclosure: `over_under` here means the set is " +
					"both over-approximated (dynamic-dispatch candidate edges) and under-approximated (depth cap; " +
					"unresolved external calls). Empty is not proof of no callers.",
			},
			Symbol:        s.Fqn,
			Depth:         depth,
			Approximation: rawOrNull(fr.Approximation),
			TotalCallers:  fr.Count,
			DirectCallers: direct,
			TestCallers:   tests,
			Callers:       fr.Results,
		}
		rel := filepath.Join(dirBlast, pkg, cardName(pkg, s.Fqn))
		n, err := b.writeJSON(rel, card)
		if err != nil {
			return nil, err
		}
		res.files = append(res.files, rel)
		res.bytes += n
		res.itemCount++
	}
	res.note = fmt.Sprintf("package %q, depth %d", pkg, depth)
	return res, nil
}

// --- 4. Dead-Code Inventory -------------------------------------------------

type deadCodeArtifact struct {
	artifactMeta
	Approximation    any         `json:"approximation"`
	TotalUnused      int         `json:"total_unused_functions"`
	FirstPartyUnused int         `json:"first_party_unused"`
	ExportedUnused   []unusedRow `json:"exported_but_unused"` // API-surface candidates, NOT dead
	UnexportedUnused []unusedRow `json:"unexported_no_ref"`   // stronger delete candidates
	Vacuous          bool        `json:"vacuous"`
}

func genDeadCode(ctx context.Context, c *cgxClient, b *bundle) (*genResult, error) {
	ur, err := c.unused(ctx, "function")
	if err != nil {
		return nil, err
	}
	var exported, unexported []unusedRow
	for _, r := range ur.Results {
		if !isFirstParty(r.File) {
			continue
		}
		if isExportedGo(r.Fqn) {
			exported = append(exported, r)
		} else {
			unexported = append(unexported, r)
		}
	}
	sort.Slice(exported, func(i, j int) bool { return exported[i].Fqn < exported[j].Fqn })
	sort.Slice(unexported, func(i, j int) bool { return unexported[i].Fqn < unexported[j].Fqn })

	art := deadCodeArtifact{
		artifactMeta: artifactMeta{
			Kind:        "dead_code_inventory",
			Description: "First-party unused functions, split into exported (API candidates) and unexported (delete candidates).",
			GeneratedBy: []string{strings.Join(c.argv("unused", "--kind", "function"), " ")},
			Honesty: "The `approximation` envelope is verbatim: direction `under` with an " +
				"`unresolved-external-calls` count — some listed functions may be reached only via " +
				"unindexed/dynamic/interface call sites and are NOT safe to delete on this evidence. " +
				"Exported-but-unused symbols are public-API candidates, not dead code. Empty is not proof.",
		},
		Approximation:    rawOrNull(ur.Approximation),
		TotalUnused:      ur.Count,
		FirstPartyUnused: len(exported) + len(unexported),
		ExportedUnused:   exported,
		UnexportedUnused: unexported,
		Vacuous:          ur.Vacuous,
	}
	n, err := b.writeJSON(fileDeadCode, art)
	if err != nil {
		return nil, err
	}
	return &genResult{files: []string{fileDeadCode}, itemCount: art.FirstPartyUnused, bytes: n}, nil
}

// --- 5. Data-Flow Provenance ------------------------------------------------

type flowEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type dataFlowArtifact struct {
	artifactMeta
	Query          string     `json:"query"`
	Approximation  any        `json:"approximation"`
	TotalEdges     int        `json:"total_edges_in_window"`
	PackageScoped  []flowEdge `json:"package_scoped"`
	RepoWideSample []flowEdge `json:"repo_wide_sample"`
	EmptySemantics string     `json:"empty_semantics,omitempty"`
}

func genDataFlow(ctx context.Context, c *cgxClient, b *bundle, pkg string) (*genResult, error) {
	cql := fmt.Sprintf("MATCH (a)-[:DATA_FLOW]->(b) RETURN a.fqn, b.fqn LIMIT %d", dataFlowRowLimit)
	qr, err := c.query(ctx, cql)
	if err != nil {
		return nil, err
	}
	var scoped, sample []flowEdge
	for _, row := range qr.Rows {
		if len(row) < 2 {
			continue
		}
		from, to := unquote(row[0]), unquote(row[1])
		e := flowEdge{From: from, To: to}
		if strings.HasPrefix(from, pkg+"::") || strings.HasPrefix(to, pkg+"::") {
			scoped = append(scoped, e)
		}
		if len(sample) < 25 {
			sample = append(sample, e)
		}
	}

	art := dataFlowArtifact{
		artifactMeta: artifactMeta{
			Kind:        "data_flow_provenance",
			Description: "Structural value-provenance edges (SSA derives-from). NOT security-typed taint.",
			GeneratedBy: []string{strings.Join(c.argv("query", cql), " ")},
			Honesty: "STRUCTURAL provenance only — source/sink/sanitizer taint classes are deferred in cgx, " +
				"so this is never a taint verdict. Confidence: `certain` = direct assignment, `probable` = " +
				"crosses a function-summary boundary.",
		},
		Query:          cql,
		Approximation:  rawOrNull(qr.Approximation),
		TotalEdges:     qr.Count,
		PackageScoped:  scoped,
		RepoWideSample: sample,
	}
	if qr.Count == 0 {
		art.EmptySemantics = "This index returned zero DATA_FLOW edges. Empty is NOT proof that no value flows " +
			"exist. Cause undetermined: DATA_FLOW is empty while IMPLEMENTS is populated on this same index, so " +
			"this is index-build-dependent, not a fixed cgx limitation. A `cgx index` rebuild is the reproduction " +
			"step (a dataflow-absent build, e.g. `cgx index --no-dataflow`, is one hypothesis)."
	}
	n, err := b.writeJSON(fileDataFlow, art)
	if err != nil {
		return nil, err
	}
	return &genResult{files: []string{fileDataFlow}, itemCount: len(scoped), bytes: n, note: art.EmptySemantics}, nil
}

// --- 6. PR Call-Graph Diff --------------------------------------------------

type prDiffArtifact struct {
	artifactMeta
	Base       string      `json:"base"`
	Head       string      `json:"head"`
	Degenerate bool        `json:"degenerate"`
	Note       string      `json:"note,omitempty"`
	Diff       *diffResult `json:"diff"`
}

func genPRDiff(ctx context.Context, c *cgxClient, b *bundle, base, head string) (*genResult, error) {
	dr, err := c.diff(ctx, base, head)
	degenerate := false
	note := ""
	if err != nil {
		// The requested range could not be resolved (single-commit history, or a
		// rev syntax cgx's git layer rejects, e.g. HEAD~1). Fall back to a self-diff
		// so the artifact is still emitted, and disclose the degradation.
		self, selfErr := c.diff(ctx, head, head)
		if selfErr != nil {
			return nil, fmt.Errorf("diff %s..%s failed (%v) and self-diff %s..%s also failed: %w", base, head, err, head, head, selfErr)
		}
		dr = self
		degenerate = true
		base = head
		note = fmt.Sprintf("requested base could not be resolved (%v); emitted a degenerate self-diff (base==head). "+
			"An empty diff here is structural — there is no range to compare — not a proven 'no changes in a PR'. "+
			"Pass -base/-head with resolvable refs (or SHAs) for a real PR diff.", err)
	}
	art := prDiffArtifact{
		artifactMeta: artifactMeta{
			Kind:        "pr_call_graph_diff",
			Description: "Added/removed/changed call-graph edges and nodes between two git refs.",
			GeneratedBy: []string{strings.Join(c.argv("diff", base, head), " ")},
			Honesty: "`diff` carries NO per-edge confidence — it is set math over two indexed snapshots. " +
				"To judge an added edge's certainty, re-query it with `callers`/`paths`. Empty is not proof of no change.",
		},
		Base:       base,
		Head:       head,
		Degenerate: degenerate,
		Note:       note,
		Diff:       dr,
	}
	n, err := b.writeJSON(filePRDiff, art)
	if err != nil {
		return nil, err
	}
	count := len(dr.AddedEdges) + len(dr.RemovedEdges) + len(dr.ChangedEdges)
	return &genResult{files: []string{filePRDiff}, itemCount: count, bytes: n, note: note}, nil
}
