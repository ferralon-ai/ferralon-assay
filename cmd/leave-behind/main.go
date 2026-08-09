// Command leave-behind generates a bundle of pre-computed, agent-consumable
// leave-behinds by driving the cgx CLI (Path A) over a repository's already-built
// index. A leave-behind is an addressable, deterministic answer to a question a
// coding agent would otherwise derive by grep -> read -> infer: hub ranking,
// symbol orientation, blast radius, dead code, structural provenance, and a PR
// call-graph diff. Every artifact preserves cgx's `approximation` envelope (or
// per-row confidence) verbatim, so the graph's real certainty is never laundered.
//
// This is a walled-garden POC: it imports nothing from the assay pipeline and
// shells only to the cgx binary. Build: go build -o leave-behind ./cmd/leave-behind
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

// honestySpine is the framing constraint carried at the top of the manifest.
const honestySpine = "On this index nearly all call edges are labeled `possible` (high coverage, " +
	"trust:high, 0 unresolved — but low per-edge precision without a SCIP index). An agent grepping has " +
	"the same uncertainty with zero labels; these leave-behinds hand it that uncertainty quantified, " +
	"labeled, and reproducible. Never present a `possible` edge as fact; read the confidence label per " +
	"row and the approximation envelope per artifact. Empty result != proven absent."

type options struct {
	repo   string
	out    string
	cgxBin string
	pkg    string
	depth  int
	base   string
	head   string
}

func main() {
	var opt options
	flag.StringVar(&opt.repo, "repo", ".", "path to the indexed repository (must contain .cgx/)")
	flag.StringVar(&opt.out, "out", "./leave-behind-bundle", "output bundle directory")
	flag.StringVar(&opt.cgxBin, "cgx-bin", "", "path to the cgx binary (default: look up `cgx` on PATH)")
	flag.StringVar(&opt.pkg, "pkg", "hostmatch", "first-party package to card (symbol + blast-radius)")
	flag.IntVar(&opt.depth, "depth", 3, "traversal depth for blast-radius callers")
	flag.StringVar(&opt.base, "base", "HEAD~1", "base git ref for the PR diff")
	flag.StringVar(&opt.head, "head", "HEAD", "head git ref for the PR diff")
	flag.Parse()

	if err := run(context.Background(), opt); err != nil {
		fmt.Fprintln(os.Stderr, "leave-behind:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, opt options) error {
	bin, err := resolveCgxBin(opt.cgxBin)
	if err != nil {
		return err
	}
	c := &cgxClient{bin: bin, repo: opt.repo}
	b := &bundle{dir: opt.out}

	doctor, err := c.doctor(ctx)
	if err != nil {
		return fmt.Errorf("graph-honesty header (cgx doctor): %w", err)
	}

	syms, err := discoverPkgSymbols(ctx, c, opt.pkg)
	if err != nil {
		return fmt.Errorf("discover package %q: %w", opt.pkg, err)
	}
	if len(syms) == 0 {
		return fmt.Errorf("package %q has no first-party function/method/type symbols in the index", opt.pkg)
	}

	live := map[int]*genResult{}

	if live[1], err = genAtlas(ctx, c, b); err != nil {
		return fmt.Errorf("atlas: %w", err)
	}
	if live[2], err = genSymbolCards(ctx, c, b, opt.pkg, syms); err != nil {
		return fmt.Errorf("symbol cards: %w", err)
	}
	if live[3], err = genBlastRadius(ctx, c, b, opt.pkg, syms, opt.depth); err != nil {
		return fmt.Errorf("blast radius: %w", err)
	}
	if live[6], err = genDeadCode(ctx, c, b); err != nil {
		return fmt.Errorf("dead code: %w", err)
	}
	if live[9], err = genDataFlow(ctx, c, b, opt.pkg); err != nil {
		return fmt.Errorf("data flow: %w", err)
	}
	if live[10], err = genPRDiff(ctx, c, b, opt.base, opt.head); err != nil {
		return fmt.Errorf("pr diff: %w", err)
	}

	man := buildManifest(opt, bin, doctor, live)
	if _, err := b.writeJSON(fileManifest, man); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	printSummary(opt, man, live)
	return nil
}

func printSummary(opt options, man manifest, live map[int]*genResult) {
	fmt.Printf("leave-behind bundle written to %s\n", opt.out)
	for _, e := range man.LeaveBehinds {
		status := e.Status
		if status == "live" {
			status = fmt.Sprintf("live (%d item(s), %d file(s))", e.ItemCount, len(e.Files))
		}
		fmt.Printf("  [%2d] %-28s %s\n", e.ID, e.Name, status)
	}
}

// --- manifest ---------------------------------------------------------------

type manifestEntry struct {
	ID            int      `json:"id"`
	Name          string   `json:"name"`
	Shelf         string   `json:"shelf"`
	AddressScheme string   `json:"address_scheme"`
	Files         []string `json:"files"`
	TokenCostEst  string   `json:"token_cost_estimate"`
	ReachForWhen  string   `json:"reach_for_this_when"`
	Status        string   `json:"status"`
	CgxCommand    string   `json:"cgx_command"`
	ItemCount     int      `json:"item_count,omitempty"`
	Note          string   `json:"note,omitempty"`
}

type manifest struct {
	Schema       string          `json:"schema"`
	GeneratedAt  string          `json:"generated_at"`
	Repo         string          `json:"repo"`
	CgxBin       string          `json:"cgx_bin"`
	GraphHonesty json.RawMessage `json:"graph_honesty"`
	HonestySpine string          `json:"honesty_spine"`
	LeaveBehinds []manifestEntry `json:"leave_behinds"`
}

func tokenCost(g *genResult) string {
	if g == nil {
		return ""
	}
	return fmt.Sprintf("~%d tokens (%d bytes across %d file(s))", g.bytes/4, g.bytes, len(g.files))
}

// buildManifest assembles all ten leave-behinds in address order: the six live
// generators' results plus four schema stubs (built-ready but out of POC scope).
func buildManifest(opt options, bin string, doctor json.RawMessage, live map[int]*genResult) manifest {
	entries := []manifestEntry{
		{
			ID: 1, Name: "Repo Atlas & Hotspot Map", Shelf: "structural",
			AddressScheme: "whole-repo / by-package",
			ReachForWhen:  "orienting in an unfamiliar repo: what's central, what's first-party, where a package lives.",
			CgxCommand:    "cgx symbols --rank {inbound,outbound,total} + cgx search --all",
		},
		{
			ID: 2, Name: "Symbol Card", Shelf: "structural",
			AddressScheme: "by-FQN (symbols/<pkg>/<sym>.json)",
			ReachForWhen:  "before touching a named symbol: its definition, degree, and every incident edge in one read.",
			CgxCommand:    "cgx explain <FQN>",
		},
		{
			ID: 3, Name: "Blast-Radius Card", Shelf: "structural",
			AddressScheme: "by-FQN (blast-radius/<pkg>/<sym>.json)",
			ReachForWhen:  "estimating what breaks if you change X: the reverse-reachability closure of callers.",
			CgxCommand:    "cgx callers <FQN> --depth N",
		},
		{
			ID: 4, Name: "Dependency Footprint", Shelf: "structural",
			AddressScheme: "by-FQN (dependency-footprint/<pkg>/<sym>.json)",
			Files:         []string{"dependency-footprint/<pkg>/<sym>.json"},
			TokenCostEst:  "~300 tokens/card",
			ReachForWhen:  "what X transitively touches (internal vs external, side-effecting).",
			Status:        "stub", CgxCommand: "cgx callees <FQN> --depth N",
			Note: "Symmetric to Blast-Radius (generator reuse trivial); omitted from the POC's six live artifacts.",
		},
		{
			ID: 5, Name: "Reachability & Paths", Shelf: "structural",
			AddressScheme: "by-FQN-pair (reachability/<A>__<B>.json)",
			Files:         []string{"reachability/<A>__<B>.json"},
			TokenCostEst:  "~200-800 tokens/pair",
			ReachForWhen:  "does A actually reach B; enumerate the call paths; is a symbol live vs dead.",
			Status:        "stub", CgxCommand: "cgx reaches <A> <B> / cgx paths <A> <B> --depth N",
			Note: "Needs a from/to symbol pair as input; a driver would pull anchors from the atlas hubs. Depth-capped (8 hops); state the bound.",
		},
		{
			ID: 6, Name: "Dead-Code Inventory", Shelf: "semantic",
			AddressScheme: "by-question (dead-code.json)",
			ReachForWhen:  "what is safe to delete: exported-but-unused (API candidates) vs unexported no-ref.",
			CgxCommand:    "cgx unused --kind function",
		},
		{
			ID: 7, Name: "Entrypoint & Attack-Surface Catalog", Shelf: "semantic",
			AddressScheme: "by-question (entrypoints.json)",
			Files:         []string{"entrypoints.json"},
			TokenCostEst:  "~1-3k tokens",
			ReachForWhen:  "where does control enter: CallGraph roots (main/init), hubs, entrypoint symbols.",
			Status:        "stub", CgxCommand: "cgx symbols (hubs) + cgx unused --kind entrypoint",
			Note: "cgx-light only in v0.3 (framework-idiomatic HTTP routes are deferred); the tegron plugin's FindIngresses would enrich this.",
		},
		{
			ID: 8, Name: "Interface / Implementer Map", Shelf: "semantic",
			AddressScheme: "by-question / by-FQN (interfaces.json)",
			Files:         []string{"interfaces.json"},
			TokenCostEst:  "~1-2k tokens",
			ReachForWhen:  "what implements interface X / what interfaces type Y satisfies (grep botches this).",
			Status:        "stub", CgxCommand: "cgx query 'MATCH (t)-[:IMPLEMENTS]->(i) RETURN ...'",
			Note: "Most build-ready stub: the IMPLEMENTS edge is populated on this index (sampled rows returned).",
		},
		{
			ID: 9, Name: "Data-Flow Provenance", Shelf: "semantic",
			AddressScheme: "by-question (data-flow.json)",
			ReachForWhen:  "where a value's contents came from / go — STRUCTURAL provenance, never a taint verdict.",
			CgxCommand:    "cgx query 'MATCH (a)-[:DATA_FLOW]->(b) RETURN ...'",
		},
		{
			ID: 10, Name: "PR Call-Graph Diff", Shelf: "semantic",
			AddressScheme: "by-question (pr-diff.json)",
			ReachForWhen:  "what structurally changed in a PR: new/removed/changed edges and nodes.",
			CgxCommand:    "cgx diff <base> <head>",
		},
	}

	for i := range entries {
		g, ok := live[entries[i].ID]
		if !ok {
			continue // stub entry already fully populated above
		}
		entries[i].Status = "live"
		entries[i].Files = g.files
		entries[i].ItemCount = g.itemCount
		entries[i].TokenCostEst = tokenCost(g)
		if g.note != "" {
			entries[i].Note = g.note
		}
	}

	return manifest{
		Schema:       "ferralon.leave-behind/v0",
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Repo:         opt.repo,
		CgxBin:       bin,
		GraphHonesty: doctor,
		HonestySpine: honestySpine,
		LeaveBehinds: entries,
	}
}
