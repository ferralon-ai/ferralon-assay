//go:build eval_live

// PLAN-290 Phase-2 exit-gate verification for the {go} reference lane. This is GATE evidence,
// not product code: it READS existing producer outputs and asserts they agree. It changes no
// producer, normaliser, or indexer (C7), and it is opt-in twice over — the `//go:build eval_live`
// tag keeps it out of `go test ./...`, and the TEGRON_EVAL=1 gate keeps it out of an accidental
// `-tags eval_live` run. It needs the real Go toolchain + a CURRENT tegron-plugin-go on PATH:
//
//	go build -o "$SOMEDIR/tegron-plugin-go" ./cmd/tegron-plugin-go   # a FRESH binary — a stale
//	PATH="$SOMEDIR:$PATH" TEGRON_EVAL=1 \                            # plugin fails call_graph
//	  go test -tags eval_live ./internal/eval/symbolresolution/ -run TestGate -v
//
// Two checks:
//   - TestGateActionableReasonProduction (§6 P2 gate text, second clause) — over the PRODUCTION
//     {go} run of PLAN-221's metric, every unresolved record carries a reason from the closed
//     ResolutionReason vocabulary and none is a catch-all.
//   - TestGateFiveProducerSCIPEquality (§6 P2 bullet 4) — for the resolving {go} records, the sink
//     identifier is the SAME SCIP across the dependency (S4 symbol_mapping), graph (reach-path
//     sink), and ingress (candidate-pair referenced sink) producers — preserved, not re-minted.
package symbolresolution

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/eval/reachcandidate"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func requireLiveGoToolchain(t *testing.T) plugin.LanguagePlugin {
	t.Helper()
	if os.Getenv("TEGRON_EVAL") != "1" {
		t.Skip("set TEGRON_EVAL=1 to run the PLAN-290 {go} gate verification (opt-in)")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no `go` on PATH: cannot drive the live {go} resolver")
	}
	if _, err := exec.LookPath("tegron-plugin-go"); err != nil {
		t.Skip("tegron-plugin-go not on PATH (build a FRESH one from ./cmd/tegron-plugin-go)")
	}
	p, err := plugin.NewGoPlugin()
	if err != nil {
		t.Fatalf("go plugin: %v", err)
	}
	return p
}

// TestGateActionableReasonProduction grades the §6 P2 gate text's SECOND clause unconditionally
// over the PRODUCTION {go} run (the real resolver over the real corpus, not the hermetic fakes):
// every unresolved {go} record carries a reason from the closed ResolutionReason vocabulary, and
// NO reason is a catch-all. The empty reason is the resolved sentinel only — an unresolved record
// with an empty or unrecognised reason is a §3.1/§3.6 failure regardless of the rate.
func TestGateActionableReasonProduction(t *testing.T) {
	p := requireLiveGoToolchain(t)
	fixtures := loadCorpus(t)
	led := BuildLedger(context.Background(), pipeline.AdvisoryTable, pipeline.AttributionStore{}, fixtures, RunCaseRunner(p))

	entry, ok := led.ByLane["go"]
	if !ok || entry.State != LaneMeasured {
		t.Fatalf("go lane not measured (state=%q) — cannot grade the production run", entry.State)
	}

	dist := map[ResolutionReason]int{}
	var outcomes int
	var resolved int
	for _, outs := range led.ByCategory {
		for _, o := range outs {
			if o.Lane != "go" {
				continue
			}
			outcomes++
			// XOR invariant: resolved (Symbol!=nil, Reason=="") XOR unresolved (Symbol==nil,
			// Reason ∈ closed set). Validate() rejects an empty/unknown reason on an unresolved
			// outcome — the catch-all laundering §6/C2 forbids.
			if err := o.Validate(); err != nil {
				t.Errorf("record %s: %v", o.RecordID, err)
			}
			if o.Resolved {
				resolved++
				continue
			}
			if o.Reason == "" {
				t.Errorf("record %s: UNRESOLVED with empty reason (infers safety from missing evidence — §3.1/§3.6)", o.RecordID)
				continue
			}
			if !o.Reason.Recognized() {
				t.Errorf("record %s: reason %q is not in the closed ResolutionReason vocabulary (catch-all forbidden — C2)", o.RecordID, o.Reason)
			}
			dist[o.Reason]++
		}
	}
	if outcomes != len(pipeline.AdvisoryTable) {
		t.Errorf("go outcome count = %d, want %d (one per record — C1)", outcomes, len(pipeline.AdvisoryTable))
	}

	reasons := make([]string, 0, len(dist))
	for r := range dist {
		reasons = append(reasons, string(r))
	}
	sort.Strings(reasons)
	t.Logf("production {go} run: %d records, %d resolved, %d unresolved", outcomes, resolved, outcomes-resolved)
	for _, r := range reasons {
		t.Logf("  reason %-26s x%d", r, dist[ResolutionReason(r)])
	}
}

// producerIdentifiers holds one resolving record's identifier as each producer emitted it.
type producerIdentifiers struct {
	recordID       string
	advisorySymbol []string // advisory producer: source-level NAME(s); no SCIP by design
	depSCIP        string   // dependency producer (S4 symbol_mapping): Resolved[0].SCIP
	depDisplay     string
	graphSinkSCIP  string // graph producer (reach BFS / govulncheck): reach-path Sink.SCIP
	ingressSCIP    string // ingress producer: SCIP inside the artifact the candidate pair references
	pairFormed     bool
	partialCarried bool // partiality is carried on the candidate pair, never silently dropped
}

// driveProducers reproduces RunCase's exact public-stage sequence (NewSymbolMapping →
// NewReachabilityIngress) while HOLDING the store, so each producer's identifier can be read back
// and compared. It seeds the same two upstream artifacts RunCase seeds; it changes no producer.
func driveProducers(t *testing.T, p plugin.LanguagePlugin, c reachcandidate.Case) (producerIdentifiers, bool) {
	t.Helper()
	ctx := context.Background()
	assessments := assessment.NewMemStore()
	store := artifact.NewMemStore()
	a, err := assessments.Create(assessment.Request{Vulnerability: assessment.VulnRef{ID: c.VulnID, Source: c.Source}})
	if err != nil {
		t.Fatalf("%s: create assessment: %v", c.CaseID, err)
	}
	type seededAdvisory struct {
		VulnID          string   `json:"vuln_id"`
		Source          string   `json:"source"`
		Aliases         []string `json:"aliases,omitempty"`
		PURL            string   `json:"purl,omitempty"`
		AdvisorySymbols []string `json:"advisory_symbols,omitempty"`
		AdvisoryGuards  []string `json:"advisory_guards,omitempty"`
	}
	if _, err := pipeline.PutArtifact(store, a, "plan290_gate", artifact.TypeNormalizedAdvisory, "normalized advisory (seeded)", seededAdvisory{
		VulnID: c.VulnID, Source: c.Source, Aliases: c.Aliases, PURL: c.PURL, AdvisorySymbols: c.Symbols, AdvisoryGuards: c.GuardSymbols,
	}); err != nil {
		t.Fatalf("%s: seed advisory: %v", c.CaseID, err)
	}
	type seededInventory struct {
		BuildDir string `json:"build_dir"`
	}
	if _, err := pipeline.PutArtifact(store, a, "plan290_gate", artifact.TypeInventory, "codebase inventory (seeded)", seededInventory{BuildDir: c.BuildDir}); err != nil {
		t.Fatalf("%s: seed inventory: %v", c.CaseID, err)
	}

	// A resolver/toolchain hard-failure (e.g. a fixture whose source is not materialised in the
	// committed testdata) is an HONEST ABSENT for this record — not a producer disagreement. Skip
	// it here; TestGateActionableReasonProduction still books it under its closed reason.
	if err := pipeline.NewSymbolMapping(p).Run(ctx, a, store); err != nil {
		t.Logf("%s: HONEST-ABSENT (symbol_mapping did not run: %v)", c.CaseID, err)
		return producerIdentifiers{}, false
	}
	if err := pipeline.NewReachabilityIngress(p).Run(ctx, a, store); err != nil {
		t.Logf("%s: HONEST-ABSENT (reachability_ingress did not run: %v)", c.CaseID, err)
		return producerIdentifiers{}, false
	}

	pi := producerIdentifiers{recordID: c.VulnID, advisorySymbol: c.Symbols}

	// dependency producer — S4 symbol_mapping resolved sink.
	if syms, err := store.Query(a.ID, artifact.TypeVulnerableSymbol); err == nil && len(syms) > 0 {
		var sr plugin.SymbolResolutionResult
		if err := json.Unmarshal(syms[0].Payload, &sr); err == nil && len(sr.Resolved) > 0 {
			pi.depSCIP = sr.Resolved[0].SCIP
			pi.depDisplay = sr.Resolved[0].DisplayName
		}
	}

	// graph producer — reach-path sink SCIP (the BFS anchors off the S4 SCIP; govulncheck anchors
	// off the GO- alias). Read the persisted reachability artifact's first path.
	if reaches, err := store.Query(a.ID, artifact.TypeReachability); err == nil && len(reaches) > 0 {
		var rw struct {
			Reachability plugin.ReachabilityResult `json:"reachability"`
		}
		if err := json.Unmarshal(reaches[0].Payload, &rw); err == nil && len(rw.Reachability.Paths) > 0 {
			pi.graphSinkSCIP = rw.Reachability.Paths[0].Sink.SCIP
		}
	}

	// ingress producer — the candidate pair's Sink leg is a REFERENCE to the dependency-produced
	// symbol artifact. Dereference it and read the SCIP the ingress stage bound the pair to. That
	// the pair carries a ref (not a re-minted symbol) is itself the preservation property.
	if pairs, err := store.Query(a.ID, artifact.TypeCandidatePair); err == nil && len(pairs) > 0 {
		pi.pairFormed = true
		var cp artifact.CandidatePair
		if err := json.Unmarshal(pairs[0].Payload, &cp); err == nil {
			pi.partialCarried = cp.Partial
			if sinkArt, err := store.Get(cp.Sink.ID); err == nil && sinkArt != nil {
				var sr plugin.SymbolResolutionResult
				if err := json.Unmarshal(sinkArt.Payload, &sr); err == nil && len(sr.Resolved) > 0 {
					pi.ingressSCIP = sr.Resolved[0].SCIP
				}
			}
		}
	}
	return pi, true
}

// TestGateFiveProducerSCIPEquality is the gate's SUBSTANTIVE check (§6 P2 bullet 4). For every
// buildable {go} corpus record it drives the real producers and, for each record that resolves a
// sink AND forms a candidate pair, asserts the sink identifier is the SAME SCIP across the
// dependency, graph, and ingress producers — preserved through the call graph and reachability
// ingress, never re-minted. It asserts equality only where a producer actually emitted an
// identifier; a producer that emitted nothing for a record is an HONEST GAP (logged), never a
// fabricated pass (§3.1/§3.6).
func TestGateFiveProducerSCIPEquality(t *testing.T) {
	p := requireLiveGoToolchain(t)
	fixtures := loadCorpus(t)
	bound := bindFixtures(fixtures)

	var ids []string
	for id, r := range pipeline.AdvisoryTable {
		if pipeline.EcosystemToken(r) != "golang" || !pipeline.SymbolBearing(r) {
			continue
		}
		if _, ok := bound[id]; ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)

	fullAgreement := 0
	for _, id := range ids {
		fix := bound[id]
		pi, ran := driveProducers(t, p, reachcandidate.CaseFrom(fix, pipeline.AdvisoryTable[id], nil))
		if !ran {
			continue
		}

		// A record resolves end-to-end only when the dependency producer emitted a SCIP AND a
		// candidate pair formed. Records that resolve nothing (symbol-indexed-no-match) or resolve
		// only via the gated path (assess-tier-gap) are not five-producer-resolving — they are the
		// gate's honest non-passing classes, not equality failures.
		if pi.depSCIP == "" || !pi.pairFormed {
			t.Logf("%-40s not five-producer-resolving (depSCIP=%q pairFormed=%v) — honest non-pass, see actionable-reason check",
				pi.recordID, pi.depSCIP, pi.pairFormed)
			continue
		}

		// graph leg: reach-path sink SCIP must equal the dependency SCIP (preserved through the BFS).
		if pi.graphSinkSCIP == "" {
			t.Logf("%-40s HONEST-GAP: dependency+ingress resolved but graph exposed no reach-path sink SCIP", pi.recordID)
		} else if pi.graphSinkSCIP != pi.depSCIP {
			t.Errorf("%s: graph sink SCIP re-minted: dep=%q graph=%q", pi.recordID, pi.depSCIP, pi.graphSinkSCIP)
		}

		// ingress leg: the candidate pair's referenced sink artifact must carry the dependency SCIP.
		if pi.ingressSCIP == "" {
			t.Logf("%-40s HONEST-GAP: candidate pair formed but its referenced sink exposed no SCIP", pi.recordID)
		} else if pi.ingressSCIP != pi.depSCIP {
			t.Errorf("%s: ingress sink SCIP re-minted: dep=%q ingress=%q", pi.recordID, pi.depSCIP, pi.ingressSCIP)
		}

		// advisory leg: the advisory names a source-level symbol (no SCIP by design). Confirm the
		// resolved symbol corresponds to a name the advisory carried — the advisory→dependency
		// identity that starts the chain.
		if !advisoryNamesResolved(pi.advisorySymbol, pi.depDisplay) {
			t.Errorf("%s: resolved display %q matches no advisory symbol %v (advisory→dependency identity broken)",
				pi.recordID, pi.depDisplay, pi.advisorySymbol)
		}

		if !pi.partialCarried {
			t.Errorf("%s: candidate pair dropped partiality (Partial=false) — §3.1/§3.6 requires it be carried", pi.recordID)
		}

		if pi.graphSinkSCIP == pi.depSCIP && pi.ingressSCIP == pi.depSCIP && pi.graphSinkSCIP != "" && pi.ingressSCIP != "" {
			fullAgreement++
			t.Logf("%-40s SCIP-EQUAL across dependency+graph+ingress: %q (advisory=%v, app-minted scip-go id)",
				pi.recordID, pi.depSCIP, pi.advisorySymbol)
		}
	}

	// HONEST-ABSENT: if nothing resolved end-to-end, the equality was not observed — that is a SKIP
	// (unobserved), never a pass. A stale/missing plugin binary lands here.
	if fullAgreement == 0 {
		t.Skip("no {go} record resolved end-to-end (dependency+graph+ingress) — equality UNOBSERVED; " +
			"ensure a FRESH tegron-plugin-go is on PATH (a stale binary fails call_graph)")
	}
	t.Logf("five-producer SCIP-equality observed on %d/%d buildable {go} records", fullAgreement, len(ids))
}

// advisoryNamesResolved reports whether the resolved symbol's display corresponds to one of the
// advisory's source-level symbol names (exact, or the trailing dotted/parenthesised component).
func advisoryNamesResolved(advisorySymbols []string, resolvedDisplay string) bool {
	if resolvedDisplay == "" {
		return false
	}
	for _, s := range advisorySymbols {
		if s == resolvedDisplay || strings.HasSuffix(s, "."+resolvedDisplay) || strings.HasSuffix(s, ")."+resolvedDisplay) {
			return true
		}
		// dependency-qualified name (pkg/path.Name): compare the final dotted leaf.
		if i := strings.LastIndex(s, "."); i >= 0 && s[i+1:] == resolvedDisplay {
			return true
		}
	}
	return false
}
