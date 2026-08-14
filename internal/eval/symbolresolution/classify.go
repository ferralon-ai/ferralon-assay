package symbolresolution

import (
	"context"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/corpus"
	"github.com/ferralon-ai/ferralon-assay/internal/eval/reachcandidate"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ecosystemLane is the ONE closed map deciding ecosystem-unsupported vs out-of-lane-ecosystem
// (field contract §7.4). A PURL ecosystem token absent from this map has no lane in the program;
// a token present but mapping to a lane other than the one under measurement is out-of-lane.
// Defined once so step-1 and step-2 of the classifier read the same source.
var ecosystemLane = map[string]string{
	"golang": "go",
	"maven":  "java",
	"npm":    "js",
	"pypi":   "python",
	"nuget":  "dotnet",
}

// laneEcosystem is the reverse of ecosystemLane: the ecosystem token an in-scope lane measures
// ("golang" for "go"). Empty for a lane not in the program set.
func laneEcosystem(lane string) string {
	for eco, l := range ecosystemLane {
		if l == lane {
			return eco
		}
	}
	return ""
}

// CaseRunner drives the deterministic Assess resolver over one bound corpus record and returns
// the per-case signal. Production binds reachcandidate.RunCase to the lane's LanguagePlugin via
// RunCaseRunner (the sanctioned deterministic eval path over checked-in vendored_repro fixtures);
// the hermetic suite injects a deterministic fake so it needs no toolchain. It is invoked ONLY
// for the in-lane, symbol-bearing, buildable subset (classifier step 5) — never for records the
// committed fields already classify.
type CaseRunner func(ctx context.Context, rec pipeline.AdvisoryFacts, fix corpus.Fixture) reachcandidate.CaseResult

// RunCaseRunner returns the production CaseRunner: it synthesises the Case via
// reachcandidate.CaseFrom and drives reachcandidate.RunCase over the given lane plugin, so the
// per-record resolution is byte-identical to the live eval path. It runs the real toolchain and
// so is used only on the opt-in live path, never in `go test ./...`.
func RunCaseRunner(p plugin.LanguagePlugin) CaseRunner {
	return func(ctx context.Context, rec pipeline.AdvisoryFacts, fix corpus.Fixture) reachcandidate.CaseResult {
		return reachcandidate.RunCase(ctx, p, reachcandidate.CaseFrom(fix, rec, nil))
	}
}

// Classify computes the resolution outcome for one advisory record under one in-scope lane, by
// the §3.1 precedence classifier (first match wins). Steps 1-4 are pure over committed fields;
// only step 5 runs the resolver, and only when a vendored_repro fixture is bound (bound==true,
// fix carrying its BuildDir/Category). run is invoked exactly once, in step 5.
func Classify(ctx context.Context, recordID, lane string, rec pipeline.AdvisoryFacts, fix corpus.Fixture, bound bool, run CaseRunner) ResolutionOutcome {
	eco := pipeline.EcosystemToken(rec)
	out := ResolutionOutcome{RecordID: recordID, Lane: lane, Ecosystem: eco}
	if bound {
		out.Category = fix.Category // kept visible; "" for unbound records (§5)
	}
	switch {
	case ecosystemLane[eco] == "": // step 1: ecosystem maps to no program lane (also "(none)")
		out.Reason = ReasonEcosystemUnsupported
	case ecosystemLane[eco] != lane: // step 2: in-program but a DIFFERENT lane
		out.Reason = ReasonOutOfLaneEcosystem
	case !pipeline.SymbolBearing(rec): // step 3: advisory names no symbol
		out.Reason = ReasonAdvisoryNamesNoSymbol
	case !bound: // step 4: no build context — the resolver never runs
		out.Reason = ReasonArtifactNotIndexed
	default: // step 5: run the deterministic resolver and map CaseResult → outcome
		classifyCaseResult(&out, run(ctx, rec, fix))
	}
	return out
}

// classifyCaseResult maps a per-case CaseResult onto the resolved/unresolved outcome by the §3.1
// step-5 precedence. Partiality folds IN here (a method-limit that still matched ≥1 symbol is
// resolved; the same partiality with 0 matches is symbol-indexed-no-match) — it is never its own
// resolution reason (§1.3).
func classifyCaseResult(out *ResolutionOutcome, res reachcandidate.CaseResult) {
	switch {
	case res.Err != nil || res.PartialReason == plugin.PartialReasonToolFailure:
		out.Reason = ReasonResolverToolFailure
	case !res.Measured:
		// The lane's analyzer did not run against the artifact (NoPlugin route) — the cross-lane
		// path. For {go} with the Go plugin present this branch does not fire.
		out.Reason = ReasonArtifactNotIndexed
	case res.ResolvedCount > 0:
		out.Resolved = true
		out.Symbol = &ResolvedSymbol{SCIP: res.ResolvedSinkSCIP, DisplayName: res.ResolvedSinkDisplay}
	case res.CandidatePairFormed:
		// Matched 0 at the static tier, but a gated-path candidate formed — the Assess-tier gap.
		out.Reason = ReasonAssessTierGap
	default:
		out.Reason = ReasonSymbolIndexedNoMatch
	}
}

// ClassifyLane produces one ResolutionOutcome per record for one in-scope lane, in vuln_id order.
// The result count is exactly len(records) — the C1 count guard (records × one lane).
func ClassifyLane(ctx context.Context, lane string, records map[string]pipeline.AdvisoryFacts, bound map[string]corpus.Fixture, run CaseRunner) []ResolutionOutcome {
	ids := sortedRecordIDs(records)
	out := make([]ResolutionOutcome, 0, len(ids))
	for _, id := range ids {
		fix, isBound := bound[id]
		out = append(out, Classify(ctx, id, lane, records[id], fix, isBound, run))
	}
	return out
}

// bindFixtures indexes the code-fixture corpus by advisory vuln_id, keeping only vendored_repro
// fixtures (the ones with a BuildDir to resolve against). When an advisory has multiple
// vendored_repro variants, the lowest fixture ID wins — a deterministic pick so the join is
// stable across runs.
func bindFixtures(fixtures []corpus.Fixture) map[string]corpus.Fixture {
	sorted := append([]corpus.Fixture(nil), fixtures...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	out := map[string]corpus.Fixture{}
	for _, f := range sorted {
		if f.Codebase.Acquisition.Mode != "vendored_repro" {
			continue
		}
		if _, ok := out[f.Advisory.ID]; !ok {
			out[f.Advisory.ID] = f
		}
	}
	return out
}

func sortedRecordIDs(records map[string]pipeline.AdvisoryFacts) []string {
	ids := make([]string, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
