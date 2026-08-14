package reachcandidate

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Case is one CVE under measurement: a fixture codebase plus the corpus symbol list to
// resolve against it, and the curated ground-truth sink(s) the upstream fix guards.
//
// Symbols/GuardSymbols are the INDEPENDENT VARIABLE — swap the partial-corpus list for the
// complete-corpus list and re-run to get a before/after delta (see Diff). ExpectedSinks is
// the ground truth for the precision metric; it is verified against the upstream fix
// (validate-verdict-before-lock), NOT derived from Symbols, so a wrong-but-resolving symbol
// is caught as a precision miss rather than laundered into a pass.
type Case struct {
	// CaseID is the unique, schema-validated corpus fixture id (`<advisory>-<variant>`,
	// distinct per fixture file). It is the diff/sort key: VulnID collides across the
	// vulnerable/fixed/patched/absent variants that share one advisory id, so keying on
	// VulnID silently collapses per-variant results (see Diff). CaseID never collides.
	CaseID string `json:"case_id"`
	VulnID string // advisory primary id, e.g. "CVE-2024-45337" / "GO-2021-0113"
	Source string // advisory source, e.g. "osv"
	// Aliases feeds govulnMatchID (the GO- alias govulncheck keys dependency findings by).
	// Empty is fine for a first-party / call-graph-reachable fixture.
	Aliases []string
	// PURL scopes the resolver's package filter, e.g. "pkg:golang/golang.org/x/text". Empty
	// relaxes the scope to whole-program symbol-name matching (still sound: identity, not scope).
	PURL string
	// Symbols is the corpus `symbols` list under test — bare, source-level (DisplayName-form)
	// identifiers (see package doc). This is what completeness populates.
	Symbols []string
	// GuardSymbols is the corpus `guard_symbols` list under test (presence candidates only).
	GuardSymbols []string
	// BuildDir is the absolute path to the checked-out fixture repo the plugin analyzes.
	BuildDir string
	// ExpectedSinks is the curated, upstream-verified correct fix-guarded sink identifier(s)
	// in DisplayName form. A resolved sink matching any of these is "correct" (precision hit).
	// Empty means "no sink applicable" — the case is excluded from the recall denominator and
	// the precision metric (SinkApplicable() == false).
	ExpectedSinks []string
}

// SinkApplicable reports whether a sink symbol is expected for this CVE (i.e. the case
// belongs in the recall denominator and the precision metric). A CVE with no expected sink
// — e.g. a pure-config advisory — is measured for candidate formation but not counted
// against symbol recall/precision.
func (c Case) SinkApplicable() bool { return len(c.ExpectedSinks) > 0 }

// CaseResult is the per-CVE measurement.
//
// The json tags give the committed golden baseline (testdata/baseline.json) stable
// snake_case keys. Err carries a runtime error interface that does not round-trip through
// JSON and is never part of the recall/precision signal the golden diffs on, so it is
// excluded from serialization (json:"-").
type CaseResult struct {
	// CaseID is the unique fixture id — the diff/sort key (see Case.CaseID). VulnID is kept
	// for display/grouping but is NOT unique across variants.
	CaseID string `json:"case_id"`
	VulnID string `json:"vuln_id"`
	// CandidatePairFormed is true iff reachability_ingress wrote >=1 TypeCandidatePair
	// artifact — i.e. the resolver anchored a sink AND a reach path (govulncheck or the
	// first-party call-graph fallback) connected it. This is the recall signal.
	CandidatePairFormed bool `json:"candidate_pair_formed"`
	// ResolvedSinkSCIP / ResolvedSinkDisplay are the first resolved sink (empty if the
	// symbol list matched nothing — the silent-miss case).
	ResolvedSinkSCIP    string `json:"resolved_sink_scip"`
	ResolvedSinkDisplay string `json:"resolved_sink_display"`
	// SinkCorrect is true iff a candidate formed AND the resolved sink matches an
	// ExpectedSink (the precision signal). Meaningless when !SinkApplicable.
	SinkCorrect bool `json:"sink_correct"`
	// GuardsPresent lists the declared guard symbols the resolver matched into the program
	// (presence candidates only — never a sufficiency claim).
	ResolvedCount  int  `json:"resolved_count"` // number of symbols the resolver matched (diagnostic)
	SinkApplicable bool `json:"sink_applicable"`
	// Measured is true iff a real language plugin analyzed this case — i.e. it did NOT route to
	// the NoPlugin stub (no "no_language_plugin" reason) and did not hard-error before readback.
	// This is the EXPLICIT unmeasured/miss distinction and the denominator gate for the rate
	// metrics: a NoPlugin-routed or errored fixture is unmeasured (never a recall miss), while a
	// case a plugin analyzed is Measured even when its analysis is PARTIAL. Static reachability is
	// almost always partial (dynamic_dispatch/reflection), so Complete≈never for real code —
	// gating the metrics on Measured (ran), not Complete (sound), is what lets them produce a
	// number at all. Preserves three-valued Partiality — a missing analyzer withholds evidence,
	// it never refutes (inv.5).
	Measured bool `json:"measured"`
	// Complete is true iff BOTH plugin stages (S4 symbol_mapping, S5 reachability_ingress)
	// returned Partiality.Complete — the SOUNDNESS signal (a total over-approximation). Distinct
	// from Measured: a case can be Measured (a plugin ran) yet !Complete (the analysis is partial,
	// e.g. dynamic_dispatch). Reported per-case for honesty; the rate metrics gate on Measured.
	Complete bool `json:"complete"`
	// PartialReason is the incomplete stage's canonical partiality reason code (e.g.
	// "no_language_plugin" for unmeasured, "dynamic_dispatch" for measured-but-partial), for
	// honest reporting. Empty when Complete.
	PartialReason string `json:"partial_reason,omitempty"`
	// RuntimeMS is the wall-clock duration of RunCase in milliseconds (§4.7.13). It is
	// environment-variant: captured and reported, but NEVER part of the Diff/Regressed gate or
	// the golden equality (a slower run is not a regression).
	RuntimeMS int64 `json:"runtime_ms"`
	Err       error `json:"-"`
}

// Report is the tabulation over a run of cases.
type Report struct {
	Label   string       `json:"label"` // e.g. "corpus vN (partial)" — for the diff header
	Results []CaseResult `json:"results"`
}

// Run measures every case against the given plugin and returns the tabulated report.
// It is deterministic (Assess is deterministic): no model, no sandbox. The plugin must be
// real (plugin.NewGoPlugin, containerized Java/JS/py/dotnet) for a real fixture, or a stub
// for a hermetic self-test.
func Run(ctx context.Context, p plugin.LanguagePlugin, label string, cases []Case) Report {
	rep := Report{Label: label, Results: make([]CaseResult, 0, len(cases))}
	for _, c := range cases {
		rep.Results = append(rep.Results, RunCase(ctx, p, c))
	}
	return rep
}

// RunCase drives the real, exported Assess symbol-resolution + reachability stages over one
// case and reads back the candidate-pair + resolved-sink signals.
//
// It seeds the two upstream artifacts those stages read (the normalized_advisory projection
// — verbatim the four fields symbol_mapping/reachability_ingress consume — and the
// codebase_inventory build_dir) and then runs the genuine NewSymbolMapping +
// NewReachabilityIngress stages. The symbol list is thus the only independent variable; the
// resolver and the reach BFS are the real engine consumer path, unmodified.
func RunCase(ctx context.Context, p plugin.LanguagePlugin, c Case) (res CaseResult) {
	res = CaseResult{CaseID: c.CaseID, VulnID: c.VulnID, SinkApplicable: c.SinkApplicable()}

	// Wall-clock the whole case (§4.7.13). Set on every return path via defer.
	start := time.Now()
	defer func() { res.RuntimeMS = time.Since(start).Milliseconds() }()

	assessments := assessment.NewMemStore()
	store := artifact.NewMemStore()
	a, err := assessments.Create(assessment.Request{
		Vulnerability: assessment.VulnRef{ID: c.VulnID, Source: c.Source},
	})
	if err != nil {
		res.Err = fmt.Errorf("create assessment: %w", err)
		return res
	}

	// Seed the normalized_advisory projection. These are exactly the fields the downstream
	// consumers read: advisoryPURLAndSymbols reads purl + advisory_symbols; advisoryGuards
	// reads advisory_guards; govulnMatchID reads aliases. (Mirrors advisory_intake's output
	// shape; a guard test asserts it does not drift — see reachcandidate_test.go.)
	normAdvisory := seededAdvisory{
		VulnID:          c.VulnID,
		Source:          c.Source,
		Aliases:         c.Aliases,
		PURL:            c.PURL,
		AdvisorySymbols: c.Symbols,
		AdvisoryGuards:  c.GuardSymbols,
	}
	if _, err := pipeline.PutArtifact(store, a, "reachcandidate_eval", artifact.TypeNormalizedAdvisory, "normalized advisory (seeded)", normAdvisory); err != nil {
		res.Err = fmt.Errorf("seed normalized_advisory: %w", err)
		return res
	}
	// Seed the codebase_inventory build_dir (the only inventory field S4/S5 read back).
	if _, err := pipeline.PutArtifact(store, a, "reachcandidate_eval", artifact.TypeInventory, "codebase inventory (seeded)", seededInventory{BuildDir: c.BuildDir}); err != nil {
		res.Err = fmt.Errorf("seed inventory: %w", err)
		return res
	}

	// Real S4: symbol_mapping → TypeVulnerableSymbol (the resolver runs here).
	if err := pipeline.NewSymbolMapping(p).Run(ctx, a, store); err != nil {
		res.Err = fmt.Errorf("symbol_mapping: %w", err)
		return res
	}
	// Real S5: reachability_ingress → TypeCandidatePair (the reach BFS runs here).
	if err := pipeline.NewReachabilityIngress(p).Run(ctx, a, store); err != nil {
		res.Err = fmt.Errorf("reachability_ingress: %w", err)
		return res
	}

	// Readback: resolved sink + S4 (symbol_mapping) partiality. The resolver's
	// SymbolResolutionResult carries the stage's declared Partiality (plugin.go:230).
	var s4, s5 plugin.Partiality
	if syms, err := store.Query(a.ID, artifact.TypeVulnerableSymbol); err == nil && len(syms) > 0 {
		var sr plugin.SymbolResolutionResult
		if err := json.Unmarshal(syms[0].Payload, &sr); err == nil {
			s4 = sr.Partiality
			res.ResolvedCount = len(sr.Resolved)
			if len(sr.Resolved) > 0 {
				res.ResolvedSinkSCIP = sr.Resolved[0].SCIP
				res.ResolvedSinkDisplay = sr.Resolved[0].DisplayName
			}
		}
	}
	// Readback: S5 (reachability_ingress) partiality. The stage persists the plugin's
	// ReachabilityResult inside the TypeReachability artifact under a "reachability" key
	// (stages.go reachabilityIngress.runWithPlugin) — read it back for the stage's Partiality.
	// This artifact is written even when no candidate pair forms (e.g. the NoPlugin route),
	// so it is the honest source of the completion signal for unmeasured cases.
	if reaches, err := store.Query(a.ID, artifact.TypeReachability); err == nil && len(reaches) > 0 {
		var rw struct {
			Reachability plugin.ReachabilityResult `json:"reachability"`
		}
		if err := json.Unmarshal(reaches[0].Payload, &rw); err == nil {
			s5 = rw.Reachability.Partiality
		}
	}
	// Measured (§4.7.12): a real plugin analyzed this case iff neither stage routed to the
	// NoPlugin stub. (An early hard error returns above with Measured:false — the zero value.)
	res.Measured = !hasReason(s4, plugin.PartialReasonNoPlugin) && !hasReason(s5, plugin.PartialReasonNoPlugin)
	// Soundness signal: both plugin stages a total over-approximation. A partial (dynamic_dispatch)
	// or NoPlugin stage yields Complete:false with the stage's canonical reason code.
	res.Complete = s4.Complete && s5.Complete
	if !res.Complete {
		res.PartialReason = firstPartialReason(s4, s5)
	}
	// Readback: candidate pair formed?
	if pairs, err := store.Query(a.ID, artifact.TypeCandidatePair); err == nil {
		res.CandidatePairFormed = len(pairs) > 0
	}
	// Precision: resolved sink matches a curated expected sink?
	if res.CandidatePairFormed && res.SinkApplicable {
		res.SinkCorrect = symbolMatchesAny(res.ResolvedSinkDisplay, c.ExpectedSinks)
	}
	return res
}

// Recall is the fraction of sink-applicable cases that produced a candidate pair. It is the
// "did completeness surface the dropped CVE" number: a partial corpus scores lower because a
// missing/wrong symbol resolves nothing → no candidate.
func (r Report) Recall() Rate {
	var denom, num int
	for _, res := range r.Results {
		// Skip UNMEASURED rows (NoPlugin/errored) EXPLICITLY as well as non-sink-applicable ones,
		// so an unmeasured non-Go row can never silently enter the denominator as a miss once
		// ground truth lands. A measured-but-partial case still counts (a formed candidate is a
		// definitive hit; a partial miss is counted conservatively as a miss — a recall lower
		// bound). Gating on Measured, not Complete, matters because Complete≈never for real code.
		// Today recall is n/a because ExpectedSinks is empty — this skip is the durable guard.
		if !res.SinkApplicable || !res.Measured {
			continue
		}
		denom++
		if res.CandidatePairFormed {
			num++
		}
	}
	return Rate{Num: num, Denom: denom}
}

// CompletionRate is the fraction of cases a real plugin analyzed (§4.7.12) — the Phase-0 signal
// that proves per-language dispatch works: a NoPlugin-routed or errored fixture is not measured.
// Denominator is all results. (This is operational "did the analysis run," not the soundness
// signal — see CaseResult.Complete, which is ~never true for real static analysis.)
func (r Report) CompletionRate() Rate {
	var num int
	for _, res := range r.Results {
		if res.Measured {
			num++
		}
	}
	return Rate{Num: num, Denom: len(r.Results)}
}

// SymbolResolutionRate is the fraction of MEASURED cases where the resolver matched >=1 symbol
// (§4.7.11). The denominator is measured cases: an unmeasured (NoPlugin/errored) row has no
// resolution to score. A measured-but-partial case still counts — resolution is a definitive
// per-case fact independent of the analysis's soundness.
func (r Report) SymbolResolutionRate() Rate {
	var denom, num int
	for _, res := range r.Results {
		if !res.Measured {
			continue
		}
		denom++
		if res.ResolvedCount > 0 {
			num++
		}
	}
	return Rate{Num: num, Denom: denom}
}

// TotalRuntimeMS is the summed wall-clock of every case (§4.7.13). Environment-variant —
// reported, never gated.
func (r Report) TotalRuntimeMS() int64 {
	var total int64
	for _, res := range r.Results {
		total += res.RuntimeMS
	}
	return total
}

// MeanRuntimeMS is the mean per-case wall-clock in milliseconds (0 for an empty report).
func (r Report) MeanRuntimeMS() int64 {
	if len(r.Results) == 0 {
		return 0
	}
	return r.TotalRuntimeMS() / int64(len(r.Results))
}

// hasReason reports whether a partiality carries the given canonical reason code. Used to detect
// the NoPlugin route (reason "no_language_plugin") — the unmeasured signal.
func hasReason(p plugin.Partiality, reason string) bool {
	for _, r := range p.Reasons {
		if r == reason {
			return true
		}
	}
	return false
}

// firstPartialReason returns the first canonical reason code from the incomplete partialities,
// in argument order (S4 before S5). Empty when every argument is Complete or carries no reason.
func firstPartialReason(ps ...plugin.Partiality) string {
	for _, p := range ps {
		if p.Complete {
			continue
		}
		for _, r := range p.Reasons {
			if r != "" {
				return r
			}
		}
	}
	return ""
}

// Precision is the fraction of formed candidates (over sink-applicable cases) whose resolved
// sink is the correct upstream-fixed symbol. It catches over-population: a wrong-but-present
// symbol raises recall while lowering precision.
func (r Report) Precision() Rate {
	var denom, num int
	for _, res := range r.Results {
		if !res.SinkApplicable || !res.CandidatePairFormed {
			continue
		}
		denom++
		if res.SinkCorrect {
			num++
		}
	}
	return Rate{Num: num, Denom: denom}
}

// Rate is a fraction reported honestly as num/denom (denom 0 ⇒ undefined, printed "n/a").
type Rate struct {
	Num   int `json:"num"`
	Denom int `json:"denom"`
}

func (r Rate) Float() float64 {
	if r.Denom == 0 {
		return 0
	}
	return float64(r.Num) / float64(r.Denom)
}

func (r Rate) String() string {
	if r.Denom == 0 {
		return "n/a (0/0)"
	}
	return fmt.Sprintf("%.3f (%d/%d)", r.Float(), r.Num, r.Denom)
}

// Table renders the per-CVE tabulation plus the aggregate recall/precision — the R1 line.
func (r Report) Table() string {
	var b strings.Builder
	fmt.Fprintf(&b, "reachable-candidate eval — %s\n", r.Label)
	fmt.Fprintf(&b, "%-32s  %-24s  %-9s  %-8s  %-8s  %s\n", "CASE_ID", "VULN_ID", "CANDIDATE", "SINK_OK", "RESOLVED", "NOTE")
	rows := append([]CaseResult(nil), r.Results...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].CaseID < rows[j].CaseID })
	for _, res := range rows {
		cand := "no"
		if res.CandidatePairFormed {
			cand = "yes"
		}
		sinkOK := "-"
		if res.SinkApplicable {
			sinkOK = "no"
			if res.SinkCorrect {
				sinkOK = "yes"
			}
		}
		note := res.ResolvedSinkDisplay
		switch {
		case res.Err != nil:
			note = "ERR: " + res.Err.Error()
		case !res.Measured:
			note = "UNMEASURED"
			if res.PartialReason != "" {
				note = "UNMEASURED: " + res.PartialReason
			}
		case !res.Complete && res.ResolvedSinkDisplay == "":
			note = "(no symbol resolved)"
			if res.PartialReason != "" {
				note = "partial (" + res.PartialReason + "), no symbol resolved"
			}
		case res.ResolvedSinkDisplay == "":
			note = "(no symbol resolved)"
		}
		resolved := fmt.Sprintf("%d", res.ResolvedCount)
		fmt.Fprintf(&b, "%-32s  %-24s  %-9s  %-8s  %-8s  %s\n", res.CaseID, res.VulnID, cand, sinkOK, resolved, note)
	}
	fmt.Fprintf(&b, "\nRECALL     (candidate formed / sink-applicable & measured) : %s\n", r.Recall())
	fmt.Fprintf(&b, "PRECISION  (correct sink   / candidates formed)            : %s\n", r.Precision())
	fmt.Fprintf(&b, "COMPLETION (analysis ran    / all cases)                   : %s\n", r.CompletionRate())
	fmt.Fprintf(&b, "SYMBOL-RES (resolved >=1    / measured cases)              : %s\n", r.SymbolResolutionRate())
	fmt.Fprintf(&b, "RUNTIME    total=%dms mean=%dms\n", r.TotalRuntimeMS(), r.MeanRuntimeMS())
	return b.String()
}

// seededAdvisory mirrors advisory_intake's normalized_advisory projection for the four
// fields the resolver + reach BFS consume. Kept as a named type so the guard test can
// compare its JSON keys against the real S1 output and fail on drift.
type seededAdvisory struct {
	VulnID          string   `json:"vuln_id"`
	Source          string   `json:"source"`
	Aliases         []string `json:"aliases,omitempty"`
	PURL            string   `json:"purl,omitempty"`
	AdvisorySymbols []string `json:"advisory_symbols,omitempty"`
	AdvisoryGuards  []string `json:"advisory_guards,omitempty"`
}

type seededInventory struct {
	BuildDir string `json:"build_dir"`
}
