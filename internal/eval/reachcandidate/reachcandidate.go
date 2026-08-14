package reachcandidate

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

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
type CaseResult struct {
	VulnID string
	// CandidatePairFormed is true iff reachability_ingress wrote >=1 TypeCandidatePair
	// artifact — i.e. the resolver anchored a sink AND a reach path (govulncheck or the
	// first-party call-graph fallback) connected it. This is the recall signal.
	CandidatePairFormed bool
	// ResolvedSinkSCIP / ResolvedSinkDisplay are the first resolved sink (empty if the
	// symbol list matched nothing — the silent-miss case).
	ResolvedSinkSCIP    string
	ResolvedSinkDisplay string
	// SinkCorrect is true iff a candidate formed AND the resolved sink matches an
	// ExpectedSink (the precision signal). Meaningless when !SinkApplicable.
	SinkCorrect bool
	// GuardsPresent lists the declared guard symbols the resolver matched into the program
	// (presence candidates only — never a sufficiency claim).
	ResolvedCount  int // number of symbols the resolver matched (diagnostic)
	SinkApplicable bool
	Err            error
}

// Report is the tabulation over a run of cases.
type Report struct {
	Label   string // e.g. "corpus vN (partial)" — for the diff header
	Results []CaseResult
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
func RunCase(ctx context.Context, p plugin.LanguagePlugin, c Case) CaseResult {
	res := CaseResult{VulnID: c.VulnID, SinkApplicable: c.SinkApplicable()}

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

	// Readback: resolved sink.
	if syms, err := store.Query(a.ID, artifact.TypeVulnerableSymbol); err == nil && len(syms) > 0 {
		var sr plugin.SymbolResolutionResult
		if err := json.Unmarshal(syms[0].Payload, &sr); err == nil {
			res.ResolvedCount = len(sr.Resolved)
			if len(sr.Resolved) > 0 {
				res.ResolvedSinkSCIP = sr.Resolved[0].SCIP
				res.ResolvedSinkDisplay = sr.Resolved[0].DisplayName
			}
		}
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
		if !res.SinkApplicable {
			continue
		}
		denom++
		if res.CandidatePairFormed {
			num++
		}
	}
	return Rate{Num: num, Denom: denom}
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
type Rate struct{ Num, Denom int }

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
	fmt.Fprintf(&b, "%-24s  %-9s  %-8s  %-8s  %s\n", "VULN_ID", "CANDIDATE", "SINK_OK", "RESOLVED", "NOTE")
	rows := append([]CaseResult(nil), r.Results...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].VulnID < rows[j].VulnID })
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
		if res.Err != nil {
			note = "ERR: " + res.Err.Error()
		} else if res.ResolvedSinkDisplay == "" {
			note = "(no symbol resolved)"
		}
		resolved := fmt.Sprintf("%d", res.ResolvedCount)
		fmt.Fprintf(&b, "%-24s  %-9s  %-8s  %-8s  %s\n", res.VulnID, cand, sinkOK, resolved, note)
	}
	fmt.Fprintf(&b, "\nRECALL    (candidate formed / sink-applicable) : %s\n", r.Recall())
	fmt.Fprintf(&b, "PRECISION (correct sink  / candidates formed)  : %s\n", r.Precision())
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
