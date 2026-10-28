package trigger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/internal/intel"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// AnalyzerVersion is stamped into Report.Provenance.AnalyzerVersion so a reader can
// reason about analyzer-driven verdict changes across runs. Callers may override it
// via the run request; this is the default for an unset value. It is a var (not a
// const) so the brand name/version flow through at link time via the brand package.
var AnalyzerVersion = brand.AnalyzerVersion()

// assess runs the deterministic S1–S6 Assess pipeline for one advisory against one
// codebase and returns the artifact store holding the run's output. It is the shared
// engine behind every run mode: baseline runs it for each advisory in the corpus
// scope, PR-inherit and CVE-watch run it for the affected slice.
//
// It composes pipeline.AssessStages(opts...) — the OSS stage-assembly seam — so the
// run modes never reach into the prove tier. The injected Plugin/Checkout seams flow
// through AssessStages into S2/S4/S5; an empty opts set yields the hermetic stub path
// (no network, no git), which is what the offline tests exercise.
func assess(ctx context.Context, req assessment.Request, opts ...pipeline.AssessOption) (artifact.Store, string, error) {
	assessments := assessment.NewMemStore()
	store := artifact.NewMemStore()

	a, err := assessments.Create(req)
	if err != nil {
		return nil, "", fmt.Errorf("trigger: create assessment: %w", err)
	}

	// finding() settles a disqualified advisory on the discovery artifact alone, so the symbol and
	// reach work S4/S5 would do for it is never read; skip it.
	opts = append(opts[:len(opts):len(opts)], pipeline.WithSkipDisqualifiedAnalysis(true))
	orch := pipeline.NewOrchestrator(assessments, store, pipeline.AssessStages(opts...))
	if err := orch.Run(ctx, a.ID); err != nil {
		return nil, "", fmt.Errorf("trigger: assess %s: %w", req.Vulnerability.ID, err)
	}
	return store, a.ID, nil
}

// finding maps one advisory's S1–S6 artifacts into a single report.AdvisoryFinding,
// applying the deterministic verdict rule (inv. 5):
//
//   - disqualification_discovery disqualified  → VerdictDisqualified.
//   - a candidate (ingress→sink) reach path    → VerdictReachableCandidate, or
//     VerdictUndetermined/advisory_range_absent with the path kept when the advisory
//     carries no affected range the version axis can bound for the admitted package.
//   - neither, and the empty path set is not evidence about the subject (see
//     undeterminedReason) or has no positive grounds (see
//     notExploitableGrounds)                    → VerdictUndetermined, no basis.
//   - otherwise (no disqualification, no reach, grounds named) → VerdictNotExploitable, on the
//     basis the grounds name: symbol-unreachable when the code is installed and nothing reaches it
//     (no path, or no loaded module imports its package), symbol-absent when it is not in the build.
//
// The OSS tool stops at reachable_candidate; it never emits exploitable/reasoned_*.
func finding(store artifact.Store, assessmentID string, adv report.Advisory, pkg *report.Package) report.AdvisoryFinding {
	return findingInBuild(store, assessmentID, adv, pkg, nil)
}

// findingInBuild is finding with the scan's Go module list, which lets the not_exploitable gate
// read a Go package path the advisory names as part of the module that holds it (see
// samePackage). finding passes none, so every such path counts as another package.
func findingInBuild(store artifact.Store, assessmentID string, adv report.Advisory, pkg *report.Package, mods goModules) report.AdvisoryFinding {
	var f report.AdvisoryFinding
	switch {
	case maliciousPresent(store, assessmentID):
		// The one new signal: an AFFIRMATIVE, decisive OSS "affected". A known-malicious package
		// resolved to a version the advisory enumerates as affected. Ordered FIRST so it wins over a
		// co-present reachability candidate or disqualification — presence is deterministic proof the
		// bad artifact is installed, not a reachability lean. Affirmatives are never trust-gated
		// (inv.5), and the whole design keeps disqualify's trust gate untouched by never minting a
		// not-affected here.
		res, _ := maliciousPresenceResult(store, assessmentID)
		f = report.AdvisoryFinding{
			Advisory: adv,
			Package:  pkg,
			Verdict:  report.VerdictMaliciousPresent,
			Evidence: report.EvidenceSummary{
				Detail: maliciousPresentDetail(res.MatchedVersion),
			},
		}
	case disqualified(store, assessmentID):
		_, reason := disqualResult(store, assessmentID)
		f = report.AdvisoryFinding{
			Advisory: adv,
			Package:  pkg,
			Verdict:  report.VerdictDisqualified,
			Evidence: report.EvidenceSummary{
				Basis:  disqualBasis(reason),
				Detail: disqualDetail(reason),
			},
		}
	case hasCandidate(store, assessmentID):
		path, _ := candidatePath(store, assessmentID)
		grade, entry, frames := reachabilityEvidence(store, assessmentID)
		guards := guardsOnPath(store, assessmentID, frames)
		f = report.AdvisoryFinding{
			Advisory: adv,
			Package:  pkg,
			Verdict:  report.VerdictReachableCandidate,
			Evidence: report.EvidenceSummary{
				ReachablePath:    path,
				Grade:            grade,
				EntryPoint:       entry,
				CallPath:         frames,
				MitigatingGuards: guards,
				// B1 provenance-as-confidence (RFC §4.1): qualify the candidate's strength by how
				// its vulnerable symbols were DERIVED. Read HERE, inside the reachable_candidate
				// arm and only after the candidate has formed, so it is structurally unreachable
				// from admission / disqualify / refute. Absent or unrecognized provenance ⇒ "" ⇒
				// no annotation (honest-absent, inv.5): the candidate is reported exactly as today.
				SymbolConfidence: symbolConfidenceFor(advisorySymbolProvenance(store, assessmentID)),
				// B3 exploit-precondition qualifier (RFC §4.2): describe the candidate with the
				// advisory-declared exploit preconditions. Read HERE, in the same post-candidate
				// arm, for the same structural reason — it cannot reach admission / disqualify /
				// refute. Presence-only: it records that exploitation is CONDITIONAL, it never
				// evaluates whether the precondition holds (a Prove-tier question) and never scores
				// the candidate. Both absent ⇒ nil ⇒ no annotation (honest-absent, inv.5): the
				// candidate is reported exactly as today, at no strength penalty.
				ExploitPreconditions: exploitPreconditionsFor(advisoryPreconditions(store, assessmentID)),
				// B-guardsuff (RFC §4.2): annotate the on-path guards (above) with the advisory's
				// DECLARED sufficiency against each guard's bypass. Read HERE, in the same
				// post-candidate arm, for the same structural reason as B1/B3 — it cannot reach
				// admission / disqualify / refute. It annotates ONLY guards guardsOnPath already
				// surfaced, so it never widens the guard set; it is DESCRIPTIVE (surfaces a
				// Prove-tier claim as context) and never adjudicates sufficiency or scores the
				// candidate. No on-path guard carries a declared sufficiency ⇒ nil ⇒ no annotation
				// (honest-absent, inv.5): the candidate is reported exactly as today.
				GuardSufficiency: guardSufficiencyFor(guards, advisoryGuardSufficiency(store, assessmentID)),
			},
		}
		// An advisory with no affected range for the admitted package is admitted at every version,
		// so the path says nothing about whether this version carries the flaw. The path stays as
		// evidence; the candidate-only annotations go with the verdict.
		if pipeline.AdvisoryRangeAbsent(store, assessmentID) {
			f.Verdict = report.VerdictUndetermined
			f.UndeterminedReason = report.ReasonAdvisoryRangeAbsent
			f.Evidence = report.EvidenceSummary{
				Detail:           report.UndeterminedDetail(report.ReasonAdvisoryRangeAbsent),
				ReachablePath:    path,
				EntryPoint:       entry,
				CallPath:         frames,
				MitigatingGuards: guards,
				AdvisoryBounds:   advisoryBounds(store, assessmentID),
			}
		}
	default:
		// This arm is the only one that can rest on an absence, so it is the one that can
		// mistake the analyzer's blind spot for a refutation. Reaching it means the axes
		// established nothing POSITIVE: no disqualification and no path. Whether the absent
		// path is evidence about the SUBJECT is a separate question, and undeterminedReason
		// answers it.
		reason, undetermined := undeterminedReason(store, assessmentID, pkg)
		// An advisory whose package no module of the build holds rests on a search of every
		// module's source rather than on a path or a symbol inside a package, so a limit of the
		// path search does not hold it (outsideBuildExempt). Every other step must have run: a run
		// that loads code from outside the build list (plugin_load) can hold the advisory's code
		// with no module declaring it.
		if !outsideBuildBlocked(store, assessmentID, pkg) {
			detail, unvetted, ok := outsideBuildGrounds(store, assessmentID, pkg, mods)
			if ok {
				f = report.AdvisoryFinding{
					Advisory: adv,
					Verdict:  report.VerdictNotExploitable,
					Evidence: report.EvidenceSummary{Basis: verdict.BasisSymbolAbsent, Detail: detail},
				}
				break
			}
			if unvetted != "" {
				reason, undetermined = unvetted, true
			}
		}
		detail, groundsReason, grounded := "", "", false
		var basis verdict.NonExploitableBasis
		var assumptions []string
		if !undetermined {
			detail, groundsReason, basis, assumptions, grounded = notExploitableGrounds(store, assessmentID, pkg, mods)
			if !grounded {
				reason, undetermined = groundsReason, true
			}
		}
		if undetermined {
			f = report.AdvisoryFinding{
				Advisory:           adv,
				Package:            pkg,
				Verdict:            report.VerdictUndetermined,
				UndeterminedReason: reason,
				Evidence:           report.EvidenceSummary{Detail: report.UndeterminedDetail(reason)},
			}
			break
		}
		f = report.AdvisoryFinding{
			Advisory: adv,
			Package:  pkg,
			Verdict:  report.VerdictNotExploitable,
			Evidence: report.EvidenceSummary{
				Basis:       basis,
				Detail:      detail,
				Assumptions: assumptions,
			},
		}
	}
	// No Priority here: EPSS/KEV context is attached by the report Builder (rankWith), after every
	// verdict is final, so nothing on this path can read it (inv. 5).
	return f
}

// guardsOnPath returns the advisory-declared guard symbols present on the candidate
// path: a declared guard G is "present" when some frame on the resolved ingress→sink
// trace calls a function whose name matches G (a call-graph edge frame→G). This is
// MITIGATING EVIDENCE about the candidate, never a verdict (inv.5): a guard's presence
// narrows attention, but the finding stays reachable_candidate because presence ≠
// sufficiency — whether the guard actually closes the hole is a runtime question only
// the Prove tier settles. Returns guards in the advisory's declared order.
func guardsOnPath(store artifact.Store, assessmentID string, frames []report.CallFrame) []string {
	declared := advisoryGuards(store, assessmentID)
	if len(declared) == 0 || len(frames) == 0 {
		return nil
	}
	edges := callGraphEdges(store, assessmentID)
	if len(edges) == 0 {
		return nil
	}
	onPath := make(map[string]bool, len(frames))
	for _, f := range frames {
		onPath[f.Symbol] = true
	}
	declaredSet := make(map[string]bool, len(declared))
	for _, g := range declared {
		declaredSet[g] = true
	}
	found := make(map[string]bool, len(declared))
	for _, e := range edges {
		if !onPath[e.Caller.SCIP] {
			continue
		}
		if name := symbolLeaf(e.Callee.SCIP); declaredSet[name] {
			found[name] = true
		}
	}
	var out []string
	for _, g := range declared {
		if found[g] {
			out = append(out, g)
		}
	}
	return out
}

// advisoryGuards reads the advisory-declared guard symbol names from the normalized
// advisory artifact (S1). Empty when the advisory declares none.
func advisoryGuards(store artifact.Store, assessmentID string) []string {
	arts, err := store.Query(assessmentID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return nil
	}
	var adv struct {
		AdvisoryGuards []string `json:"advisory_guards"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return nil
	}
	return adv.AdvisoryGuards
}

// advisorySymbolProvenance reads the corpus's record-scoped symbol_provenance derivation tag
// from the normalized advisory artifact (S1). Empty ("") when the advisory carries none, when
// the artifact is absent, or when the payload is unreadable — every miss is the honest-absent
// path (inv.5): an absent tag is UNKNOWN derivation, never low confidence. Consumed as a
// candidate-scoped strength signal (symbolConfidenceFor); the not_exploitable grounds read the same
// tag through vettedSymbols.
func advisorySymbolProvenance(store artifact.Store, assessmentID string) string {
	arts, err := store.Query(assessmentID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return ""
	}
	var adv struct {
		SymbolProvenance string `json:"symbol_provenance"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return ""
	}
	return adv.SymbolProvenance
}

// symbolConfidenceFor maps the corpus's record-scoped symbol_provenance derivation tag onto a
// candidate STRENGTH label (RFC §4.1). It is deliberately total and fail-quiet: the emitted
// vocabulary maps to a confidence, and EVERYTHING ELSE — absent, empty, or an unrecognized
// open-set tier — maps to "" (no annotation). That is the honest-absent contract made structural:
//
//   - absent / "" ⇒ ""       unknown derivation, NOT low confidence — candidate reported as today.
//   - "osv-declared"/"curated" ⇒ high      authoritatively declared symbols.
//   - "diff-lexed"           ⇒ moderate   heuristically extracted — a LOWER label, never a gate.
//   - "cna-declared"         ⇒ ""         declared by the CNA, completeness unmeasured: no label.
//   - any unrecognized tier   ⇒ ""         we never invent a confidence for a tier we don't know.
//
// No tier, including diff-lexed, yields a value that could gate a symbol out of reachability or
// flip a verdict: this function only ever ADDS a strength label to an already-formed candidate.
func symbolConfidenceFor(provenance string) report.SymbolConfidence {
	switch provenance {
	case "osv-declared", "curated":
		return report.SymbolConfidenceHigh
	case "diff-lexed":
		return report.SymbolConfidenceModerate
	default:
		return "" // absent / empty / unrecognized ⇒ no derivation signal (honest-absent)
	}
}

// advisoryPreconditions reads the advisory-declared exploit preconditions (trigger_condition /
// prerequisite) from the normalized advisory artifact (S1). Both empty ("","") when the advisory
// declares none, when the artifact is absent, or when the payload is unreadable — every miss is the
// honest-absent path (inv.5): an absent precondition is UNCONDITIONAL exploitation (the conservative
// reading), never "not exploitable." Consumed only as a candidate-scoped PoE qualifier
// (exploitPreconditionsFor), never as an admission or refute input.
func advisoryPreconditions(store artifact.Store, assessmentID string) (triggerCondition, prerequisite string) {
	arts, err := store.Query(assessmentID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return "", ""
	}
	var adv struct {
		TriggerCondition string `json:"trigger_condition"`
		Prerequisite     string `json:"prerequisite"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return "", ""
	}
	return adv.TriggerCondition, adv.Prerequisite
}

// exploitPreconditionsFor builds the candidate-scoped PoE qualifier (RFC §4.2) from the advisory's
// declared preconditions. It is deliberately total and fail-quiet: when BOTH fields are empty it
// returns nil (no annotation) — that is the honest-absent contract made structural, absent =
// unconditional, the candidate reported exactly as today. Any declared precondition yields a non-nil
// block carrying the text verbatim.
//
// This is DESCRIPTIVE, presence-only context: it never evaluates whether a precondition holds (a
// runtime question the Prove tier settles) and never scores the candidate, so it can only ADD context
// to an already-formed candidate — never gate admission, never refute, never flip a verdict.
func exploitPreconditionsFor(triggerCondition, prerequisite string) *report.ExploitPreconditions {
	p := report.ExploitPreconditions{TriggerCondition: triggerCondition, Prerequisite: prerequisite}
	if p.Empty() {
		return nil // both absent ⇒ no annotation (honest-absent)
	}
	return &p
}

// guardSufficiencyVariant is the trigger-local decode shape of one normalized_advisory
// guard_sufficiency element. It is DECLARED advisory data (Assess reads facts off the artifact as
// JSON, into its own local structs — the same pattern as advisoryGuards); it is never a Prove verdict.
type guardSufficiencyVariant struct {
	Symbol     string `json:"symbol"`
	Version    string `json:"version"`
	ForBypass  string `json:"for_bypass"`
	Sufficient bool   `json:"sufficient"`
}

// advisoryGuardSufficiency reads the advisory-declared guard_sufficiency variants from the normalized
// advisory artifact (S1). Nil when the advisory declares none, when the artifact is absent, or when the
// payload is unreadable — every miss is the honest-absent path (inv.5): an absent sufficiency claim is
// "NOT ESTABLISHED," never "insufficient." Consumed only as a candidate-scoped descriptive annotation
// (guardSufficiencyFor), never as an admission or refute input.
func advisoryGuardSufficiency(store artifact.Store, assessmentID string) []guardSufficiencyVariant {
	arts, err := store.Query(assessmentID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return nil
	}
	var adv struct {
		GuardSufficiency []guardSufficiencyVariant `json:"guard_sufficiency"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return nil
	}
	return adv.GuardSufficiency
}

// guardSufficiencyFor annotates each guard ALREADY on the candidate path (onPath, from guardsOnPath)
// with the advisory's DECLARED sufficiency against its bypass (RFC §4.2). It is deliberately total and
// fail-quiet: a guard with no declared variant, an empty on-path set, or an empty declared set all yield
// no note (nil) — that is the honest-absent contract made structural, absent = not established, the
// candidate reported exactly as today. It iterates onPath (preserving MitigatingGuards' declared order)
// and emits a note only for a guard the advisory declares a variant for, so it NEVER widens the guard
// set past what guardsOnPath already surfaced.
//
// This is DESCRIPTIVE, presence-only: it surfaces the advisory's declared sufficiency as candidate
// context; it never evaluates whether the guard actually closes the hole (a runtime question the Prove
// tier settles) and never scores the candidate — so it can only ADD context to an already-formed
// candidate, never gate admission, never refute, never flip a verdict.
func guardSufficiencyFor(onPath []string, declared []guardSufficiencyVariant) []report.GuardSufficiencyNote {
	if len(onPath) == 0 || len(declared) == 0 {
		return nil
	}
	var out []report.GuardSufficiencyNote
	for _, g := range onPath {
		for _, d := range declared {
			if d.Symbol == "" || d.Symbol != g {
				continue
			}
			out = append(out, report.GuardSufficiencyNote{
				Symbol:      d.Symbol,
				ForBypass:   d.ForBypass,
				Sufficiency: report.SufficiencyLabel(d.Sufficient),
			})
		}
	}
	return out
}

// callGraphEdges reads the resolved call-graph edges from the reachability artifact
// (S5 records the call graph alongside the reachability result). Empty when the
// stub path produced no graph.
func callGraphEdges(store artifact.Store, assessmentID string) []plugin.CallEdge {
	cg, _ := callGraphResult(store, assessmentID)
	return cg.Edges
}

// callGraphResult reads the whole call-graph leg of the reachability artifact, partiality
// included. ok is false when there is no reachability artifact to read it from.
func callGraphResult(store artifact.Store, assessmentID string) (plugin.CallGraphResult, bool) {
	arts, err := store.Query(assessmentID, artifact.TypeReachability)
	if err != nil || len(arts) == 0 {
		return plugin.CallGraphResult{}, false
	}
	var payload struct {
		CallGraph plugin.CallGraphResult `json:"call_graph"`
	}
	if err := json.Unmarshal(arts[0].Payload, &payload); err != nil {
		return plugin.CallGraphResult{}, false
	}
	return payload.CallGraph, true
}

// symbolLeaf extracts the bare function/method name from a self-emitted SCIP id
// (e.g. "scip-go gomod m . pkg/Recv#Method()." → "Method", "…/pkg/fn()." → "fn").
// JS/TS ids disambiguate same-named declarations by arity ("…/fn(2)." — see
// jsanalysis.functionDescriptor), so the trailing parenthesized group is stripped
// whatever it contains, not just the empty-parens Go/Java case.
func symbolLeaf(scip string) string {
	fields := strings.Fields(scip)
	if len(fields) == 0 {
		return ""
	}
	leaf := fields[len(fields)-1]
	if i := strings.LastIndexByte(leaf, '/'); i >= 0 {
		leaf = leaf[i+1:]
	}
	if i := strings.LastIndexByte(leaf, '#'); i >= 0 {
		leaf = leaf[i+1:]
	}
	leaf = strings.TrimSuffix(leaf, ".")
	if strings.HasSuffix(leaf, ")") {
		if i := strings.LastIndexByte(leaf, '('); i >= 0 {
			leaf = leaf[:i]
		}
	}
	return leaf
}

func disqualified(store artifact.Store, assessmentID string) bool {
	d, _ := disqualResult(store, assessmentID)
	return d
}

func hasCandidate(store artifact.Store, assessmentID string) bool {
	_, ok := candidatePath(store, assessmentID)
	return ok
}

// maliciousPresenceResult reads the affirmative TypeMaliciousPresence artifact the maliciousPresence
// Assess stage emits ONLY on a decisive match (a known-malicious package resolved to a listed
// affected version). Absent artifact ⇒ (zero, false): the stage emits nothing for every non-match
// (not malicious / unresolvable / version-not-listed), so absence is the fail-open path (inv.5).
func maliciousPresenceResult(store artifact.Store, assessmentID string) (pipeline.MaliciousPresenceResult, bool) {
	arts, err := store.Query(assessmentID, artifact.TypeMaliciousPresence)
	if err != nil || len(arts) == 0 {
		return pipeline.MaliciousPresenceResult{}, false
	}
	var res pipeline.MaliciousPresenceResult
	if err := json.Unmarshal(arts[0].Payload, &res); err != nil || !res.Present {
		return pipeline.MaliciousPresenceResult{}, false
	}
	return res, true
}

func maliciousPresent(store artifact.Store, assessmentID string) bool {
	_, ok := maliciousPresenceResult(store, assessmentID)
	return ok
}

// maliciousPresentDetail renders the customer-visible basis for a malicious-present finding: the
// exact resolved version that matched the advisory's enumerated malicious set. The presence itself
// is the grounds — no reachability/symbol comparison is run or claimed.
func maliciousPresentDetail(matchedVersion string) string {
	if matchedVersion != "" {
		return fmt.Sprintf("the resolved dependency version %s is listed by the advisory as a known-malicious package release", matchedVersion)
	}
	return "the resolved dependency version is listed by the advisory as a known-malicious package release"
}

// priorityFor attributes the run's signals to one advisory through intel's Attribute join and
// returns each value with its own stamp. It returns nil when the run has no signals, or the join
// attributes no record to the advisory — most synthetic corpus ids have no CVE and so no likelihood
// signal, which is correct.
//
// The join takes the record under the advisory's own id, or — for an advisory not keyed by a CVE —
// the record of a CVE alias that no other advisory in the run's work set (claims) also names, and
// nothing when two such aliases' records disagree. It never
// hands a CVE-keyed advisory a GO/PYSEC/RUSTSEC/GHSA roll-up record through an alias: that record
// may carry a sibling CVE's KEV listing (GO-2023-2102 stands for CVE-2023-39325 AND KEV-listed
// CVE-2023-44487). pipeline's TestKEVAttributionFollowsListedCVE guards the rule.
//
// Ranking context only (inv. 5): it is read by Builder.WithPriority after every verdict is final.
func priorityFor(adv report.Advisory, sig *intel.Signals, claims *intel.Claims) *report.Priority {
	m, ok := sig.Attribute(adv.ID, adv.Aliases, claims)
	if !ok {
		return nil
	}
	var p report.Priority
	if e := m.EPSS; m.HasEPSS {
		p.EPSSScore, p.EPSSAsOf = e.Score, e.AsOf
		p.EPSSPercentile, p.HasPercentile = e.Percentile, e.HasPercentile
	}
	if k := m.KEV; m.HasKEV {
		p.KEVListed, p.KEVDateAdded = k.Listed, k.DateAdded
		p.KEVCatalogVersion, p.KEVDateReleased = k.CatalogVersion, k.DateReleased
	}
	if !p.HasEPSS() && !p.HasKEV() {
		return nil
	}
	return &p
}

// rankWith makes b rank every finding by the run's signals sig (nil for none). The join refuses a
// shared alias against the run's claims, and a run's claims are its work set: every advisory the run
// was asked about, by its id and the aliases its record lists, and every row its report holds, fresh
// or inherited. workSet is what the run was asked about, its records read through src, the fact
// source its assessments read; the rows are read from b itself — Build has no side effects — once
// every finding is added.
//
// So an advisory the run deferred, or assessed into no row, still claims its aliases, and a row ranks
// the same over the same work set on every path that ranks one: the baseline, the PR-inherit fast
// path, the PR re-analysis and the CVE-watch earnest run. pipeline's
// TestKEVAttributionFollowsListedCVE guards the join over the same scope.
func rankWith(b *report.Builder, sig *intel.Signals, workSet []assessment.VulnRef, src pipeline.AdvisorySource) {
	claims := new(intel.Claims)
	if sig != nil {
		ids := make([]string, 0, len(workSet))
		for _, v := range workSet {
			ids = append(ids, v.ID)
		}
		// An id whose record does not resolve still claims itself.
		pipeline.LookupEach(src, ids, func(id string, facts pipeline.AdvisoryFacts, _ bool) {
			claims.Add(id, facts.Aliases...)
		})
		for _, f := range b.Build().Advisories {
			claims.Add(f.Advisory.ID, f.Advisory.Aliases...)
		}
	}
	b.WithPriority(func(adv report.Advisory) *report.Priority { return priorityFor(adv, sig, claims) })
}

// withSignals records, on the provenance p a run is about to hand its Builder, which signals file
// ranked the run's rows: Provenance.Intel.SignalsDigest is sig's Digest, which Load and Parse set only
// after recomputing it from the file's payload. Every run that ranks with a request's Signals passes
// its provenance through here, so a library caller's Report names the file as the CLI's does. With no
// signals p is returned as it came: no Intel block, no digest. Disclosure only (inv. 5): nothing that
// decides a verdict reads it.
func withSignals(p report.Provenance, sig *intel.Signals) report.Provenance {
	if sig == nil || sig.Digest == "" {
		return p
	}
	p.Intel = &report.IntelProvenance{SignalsDigest: sig.Digest}
	return p
}

// reachabilityEvidence derives the structured reachability evidence for a candidate
// from the deterministic discovery artifacts: the strength grade, the ingress at the
// path head, and the ingress→sink call frames. inv. 5: this is evidence strength, not
// a verdict — the strongest grade (attacker_tainted) still means *candidate*, never
// exploitable. attacker_tainted requires BOTH an attacker-controllable ingress AND
// taint path-presence to the sink; anything less is control_flow_only.
func reachabilityEvidence(store artifact.Store, assessmentID string) (report.ReachabilityGrade, *report.EntryPoint, []report.CallFrame) {
	ingresses := ingressMap(store, assessmentID)
	frames, ingressSym := candidateTrace(store, assessmentID)

	// attacker_tainted requires an attacker-controllable ingress to lie ON the
	// ingress→sink path-presence trace (the call path IS the path-presence evidence,
	// at the taint op's own precision — call-graph reachability, not value-level
	// dataflow). If one does, the attacker can drive the path to the sink → the
	// stronger candidate grade. Otherwise the sink is only reachable via internal
	// entries (main/cli) or an unknown ingress → control_flow_only. Either way it
	// stays a candidate (inv. 5): the strong grade is evidence strength, not a proof.
	entry := attackerIngressInTrace(frames, ingresses)
	grade := report.GradeControlFlowOnly
	if entry != nil {
		grade = report.GradeAttackerTainted
	} else {
		entry = entryPointFor(ingressSym, ingresses)
	}
	return grade, entry, frames
}

// attackerIngressInTrace returns the first attacker-controllable ingress (in
// ingress→sink order) whose symbol appears among the call-path frames, or nil if the
// path traverses none. This is what lets a sink reached through an HTTP handler grade
// as attacker-tainted even though the trace's call-graph root is main.
func attackerIngressInTrace(frames []report.CallFrame, ingresses []plugin.Ingress) *report.EntryPoint {
	bySym := make(map[string]plugin.Ingress, len(ingresses))
	for _, in := range ingresses {
		if in.Symbol.SCIP != "" {
			bySym[in.Symbol.SCIP] = in
		}
	}
	for _, fr := range frames {
		if in, ok := bySym[fr.Symbol]; ok && attackerControllableKinds[in.Kind] {
			return entryPointOf(in)
		}
	}
	return nil
}

// entryPointOf maps a plugin ingress onto the neutral report EntryPoint, preferring
// the human-readable route selector over the raw SCIP symbol.
func entryPointOf(in plugin.Ingress) *report.EntryPoint {
	sym := in.Symbol.SCIP
	if in.Selector != "" {
		sym = in.Selector
	}
	return &report.EntryPoint{
		Symbol:               sym,
		Kind:                 in.Kind,
		AttackerControllable: attackerControllableKinds[in.Kind],
	}
}

// attackerControllableKinds are the ingress kinds that can carry untrusted, externally
// supplied input. Internal/dev-only entries (main, cli, test) are not attacker-reachable.
var attackerControllableKinds = map[string]bool{
	"http_route": true, "handler": true, "rpc": true, "grpc": true, "http": true,
	"ssh": true,
}

// ingressMap reads the resolved IngressMap artifact (plugin.IngressResult). It falls
// back to the hermetic stub shape {entrypoint: "..."}, which it treats as a single
// HTTP entry so the stub path still yields a sensible (control-flow-only) candidate.
func ingressMap(store artifact.Store, assessmentID string) []plugin.Ingress {
	arts, err := store.Query(assessmentID, artifact.TypeIngressMap)
	if err != nil || len(arts) == 0 {
		return nil
	}
	var res plugin.IngressResult
	if err := json.Unmarshal(arts[0].Payload, &res); err == nil && len(res.Ingresses) > 0 {
		return res.Ingresses
	}
	var stub struct {
		Entrypoint string `json:"entrypoint"`
	}
	if err := json.Unmarshal(arts[0].Payload, &stub); err == nil && stub.Entrypoint != "" {
		return []plugin.Ingress{{Kind: "http_route", Selector: stub.Entrypoint}}
	}
	return nil
}

// candidateTrace returns the ingress→sink call frames and the ingress symbol for the
// representative candidate path. It prefers the taint artifact's path-presence trace
// (populated for first-party taint flows), then the govulncheck reachability paths.
func candidateTrace(store artifact.Store, assessmentID string) ([]report.CallFrame, string) {
	if p, ok := firstTaintPath(store, assessmentID); ok {
		return framesOf(p.Trace), p.Ingress.SCIP
	}
	if p, ok := firstReachPath(store, assessmentID); ok {
		return framesOf(p.Trace), p.Ingress.SCIP
	}
	return nil, ""
}

func framesOf(trace []plugin.Symbol) []report.CallFrame {
	if len(trace) == 0 {
		return nil
	}
	frames := make([]report.CallFrame, 0, len(trace))
	for _, sym := range trace {
		frames = append(frames, report.CallFrame{Symbol: sym.SCIP})
	}
	return frames
}

// entryPointFor resolves the EntryPoint for a candidate from THIS advisory's reaching
// ingress: it matches the resolved path's ingress symbol against the ingress map (for
// kind + selector). When the path carries no reaching ingress it falls back ONLY to an
// unambiguous single ingress; it never positionally picks among several, which would
// borrow an entry point belonging to a different advisory's sink — the mis-attribution
// inv. 5 forbids (evidence must be advisory-specific). Returns nil (honest unknown
// entry point) rather than fabricate one. The attacker_tainted path in
// reachabilityEvidence resolves the entry from the trace directly, so this fallback runs
// only for a control_flow_only candidate.
func entryPointFor(ingressSym string, ingresses []plugin.Ingress) *report.EntryPoint {
	// 1. The advisory-specific reaching ingress (ReachPath.Ingress for the resolved sink).
	if ingressSym != "" {
		for _, in := range ingresses {
			if in.Symbol.SCIP == ingressSym {
				return entryPointOf(in)
			}
		}
	}
	// 2. No reaching ingress recorded: fall back only when the ingress is UNAMBIGUOUS —
	//    a single attacker-controllable ingress, or a single ingress overall (the stub /
	//    single-route shape). With several ingresses there is no advisory-specific signal,
	//    so declare the entry unknown rather than borrow a positionally-first one.
	var controllable []plugin.Ingress
	for _, in := range ingresses {
		if attackerControllableKinds[in.Kind] {
			controllable = append(controllable, in)
		}
	}
	if len(controllable) == 1 {
		return entryPointOf(controllable[0])
	}
	if len(ingresses) == 1 {
		return entryPointOf(ingresses[0])
	}
	return nil
}

func firstTaintPath(store artifact.Store, assessmentID string) (plugin.ReachPath, bool) {
	arts, err := store.Query(assessmentID, artifact.TypeTaint)
	if err != nil || len(arts) == 0 {
		return plugin.ReachPath{}, false
	}
	var td struct {
		Result plugin.TaintResult `json:"result"`
	}
	if err := json.Unmarshal(arts[0].Payload, &td); err != nil || len(td.Result.Paths) == 0 {
		return plugin.ReachPath{}, false
	}
	return td.Result.Paths[0], true
}

func firstReachPath(store artifact.Store, assessmentID string) (plugin.ReachPath, bool) {
	arts, err := store.Query(assessmentID, artifact.TypeReachability)
	if err != nil || len(arts) == 0 {
		return plugin.ReachPath{}, false
	}
	var payload struct {
		Reachability plugin.ReachabilityResult `json:"reachability"`
	}
	if err := json.Unmarshal(arts[0].Payload, &payload); err != nil || len(payload.Reachability.Paths) == 0 {
		return plugin.ReachPath{}, false
	}
	return payload.Reachability.Paths[0], true
}

// disqualResult reads the disqualification_discovery artifact (TypeDiscovery).
func disqualResult(store artifact.Store, assessmentID string) (disqualified bool, reason string) {
	arts, err := store.Query(assessmentID, artifact.TypeDiscovery)
	if err != nil || len(arts) == 0 {
		return false, ""
	}
	var res pipeline.DisqualResult
	if err := json.Unmarshal(arts[0].Payload, &res); err != nil {
		return false, ""
	}
	return res.Disqualified, res.Reason
}

// disqualBasis records the refutation grounds a disqualification stands on. Only the version and
// symbol axes are grounded refutations: an adjudicated comparison ran against the subject and
// cleared it. The intake codes (advisory ecosystem mismatch, no manifest entry) record that the
// advisory is not adjudicable against this subject at all — no comparison ran, so there are no
// grounds to state, and the honest Basis is none. That is already how this Report says it:
// report.go:94 requires an empty Basis wherever there are no refutation grounds to state, and
// Validate enforces it for the candidate and undetermined verdicts.
//
// An unrecognized reason code lands on none for the same reason, and a stronger one: an axis this
// function cannot name has no standing to claim grounds it cannot describe.
func disqualBasis(reason string) verdict.NonExploitableBasis {
	switch reason {
	case pipeline.ReasonVersionNotInRange:
		return verdict.BasisVersionNotAffected
	case pipeline.ReasonSymbolAbsent:
		return verdict.BasisSymbolAbsent
	default:
		return verdict.BasisNone
	}
}

// disqualDetail renders the customer-visible grounds for a disqualification. Each reason code
// gets its own arm: the version and symbol axes record an adjudicated comparison that cleared
// the subject, while the intake codes (pipeline stages.go) record that no such comparison was
// ever run — the advisory is not adjudicable against this subject at all. Collapsing the two
// kinds onto one string is the conflation README.md "What it reports" promises the tool does
// not perform, so the default arm claims nothing about a comparison it cannot name.
func disqualDetail(reason string) string {
	switch reason {
	case pipeline.ReasonVersionNotInRange:
		return "resolved dependency version is outside the advisory's affected range"
	case pipeline.ReasonSymbolAbsent:
		return "the vulnerable symbol is absent from the built artifact"
	case pipeline.ReasonAdvisoryEcosystemMismatch:
		return "the advisory targets a different ecosystem than this codebase; no version or symbol comparison was performed"
	case pipeline.ReasonNoManifestEntry:
		return "the advisory's package is not installed by the build: its dependency manifest or build graph has no entry for it; no version or symbol comparison was performed"
	default:
		return "disqualified on an axis that is neither a version nor a symbol comparison; neither comparison was performed"
	}
}

// candidatePath reports whether the reachability_ingress stage recorded at least one
// candidate (ingress→sink) pair, and returns a compact path string for the Report.
func candidatePath(store artifact.Store, assessmentID string) (string, bool) {
	arts, err := store.Query(assessmentID, artifact.TypeCandidatePair)
	if err != nil || len(arts) == 0 {
		return "", false
	}
	var pair artifact.CandidatePair
	if err := json.Unmarshal(arts[0].Payload, &pair); err != nil {
		return "", false
	}
	if pair.Ingress != nil {
		return "entrypoint → advisory symbol", true
	}
	return "advisory symbol reachable", true
}

// advisoryFromArtifacts reads the normalized-advisory artifact and returns the
// report.Advisory identity plus the resolved SBOM package the scan evaluated. When
// the codebase resolved a version it is attached; a C/C++ advisory instead carries its
// inventory observation (cfamilyObservedPackage); otherwise the package is nil. sbom is
// the scan's report SBOM, read only for the C/C++ observation.
func advisoryFromArtifacts(store artifact.Store, assessmentID string, req assessment.Request, sbom []report.Package) (report.Advisory, *report.Package) {
	adv := report.Advisory{ID: req.Vulnerability.ID, Source: req.Vulnerability.Source}

	arts, err := store.Query(assessmentID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return adv, nil
	}
	var raw struct {
		Aliases []string `json:"aliases"`
	}
	if err := json.Unmarshal(arts[0].Payload, &raw); err != nil {
		return adv, nil
	}
	adv.Aliases = raw.Aliases

	name, purl := pipeline.AdvisoryPackage(store, assessmentID)
	inv, ok := inventory(store, assessmentID)
	if !ok || name == "" {
		return adv, nil
	}
	if inv.ResolvedVersion == "" {
		if inv.Language == cfamilyLanguage {
			return adv, cfamilyObservedPackage(name, purl, inv, sbom)
		}
		// Copies at more than one version: the row names the package but no single version, so
		// an inventory limit of its ecosystem still reaches it (withInventoryLimits).
		if len(inv.ResolvedVersions) > 0 && !pipeline.ToolchainSubject(store, assessmentID) {
			return adv, &report.Package{Ecosystem: ecosystemFor(inv.Language), Name: name, PURL: purl, Root: pipeline.RootSubject(store, assessmentID)}
		}
		return adv, nil
	}
	// The Go toolchain is not an SBOM dependency package. When the adjudicated element is the
	// toolchain, resolved_version is a go1.x.y toolchain release (M3) while the package name is the
	// advisory's top-level MODULE — pairing them would emit an SBOM entry like
	// golang.org/x/net@go1.21.0, a coordinate that does not exist.
	if pipeline.ToolchainSubject(store, assessmentID) {
		return adv, nil
	}
	return adv, &report.Package{
		Ecosystem: ecosystemFor(inv.Language),
		Name:      name,
		Version:   inv.ResolvedVersion,
		PURL:      purl,
		Root:      pipeline.RootSubject(store, assessmentID),
	}
}

const cfamilyLanguage = "cfamily"

// cfamilyObservedPackage names the package a C/C++ advisory was evaluated against. The C/C++
// lane never resolves a version, so the row would otherwise carry no package at all. The
// package takes the found-but-unresolved shape the SBOM already uses: Version is the
// inventory's pin, set only when the SBOM holds exactly one for the name and the assessment
// declared it source_unpinned, and PartialReason carries that declaration. G1
// (admittedPackage) rejects the shape, and the version is read from the report SBOM, never
// from the assessment's resolved_version, so the pin feeds no version axis.
func cfamilyObservedPackage(name, purl string, inv inventoryFacts, sbom []report.Package) *report.Package {
	ecosystem := ecosystemFor(inv.Language)
	pkg := &report.Package{Ecosystem: ecosystem, Name: name, PURL: purl}
	for _, f := range inv.PartialityFlags {
		if strings.HasPrefix(f, plugin.PartialReasonSourceUnpinned) {
			pkg.PartialReason = f
			break
		}
	}
	if pkg.PartialReason == "" {
		if len(inv.PartialityFlags) > 0 {
			pkg.PartialReason = inv.PartialityFlags[0]
		}
		return pkg
	}
	pins := make(map[string]struct{})
	for _, p := range sbom {
		if p.Ecosystem == ecosystem && p.Name == name && p.Version != "" {
			pins[p.Version] = struct{}{}
		}
	}
	if len(pins) == 1 {
		for v := range pins {
			pkg.Version = v
		}
	}
	return pkg
}

type inventoryFacts struct {
	Language         string   `json:"language"`
	ResolvedVersion  string   `json:"resolved_version"`
	ResolvedVersions []string `json:"resolved_versions"`
	PartialityFlags  []string `json:"partiality_flags"`
}

// undeterminedReason decides whether this assessment established NOTHING about the advisory —
// in which case the honest emission is report.VerdictUndetermined rather than a refutation —
// and returns the machine-readable reason.
//
// It is called from ONE place: finding()'s default arm. That placement is load-bearing and
// replaces two clauses this predicate used to carry itself. A disqualified advisory is
// reported (M3's version axis DERIVED the not-affected — a stronger claim than the one being
// withdrawn, so eating it would discard the fix), and a reachable candidate is reported
// (declaring a positive finding undetermined would be a far worse failure than the one this
// closes). Both are earlier arms of that switch, so control flow enforces them rather than a
// duplicated condition that could drift out of step with it.
//
// Two axes decide it, in order of how specifically they can name the missing fact:
//
//   - toolchainUndetermined, the Go toolchain/stdlib case (the subject's toolchain was not
//     resolved exactly, or reachability did not run under it), which names WHICH fact
//     was missing and is therefore tried first.
//   - analysisDidNotRun, the general case for every ecosystem: whether any step this refutation
//     would have to rest on declared that it did not run.
//
// Either one firing means the same thing — the empty path set is a fact about the analysis, not
// about the subject — and `undetermined` is what v2 added to say so out loud instead of
// withholding the row (which v1 had to do, having no cell for it).
func undeterminedReason(store artifact.Store, assessmentID string, pkg *report.Package) (string, bool) {
	if reason, ok := toolchainUndetermined(store, assessmentID); ok {
		return reason, true
	}
	// The same rule, stated without reference to Go. Reaching finding()'s default arm means no
	// path was found; that absence REFUTES only if the steps which would have found one actually
	// ran. A did-not-run limit on this assessment says they did not — the analyzer resolved no
	// dependency version, or resolved no symbol, or had no manifest to read — so
	// a not_exploitable basis would be a refutation asserted on evidence that does not exist.
	//
	// It is derived from the basis THIS assessment recorded (report.ClassifyPartialityReason over
	// the limits the run declared), never from the language and never from a per-language table.
	// An analyzer that starts resolving versions and symbols stops declaring those limits, and
	// unlocks its own refutations here with nothing in this file to edit.
	return analysisDidNotRun(store, assessmentID, pkg)
}

// analysisDidNotRun reports whether a step this refutation would have to rest on did not happen on
// THIS assessment. Two independent signals decide it, and neither reads the language:
//
//   - A declared limit of the DID-NOT-RUN class. report.ClassifyPartialityReason draws the line
//     between a step that did not happen on this run and a limit of the method that holds on every
//     scan of every codebase, and it leans unknown codes to did-not-run — so a limit this build
//     cannot name suppresses a refutation rather than passing one through. The reason set is the
//     SAME one partialityNotes publishes at scan scope (the exposure footprint's union over every
//     axis, falling back to the inventory's own flags when no footprint artifact exists), so a row
//     and the scan-level disclosure can never disagree about what the run did.
//
//   - An empty call graph the analyzer DECLINED TO CALL COMPLETE. A refutation by absence of a
//     path needs a path structure to have been built and searched, and a graph that is both empty
//     and self-declared partial is not a search that came back empty — it is a search that did not
//     happen. Both halves are load-bearing: an analyzer that reports a COMPLETE graph with no edges
//     has answered (an empty program has no edges), and a partial graph with edges in it has
//     searched, however incompletely. This is the arm that catches an analyzer which reads a
//     manifest and resolves a version but never opens the dependency's code, so every axis it did
//     run can report itself complete while nothing was ever searched for the symbol.
//
// A scoped limit (plugin.ScopedReason) joins the run-wide reasons only when it counts for this
// advisory's package (scopedLimitCounts).
//
// The reason is analysis_did_not_run, except when the only did-not-run limit is the analyzer
// declaring it does not know the advisory: that is the more precise statement of the same fact.
func analysisDidNotRun(store artifact.Store, assessmentID string, pkg *report.Package) (string, bool) {
	if emptyGraphUncalledComplete(store, assessmentID) {
		return report.ReasonAnalysisDidNotRun, true
	}
	reasons := didNotRunReasons(store, assessmentID, pkg)
	switch {
	case len(reasons) == 0:
		return "", false
	case !slices.ContainsFunc(reasons, func(r string) bool { return r != plugin.PartialReasonAdvisoryUnknownToAnalyzer }):
		return report.ReasonAdvisoryUnknownToAnalyzer, true
	}
	return report.ReasonAnalysisDidNotRun, true
}

// emptyGraphUncalledComplete reports whether the call graph is empty and the analyzer declined to
// call it complete: a search that did not happen (see analysisDidNotRun).
func emptyGraphUncalledComplete(store artifact.Store, assessmentID string) bool {
	cg, ok := callGraphResult(store, assessmentID)
	return ok && len(cg.Edges) == 0 && !cg.Partiality.Complete
}

// didNotRunReasons returns the did-not-run limits analysisDidNotRun weighs for this assessment, in
// the order they were declared.
func didNotRunReasons(store artifact.Store, assessmentID string, pkg *report.Package) []string {
	reasons := footprintPartialityFlags(store, assessmentID)
	if len(reasons) == 0 {
		if inv, ok := inventory(store, assessmentID); ok {
			reasons = inv.PartialityFlags
		}
	}
	if scoped := footprintScoped(store, assessmentID); len(scoped) > 0 {
		admitted, _, resolved := admittedPackage(store, assessmentID, pkg)
		for _, r := range scoped {
			if scopedLimitCounts(r, admitted, resolved, pkg != nil && pkg.Root) {
				reasons = append(reasons, r.Reason)
			}
		}
	}
	// A symbol the build's target of the package does not define was searched for and is not there.
	absent := false
	if res, err := pipeline.VulnerableSymbols(store, assessmentID); err == nil {
		absent = len(targetConditionalAbsent(pipeline.AdvisorySymbols(store, assessmentID), pipeline.AdvisoryTargetConditionalSymbols(store, assessmentID), res)) > 0
	}
	var out []string
	for _, reason := range reasons {
		if absent && reason == plugin.PartialReasonAdvisorySymbolUnresolved {
			continue
		}
		if report.ClassifyPartialityReason(reason) == report.PartialityDidNotRun {
			out = append(out, reason)
		}
	}
	return out
}

// outsideBuildExempt holds the did-not-run limits that cannot undermine outsideBuildGrounds. Those
// grounds are not a search for a path: they rest on the build's module list (`go mod graph`, see
// goModulesOf) and on reading every .go file of every listed module (the Go lane's ModuleSearch,
// the only producer of one). A limit of the call-graph search leaves both intact. Any limit not
// listed here, a future one included, blocks the grounds.
var outsideBuildExempt = map[string]bool{
	// govulncheck's silence about a module outside the graph it loads; the module search does not
	// consult govulncheck.
	plugin.PartialReasonAdvisoryUnknownToAnalyzer: true,
	// A reflective call runs only code compiled into the build, which comes from a listed module.
	plugin.PartialReasonReflectiveCall: true,
	// The module graph does not depend on GOOS, GOARCH or build tags, and the module search reads
	// every .go file whatever its build constraints.
	plugin.PartialReasonExcludedFiles: true,
}

// outsideBuildBlocked reports whether a step outsideBuildGrounds rests on may not have run: the
// Go toolchain axis is undetermined, the call graph is empty and not called complete, or a
// did-not-run limit outside outsideBuildExempt was declared.
func outsideBuildBlocked(store artifact.Store, assessmentID string, pkg *report.Package) bool {
	if _, ok := toolchainUndetermined(store, assessmentID); ok || emptyGraphUncalledComplete(store, assessmentID) {
		return true
	}
	return slices.ContainsFunc(didNotRunReasons(store, assessmentID, pkg), func(r string) bool { return !outsideBuildExempt[r] })
}

// scopedLimitCounts reports whether a scoped limit counts against an advisory admitted on the given
// package: it does unless its Targets are bounded and neither its Package nor any Target could be that
// package. An unbounded limit (no Targets, nil or empty, since JSON drops an empty list), or an
// advisory whose package did not resolve, always counts.
//
// Every entry fails wide:
//
//   - An entry that is not a package URL counts, so a producer's malformed scope cannot narrow it.
//     The one non-PURL value allowed is "", the first-party code.
//   - Go names match when either path is the other or under it, so a package path inside the
//     admitted module counts, and so does a module path holding an admitted package path.
//
// The standard library is matched like any other package: a limit whose hidden code can call into
// it names it among its Targets, as the Targets contract requires of every package a hidden edge
// could reach. The first-party entry matches only when the advisory's package is the scanned
// project itself.
func scopedLimitCounts(r artifact.ScopedPartialityFlag, admitted pkgKey, resolved, root bool) bool {
	if len(r.Targets) == 0 || !resolved {
		return true
	}
	for _, p := range append([]string{r.Package}, r.Targets...) {
		if p == "" {
			if root {
				return true
			}
			continue
		}
		key, ok := purlKey(p)
		switch {
		case !ok, key == admitted:
			return true
		case key.typ == "golang" && admitted.typ == "golang":
			if goPathWithin(key.name, admitted.name) || goPathWithin(admitted.name, key.name) {
				return true
			}
		}
	}
	return false
}

// goPathWithin reports whether the Go import path p is root or lies under it, ignoring case so that
// two spellings of one module path fail wide.
func goPathWithin(p, root string) bool {
	p, root = strings.ToLower(p), strings.ToLower(root)
	return p == root || strings.HasPrefix(p, root+"/")
}

// toolchainUndetermined is the Go toolchain/stdlib arm of undeterminedReason. Two clauses:
//
//   - The advisory's assessed subject must be the Go toolchain/stdlib (pipeline.ToolchainSubject).
//     A multi-package advisory adjudicated against a module the codebase actually requires is a
//     module case with a genuinely resolved version and is reported normally.
//   - The subject's toolchain must NOT have been scanned (M4). This is the clause that LIFTS the
//     undetermined verdict rather than adding to it: once the analysis has actually run under an
//     exact subject toolchain, the empty path set IS evidence about the subject, and
//     not_exploitable/vulnerable_symbol_unreachable becomes the established claim it always purported
//     to be.
//
// What is left is the empty path set govulncheck produced against the ANALYZER's Go rather than
// the subject's.
func toolchainUndetermined(store artifact.Store, assessmentID string) (string, bool) {
	if !pipeline.ToolchainSubject(store, assessmentID) {
		return "", false
	}
	fact, ok := pipeline.Toolchain(store, assessmentID)
	if !ok || fact.Bound == pipeline.ToolchainBoundNone {
		// Nothing was established on either axis. The weaker code, because there is no fact at all
		// to have scanned against.
		return report.ReasonGoToolchainUnresolved, true
	}
	// M4: the undetermined verdict LIFTS here and only here.
	//
	// Both clauses are stated even though the second implies the first (the stage only requests a
	// toolchain on an exact bound), because this predicate is the inv.5 boundary and has to be
	// readable on its own: the bound licenses the refutation, the scan supplies it.
	if fact.Bound == pipeline.ToolchainBoundExact && pipeline.SubjectToolchainScanned(store, assessmentID) {
		return "", false
	}
	// Everything else is a scan under the ANALYZER's toolchain: the flag is off, the fact is a floor
	// (a floor licenses a disqualification by monotonicity, never a refutation by absence — inv.5),
	// or the subject's toolchain was requested and could not be run. An exact fact narrows the
	// version axis without making the empty path set evidence about the subject.
	return report.ReasonGoToolchainNotScanned, true
}

// toolchainLimitNote is the scan-level disclosure that accompanies an undetermined row: the row
// says WHICH advisory got no verdict, the note says what the limit was and which ecosystem it
// scoped. They name one fact at two scopes and carry the same reason code.
//
// It names no advisory ids. In v1 the note's Advisories list was the ONLY thing that kept a
// suppressed advisory nameable; in v2 the row carries the id, and repeating it here would make
// every renderer count the same advisory twice.
//
// Under M4 both reason codes mean "on THIS run": the analysis environment decides them, so two
// scans of the same commit can legitimately differ. Nothing here may imply permanence.
func toolchainLimitNote(reason string) report.PartialityNote {
	return report.PartialityNote{
		Reason: reason,
		// Scoped from the ADVISORY, not the inventory's detected language: this limit is about the
		// Go toolchain by construction (both reason codes name it), and a scan whose language went
		// undetected would otherwise emit a go_toolchain_* limit scoped to no ecosystem at all.
		Ecosystem: ecosystemFor("go"),
	}
}

// limitNoteFor returns the scan-level disclosure a freshly-built finding owes, and whether it
// owes one. Keeping it beside the row's construction is what stops the two from drifting: every
// run mode adds the finding and then asks this, so a surface can never show a row with no limit
// or a limit with no row.
// An analysis_did_not_run or advisory_unknown_to_analyzer row owes NO note of its own. That row stands on limits partialityNotes
// already publishes at scan scope, each named precisely (unsupported_phase1, no_manifest, …) and
// each scoped to the ecosystem the run actually detected. Synthesizing a second note here would
// disclose one fact twice and scope the copy to Go.
//
// The positive-grounds reasons (notExploitableGrounds) are scoped to the finding's own package
// ecosystem: they are about that package's admission and symbols, not the Go toolchain.
func limitNoteFor(f report.AdvisoryFinding) (report.PartialityNote, bool) {
	switch {
	case f.Verdict != report.VerdictUndetermined,
		f.UndeterminedReason == report.ReasonAnalysisDidNotRun,
		f.UndeterminedReason == report.ReasonAdvisoryUnknownToAnalyzer:
		return report.PartialityNote{}, false
	}
	switch f.UndeterminedReason {
	case report.ReasonPackageVersionUnresolved, report.ReasonAdvisorySymbolAbsent, report.ReasonVulnerableSymbolUnresolved,
		report.ReasonAdvisorySymbolsUnvetted, report.ReasonAdvisoryRangeAbsent:
		note := report.PartialityNote{Reason: f.UndeterminedReason}
		if f.Package != nil {
			note.Ecosystem = f.Package.Ecosystem
		}
		return note, true
	}
	return toolchainLimitNote(f.UndeterminedReason), true
}

// partialityNotes maps one assessment's partiality onto the scan-level Report
// disclosures. An assessment that could not pin an installed version leaves
// ResolvedVersion empty, which on its own is indistinguishable from "this codebase
// does not use that dependency" — the note is what keeps the two apart at the
// customer surface. Disclosure only: it touches no verdict.
//
// The reasons are read off the EXPOSURE FOOTPRINT, not the inventory artifact. The
// footprint stage (pipeline.exposureFootprintStage) is the single place that unions
// all four partiality axes — S2 dependency-version resolution, S4 ingress discovery,
// S5 vulnerable-symbol resolution and S6 reachability. Reading the inventory artifact
// alone, as this did before, harvested the S2 axis and silently dropped the other
// three: an assessment whose ingress could not be resolved reported no limit at all
// and rendered as a clean not_exploitable. The inventory is still read, but only for
// the language tag that scopes each note to an ecosystem.
func partialityNotes(store artifact.Store, assessmentID string) []report.PartialityNote {
	// A disqualified advisory is settled on the version axis alone: the resolved version
	// is provably outside the affected range, and that comparison is conclusive (an
	// UNRESOLVED version can never disqualify — the axis fails open, inv.5). The analysis
	// steps below it ran anyway, and their limits say nothing about a verdict that did not
	// depend on them. Surfacing those limits would qualify a scan whose findings are all
	// cleanly disqualified, and a disclosure that appears on nearly every run stops
	// carrying any signal at all.
	if disqualified(store, assessmentID) {
		return nil
	}
	reasons := footprintPartialityFlags(store, assessmentID)
	scoped := footprintScoped(store, assessmentID)
	inv, haveInv := inventory(store, assessmentID)
	if len(reasons) == 0 && haveInv {
		// No footprint artifact (a run that failed before S4, or a stage set that omits
		// the footprint) — fall back to the inventory's own flags so the S2 axis is never
		// lost when the union is unavailable.
		reasons = inv.PartialityFlags
	}
	if len(reasons) == 0 && len(scoped) == 0 {
		return nil
	}
	ecosystem := ""
	if haveInv {
		ecosystem = ecosystemFor(inv.Language)
	}
	notes := make([]report.PartialityNote, 0, len(reasons)+len(scoped))
	for _, reason := range reasons {
		notes = append(notes, report.PartialityNote{
			Reason:    reason,
			Ecosystem: ecosystem,
		})
	}
	// A scoped limit is disclosed whether or not it counted against any advisory: it is still a
	// part of the program the analysis could not see.
	for _, r := range scoped {
		notes = append(notes, report.PartialityNote{
			Reason:    r.Reason,
			Ecosystem: ecosystem,
			Package:   r.Package,
			Path:      r.Path,
		})
	}
	return notes
}

// footprintPartialityFlags reads the unioned partiality reason codes off the
// assessment's exposure-footprint artifact. Absent artifact or unreadable payload
// yields no reasons; the caller falls back to the inventory artifact.
func footprintPartialityFlags(store artifact.Store, assessmentID string) []string {
	fp, _ := exposureFootprint(store, assessmentID)
	return fp.PartialityFlags
}

// footprintScoped reads the unioned scoped limits off the exposure-footprint artifact.
func footprintScoped(store artifact.Store, assessmentID string) []artifact.ScopedPartialityFlag {
	fp, _ := exposureFootprint(store, assessmentID)
	return fp.ScopedPartiality
}

func exposureFootprint(store artifact.Store, assessmentID string) (artifact.ExposureFootprintPayload, bool) {
	var fp artifact.ExposureFootprintPayload
	arts, err := store.Query(assessmentID, artifact.TypeExposureFootprint)
	if err != nil || len(arts) == 0 {
		return fp, false
	}
	if err := json.Unmarshal(arts[0].Payload, &fp); err != nil {
		return artifact.ExposureFootprintPayload{}, false
	}
	return fp, true
}

// assessFailureNote turns a failed assessment into a scan-level disclosure. One
// advisory whose analysis did not run must not discard the whole Report — that is the
// "failed scan renders as no results" conflation. The advisory's row is
// assessFailureFinding; this note names the step that failed at the scan level.
func assessFailureNote(adv assessment.VulnRef, err error) report.PartialityNote {
	return report.PartialityNote{
		Reason: plugin.PartialReasonToolFailure,
		Detail: fmt.Sprintf("%s (%s)", failedStep(err), adv.ID),
	}
}

// assessFailureFinding is the row for an advisory whose assessment failed. Without it the
// advisory is absent from the rows, and a reader of rows (console, SARIF, carry-forward) sees
// no verdict where it should see that none was established.
//
// The row carries no Package: the failed assessment resolved none, and pairing the advisory
// with a guessed coordinate would be a fabricated fact.
func assessFailureFinding(adv assessment.VulnRef, err error) report.AdvisoryFinding {
	return report.AdvisoryFinding{
		Advisory:           report.Advisory{ID: adv.ID, Source: adv.Source},
		Verdict:            report.VerdictUndetermined,
		UndeterminedReason: report.ReasonAnalysisDidNotRun,
		Evidence: report.EvidenceSummary{
			Detail: fmt.Sprintf("the %s step failed (%s), so no verdict was established", failedStep(err), assessErrorText(stageCause(err))),
		},
	}
}

func failedStep(err error) string {
	var se *pipeline.StageError
	if errors.As(err, &se) && se.Stage != "" {
		return se.Stage
	}
	return "assess"
}

// stageCause is the error a failed stage returned, without the wrapping that repeats the
// advisory and stage the row already names.
func stageCause(err error) error {
	var se *pipeline.StageError
	if errors.As(err, &se) && se.Err != nil {
		return se.Err
	}
	return err
}

// assessErrorLimit bounds the error text a failed-assessment row carries, in runes.
const assessErrorLimit = 200

// secretREs match the credentials a tool error can echo, each with what replaces them: the
// userinfo of a URL (with or without a scheme, up to the authority's last '@', since a password
// may hold one), a user:password@host without one (a proxy setting), query-string values, an
// Authorization header, a bearer token and a GitLab PRIVATE-TOKEN header; a token= or npm
// _authToken= setting outside a query string; a .netrc entry's password; and a bare GitHub, GitLab
// or npm token, by its prefix and a body of a token's length (the prefix is kept). A Go
// module@version has no ':' before its '@', so it is kept; a word that only contains "token" or
// "password" (tokenizer, password-reset) has no value to redact, so it is kept.
var secretREs = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`((?:[A-Za-z][A-Za-z0-9+.-]*:)?//)[^/\s]*@`), "${1}REDACTED@"},
	{regexp.MustCompile(`[^\s/:@]+:[^\s/]*@`), "REDACTED@"},
	{regexp.MustCompile(`([?&][^\s?&#=]+=)[^\s&#]*`), "${1}REDACTED"},
	{regexp.MustCompile(`(?i)\b((?:proxy-)?authorization)\s*[:=]\s*(?:(?:bearer|basic|token|digest)\s+)?[^\s,;]+`), "${1}: REDACTED"},
	{regexp.MustCompile(`(?i)\b(bearer)\s+[^\s,;]+`), "${1} REDACTED"},
	{regexp.MustCompile(`(?i)\b(private-token)\s*[:=]\s*[^\s,;]+`), "${1}: REDACTED"},
	{regexp.MustCompile(`(?i)(_authToken)\s*=\s*[^\s,;]+`), "${1}=REDACTED"},
	{regexp.MustCompile(`(?i)\b([A-Za-z0-9_-]*token)=[^\s&#,;]+`), "${1}=REDACTED"},
	{regexp.MustCompile(`(?i)\b((?:machine\s+\S+(?:\s+(?:login|account)\s+\S+)*|default(?:\s+(?:login|account)\s+\S+)+)\s+password)\s+\S+`), "${1} REDACTED"},
	{regexp.MustCompile(`\b(gh[pousr]_)[A-Za-z0-9]{36,}`), "${1}REDACTED"},
	{regexp.MustCompile(`\b(github_pat_)[A-Za-z0-9_]{22,}`), "${1}REDACTED"},
	{regexp.MustCompile(`\b(glpat-)[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]+)*`), "${1}REDACTED"},
	{regexp.MustCompile(`\b(npm_)[A-Za-z0-9]{36,}`), "${1}REDACTED"},
}

// assessErrorText renders err for a report row: one line, credentials redacted, at most
// assessErrorLimit runes.
func assessErrorText(err error) string {
	s := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, err.Error())
	s = strings.Join(strings.Fields(s), " ")
	for _, r := range secretREs {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	if r := []rune(s); len(r) > assessErrorLimit {
		s = string(r[:assessErrorLimit-1]) + "…"
	}
	return s
}

func inventory(store artifact.Store, assessmentID string) (inventoryFacts, bool) {
	arts, err := store.Query(assessmentID, artifact.TypeInventory)
	if err != nil || len(arts) == 0 {
		return inventoryFacts{}, false
	}
	var inv inventoryFacts
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		return inventoryFacts{}, false
	}
	return inv, true
}

// ecosystemFor maps a pipeline language tag onto the OSV.dev / PURL ecosystem name
// the SBOM Package carries (so CVE-watch querybatch keys correctly).
func ecosystemFor(language string) string {
	switch language {
	case "go":
		return "Go"
	case "java":
		return "Maven"
	case "kotlin":
		return "Maven" // Kotlin/JVM artifacts are Maven-keyed in OSV regardless of source language (A2).
	case "javascript", "js":
		return "npm"
	case "python", "py":
		return "PyPI"
	case "dotnet":
		return "NuGet"
	default:
		return language
	}
}

// advisoryBounds carries the partial bounds of a range-absent advisory onto its finding.
func advisoryBounds(store artifact.Store, caseID string) []report.AdvisoryBound {
	var out []report.AdvisoryBound
	for _, b := range pipeline.AdvisoryRecordedBounds(store, caseID) {
		out = append(out, report.AdvisoryBound{Type: b.Type, Introduced: b.Introduced, Fixed: b.Fixed, LastAffected: b.LastAffected})
	}
	return out
}
