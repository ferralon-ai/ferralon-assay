package trigger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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
//   - a candidate (ingress→sink) reach path    → VerdictReachableCandidate.
//   - neither, and the empty path set is not evidence about the subject (see
//     undeterminedReason)                      → VerdictUndetermined, no basis.
//   - otherwise (no disqualification, no reach) → VerdictNotExploitable, basis
//     symbol-absent (the vulnerable symbol/path was not found).
//
// The OSS tool stops at reachable_candidate; it never emits exploitable/reasoned_*.
func finding(store artifact.Store, assessmentID string, adv report.Advisory, pkg *report.Package) report.AdvisoryFinding {
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
		f = report.AdvisoryFinding{
			Advisory: adv,
			Package:  pkg,
			Verdict:  report.VerdictReachableCandidate,
			Evidence: report.EvidenceSummary{
				ReachablePath:    path,
				Grade:            grade,
				EntryPoint:       entry,
				CallPath:         frames,
				MitigatingGuards: guardsOnPath(store, assessmentID, frames),
			},
		}
	default:
		// This arm is the one that shipped the defect ADR 0014 records, and the only one
		// that can rest on an absence. Reaching it means the axes established nothing
		// POSITIVE: no disqualification and no path. Whether the absent path is evidence
		// about the SUBJECT is a separate question, and undeterminedReason answers it.
		reason, undetermined := undeterminedReason(store, assessmentID)
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
				Basis:  verdict.BasisSymbolAbsent,
				Detail: "no reachable path to the advisory symbol was found",
			},
		}
	}
	// Attach offline EPSS/KEV likelihood context (package intel) to every finding by
	// the advisory's CVE id/aliases. It only ranks attention; it NEVER changes the
	// deterministic verdict (inv. 5) — a disqualified high-EPSS CVE stays disqualified.
	f.Priority = priorityFor(adv)
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

// priorityFor looks the advisory up in the pinned EPSS/KEV snapshot by its id and
// aliases (EPSS/KEV are CVE-keyed; a GO-/GHSA-keyed advisory matches via its CVE
// alias). Returns nil when neither feed has a record — most synthetic corpus ids
// have no CVE, so they carry no likelihood signal, which is correct.
func priorityFor(adv report.Advisory) *report.Priority {
	ids := append([]string{adv.ID}, adv.Aliases...)
	p := &report.Priority{}
	matched := false
	if s, ok := intel.EPSS(ids...); ok {
		p.EPSSScore, p.EPSSPercentile = s.Score, s.Percentile
		matched = true
	}
	if k, ok := intel.KEV(ids...); ok {
		p.KEVListed, p.KEVDateAdded = true, k.DateAdded
		matched = true
	}
	if !matched {
		return nil
	}
	p.Snapshot = intel.SnapshotDate
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
		return "the advisory's package is absent from this codebase's dependency manifest; no version or symbol comparison was performed"
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
// the codebase resolved a version it is attached; otherwise the package is nil.
func advisoryFromArtifacts(store artifact.Store, assessmentID string, req assessment.Request) (report.Advisory, *report.Package) {
	adv := report.Advisory{ID: req.Vulnerability.ID, Source: req.Vulnerability.Source}

	arts, err := store.Query(assessmentID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return adv, nil
	}
	var raw struct {
		Module  string   `json:"module"`
		PURL    string   `json:"purl"`
		Aliases []string `json:"aliases"`
	}
	if err := json.Unmarshal(arts[0].Payload, &raw); err != nil {
		return adv, nil
	}
	adv.Aliases = raw.Aliases

	inv, ok := inventory(store, assessmentID)
	if !ok || raw.Module == "" || inv.ResolvedVersion == "" {
		return adv, nil
	}
	// The Go toolchain is not an SBOM dependency package. When the adjudicated element is the
	// toolchain, resolved_version is a go1.x.y toolchain release (M3) while raw.Module is the
	// advisory's top-level MODULE — pairing them would emit an SBOM entry like
	// golang.org/x/net@go1.21.0, a coordinate that does not exist.
	if pipeline.ToolchainSubject(store, assessmentID) {
		return adv, nil
	}
	return adv, &report.Package{
		Ecosystem: ecosystemFor(inv.Language),
		Name:      raw.Module,
		Version:   inv.ResolvedVersion,
		PURL:      raw.PURL,
	}
}

type inventoryFacts struct {
	Language        string   `json:"language"`
	ResolvedVersion string   `json:"resolved_version"`
	PartialityFlags []string `json:"partiality_flags"`
}

// undeterminedReason decides whether this assessment established NOTHING about the advisory —
// in which case the honest emission is report.VerdictUndetermined rather than a refutation —
// and returns the machine-readable reason (ADR 0014 §3.3).
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
//   - toolchainUndetermined, the Go toolchain/stdlib case (ADR 0014 M4), which names WHICH fact
//     was missing and is therefore tried first.
//   - analysisDidNotRun, the general case for every ecosystem: whether any step this refutation
//     would have to rest on declared that it did not run.
//
// Either one firing means the same thing — the empty path set is a fact about the analysis, not
// about the subject — and `undetermined` is what v2 added to say so out loud instead of
// withholding the row (which v1 had to do, having no cell for it).
func undeterminedReason(store artifact.Store, assessmentID string) (string, bool) {
	if reason, ok := toolchainUndetermined(store, assessmentID); ok {
		return reason, true
	}
	// The same rule, stated without reference to Go. Reaching finding()'s default arm means no
	// path was found; that absence REFUTES only if the steps which would have found one actually
	// ran. A did-not-run limit on this assessment says they did not — the analyzer resolved no
	// dependency version, or resolved no symbol, or had no manifest to read — so
	// `vulnerable_symbol_absent` would be a refutation asserted on evidence that does not exist.
	//
	// It is derived from the basis THIS assessment recorded (report.ClassifyPartialityReason over
	// the limits the run declared), never from the language and never from a per-language table.
	// An analyzer that starts resolving versions and symbols stops declaring those limits, and
	// unlocks its own refutations here with nothing in this file to edit.
	if analysisDidNotRun(store, assessmentID) {
		return report.ReasonAnalysisDidNotRun, true
	}
	return "", false
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
func analysisDidNotRun(store artifact.Store, assessmentID string) bool {
	if cg, ok := callGraphResult(store, assessmentID); ok && len(cg.Edges) == 0 && !cg.Partiality.Complete {
		return true
	}
	reasons := footprintPartialityFlags(store, assessmentID)
	if len(reasons) == 0 {
		inv, ok := inventory(store, assessmentID)
		if !ok {
			return false
		}
		reasons = inv.PartialityFlags
	}
	for _, reason := range reasons {
		if report.ClassifyPartialityReason(reason) == report.PartialityDidNotRun {
			return true
		}
	}
	return false
}

// toolchainUndetermined is the Go toolchain/stdlib arm of undeterminedReason. Two clauses:
//
//   - The advisory's assessed subject must be the Go toolchain/stdlib (pipeline.ToolchainSubject).
//     A multi-package advisory adjudicated against a module the codebase actually requires is a
//     module case with a genuinely resolved version and is reported normally.
//   - The subject's toolchain must NOT have been scanned (M4). This is the clause that LIFTS the
//     undetermined verdict rather than adding to it: once the analysis has actually run under an
//     exact subject toolchain, the empty path set IS evidence about the subject, and
//     not_exploitable/vulnerable_symbol_absent becomes the established claim it always purported
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
// An analysis_did_not_run row owes NO note of its own. That row stands on limits partialityNotes
// already publishes at scan scope, each named precisely (unsupported_phase1, no_manifest, …) and
// each scoped to the ecosystem the run actually detected. Synthesizing a second note here would
// disclose one fact twice and scope the copy to Go.
func limitNoteFor(f report.AdvisoryFinding) (report.PartialityNote, bool) {
	if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason == report.ReasonAnalysisDidNotRun {
		return report.PartialityNote{}, false
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
	inv, haveInv := inventory(store, assessmentID)
	if len(reasons) == 0 {
		// No footprint artifact (a run that failed before S4, or a stage set that omits
		// the footprint) — fall back to the inventory's own flags so the S2 axis is never
		// lost when the union is unavailable.
		if !haveInv {
			return nil
		}
		reasons = inv.PartialityFlags
	}
	if len(reasons) == 0 {
		return nil
	}
	ecosystem := ""
	if haveInv {
		ecosystem = ecosystemFor(inv.Language)
	}
	notes := make([]report.PartialityNote, 0, len(reasons))
	for _, reason := range reasons {
		notes = append(notes, report.PartialityNote{
			Reason:    reason,
			Ecosystem: ecosystem,
		})
	}
	return notes
}

// footprintPartialityFlags reads the unioned partiality reason codes off the
// assessment's exposure-footprint artifact. Absent artifact or unreadable payload
// yields no reasons; the caller falls back to the inventory artifact.
func footprintPartialityFlags(store artifact.Store, assessmentID string) []string {
	arts, err := store.Query(assessmentID, artifact.TypeExposureFootprint)
	if err != nil || len(arts) == 0 {
		return nil
	}
	var fp artifact.ExposureFootprintPayload
	if err := json.Unmarshal(arts[0].Payload, &fp); err != nil {
		return nil
	}
	return fp.PartialityFlags
}

// assessFailureNote turns a failed assessment into a scan-level disclosure. One
// advisory whose analysis did not run must not discard the whole Report — that is the
// "failed scan renders as no results" conflation — but it must not vanish either: the
// advisory produces no finding, so without this note the counts silently shrink and a
// scan that could not complete reads exactly like one that found nothing.
//
// Detail names the analysis step that failed and the advisory it was evaluating, so a
// reader can act on it. Disclosure only: no verdict is emitted for the advisory.
func assessFailureNote(adv assessment.VulnRef, err error) report.PartialityNote {
	step := "assess"
	var se *pipeline.StageError
	if errors.As(err, &se) && se.Stage != "" {
		step = se.Stage
	}
	return report.PartialityNote{
		Reason: plugin.PartialReasonToolFailure,
		Detail: fmt.Sprintf("%s (%s)", step, adv.ID),
	}
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
