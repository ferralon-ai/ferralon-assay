package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// undeterminedOutranksCandidateWhenSafe decides how a finding whose truth is unreachable or
// not_affected ranks undetermined against reachable_candidate. True: undetermined is the better
// verdict, so a reachable_candidate below an undetermined floor is a regression (a false positive
// appeared where the engine used to abstain). False: the two rank equal, both short of the
// refutation, so moving between them is neither a regression nor an improvement. This is the only
// line to change to switch orderings.
const undeterminedOutranksCandidateWhenSafe = true

// missingIsRegression decides what an expected finding absent from the report is. True: regressed —
// the inputs are pinned, so a finding that disappears is a behavior change. False: that expectation
// is incomplete (nothing to compare).
const missingIsRegression = true

// orderRules carries the comparator's named rules, so tests can run both settings of each.
type orderRules struct {
	undeterminedOutranksCandidate bool
	missingIsRegression           bool
}

var defaultRules = orderRules{
	undeterminedOutranksCandidate: undeterminedOutranksCandidateWhenSafe,
	missingIsRegression:           missingIsRegression,
}

// rank orders the verdicts a finding of the given truth may carry, higher better. ok is false for a
// verdict that is always wrong for the truth: a refutation of a reachable finding,
// malicious_package_present for any truth, and disqualified for an unreachable one (the package is
// affected; only reachability rules it out).
func (r orderRules) rank(truth string, v report.Verdict) (int, bool) {
	switch truth {
	case TruthReachable:
		switch v {
		case report.VerdictReachableCandidate:
			return 2, true
		case report.VerdictUndetermined:
			return 1, true
		}
	case TruthUnreachable, TruthNotAffected:
		switch v {
		case report.VerdictNotExploitable:
			return 3, true
		case report.VerdictDisqualified:
			if truth == TruthNotAffected {
				return 3, true
			}
		case report.VerdictUndetermined:
			return 2, true
		case report.VerdictReachableCandidate:
			if r.undeterminedOutranksCandidate {
				return 1, true
			}
			return 2, true
		}
	}
	return 0, false
}

// best is the verdicts at the top rank for a truth.
func (r orderRules) best(truth string) []report.Verdict {
	top, out := 0, []report.Verdict(nil)
	for _, v := range verdictOrder {
		n, ok := r.rank(truth, v)
		switch {
		case !ok || n < top:
		case n > top:
			top, out = n, []report.Verdict{v}
		default:
			out = append(out, v)
		}
	}
	return out
}

// Per-expectation outcomes.
const (
	OutcomeRegressed  = "regressed"
	OutcomeMet        = "met"
	OutcomeImproved   = "improved"
	OutcomeIncomplete = "incomplete"
	// OutcomePass is a fixture's outcome when nothing regressed and nothing was incomplete.
	OutcomePass = "pass"
)

// Reasons a finding regressed.
const (
	ReasonBelowFloor    = "below_floor"
	ReasonAlwaysWrong   = "always_wrong"
	ReasonBasisMismatch = "basis_mismatch"
	ReasonMissing       = "missing"
)

// ResultSchema names result.json.
const ResultSchema = "ferralon.floor-result.v1"

// Observed is one report finding matched to an expectation.
type Observed struct {
	ID                 string                      `json:"id"`
	Verdict            report.Verdict              `json:"verdict"`
	Basis              verdict.NonExploitableBasis `json:"basis,omitempty"`
	UndeterminedReason string                      `json:"undetermined_reason,omitempty"`
	PathSHA            string                      `json:"path_sha,omitempty"`
}

// ExpectResult is one expectation's outcome.
type ExpectResult struct {
	Advisory string         `json:"advisory"`
	Package  string         `json:"package"`
	Truth    string         `json:"truth"`
	Floor    report.Verdict `json:"floor"`
	// Basis is the expected non-exploitable basis, when the expectation pins one.
	Basis   verdict.NonExploitableBasis `json:"basis,omitempty"`
	Outcome string                      `json:"outcome"`
	Reason  string                      `json:"reason,omitempty"`
	// Compared is the matching finding the outcome was judged on: the worst one when several match.
	Compared *Observed `json:"compared,omitempty"`
	// Matches is every matching finding, when more than one matched.
	Matches []Observed `json:"matches,omitempty"`
	// StaleReview is set when the review's path_sha no longer hashes the compared finding's path. It
	// is reported beside the outcome and never changes it.
	StaleReview   bool   `json:"stale_review,omitempty"`
	ReviewPathSHA string `json:"review_path_sha,omitempty"`
}

// FixtureResult is result.json: one fixture's comparison.
type FixtureResult struct {
	Schema       string         `json:"schema"`
	Fixture      string         `json:"fixture"`
	Repo         string         `json:"repo,omitempty"`
	Commit       string         `json:"commit,omitempty"`
	Outcome      string         `json:"outcome"`
	Incomplete   []Failure      `json:"incomplete,omitempty"`
	Expectations []ExpectResult `json:"expectations"`
	// Unexpected counts the report's findings no expectation names.
	Unexpected int `json:"unexpected"`
	// Drift is how those findings moved since the prior observation; DriftBase names it, and is empty
	// when there was none to compare with.
	DriftBase string   `json:"drift_base,omitempty"`
	Drift     []Change `json:"drift,omitempty"`
	// Notes are what the harness did around the scan that a reader needs, such as a failed module
	// warm-up; they never change the outcome.
	Notes []string `json:"notes,omitempty"`
}

// exit is the fixture's exit status: 1 regressed, 2 incomplete, 0 otherwise.
func (r FixtureResult) exit() int {
	switch r.Outcome {
	case OutcomeRegressed:
		return 1
	case OutcomeIncomplete:
		return 2
	}
	return 0
}

// aggregateExit is the run's status: any regression is 1 whatever else is incomplete; otherwise any
// incomplete is 2.
func aggregateExit(rs []FixtureResult) int {
	code := 0
	for _, r := range rs {
		switch r.exit() {
		case 1:
			return 1
		case 2:
			code = 2
		}
	}
	return code
}

// observation is what a scan left behind for one fixture.
type observation struct {
	// scanFailed describes how the scan failed; empty when the scanner exited 0.
	scanFailed string
	report     []byte
	hasReport  bool
}

// incompleteResult is a fixture with nothing compared.
func incompleteResult(name string, fx *Fixture, fails []Failure) FixtureResult {
	res := FixtureResult{Schema: ResultSchema, Fixture: name, Outcome: OutcomeIncomplete, Incomplete: fails,
		Expectations: []ExpectResult{}}
	if fx != nil {
		res.Repo, res.Commit = fx.Scenario.Repo, fx.Scenario.Commit
		for _, x := range fx.Expect.Findings {
			res.Expectations = append(res.Expectations, ExpectResult{Advisory: x.Advisory, Package: x.Package,
				Truth: x.Truth, Floor: x.Floor, Basis: x.Basis, Outcome: OutcomeIncomplete})
		}
	}
	return res
}

// compareFixture judges one observation against a fixture's expectations. prior, when not nil, is
// the earlier observation the unexpected findings are diffed against, named by priorName.
func compareFixture(fx Fixture, obs observation, prior *report.Report, priorName string, rules orderRules) FixtureResult {
	r, fails := completeness(fx, obs)
	if len(fails) > 0 {
		return incompleteResult(fx.Name, &fx, fails)
	}
	res := FixtureResult{Schema: ResultSchema, Fixture: fx.Name, Repo: fx.Scenario.Repo, Commit: fx.Scenario.Commit,
		Outcome: OutcomePass, Expectations: []ExpectResult{}}
	expected := make([]bool, len(r.Advisories))
	for _, x := range fx.Expect.Findings {
		var matches []report.AdvisoryFinding
		for i, f := range r.Advisories {
			if matchesExpectation(x, f) {
				matches = append(matches, f)
				expected[i] = true
			}
		}
		er := judge(x, matches, rules)
		res.Expectations = append(res.Expectations, er)
		switch {
		case er.Outcome == OutcomeRegressed:
			res.Outcome = OutcomeRegressed
		case er.Outcome == OutcomeIncomplete:
			if res.Outcome != OutcomeRegressed {
				res.Outcome = OutcomeIncomplete
			}
			res.Incomplete = append(res.Incomplete, Failure{Kind: KindMissingFinding,
				Detail: fmt.Sprintf("%s %s is not in the report", x.Advisory, x.Package)})
		}
	}
	var unexpected []report.AdvisoryFinding
	for i, f := range r.Advisories {
		if !expected[i] {
			unexpected = append(unexpected, f)
		}
	}
	res.Unexpected = len(unexpected)
	if prior != nil {
		var before []report.AdvisoryFinding
		for _, f := range prior.Advisories {
			if !slices.ContainsFunc(fx.Expect.Findings, func(x Expectation) bool { return matchesExpectation(x, f) }) {
				before = append(before, f)
			}
		}
		res.DriftBase = priorName
		res.Drift = diffFindings(before, unexpected)
	}
	return res
}

// completeness decodes the report and returns every reason the scan cannot be compared. "complete"
// means no tool failure and no time-limit cut; a partial expectation tolerates exactly the reasons it
// lists. Partiality notes that record no failure are never compared. Every advisory the fixture
// carries must be assessed: a scan that dropped one is incomplete, whatever its expectations list.
func completeness(fx Fixture, obs observation) (report.Report, []Failure) {
	if obs.scanFailed != "" {
		return report.Report{}, []Failure{{Kind: KindScanFailed, Detail: obs.scanFailed}}
	}
	if !obs.hasReport {
		return report.Report{}, []Failure{{Kind: KindNoReport, Detail: "the scan wrote no report.json"}}
	}
	r, err := decodeReport(obs.report)
	if err != nil {
		return report.Report{}, []Failure{{Kind: KindMalformed, Detail: err.Error()}}
	}
	var out []Failure
	if r.Subject.ResolvedCommit != fx.Scenario.Commit {
		out = append(out, Failure{Kind: KindSubjectMismatch,
			Detail: fmt.Sprintf("the report is of commit %q, the scenario pins %s", r.Subject.ResolvedCommit, fx.Scenario.Commit)})
	}
	if len(r.SBOM.Packages) == 0 {
		out = append(out, Failure{Kind: KindIncompleteScan,
			Detail: "the scan's package inventory is empty: it resolved no dependencies"})
	}
	for _, n := range r.Partiality {
		kind := ""
		switch {
		case n.Reason == report.ReasonScanCutShort:
			kind = KindTruncated
		case n.Reason == plugin.PartialReasonToolFailure || strings.HasPrefix(n.Reason, plugin.PartialReasonToolFailure+":"):
			kind = KindIncompleteScan
		}
		if kind == "" || slices.Contains(fx.Expect.Partiality, n.Reason) {
			continue
		}
		detail := n.Reason
		if n.Detail != "" {
			detail += ": " + n.Detail
		}
		out = append(out, Failure{Kind: kind, Detail: detail})
	}
	for _, id := range fx.AdvisoryIDs {
		if !slices.ContainsFunc(r.Advisories, func(f report.AdvisoryFinding) bool {
			return f.Advisory.ID == id || slices.Contains(f.Advisory.Aliases, id)
		}) {
			out = append(out, Failure{Kind: KindIncompleteScan,
				Detail: fmt.Sprintf("advisory %s was not assessed: the report has no finding for it", id)})
		}
	}
	return r, out
}

// matchesExpectation: the finding's id or any alias is the expectation's advisory, on the same
// package instance.
func matchesExpectation(x Expectation, f report.AdvisoryFinding) bool {
	if packageInstance(f) != x.Package {
		return false
	}
	return f.Advisory.ID == x.Advisory || slices.Contains(f.Advisory.Aliases, x.Advisory)
}

func observedOf(f report.AdvisoryFinding) Observed {
	o := Observed{ID: f.Advisory.ID, Verdict: f.Verdict, Basis: f.Evidence.Basis, UndeterminedReason: f.UndeterminedReason}
	if p, _ := callPath(f); len(p) > 0 {
		o.PathSHA = pathSHA(p)
	}
	return o
}

// outcomeSeverity orders outcomes worst first, for choosing among several matches.
var outcomeSeverity = map[string]int{OutcomeRegressed: 0, OutcomeMet: 1, OutcomeImproved: 2}

// judge decides one expectation from its matching findings. Several matches are judged on the worst,
// so a regression is never masked by a better duplicate.
func judge(x Expectation, matches []report.AdvisoryFinding, rules orderRules) ExpectResult {
	er := ExpectResult{Advisory: x.Advisory, Package: x.Package, Truth: x.Truth, Floor: x.Floor, Basis: x.Basis}
	if len(matches) == 0 {
		er.Reason = ReasonMissing
		er.Outcome = OutcomeIncomplete
		if rules.missingIsRegression {
			er.Outcome = OutcomeRegressed
		}
		return er
	}
	worst, worstRank := -1, 0
	for i, f := range matches {
		outcome, reason, rank := judgeOne(x, f, rules)
		if worst < 0 || outcomeSeverity[outcome] < outcomeSeverity[er.Outcome] ||
			(outcome == er.Outcome && rank < worstRank) {
			worst, worstRank, er.Outcome, er.Reason = i, rank, outcome, reason
		}
	}
	c := observedOf(matches[worst])
	er.Compared = &c
	if len(matches) > 1 {
		for _, f := range matches {
			er.Matches = append(er.Matches, observedOf(f))
		}
	}
	if x.Review != nil && x.Review.PathSHA != "" && x.Review.PathSHA != c.PathSHA {
		er.StaleReview, er.ReviewPathSHA = true, x.Review.PathSHA
	}
	return er
}

// judgeOne is one finding's outcome against an expectation; an always-wrong verdict ranks -1.
func judgeOne(x Expectation, f report.AdvisoryFinding, rules orderRules) (outcome, reason string, rank int) {
	got, ok := rules.rank(x.Truth, f.Verdict)
	if !ok {
		return OutcomeRegressed, ReasonAlwaysWrong, -1
	}
	floor, _ := rules.rank(x.Truth, x.Floor)
	switch {
	case got < floor:
		return OutcomeRegressed, ReasonBelowFloor, got
	case x.Basis != verdict.BasisNone && slices.Contains(rules.best(x.Truth), f.Verdict) && f.Evidence.Basis != x.Basis:
		return OutcomeRegressed, ReasonBasisMismatch, got
	case got == floor:
		return OutcomeMet, "", got
	}
	return OutcomeImproved, "", got
}
