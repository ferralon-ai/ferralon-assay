package main

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"

// floorReport is a valid report.json of testCommit with one resolved package and the given findings
// and partiality notes.
func floorReport(t *testing.T, findings []report.AdvisoryFinding, notes ...report.PartialityNote) []byte {
	t.Helper()
	var r report.Report
	if err := json.Unmarshal([]byte(reportJSON("", "")), &r); err != nil {
		t.Fatal(err)
	}
	r.Subject.ResolvedCommit, r.Provenance.CommitSHA = testCommit, testCommit
	r.SBOM.Packages = []report.Package{{Ecosystem: "Go", Name: "m", Version: "v1"}}
	r.Advisories, r.Partiality = findings, notes
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeReport(data); err != nil {
		t.Fatalf("test report does not decode: %v", err)
	}
	return data
}

// fv is a finding on m@v1 with a basis or undetermined reason valid for its verdict.
func fv(id string, v report.Verdict, aliases ...string) report.AdvisoryFinding {
	reason := map[report.Verdict]string{
		report.VerdictNotExploitable: string(verdict.BasisSymbolUnreachable),
		report.VerdictDisqualified:   string(verdict.BasisVersionNotAffected),
		report.VerdictUndetermined:   "advisory_symbol_absent",
	}[v]
	return finding(id, "m", "v1", v, reason, aliases...)
}

func testFixture(scan string, partiality []string, xs ...Expectation) Fixture {
	return Fixture{Name: "fx", Scenario: Scenario{Repo: "https://github.com/o/r", Commit: testCommit},
		Expect: Expect{Schema: ExpectSchema, Scan: scan, Partiality: partiality, Findings: xs}}
}

func expect(truth string, floor report.Verdict) Expectation {
	return Expectation{Advisory: "GO-1", Package: "m@v1", Truth: truth, Floor: floor}
}

var (
	rc  = report.VerdictReachableCandidate
	und = report.VerdictUndetermined
	ne  = report.VerdictNotExploitable
	dq  = report.VerdictDisqualified
	mal = report.VerdictMaliciousPresent
)

// TestOrderingPairs judges every observed verdict against every floor that may be written, for each
// truth, under both settings of the safe-truth rule. The ranks are restated here by hand from the
// design, so a change to rank() has to be made twice.
func TestOrderingPairs(t *testing.T) {
	ranks := func(candidateBelow bool) map[string]map[report.Verdict]int {
		rcRank := 2
		if candidateBelow {
			rcRank = 1
		}
		return map[string]map[report.Verdict]int{
			TruthReachable:   {rc: 2, und: 1},
			TruthUnreachable: {ne: 3, und: 2, rc: rcRank},
			TruthNotAffected: {ne: 3, dq: 3, und: 2, rc: rcRank},
		}
	}
	for _, setting := range []bool{true, false} {
		rules := orderRules{undeterminedOutranksCandidate: setting, missingIsRegression: true}
		want := ranks(setting)
		for _, truth := range []string{TruthReachable, TruthUnreachable, TruthNotAffected} {
			for _, floor := range verdictOrder {
				floorRank, floorOK := want[truth][floor]
				if _, ok := rules.rank(truth, floor); ok != floorOK {
					t.Errorf("setting %v: rank(%s, %s) ok = %v, want %v", setting, truth, floor, ok, floorOK)
				}
				if !floorOK {
					if err := expect(truth, floor).validate(rules); err == nil {
						t.Errorf("setting %v: floor %s for truth %s validated; it is always wrong", setting, floor, truth)
					}
					continue
				}
				for _, got := range verdictOrder {
					name := fmt.Sprintf("safe=%v/%s/floor=%s/got=%s", setting, truth, floor, got)
					outcome, reason, _ := judgeOne(expect(truth, floor), fv("GO-1", got), rules)
					gotRank, gotOK := want[truth][got]
					wantOutcome, wantReason := OutcomeImproved, ""
					switch {
					case !gotOK:
						wantOutcome, wantReason = OutcomeRegressed, ReasonAlwaysWrong
					case gotRank < floorRank:
						wantOutcome, wantReason = OutcomeRegressed, ReasonBelowFloor
					case gotRank == floorRank:
						wantOutcome = OutcomeMet
					}
					if outcome != wantOutcome || reason != wantReason {
						t.Errorf("%s: %s/%s, want %s/%s", name, outcome, reason, wantOutcome, wantReason)
					}
				}
			}
		}
	}
}

func TestSafeTruthDefault(t *testing.T) {
	if !undeterminedOutranksCandidateWhenSafe || !defaultRules.undeterminedOutranksCandidate {
		t.Error("the shipped ordering is the design's: undetermined outranks reachable_candidate when the truth is safe")
	}
	if !missingIsRegression || !defaultRules.missingIsRegression {
		t.Error("the shipped reading of a missing expected finding is a regression")
	}
}

func TestJudge(t *testing.T) {
	withBasis := func(x Expectation, b verdict.NonExploitableBasis) Expectation { x.Basis = b; return x }
	reviewed := func(x Expectation, sha string) Expectation { x.Review = &Review{By: "r", PathSHA: sha}; return x }
	otherBasis := fv("GO-1", ne)
	otherBasis.Evidence.Basis = verdict.BasisSymbolAbsent
	withPath := rcFinding("GO-1", "a", "b")
	other := finding("GO-1", "m", "v2", ne, string(verdict.BasisSymbolUnreachable))
	for _, tc := range []struct {
		name        string
		x           Expectation
		findings    []report.AdvisoryFinding
		missingRule bool
		outcome     string
		reason      string
		compared    report.Verdict
		matches     int
		stale       bool
	}{
		{name: "met", x: expect(TruthReachable, rc), findings: []report.AdvisoryFinding{fv("GO-1", rc)}, outcome: OutcomeMet, compared: rc},
		{name: "improved", x: expect(TruthUnreachable, und), findings: []report.AdvisoryFinding{fv("GO-1", ne)}, outcome: OutcomeImproved, compared: ne},
		{name: "below floor", x: expect(TruthUnreachable, ne), findings: []report.AdvisoryFinding{fv("GO-1", und)}, outcome: OutcomeRegressed, reason: ReasonBelowFloor, compared: und},
		{name: "refuted when reachable", x: expect(TruthReachable, und), findings: []report.AdvisoryFinding{fv("GO-1", ne)}, outcome: OutcomeRegressed, reason: ReasonAlwaysWrong, compared: ne},
		{name: "disqualified when unreachable", x: expect(TruthUnreachable, und), findings: []report.AdvisoryFinding{fv("GO-1", dq)}, outcome: OutcomeRegressed, reason: ReasonAlwaysWrong, compared: dq},
		{name: "missing is a regression", x: expect(TruthReachable, rc), missingRule: true, outcome: OutcomeRegressed, reason: ReasonMissing},
		{name: "missing is incomplete under the other rule", x: expect(TruthReachable, rc), outcome: OutcomeIncomplete, reason: ReasonMissing},
		{name: "another package instance does not match", x: expect(TruthReachable, rc), findings: []report.AdvisoryFinding{other}, missingRule: true, outcome: OutcomeRegressed, reason: ReasonMissing},
		{name: "alias match", x: expect(TruthReachable, rc), findings: []report.AdvisoryFinding{fv("GHSA-x", rc, "CVE-9", "GO-1")}, outcome: OutcomeMet, compared: rc},
		{name: "several matches judged on the worst", x: expect(TruthNotAffected, und),
			findings: []report.AdvisoryFinding{fv("GO-1", ne), fv("GHSA-x", rc, "GO-1"), fv("GO-1", und)},
			outcome:  OutcomeRegressed, reason: ReasonBelowFloor, compared: rc, matches: 3},
		{name: "several matches, worst still met", x: expect(TruthNotAffected, und),
			findings: []report.AdvisoryFinding{fv("GO-1", dq), fv("GHSA-x", und, "GO-1")},
			outcome:  OutcomeMet, compared: und, matches: 2},
		{name: "always wrong outranks below floor among matches", x: expect(TruthUnreachable, ne),
			findings: []report.AdvisoryFinding{fv("GO-1", rc), fv("GO-1", dq)},
			outcome:  OutcomeRegressed, reason: ReasonAlwaysWrong, compared: dq, matches: 2},
		{name: "basis mismatch at the best verdict", x: withBasis(expect(TruthUnreachable, ne), verdict.BasisSymbolUnreachable),
			findings: []report.AdvisoryFinding{otherBasis}, outcome: OutcomeRegressed, reason: ReasonBasisMismatch, compared: ne},
		{name: "basis met", x: withBasis(expect(TruthUnreachable, und), verdict.BasisSymbolUnreachable),
			findings: []report.AdvisoryFinding{fv("GO-1", ne)}, outcome: OutcomeImproved, compared: ne},
		{name: "basis not checked below the best verdict", x: withBasis(expect(TruthUnreachable, und), verdict.BasisSymbolUnreachable),
			findings: []report.AdvisoryFinding{fv("GO-1", und)}, outcome: OutcomeMet, compared: und},
		{name: "review path still current", x: reviewed(expect(TruthReachable, rc), pathSHA([]string{"a", "b"})),
			findings: []report.AdvisoryFinding{withPath}, outcome: OutcomeMet, compared: rc},
		{name: "stale review beside the outcome", x: reviewed(expect(TruthReachable, rc), "deadbeef"),
			findings: []report.AdvisoryFinding{withPath}, outcome: OutcomeMet, compared: rc, stale: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := orderRules{undeterminedOutranksCandidate: true, missingIsRegression: tc.missingRule}
			var matches []report.AdvisoryFinding
			for _, f := range tc.findings {
				if matchesExpectation(tc.x, f) {
					matches = append(matches, f)
				}
			}
			er := judge(tc.x, matches, rules)
			if er.Outcome != tc.outcome || er.Reason != tc.reason {
				t.Errorf("outcome %s/%s, want %s/%s", er.Outcome, er.Reason, tc.outcome, tc.reason)
			}
			switch {
			case tc.compared == "" && er.Compared != nil:
				t.Errorf("compared %+v, want none", er.Compared)
			case tc.compared != "" && (er.Compared == nil || er.Compared.Verdict != tc.compared):
				t.Errorf("compared %+v, want verdict %s", er.Compared, tc.compared)
			}
			if len(er.Matches) != tc.matches {
				t.Errorf("%d matches listed, want %d", len(er.Matches), tc.matches)
			}
			if er.StaleReview != tc.stale {
				t.Errorf("stale review = %v, want %v", er.StaleReview, tc.stale)
			}
		})
	}
}

// TestMaliciousAlwaysWrong: the report schema refuses malicious_package_present from the OSS engine, so
// it reaches the comparator only in a hand-made finding; for every truth it is always wrong.
func TestMaliciousAlwaysWrong(t *testing.T) {
	for _, truth := range []string{TruthReachable, TruthUnreachable, TruthNotAffected} {
		for _, floor := range []report.Verdict{rc, und} {
			if outcome, reason, _ := judgeOne(expect(truth, floor), report.AdvisoryFinding{Verdict: mal}, defaultRules); outcome != OutcomeRegressed || reason != ReasonAlwaysWrong {
				t.Errorf("%s floor %s: malicious judged %s/%s", truth, floor, outcome, reason)
			}
		}
	}
}

func TestCompareFixture(t *testing.T) {
	note := func(reason string) report.PartialityNote { return report.PartialityNote{Reason: reason, Detail: "d"} }
	met := expect(TruthReachable, rc)
	good := []report.AdvisoryFinding{fv("GO-1", rc)}
	wrongCommit := func() []byte {
		var r report.Report
		_ = json.Unmarshal(floorReport(t, good), &r)
		r.Subject.ResolvedCommit = strings.Repeat("f", 40)
		data, _ := json.Marshal(r)
		return data
	}
	noPackages := func() []byte {
		var r report.Report
		_ = json.Unmarshal(floorReport(t, good), &r)
		r.SBOM.Packages = nil
		data, _ := json.Marshal(r)
		return data
	}
	for _, tc := range []struct {
		name       string
		fx         Fixture
		obs        observation
		outcome    string
		incomplete []string
		exit       int
	}{
		{name: "pass", fx: testFixture(ScanComplete, nil, met), obs: observation{report: floorReport(t, good), hasReport: true}, outcome: OutcomePass},
		{name: "scan failed", fx: testFixture(ScanComplete, nil, met), obs: observation{scanFailed: "the scanner exited 3", report: floorReport(t, good), hasReport: true},
			outcome: OutcomeIncomplete, incomplete: []string{KindScanFailed}, exit: 2},
		{name: "no report", fx: testFixture(ScanComplete, nil, met), obs: observation{}, outcome: OutcomeIncomplete, incomplete: []string{KindNoReport}, exit: 2},
		{name: "malformed report", fx: testFixture(ScanComplete, nil, met), obs: observation{report: []byte(`{"schema_version":`), hasReport: true},
			outcome: OutcomeIncomplete, incomplete: []string{KindMalformed}, exit: 2},
		{name: "report of another commit", fx: testFixture(ScanComplete, nil, met), obs: observation{report: wrongCommit(), hasReport: true},
			outcome: OutcomeIncomplete, incomplete: []string{KindSubjectMismatch}, exit: 2},
		{name: "empty inventory", fx: testFixture(ScanComplete, nil, met), obs: observation{report: noPackages(), hasReport: true},
			outcome: OutcomeIncomplete, incomplete: []string{KindIncompleteScan}, exit: 2},
		{name: "cut short", fx: testFixture(ScanComplete, nil, met), obs: observation{report: floorReport(t, good, note(report.ReasonScanCutShort)), hasReport: true},
			outcome: OutcomeIncomplete, incomplete: []string{KindTruncated}, exit: 2},
		{name: "tool failure", fx: testFixture(ScanComplete, nil, met), obs: observation{report: floorReport(t, good, note("tool_failure:govulncheck")), hasReport: true},
			outcome: OutcomeIncomplete, incomplete: []string{KindIncompleteScan}, exit: 2},
		{name: "partial tolerates the listed reason", fx: testFixture(ScanPartial, []string{"tool_failure:govulncheck"}, met),
			obs: observation{report: floorReport(t, good, note("tool_failure:govulncheck")), hasReport: true}, outcome: OutcomePass},
		{name: "partial does not tolerate another reason", fx: testFixture(ScanPartial, []string{"tool_failure:govulncheck"}, met),
			obs:     observation{report: floorReport(t, good, note("tool_failure:govulncheck"), note(report.ReasonScanCutShort)), hasReport: true},
			outcome: OutcomeIncomplete, incomplete: []string{KindTruncated}, exit: 2},
		{name: "non-failure partiality is not compared", fx: testFixture(ScanComplete, nil, met),
			obs: observation{report: floorReport(t, good, note("no_manifest")), hasReport: true}, outcome: OutcomePass},
		{name: "regressed", fx: testFixture(ScanComplete, nil, expect(TruthUnreachable, ne)),
			obs: observation{report: floorReport(t, good), hasReport: true}, outcome: OutcomeRegressed, exit: 1},
		{name: "regression outranks a missing finding read as incomplete", fx: testFixture(ScanComplete, nil, expect(TruthUnreachable, ne),
			Expectation{Advisory: "GO-404", Package: "m@v1", Truth: TruthReachable, Floor: rc}),
			obs: observation{report: floorReport(t, good), hasReport: true}, outcome: OutcomeRegressed, incomplete: []string{KindMissingFinding}, exit: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := defaultRules
			if strings.Contains(tc.name, "read as incomplete") {
				rules.missingIsRegression = false
			}
			res := compareFixture(tc.fx, tc.obs, nil, "", rules)
			if res.Outcome != tc.outcome {
				t.Errorf("outcome %s, want %s (%+v)", res.Outcome, tc.outcome, res.Incomplete)
			}
			if got := kinds(res.Incomplete); !slices.Equal(got, tc.incomplete) {
				t.Errorf("incomplete kinds %v, want %v", got, tc.incomplete)
			}
			if res.exit() != tc.exit {
				t.Errorf("exit %d, want %d", res.exit(), tc.exit)
			}
		})
	}
}

func TestDrift(t *testing.T) {
	fx := testFixture(ScanComplete, nil, expect(TruthReachable, rc))
	before := []report.AdvisoryFinding{fv("GO-1", und), fv("GO-2", und), fv("GO-3", ne)}
	after := []report.AdvisoryFinding{fv("GO-1", rc), fv("GO-2", rc), fv("GO-4", und)}
	prior, err := decodeReport(floorReport(t, before))
	if err != nil {
		t.Fatal(err)
	}
	res := compareFixture(fx, observation{report: floorReport(t, after), hasReport: true}, &prior, "old/report.json", defaultRules)
	var got []string
	for _, c := range res.Drift {
		got = append(got, c.String())
	}
	want := []string{
		"changed GO-2 m@v1: undetermined/advisory_symbol_absent -> reachable_candidate",
		"removed GO-3 m@v1: not_exploitable/vulnerable_symbol_unreachable -> -",
		"added GO-4 m@v1: - -> undetermined/advisory_symbol_absent",
	}
	if !slices.Equal(got, want) {
		t.Errorf("drift (the expected GO-1 excluded) =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if res.Unexpected != 2 || res.DriftBase != "old/report.json" || res.Outcome != OutcomePass {
		t.Errorf("unexpected %d, drift base %q, outcome %s", res.Unexpected, res.DriftBase, res.Outcome)
	}
	if res := compareFixture(fx, observation{report: floorReport(t, after), hasReport: true}, nil, "", defaultRules); res.Drift != nil || res.DriftBase != "" {
		t.Errorf("drift without a prior: %+v", res.Drift)
	}
}

func TestAggregateExit(t *testing.T) {
	r := func(outcome string) FixtureResult { return FixtureResult{Outcome: outcome} }
	for _, tc := range []struct {
		name string
		rs   []FixtureResult
		want int
	}{
		{"none", nil, 0},
		{"all pass", []FixtureResult{r(OutcomePass), r(OutcomePass)}, 0},
		{"incomplete", []FixtureResult{r(OutcomePass), r(OutcomeIncomplete)}, 2},
		{"regressed", []FixtureResult{r(OutcomeRegressed), r(OutcomePass)}, 1},
		{"regressed and incomplete", []FixtureResult{r(OutcomeIncomplete), r(OutcomeRegressed), r(OutcomeIncomplete)}, 1},
	} {
		if got := aggregateExit(tc.rs); got != tc.want {
			t.Errorf("%s: exit %d, want %d", tc.name, got, tc.want)
		}
	}
}
