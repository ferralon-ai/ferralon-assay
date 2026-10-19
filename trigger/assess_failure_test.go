package trigger

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// failingReachabilityPlugin is the wiring plugin with a reachability pass that errors, so every
// assessment of GO-2021-0113 fails. The error carries a newline and URL credentials, which the
// row must not.
type failingReachabilityPlugin struct{ refutingGoPlugin }

func (failingReachabilityPlugin) Reachability(context.Context, plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	return plugin.ReachabilityResult{}, errors.New("fetch https://user:s3cret@proxy.example/x failed\nexit status 1")
}

func failingOptions(t *testing.T) []pipeline.AssessOption {
	t.Helper()
	return []pipeline.AssessOption{
		pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, wiringGoMod), lang: "go"}),
		pipeline.WithPlugin(failingReachabilityPlugin{refutingGoPlugin{inventory: plugin.Complete()}}),
	}
}

// migratedBaseline holds the row report.Upgrade makes from a v1 document: undetermined, and with
// no source, so it cannot match a fresh row on the (id, source) key.
func migratedBaseline() *memStore {
	store := emptyBaseline()
	store.state.Report.Advisories = append(store.state.Report.Advisories, report.AdvisoryFinding{
		Advisory:           report.Advisory{ID: wiringAdvisory.ID},
		Verdict:            report.VerdictUndetermined,
		UndeterminedReason: report.ReasonUnspecifiedLimit,
	})
	return store
}

// emptyBaseline is a stored baseline that holds the wiring package and no row for any advisory.
func emptyBaseline() *memStore {
	pkg := wiringPkg
	baseline := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base-sha"}).
		AddPackage(pkg).
		WithProvenance(report.Provenance{CommitSHA: "base-sha", AdvisoryCursor: wiringAdvisory.ID}).
		Build()
	return &memStore{state: &statestore.State{Report: &baseline, SBOM: baseline.SBOM, Cursor: wiringAdvisory.ID}}
}

func runFailingPR(t *testing.T, store *memStore, head []report.Package) *report.Report {
	t.Helper()
	res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
		Subject:       Subject{Repo: "r", ResolvedCommit: "pr-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		PRSBOM:        report.SBOM{Packages: head},
		Advisories:    []assessment.VulnRef{wiringAdvisory},
		AssessOptions: failingOptions(t),
	})
	if err != nil {
		t.Fatalf("RunPRInherit: %v", err)
	}
	return res.Report
}

func runFailingCVEWatch(t *testing.T, store *memStore) *report.Report {
	t.Helper()
	store.state.Cursor = ""
	osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{{ID: wiringAdvisory.ID, Package: wiringPkg}}}}
	res, err := RunCVEWatch(context.Background(), store, osv, CVEWatchRequest{
		Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		AssessOptions: failingOptions(t),
	})
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if res.Report == nil {
		t.Fatal("CVE-watch ran no earnest pass")
	}
	return res.Report
}

// TestAssessFailure_EveryRunMode: an advisory whose assessment fails gets exactly one row in every
// run mode, and that row is undetermined / analysis_did_not_run unless the run would have kept an
// inherited verdict anyway.
func TestAssessFailure_EveryRunMode(t *testing.T) {
	changedHead := []report.Package{{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.5"}}
	cases := []struct {
		name string
		want report.Verdict
		run  func(t *testing.T) *report.Report
	}{
		{"baseline", report.VerdictUndetermined, func(t *testing.T) *report.Report {
			rep, err := buildBaselineReport(context.Background(), BaselineRequest{
				Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
				Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
				Advisories:    []assessment.VulnRef{wiringAdvisory},
				AssessOptions: failingOptions(t),
			})
			if err != nil {
				t.Fatalf("buildBaselineReport: %v", err)
			}
			return rep
		}},
		{"PR re-analysis, package changed, replaces the baseline's not_exploitable", report.VerdictUndetermined, func(t *testing.T) *report.Report {
			store, _ := groundedBaseline()
			return runFailingPR(t, store, changedHead)
		}},
		{"PR re-analysis, no baseline row", report.VerdictUndetermined, func(t *testing.T) *report.Report {
			return runFailingPR(t, emptyBaseline(), changedHead)
		}},
		{"PR re-analysis, replaces a migrated v1 row", report.VerdictUndetermined, func(t *testing.T) *report.Report {
			return runFailingPR(t, migratedBaseline(), changedHead)
		}},
		{"PR re-analysis, package unchanged, keeps the baseline's not_exploitable", report.VerdictNotExploitable, func(t *testing.T) *report.Report {
			store, baseline := groundedBaseline()
			head := append([]report.Package{{Ecosystem: "Go", Name: "example.org/other", Version: "v1.0.0"}}, baseline.SBOM.Packages...)
			return runFailingPR(t, store, head)
		}},
		{"CVE-watch, replaces the prior reachable_candidate", report.VerdictUndetermined, func(t *testing.T) *report.Report {
			store, _ := seedBaseline(t)
			return runFailingCVEWatch(t, store)
		}},
		{"CVE-watch, no prior row", report.VerdictUndetermined, func(t *testing.T) *report.Report {
			return runFailingCVEWatch(t, emptyBaseline())
		}},
		{"CVE-watch, replaces a migrated v1 row", report.VerdictUndetermined, func(t *testing.T) *report.Report {
			return runFailingCVEWatch(t, migratedBaseline())
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := tc.run(t)
			var rows []report.AdvisoryFinding
			for _, f := range rep.Advisories {
				if f.Advisory.ID == wiringAdvisory.ID {
					rows = append(rows, f)
				}
			}
			if len(rows) != 1 {
				t.Fatalf("%d rows for %s, want exactly one: %+v", len(rows), wiringAdvisory.ID, rows)
			}
			f := rows[0]
			if f.Verdict != tc.want {
				t.Fatalf("verdict = %q, want %q", f.Verdict, tc.want)
			}
			if tc.want != report.VerdictUndetermined {
				return
			}
			if f.UndeterminedReason != report.ReasonAnalysisDidNotRun {
				t.Errorf("undetermined_reason = %q, want %q", f.UndeterminedReason, report.ReasonAnalysisDidNotRun)
			}
			if f.Package != nil {
				t.Errorf("Package = %+v, want none: the failed assessment resolved no package", f.Package)
			}
			if f.Evidence.Detail != "the reachability_ingress step failed (fetch https://REDACTED@proxy.example/x failed exit status 1), so no verdict was established" {
				t.Errorf("Evidence.Detail = %q, want the failed step and the sanitized error", f.Evidence.Detail)
			}
			var noted bool
			for _, n := range rep.Partiality {
				noted = noted || (n.Reason == plugin.PartialReasonToolFailure && strings.Contains(n.Detail, wiringAdvisory.ID))
			}
			if !noted {
				t.Errorf("Partiality = %+v, want the tool_failure note naming %s", rep.Partiality, wiringAdvisory.ID)
			}
		})
	}
}

func TestAssessErrorText(t *testing.T) {
	long := strings.Repeat("é", assessErrorLimit+10)
	cases := []struct {
		name string
		err  string
		want string
	}{
		{"plain", "boom", "boom"},
		{"control characters fold to one line", "a\r\nb\tc\x00d", "a b c d"},
		{"URL credentials are redacted", "GET https://x-access-token:ghs_abc@github.com/o/r: 403", "GET https://REDACTED@github.com/o/r: 403"},
		{"a URL without credentials is kept", "GET https://github.com/o/r@v1: 404", "GET https://github.com/o/r@v1: 404"},
		{"bounded in runes", long, strings.Repeat("é", assessErrorLimit-1) + "…"},
		{"at the bound is kept", long[:2*assessErrorLimit], long[:2*assessErrorLimit]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := assessErrorText(errors.New(tc.err)); got != tc.want {
				t.Errorf("assessErrorText(%q) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}
