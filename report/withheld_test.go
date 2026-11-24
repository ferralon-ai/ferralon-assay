package report

import (
	"strings"
	"testing"
)

func TestLimitPhrase(t *testing.T) {
	cases := []struct {
		name  string
		limit Limit
		want  string
	}{
		{"run-wide", Limit{Reason: "reflection:call"}, "reflection:call"},
		{"standing for others", Limit{Reason: "cgo", Others: 318}, "cgo (318 scoped limits not listed one by one)"},
		{"scoped to a place", Limit{Reason: "cgo", Package: "pkg:golang/example.com/c", Path: "bridge.go"}, "cgo in pkg:golang/example.com/c at bridge.go"},
		{"with targets", Limit{Reason: "cgo", Package: "pkg:golang/example.com/c", Targets: []string{"pkg:golang/a", "pkg:golang/b"}},
			"cgo in pkg:golang/example.com/c, which could reach pkg:golang/a, pkg:golang/b"},
		{"more targets than it names", Limit{Reason: "cgo", Targets: []string{"pkg:golang/a", "pkg:golang/b", "pkg:golang/c", "pkg:golang/d", "pkg:golang/e"}},
			"cgo, which could reach pkg:golang/a, pkg:golang/b, pkg:golang/c and 2 more"},
		{"first-party target", Limit{Reason: "cgo", Package: "pkg:golang/example.com/c", Targets: []string{"", "pkg:golang/a"}},
			"cgo in pkg:golang/example.com/c, which could reach this repository's own code, pkg:golang/a"},
		{"only a first-party target", Limit{Reason: "cgo", Package: "pkg:golang/example.com/c", Targets: []string{""}},
			"cgo in pkg:golang/example.com/c, which could reach this repository's own code"},
		{"first-party target past the cut", Limit{Reason: "cgo", Targets: []string{"pkg:golang/a", "pkg:golang/b", "pkg:golang/c", ""}},
			"cgo, which could reach pkg:golang/a, pkg:golang/b, pkg:golang/c and 1 more"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := LimitPhrase(tc.limit); got != tc.want {
				t.Errorf("LimitPhrase = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWithheldDetail(t *testing.T) {
	base := UndeterminedDetail(ReasonRefutationWithheld)
	if got := WithheldDetail(ReasonRefutationWithheld, nil); got != base {
		t.Errorf("no limits: %q, want the plain detail", got)
	}
	got := WithheldDetail(ReasonRefutationWithheld, []Limit{{Reason: "library_escape"}, {Reason: "cgo", Package: "pkg:golang/example.com/c"}})
	want := base + ". It was withheld by: library_escape; cgo in pkg:golang/example.com/c"
	if got != want {
		t.Errorf("WithheldDetail = %q, want %q", got, want)
	}
	many := make([]Limit, withheldDetailLimits+2)
	for i := range many {
		many[i] = Limit{Reason: "cgo", Path: string(rune('a' + i))}
	}
	got = WithheldDetail(ReasonRefutationWithheld, many)
	if !strings.HasSuffix(got, "cgo at h; and 2 more") {
		t.Errorf("WithheldDetail of %d limits = %q, want the first %d and a count of the rest", len(many), got, withheldDetailLimits)
	}
}

// TestValidate_WithheldBy: limits ride only on a row the analysis withheld.
// TestWithheldDetail_KeepsALongPath pins that a limit's Path reaches the row whole: a partial run's
// limit names up to five packages before the load error it reports for them, and a cut would drop
// the error first.
func TestWithheldDetail_KeepsALongPath(t *testing.T) {
	cause := "(github.com/wailsapp/wails/v3/pkg/application/menu_linux.go:7:12: undefined: pointer)"
	path := "govulncheck could not load " + strings.Repeat("github.com/wailsapp/wails/v3/pkg/application, ", 4) +
		"github.com/wailsapp/wails/v3/pkg/events and 3 more " + cause + "; it searched the build less the roots that are or import a package it could not load: example.com/m/client/ui"
	got := WithheldDetail(ReasonRefutationWithheld, []Limit{{Reason: "tool_failure", Package: "pkg:golang/github.com/wailsapp/wails/v3", Path: path}})
	if !strings.Contains(got, cause) || !strings.HasSuffix(got, "example.com/m/client/ui") {
		t.Errorf("detail lost the cause or the roots: %q", got)
	}
}

func TestValidate_WithheldBy(t *testing.T) {
	limits := []Limit{{Reason: "library_escape"}}
	cases := []struct {
		name    string
		finding AdvisoryFinding
		wantErr string
	}{
		{"refutation withheld", AdvisoryFinding{Verdict: VerdictUndetermined, UndeterminedReason: ReasonRefutationWithheld, WithheldBy: limits}, ""},
		{"analysis did not run", AdvisoryFinding{Verdict: VerdictUndetermined, UndeterminedReason: ReasonAnalysisDidNotRun, WithheldBy: limits}, ""},
		{"another undetermined reason", AdvisoryFinding{Verdict: VerdictUndetermined, UndeterminedReason: ReasonPackageVersionUnresolved, WithheldBy: limits}, "withheld_by"},
		{"not exploitable", AdvisoryFinding{Verdict: VerdictNotExploitable, Evidence: EvidenceSummary{Basis: "vulnerable_symbol_unreachable"}, WithheldBy: limits}, "withheld_by"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := undeterminedReport()
			f := tc.finding
			f.Advisory = r.Advisories[0].Advisory
			if f.Verdict == VerdictUndetermined {
				f.Evidence.Detail = UndeterminedDetail(f.UndeterminedReason)
			}
			r.Advisories = []AdvisoryFinding{f}
			err := r.Validate()
			if tc.wantErr == "" && err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("Validate = %v, want an error naming %q", err, tc.wantErr)
			}
		})
	}
}
