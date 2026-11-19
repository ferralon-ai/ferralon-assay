package main

import (
	"os"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/gittest"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestMain drops the repository-locating git variables a hook or `git rebase --exec` leaves in
// the environment, so code under test that execs git cannot reach the enclosing repository.
func TestMain(m *testing.M) {
	gittest.ScrubProcess()
	os.Exit(m.Run())
}

func TestCoverageLine(t *testing.T) {
	tests := []struct {
		name string
		rep  report.Report
		want string // substring; "" means no line
	}{
		{"complete scan prints nothing", report.Report{Advisories: []report.AdvisoryFinding{{Verdict: report.VerdictNotExploitable}}}, ""},
		{"partiality note", report.Report{Partiality: []report.PartialityNote{{Reason: "tool_failure"}}}, "Coverage: partial — 1 scan limit(s), 0 advisory finding(s) undetermined"},
		{"undetermined row", report.Report{Advisories: []report.AdvisoryFinding{{Verdict: report.VerdictUndetermined}, {Verdict: report.VerdictNotExploitable}}}, "Coverage: partial — 0 scan limit(s), 1 advisory finding(s) undetermined"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := coverageLine(&tt.rep)
			if tt.want == "" && got != "" || !strings.Contains(got, tt.want) {
				t.Fatalf("coverageLine = %q, want %q", got, tt.want)
			}
		})
	}
}
