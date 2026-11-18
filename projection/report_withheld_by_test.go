package projection_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestReport_WithheldByReachesEveryFormat: the limits that withheld a verdict are named in the SARIF
// message and the HTML row, and serialized as withheld_by in the JSON report.
func TestReport_WithheldByReachesEveryFormat(t *testing.T) {
	limits := []report.Limit{
		{Reason: "library_escape"},
		{Reason: "cgo", Package: "pkg:golang/example.com/c", Path: "bridge.go", Targets: []string{"pkg:golang/golang.org/x/text"}},
	}
	r := undeterminedReport()
	for i := range r.Advisories {
		f := &r.Advisories[i]
		if f.Verdict != report.VerdictUndetermined {
			continue
		}
		f.UndeterminedReason = report.ReasonRefutationWithheld
		f.WithheldBy = limits
		f.Evidence.Detail = report.WithheldDetail(f.UndeterminedReason, limits)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	sarif, err := projection.MarshalReportSARIF(r)
	if err != nil {
		t.Fatalf("MarshalReportSARIF: %v", err)
	}
	html, err := projection.ProjectReportHTML(r)
	if err != nil {
		t.Fatalf("ProjectReportHTML: %v", err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarif, &log); err != nil {
		t.Fatal(err)
	}
	var messages []string
	for _, run := range log.Runs {
		for _, res := range run.Results {
			messages = append(messages, res.Message.Text)
		}
	}
	for _, l := range limits {
		phrase := report.LimitPhrase(l)
		if !strings.Contains(strings.Join(messages, "\n"), phrase) {
			t.Errorf("no SARIF result message names %q", phrase)
		}
		if !strings.Contains(string(html), phrase) {
			t.Errorf("HTML does not name %q", phrase)
		}
	}
	js, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), `"withheld_by":[{"reason":"library_escape"},{"reason":"cgo","package":"pkg:golang/example.com/c","path":"bridge.go","targets":["pkg:golang/golang.org/x/text"]}]`) {
		t.Errorf("JSON report does not carry withheld_by: %s", js)
	}
}

// TestReport_WithheldByOmittedWhenEmpty: a row with no limits serializes no withheld_by key.
func TestReport_WithheldByOmittedWhenEmpty(t *testing.T) {
	js, err := json.Marshal(undeterminedReport())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(js), "withheld_by") {
		t.Errorf("a report with no limits carries withheld_by: %s", js)
	}
}
