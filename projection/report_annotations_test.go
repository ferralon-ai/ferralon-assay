package projection_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
)

var installInactive = plugin.Annotation{
	Reason: plugin.AnnotationInstallSurfaceInactive,
	Path:   "ci/steps.yml:2",
	Detail: "install commands found at ci/steps.yml:2; this analysis assumes they are not active (pip install)",
}

// annotatedReport is fixtureReport with the install-surface annotation on its disqualified row,
// so the assumption is shown on a verdict that is otherwise conclusive.
func annotatedReport(t *testing.T) (report.Report, string) {
	t.Helper()
	r := fixtureReport()
	for i := range r.Advisories {
		if r.Advisories[i].Advisory.ID == "GO-2021-0001" {
			r.Advisories[i].Annotations = []plugin.Annotation{installInactive}
			return r, r.Advisories[i].Advisory.ID
		}
	}
	t.Fatal("fixture has no GO-2021-0001 row")
	return r, ""
}

// Every machine-readable sink carries the assumption on the row it qualifies, and only there.
func TestReportProjections_CarryAnnotations(t *testing.T) {
	r, id := annotatedReport(t)
	const want = "This analysis assumes: " + "install commands found at ci/steps.yml:2; this analysis assumes they are not active (pip install)."

	log, err := projection.ProjectReportSARIF(r)
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	for _, res := range log.Runs[0].Results {
		_, has := res.Properties.Scanner["annotations"]
		inMsg := strings.Contains(res.Message.Text, want)
		if res.RuleID == id && (!has || !inMsg) {
			t.Errorf("SARIF %s: annotations property %v, message %q; want both", id, has, res.Message.Text)
		}
		if res.RuleID != id && (has || strings.Contains(res.Message.Text, "This analysis assumes")) {
			t.Errorf("SARIF %s carries an annotation it does not rest on: %q", res.RuleID, res.Message.Text)
		}
	}

	doc, err := projection.ProjectReportVEX(r)
	if err != nil {
		t.Fatalf("ProjectReportVEX: %v", err)
	}
	found := false
	for _, s := range doc.Statements {
		if s.StatusNotes == want {
			found = true
		} else if s.StatusNotes != "" {
			t.Errorf("VEX status_notes = %q on a row with no annotation", s.StatusNotes)
		}
	}
	if !found {
		raw, _ := json.Marshal(doc.Statements)
		t.Errorf("VEX: no statement carries status_notes %q\n%s", want, raw)
	}

	html, err := projection.ProjectReportHTML(r)
	if err != nil {
		t.Fatalf("ProjectReportHTML: %v", err)
	}
	if !strings.Contains(string(html), "This analysis assumes: install commands found at ci/steps.yml:2") {
		t.Errorf("HTML report does not state the assumption")
	}
}

// A report with no annotations projects exactly as before: no property, no sentence, no note.
func TestReportProjections_NoAnnotationsAddNothing(t *testing.T) {
	r := fixtureReport()
	log, err := projection.ProjectReportSARIF(r)
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	for _, res := range log.Runs[0].Results {
		if _, has := res.Properties.Scanner["annotations"]; has || strings.Contains(res.Message.Text, "This analysis assumes") {
			t.Errorf("SARIF %s: annotation without one in the report", res.RuleID)
		}
	}
	doc, err := projection.ProjectReportVEX(r)
	if err != nil {
		t.Fatalf("ProjectReportVEX: %v", err)
	}
	raw, _ := json.Marshal(doc)
	if strings.Contains(string(raw), "status_notes") {
		t.Errorf("VEX: status_notes without an annotation in the report\n%s", raw)
	}
}

// The HTML report escapes what the scanned repository names in an annotation.
func TestReportHTML_EscapesAnnotation(t *testing.T) {
	r, _ := annotatedReport(t)
	for i := range r.Advisories {
		for j := range r.Advisories[i].Annotations {
			r.Advisories[i].Annotations[j].Detail = "install commands found at <script>x</script>"
		}
	}
	html, err := projection.ProjectReportHTML(r)
	if err != nil {
		t.Fatalf("ProjectReportHTML: %v", err)
	}
	if strings.Contains(string(html), "<script>x</script>") {
		t.Errorf("HTML report renders an annotation unescaped")
	}
}
