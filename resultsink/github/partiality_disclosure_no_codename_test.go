package github_test

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
	ghsink "github.com/ferralon-ai/ferralon-assay/resultsink/github"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// The partiality disclosure is customer-visible copy on both write surfaces, so it is
// held to the same no-codename bar as the headings and the analyzer line
// (see tier0_summary_default_test.go / tier1_render_default_test.go): the rendered
// disclosure must carry zero occurrences of a retired codename ("nucleon" /
// "open-tegron" / "tegron") — an invariant of the render, not of any build
// configuration; there is only one identity now.
//
// The Tier-1 body additionally carries the sticky-comment marker, which legitimately
// contains the current brand name and must stay byte-stable — so this test strips the
// marker before scanning, exactly as the pinned-Issue codename check does (see
// tier1_issue_no_codename_test.go).
func TestPartialityDisclosure_NoCodename(t *testing.T) {
	pkg := report.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	r := report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"}).
		Disqualified(report.Advisory{ID: "CVE-2020-0001", Source: "nvd"}, &pkg, verdict.BasisVersionNotAffected, "resolved version below first affected").
		AddPartiality(report.PartialityNote{Reason: "no_manifest", Ecosystem: "npm"}).
		AddPartiality(report.PartialityNote{Reason: "future_reason_code"}).
		Build()
	res := resultsink.Result{Report: r}

	surfaces := map[string]string{
		"Tier-0": renderedTier0Summary(t, r),
		"Tier-1": renderedTier1Body(t, res),
	}
	for name, s := range surfaces {
		if !strings.Contains(s, "**Partial coverage.**") {
			t.Fatalf("%s: fixture must render the disclosure\n---\n%s", name, s)
		}
		stripped := strings.ReplaceAll(s, ghsink.PRCommentMarker, "")
		for _, bad := range []string{"nucleon", "open-tegron", "tegron"} {
			if strings.Contains(strings.ToLower(stripped), bad) {
				t.Errorf("%s: disclosure leaks codename %q\n---\n%s", name, bad, stripped)
			}
		}
	}
}
