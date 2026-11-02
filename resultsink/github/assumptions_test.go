package github_test

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

const assumptionsLabel = "**Assumptions.**"

func installAssumption(path, detail string) report.PartialityNote {
	return report.PartialityNote{Reason: plugin.AnnotationInstallSurfaceInactive, Ecosystem: "PyPI", Path: path, Detail: detail}
}

// An assumption is shown beside the counts it qualifies, never in the limits footer, and leaves
// the headline clean: the versions it rests on were resolved.
func TestBothSurfaces_AssumptionShownBesideCountsNotInFooter(t *testing.T) {
	r := goScanReport(installAssumption("ci/steps.yml:2", "install commands found at ci/steps.yml:2; this analysis assumes they are not active"))
	for name, s := range bothSurfaces(t, r) {
		if !strings.Contains(s, goCleanHeadline) {
			t.Errorf("%s: an assumption must not qualify the headline\n---\n%s", name, s)
		}
		i := strings.Index(s, assumptionsLabel)
		if i < 0 {
			t.Fatalf("%s: no assumptions block\n---\n%s", name, s)
		}
		const line = "PyPI: Install commands were found at `ci/steps.yml:2`, which nothing in the build was found to run; the verdicts assume they are not active."
		if !strings.Contains(s, line) {
			t.Errorf("%s: missing %q\n---\n%s", name, line, s)
		}
		if f := strings.Index(s, limitsFooterLabel); f >= 0 && strings.Contains(s[f:], "ci/steps.yml") {
			t.Errorf("%s: the assumption leaked into the limits footer\n---\n%s", name, s)
		}
		if j := strings.Index(s, "| Verdict"); j >= 0 && j < i {
			t.Errorf("%s: the assumptions block must precede the counts table\n---\n%s", name, s)
		}
	}
}

// A scan that made no assumption renders no block.
func TestBothSurfaces_NoAssumptionNoBlock(t *testing.T) {
	for name, s := range bothSurfaces(t, goScanReport()) {
		if strings.Contains(s, assumptionsLabel) {
			t.Errorf("%s: assumptions block without an assumption\n---\n%s", name, s)
		}
	}
}

// The comment phrases an assumption from its code and path, so markdown in the Detail the
// scanned repository shapes never reaches it, and the path renders inside a code span.
func TestBothSurfaces_AssumptionDetailNotRendered(t *testing.T) {
	r := goScanReport(installAssumption("a`b.yml:1", "[click](https://example.invalid) **bold**"))
	for name, s := range bothSurfaces(t, r) {
		if strings.Contains(s, "example.invalid") || strings.Contains(s, "**bold**") {
			t.Errorf("%s: Detail reached the comment\n---\n%s", name, s)
		}
		if !strings.Contains(s, "a`b.yml:1") {
			t.Errorf("%s: the path is missing\n---\n%s", name, s)
		}
	}
}
