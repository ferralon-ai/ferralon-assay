package brand

import "os"

// Derived identities. These reference the Name/Version consts (brand_identity.go)
// and are themselves consts where the call sites permit; the marker/title helpers
// stay funcs only because existing call sites invoke them as brand.Foo() — they
// fold to a constant at compile time.

// EnvOrLegacy resolves a brand-derived environment variable, falling back to the legacy names
// the tool has shipped under before when the brand-derived one is unset. Use it for any env var
// whose name is built from EnvPrefix (e.g. EnvPrefix+"_ADVISORY_CORPUS_DIR"): an operator may
// have set an earlier name by hand in workflow YAML, CI config, or a demo repo, and deriving
// the name from the brand must not silently break them.
//
// The brand-derived name always wins. The legacy names are tried in the order given, so call
// sites list them newest-first — ASSAY_X, then NUCLEON_X, then TEGRON_X. Empty is not a value:
// a name set to the empty string is treated as unset and resolution continues down the chain.
func EnvOrLegacy(derivedName string, legacyNames ...string) string {
	if v := os.Getenv(derivedName); v != "" {
		return v
	}
	for _, n := range legacyNames {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

// AnalyzerVersion is the version identity recorded on the Report provenance and
// the SARIF driver version: "<Name>/<Version>".
func AnalyzerVersion() string { return Name + "/" + Version }

// ReportTitle is the title used for the HTML report and Pages <title>.
func ReportTitle() string { return Name + " scan report" }

// SummaryHeading is the raw "<name> scan" heading form. The rendered Tier-0 and
// Tier-1 surfaces use Tier0SummaryHeading / Tier1SummaryHeading instead, so the
// customer-facing panels can be branded independently of the tool name
// (see brand_identity.go).
func SummaryHeading() string { return Name + " scan" }

// IssueTitle is the pinned dependency-dashboard Issue title.
func IssueTitle() string { return Name + ": dependency scan dashboard" }

// IssueMarker is the hidden HTML marker used to find/update the pinned Issue
// idempotently. It must stay stable within a process.
func IssueMarker() string { return "<!-- " + Name + ":dashboard -->" }

// PRCommentMarker is the hidden HTML marker used to find/update the sticky PR
// comment idempotently. It must stay stable within a process.
func PRCommentMarker() string { return "<!-- " + Name + ":sticky-comment -->" }
