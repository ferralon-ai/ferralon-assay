package pipeline

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

// admittedPackagePURL feeds ReachabilityRequest.Package. It must be empty whenever the advisory
// PURL or the resolved version is unknown, because an empty Package forbids a package_not_loaded
// refutation.
func TestAdmittedPackagePURL(t *testing.T) {
	cases := []struct {
		name    string
		purl    string // normalized advisory purl; "" = no advisory artifact
		version string // inventory resolved_version; "" = no inventory artifact
		want    string
	}{
		{"both known", "pkg:npm/lodash", "4.17.20", "pkg:npm/lodash@4.17.20"},
		{"scoped npm name", "pkg:npm/%40babel/traverse", "7.23.0", "pkg:npm/%40babel/traverse@7.23.0"},
		{"advisory version replaced", "pkg:npm/lodash@4.17.0", "4.17.20", "pkg:npm/lodash@4.17.20"},
		{"qualifiers dropped", "pkg:pypi/django@3.2?arch=any#sub", "3.2.25", "pkg:pypi/django@3.2.25"},
		{"version unknown", "pkg:npm/lodash", "", ""},
		{"purl unknown", "", "4.17.20", ""},
		{"both unknown", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			caseID := "case-admitted-" + tc.name
			if tc.purl != "" {
				putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{"purl": tc.purl})
			}
			if tc.version != "" {
				putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{"resolved_version": tc.version})
			}
			if got := admittedPackagePURL(store, caseID); got != tc.want {
				t.Fatalf("admittedPackagePURL = %q, want %q", got, tc.want)
			}
		})
	}
}
