package pipeline

import (
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

// admittedPackagePURL feeds ReachabilityRequest.Package. It must be empty whenever the advisory
// PURL or the resolved version is unknown, or the advisory was adjudicated against the scanned
// project itself, because an empty Package forbids a package_not_loaded refutation.
func TestAdmittedPackagePURL(t *testing.T) {
	cases := []struct {
		name    string
		purl    string // normalized advisory purl; "" = no advisory artifact
		version string // inventory resolved_version; "" = no inventory artifact
		root    bool   // inventory adjudicated the advisory against the scanned project
		want    string
	}{
		{"both known", "pkg:npm/lodash", "4.17.20", false, "pkg:npm/lodash@4.17.20"},
		{"scoped npm name", "pkg:npm/%40babel/traverse", "7.23.0", false, "pkg:npm/%40babel/traverse@7.23.0"},
		{"advisory version replaced", "pkg:npm/lodash@4.17.0", "4.17.20", false, "pkg:npm/lodash@4.17.20"},
		{"qualifiers dropped", "pkg:pypi/django@3.2?arch=any#sub", "3.2.25", false, "pkg:pypi/django@3.2.25"},
		{"version unknown", "pkg:npm/lodash", "", false, ""},
		{"purl unknown", "", "4.17.20", false, ""},
		{"both unknown", "", "", false, ""},
		{"scanned project is the package", "pkg:npm/lodash", "4.17.20", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			caseID := "case-admitted-" + tc.name
			if tc.purl != "" {
				putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{"purl": tc.purl})
			}
			if tc.version != "" {
				putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{"resolved_version": tc.version, "root": tc.root})
			}
			if got := admittedPackagePURL(store, caseID); got != tc.want {
				t.Fatalf("admittedPackagePURL = %q, want %q", got, tc.want)
			}
		})
	}
}

// affectedInstalledVersions feeds ResolveSymbolsRequest.PackageVersions when installed copies
// disagree. It drops only a version the advisory's ranges provably exclude.
func TestAffectedInstalledVersions(t *testing.T) {
	qsRange := []map[string]any{{"lower_inclusive": "6.7.0", "upper_exclusive": "6.14.2", "scheme": "npm"}}
	cases := []struct {
		name   string
		inv    map[string]any // nil = no inventory artifact
		ranges []map[string]any
		want   []string
	}{
		{"copies disagree", map[string]any{"resolved_versions": []string{"6.7.0", "6.5.2"}}, qsRange, []string{"6.7.0"}},
		{"no usable range keeps every copy", map[string]any{"resolved_versions": []string{"6.7.0", "6.5.2"}}, nil, []string{"6.7.0", "6.5.2"}},
		{"unplaceable version kept", map[string]any{"resolved_versions": []string{"6.7.0", "not-a-version"}}, qsRange, []string{"6.7.0", "not-a-version"}},
		{"single version resolved", map[string]any{"resolved_version": "6.7.0", "resolved_versions": []string{"6.7.0"}}, qsRange, nil},
		{"scanned project is the package", map[string]any{"resolved_versions": []string{"6.7.0", "6.5.2"}, "root": true}, qsRange, nil},
		{"no inventory", nil, qsRange, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			caseID := "case-installed-" + tc.name
			adv := map[string]any{"purl": "pkg:npm/qs"}
			if tc.ranges != nil {
				adv["affected_ranges"] = tc.ranges
			}
			putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, adv)
			if tc.inv != nil {
				putJSON(t, store, caseID, artifact.TypeInventory, tc.inv)
			}
			if got := affectedInstalledVersions(store, caseID); !slices.Equal(got, tc.want) {
				t.Fatalf("affectedInstalledVersions = %v, want %v", got, tc.want)
			}
		})
	}
}
