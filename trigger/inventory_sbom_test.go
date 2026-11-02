package trigger

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// A Maven PURL spells its coordinate group/artifact, but OSV addresses Maven packages as
// group:artifact. If the SBOM projection kept the slash form, every Maven package would query OSV
// under a name that never matches — a silent advisory miss. This pins the colon form, and pins that
// the other ecosystems keep the name OSV actually uses (slash for Go/npm, bare for PyPI/NuGet).
func TestEcosystemAndNameFromPURL_CoordinateForm(t *testing.T) {
	tests := []struct {
		name     string
		purl     string
		fallback string
		wantEco  string
		wantName string
	}{
		{
			name:     "maven rewrites group/artifact to group:artifact",
			purl:     "pkg:maven/com.google.code.gson/gson@2.10.1",
			fallback: "Maven",
			wantEco:  "Maven",
			wantName: "com.google.code.gson:gson",
		},
		{
			name:     "maven with qualifiers still yields the colon coordinate",
			purl:     "pkg:maven/org.apache.commons/commons-lang3@3.12.0?type=jar",
			fallback: "Maven",
			wantEco:  "Maven",
			wantName: "org.apache.commons:commons-lang3",
		},
		{
			name:     "go keeps its module path with slashes",
			purl:     "pkg:golang/golang.org/x/text@v0.3.7",
			fallback: "Go",
			wantEco:  "Go",
			wantName: "golang.org/x/text",
		},
		{
			name:     "npm scoped package keeps the slash",
			purl:     "pkg:npm/@angular/core@17.0.0",
			fallback: "npm",
			wantEco:  "npm",
			wantName: "@angular/core",
		},
		{
			name:     "pypi carries no namespace",
			purl:     "pkg:pypi/requests@2.31.0",
			fallback: "PyPI",
			wantEco:  "PyPI",
			wantName: "requests",
		},
		{
			name:     "nuget carries no namespace",
			purl:     "pkg:nuget/Newtonsoft.Json@13.0.1",
			fallback: "NuGet",
			wantEco:  "NuGet",
			wantName: "Newtonsoft.Json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eco, name := ecosystemAndNameFromPURL(tt.purl, tt.fallback)
			if eco != tt.wantEco {
				t.Errorf("ecosystem = %q, want %q", eco, tt.wantEco)
			}
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
		})
	}
}

// The Maven fix must survive the whole inventory→SBOM projection, not just the helper: a Maven
// inventory node must reach report.SBOM under the colon coordinate OSV can match.
func TestSBOMFromInventory_MavenColonCoordinate(t *testing.T) {
	inv := plugin.DependencyInventory{
		Nodes: []plugin.DependencyNode{{
			ID:      "n1",
			PURL:    "pkg:maven/com.google.code.gson/gson@2.10.1",
			Version: "2.10.1",
			Direct:  true,
		}},
	}
	sbom, _ := sbomFromInventory(inv, "Maven")
	if len(sbom.Packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(sbom.Packages))
	}
	if got := sbom.Packages[0].Name; got != "com.google.code.gson:gson" {
		t.Errorf("Maven package name = %q, want %q", got, "com.google.code.gson:gson")
	}
	if got := sbom.Packages[0].Ecosystem; got != "Maven" {
		t.Errorf("ecosystem = %q, want %q", got, "Maven")
	}
}

// A lockfile package no install the build runs puts in place reaches the SBOM marked not installed
// rather than dropped, and a package two nodes collapse into is installed when either instance is.
func TestSBOMFromInventory_NotInstalled(t *testing.T) {
	inv := plugin.DependencyInventory{
		Nodes: []plugin.DependencyNode{
			{ID: "a", PURL: "pkg:pypi/pytest@8.3.2", Version: "8.3.2", NotInstalled: true},
			{ID: "b", PURL: "pkg:pypi/colorama@0.4.6", Version: "0.4.6", NotInstalled: true},
			{ID: "c", PURL: "pkg:pypi/colorama@0.4.6", Version: "0.4.6"},
			{ID: "d", PURL: "pkg:pypi/sphinx@7.4.7", Version: "7.4.7", NotInstalled: true},
			{ID: "e", PURL: "pkg:pypi/sphinx@7.4.7", Version: "7.4.7", NotInstalled: true},
		},
	}
	sbom, _ := sbomFromInventory(inv, "PyPI")
	want := map[string]bool{"pytest": true, "colorama": false, "sphinx": true}
	if len(sbom.Packages) != len(want) {
		t.Fatalf("got %d packages, want %d: %+v", len(sbom.Packages), len(want), sbom.Packages)
	}
	for _, p := range sbom.Packages {
		if w, ok := want[p.Name]; !ok || p.NotInstalled != w {
			t.Errorf("%s NotInstalled = %v, want %v", p.Name, p.NotInstalled, w)
		}
	}
}
