package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func goBuildListReport(workspace ...string) Report {
	pkg := Package{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.15.0", PURL: "pkg:golang/golang.org/x/net@v0.15.0", Direct: true}
	return NewBuilder(Subject{Repo: "example.com/app", ResolvedCommit: "sha"}).
		AddPackages(pkg).
		SetGoBuildList(SBOM{GoBuildList: "go mod graph", GoMainModule: "example.com/app", GoWorkspaceModules: workspace}).
		WithProvenance(Provenance{Timestamp: time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)}).
		Build()
}

// The Go build-list fields reach the report, the workspace modules sorted and de-duplicated, so the
// same build serializes byte-identically whatever order its modules were listed in.
func TestBuilderCarriesGoBuildList(t *testing.T) {
	a := goBuildListReport("example.com/b", "example.com/a", "example.com/b")
	b := goBuildListReport("example.com/a", "example.com/b")

	want := SBOM{GoBuildList: "go mod graph", GoMainModule: "example.com/app", GoWorkspaceModules: []string{"example.com/a", "example.com/b"}}
	got := SBOM{GoBuildList: a.SBOM.GoBuildList, GoMainModule: a.SBOM.GoMainModule, GoWorkspaceModules: a.SBOM.GoWorkspaceModules}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Go build-list fields = %+v, want %+v", got, want)
	}
	ja, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	jb, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ja, jb) {
		t.Fatalf("report bytes differ:\n%s\n%s", ja, jb)
	}
	var back Report
	if err := json.Unmarshal(ja, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.SBOM, a.SBOM) {
		t.Fatalf("SBOM did not round-trip:\n orig=%+v\n back=%+v", a.SBOM, back.SBOM)
	}
}

// A builder never handed the fields emits none of them, so a non-Go report's bytes are unchanged.
func TestBuilderWithoutGoBuildList(t *testing.T) {
	r := NewBuilder(Subject{Repo: "r", ResolvedCommit: "sha"}).
		AddPackages(Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}).
		Build()
	j, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if s := string(j); strings.Contains(s, `"go_`) {
		t.Fatalf("report without a Go build list carries a go_ field: %s", s)
	}
}

// SetGoBuildList copies the workspace slice, so a caller reusing its SBOM cannot reorder the report's.
func TestSetGoBuildListCopies(t *testing.T) {
	ws := []string{"example.com/a"}
	b := NewBuilder(Subject{Repo: "r", ResolvedCommit: "sha"}).SetGoBuildList(SBOM{GoBuildList: "go mod graph", GoMainModule: "m", GoWorkspaceModules: ws})
	ws[0] = "example.com/z"
	if got := b.Build().SBOM.GoWorkspaceModules; !reflect.DeepEqual(got, []string{"example.com/a"}) {
		t.Fatalf("GoWorkspaceModules = %v, want [example.com/a]", got)
	}
}
