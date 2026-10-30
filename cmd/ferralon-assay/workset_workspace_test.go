package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// goWorkFixture writes a go.work monorepo whose module a builds under a workspace that also uses b,
// and returns an *acquired for a with the given -subject-gowork declaration ("" to discover). Neither
// module requires anything, so the go command computes the build list offline.
func goWorkFixture(t *testing.T, declared string) *acquired {
	t.Helper()
	tree := t.TempDir()
	for name, body := range map[string]string{
		"go.work":    "go 1.22.3\n\nuse (\n\t./a\n\t./b\n)\n",
		"a/go.mod":   "module example.com/mono/a\n\ngo 1.22\n\ntoolchain go1.24.3\n",
		"a/main.go":  "package main\n\nimport \"example.com/mono/b/pkg\"\n\nfunc main() { pkg.Vuln() }\n",
		"b/go.mod":   "module example.com/mono/b\n\ngo 1.22\n",
		"b/pkg/b.go": "package pkg\n\nfunc Vuln() {}\n",
	} {
		path := filepath.Join(tree, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if declared == "" {
		declared = filepath.Join(tree, "go.work")
	}
	return &acquired{
		buildDir:   filepath.Join(tree, "a"),
		language:   checkout.LangGo,
		goWork:     declared,
		advisories: goAdvisoryCorpus(false),
	}
}

// TestGoInventory_Workspace: under a go.work the inventory is the workspace build's, not the
// module's go.mod: a sibling member is a dependency held at no released version, and the standard
// library is keyed to go.work's go line, the members' toolchain lines being ignored.
func TestGoInventory_Workspace(t *testing.T) {
	acq := goWorkFixture(t, "")
	resolved, unresolved, notes := dependencyInventory(context.Background(), acq)
	if len(notes) != 0 {
		t.Errorf("notes = %+v, want none", notes)
	}
	if want := []report.Package{{Ecosystem: ecosystemGo, Name: goStdlibPackage, Version: "1.22.3"}}; !reflect.DeepEqual(resolved, want) {
		t.Errorf("resolved = %+v, want %+v", resolved, want)
	}
	if want := []report.Package{{Ecosystem: ecosystemGo, Name: "example.com/mono/b"}}; !reflect.DeepEqual(unresolved, want) {
		t.Errorf("unresolved = %+v, want %+v", unresolved, want)
	}

	acq.goWork = "off"
	resolved, unresolved, _ = dependencyInventory(context.Background(), acq)
	if want := []report.Package{{Ecosystem: ecosystemGo, Name: goStdlibPackage, Version: "1.24.3"}}; !reflect.DeepEqual(resolved, want) || len(unresolved) != 0 {
		t.Errorf("GOWORK=off: resolved = %+v, unresolved = %+v; want %+v and none", resolved, unresolved, want)
	}
}

// TestPolicyWorkSet_AdmitsWorkspaceMembers: a policy advisory against a module the build's go.work
// uses is admitted, and one against a module outside the build is not; with the workspace off the
// member is outside the build.
func TestPolicyWorkSet_AdmitsWorkspaceMembers(t *testing.T) {
	entries := []corpusEntry{
		{doc: goRecord("TEST-MEMBER", "example.com/mono/b")},
		{doc: goRecord("TEST-UNRELATED", "example.org/other")},
	}
	for _, tc := range []struct {
		declared string
		want     []string
	}{
		{"", []string{"TEST-MEMBER"}},
		{"off", nil},
	} {
		t.Run("gowork="+tc.declared, func(t *testing.T) {
			corpus := pipeline.NewBundleSource(writePolicyBundle(t, entries))
			acq := goWorkFixture(t, tc.declared)
			ws := selectWorkSet(context.Background(), acq, corpus, corpus, "full", false, &fakeOSV{})
			if got := extraIDs(ws, len(acq.advisories)); !slices.Equal(got, tc.want) {
				t.Fatalf("admitted %v, want %v", got, tc.want)
			}
		})
	}
}

// TestOSVWorkSet_WorkspaceMemberIsNamedNotQueried: OSV is never asked about a workspace member,
// which has no released version, and the member is disclosed as unversioned instead.
func TestOSVWorkSet_WorkspaceMemberIsNamedNotQueried(t *testing.T) {
	osv := &fakeOSV{}
	ws := resolveWorkSet(context.Background(), goWorkFixture(t, ""), osv, pipeline.NewTableSource())
	for _, p := range osv.seen {
		if p.Name == "example.com/mono/b" {
			t.Errorf("OSV was asked about the member: %+v", p)
		}
	}
	if !slices.Contains(ws.unversioned, "example.com/mono/b") {
		t.Errorf("unversioned = %v, want the member named", ws.unversioned)
	}
}
