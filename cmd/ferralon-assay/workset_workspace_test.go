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
// module's go.mod: a sibling member is a dependency held at no released version. The standard
// library follows the toolchain fact over go.work's go and toolchain lines, the members' own being
// ignored: only an exact bound is a query point, and a directive is never one, so a directive-only
// workspace names stdlib with no version. With the workspace off the module's go.mod decides.
func TestGoInventory_Workspace(t *testing.T) {
	member := report.Package{Ecosystem: ecosystemGo, Name: "example.com/mono/b"}
	stdlib := report.Package{Ecosystem: ecosystemGo, Name: goStdlibPackage}
	at := func(v string) report.Package {
		return report.Package{Ecosystem: ecosystemGo, Name: goStdlibPackage, Version: v}
	}
	for _, tc := range []struct {
		name           string
		declared       string // -subject-gowork
		toolchain      string // declared subject toolchain
		wantResolved   []report.Package
		wantUnresolved []report.Package
	}{
		{name: "directives only", wantUnresolved: []report.Package{member, stdlib}},
		{name: "declared exact", toolchain: "go1.23.1", wantResolved: []report.Package{at("1.23.1")}, wantUnresolved: []report.Package{member}},
		{name: "declared below go.work's go line, above the module's", toolchain: "go1.22.1", wantUnresolved: []report.Package{member, stdlib}},
		{name: "GOWORK=off, directives only", declared: "off", wantUnresolved: []report.Package{stdlib}},
		{name: "GOWORK=off, declared above the module's go line", declared: "off", toolchain: "go1.22.1", wantResolved: []report.Package{at("1.22.1")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acq := goWorkFixture(t, tc.declared)
			acq.goToolchain = subjectGoToolchain{declared: tc.toolchain}
			resolved, unresolved, notes := dependencyInventory(context.Background(), acq)
			if len(notes) != 0 {
				t.Errorf("notes = %+v, want none", notes)
			}
			if !reflect.DeepEqual(resolved, tc.wantResolved) {
				t.Errorf("resolved = %+v, want %+v", resolved, tc.wantResolved)
			}
			if !reflect.DeepEqual(unresolved, tc.wantUnresolved) {
				t.Errorf("unresolved = %+v, want %+v", unresolved, tc.wantUnresolved)
			}
		})
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

// TestSubjectGoWorkOff_HandedInBesideACommittedGoWork: GOWORK=off handed in on the env channel the
// Action fills from the job's GOWORK, beside a committed go.work that uses the module, puts the
// pipeline and the work set on the module's go.mod: the pipeline resolves no workspace, and the work
// set holds no workspace member.
func TestSubjectGoWorkOff_HandedInBesideACommittedGoWork(t *testing.T) {
	t.Setenv(envAdvisoryCorpusDir, "")
	t.Setenv(envAdvisoryCorpusPolicy, "")
	t.Setenv(envSubjectGoWork, "off")
	f := runFlagsFor(t)
	acq := goWorkFixture(t, "")
	tree := filepath.Dir(acq.buildDir)

	for name, build := range map[string]func() ([]pipeline.AssessOption, error){
		"baseline": func() ([]pipeline.AssessOption, error) {
			return f.baselineAssessOptions(func(*pipeline.AssessConfig) {})
		},
		"run": func() ([]pipeline.AssessOption, error) { return f.runAssessOptions(func(*pipeline.AssessConfig) {}) },
	} {
		opts, err := build()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		declared := applyAll(opts).SubjectGoWork
		ws, err := pipeline.ResolveGoWorkspace(context.Background(), acq.buildDir, tree, declared)
		if err != nil || ws.File != "" {
			t.Errorf("%s: pipeline workspace = %+v, %v (declared %q), want none", name, ws, err, declared)
		}
	}

	acq.goWork = f.declaredGoWork()
	_, unresolved, _ := dependencyInventory(context.Background(), acq)
	if want := []report.Package{{Ecosystem: ecosystemGo, Name: goStdlibPackage}}; !reflect.DeepEqual(unresolved, want) {
		t.Errorf("work set unresolved = %+v, want %+v (the go.mod path, no member)", unresolved, want)
	}
}
