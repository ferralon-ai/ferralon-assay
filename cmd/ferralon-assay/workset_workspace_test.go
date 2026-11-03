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
	"github.com/ferralon-ai/ferralon-assay/plugin"
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

// TestGoInventory_WorkspaceBuildToolchain: the analyzer's resolved build toolchain is read under the
// go.work the build runs under, as the pipeline reads it, so the stdlib query point follows the
// workspace build's toolchain rather than the module's alone. go.work's two-part go line does not
// bind, so under trust the build's resolution decides.
func TestGoInventory_WorkspaceBuildToolchain(t *testing.T) {
	acq := goWorkFixture(t, "")
	work := filepath.Join(filepath.Dir(acq.buildDir), "go.work")
	if err := os.WriteFile(work, []byte("go 1.22\n\nuse (\n\t./a\n\t./b\n)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := filepath.EvalSymlinks(work)
	if err != nil {
		t.Fatal(err)
	}
	build := &goWorkToolchainAnalyzer{unsearchingAnalyzer: unsearchingAnalyzer{language: "go"},
		byGoWork: map[string]string{file: "go1.22.9", "": "go1.22.4"}}
	acq.plugin = build
	acq.goToolchain = subjectGoToolchain{trustObserved: true}

	resolved, _, _ := dependencyInventory(context.Background(), acq)
	want := []report.Package{{Ecosystem: ecosystemGo, Name: goStdlibPackage, Version: "1.22.9"}}
	if !reflect.DeepEqual(resolved, want) {
		t.Errorf("resolved = %+v, want %+v (BuildManifest saw GOWORK %q)", resolved, want, build.seen)
	}
}

// goWorkToolchainAnalyzer is an unsearchingAnalyzer whose build manifest resolves the Go toolchain
// byGoWork[the request's GoWork], recording the GoWork it was asked under.
type goWorkToolchainAnalyzer struct {
	unsearchingAnalyzer
	byGoWork map[string]string
	seen     []string
}

func (a *goWorkToolchainAnalyzer) BuildManifest(_ context.Context, req plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	a.seen = append(a.seen, req.GoWork)
	return plugin.BuildManifestResult{Runtimes: []plugin.RuntimeSpec{{Name: "go", Resolved: a.byGoWork[req.GoWork]}}}, nil
}

// TestGoInventory_UnreadableWorkspace: when the workspace's build list cannot be read, here a used
// member's go.mod that does not parse, the module's go.mod requires are named but given no version:
// under the workspace's MVS a require is a lower bound, not the version built.
func TestGoInventory_UnreadableWorkspace(t *testing.T) {
	acq := goWorkFixture(t, "")
	tree := filepath.Dir(acq.buildDir)
	for name, body := range map[string]string{
		"a/go.mod": "module example.com/mono/a\n\ngo 1.22\n\nrequire example.com/dep v1.2.3\n",
		"b/go.mod": "this is not a go.mod\n",
	} {
		if err := os.WriteFile(filepath.Join(tree, filepath.FromSlash(name)), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ws, _ := goWorkspace(context.Background(), acq, acq.buildDir)
	if _, _, err := pipeline.GoWorkspaceModules(context.Background(), acq.buildDir, ws); err == nil {
		t.Fatal("GoWorkspaceModules read the workspace; the fixture must make it fail")
	}

	resolved, unresolved, notes := dependencyInventory(context.Background(), acq)
	if len(notes) != 0 {
		t.Errorf("notes = %+v, want none", notes)
	}
	if len(resolved) != 0 {
		t.Errorf("resolved = %+v, want none: no module or stdlib version is known", resolved)
	}
	want := []report.Package{
		{Ecosystem: ecosystemGo, Name: "example.com/dep"},
		{Ecosystem: ecosystemGo, Name: goStdlibPackage},
	}
	if !reflect.DeepEqual(unresolved, want) {
		t.Errorf("unresolved = %+v, want %+v", unresolved, want)
	}
}

// TestGoInventory_UnresolvedWorkspace: a declared go.work the build's workspace cannot be resolved
// from (missing, or not using the module) leaves what the build holds unknown, so the module's
// go.mod requires are named with no version, and so is the standard library, even under a declared
// toolchain the module's own go lines would admit: which go lines bind the build is unknown too.
func TestGoInventory_UnresolvedWorkspace(t *testing.T) {
	for _, tc := range []struct {
		name     string
		declared func(tree string) string
	}{
		{name: "missing", declared: func(string) string { return "nope/go.work" }},
		{name: "does not use the module", declared: func(tree string) string {
			other := filepath.Join(tree, "other.work")
			if err := os.WriteFile(other, []byte("go 1.22.3\n\nuse ./b\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return "other.work"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acq := goWorkFixture(t, "")
			tree := filepath.Dir(acq.buildDir)
			mod := "module example.com/mono/a\n\ngo 1.22\n\nrequire example.com/dep v1.2.3\n"
			if err := os.WriteFile(filepath.Join(acq.buildDir, "go.mod"), []byte(mod), 0o600); err != nil {
				t.Fatal(err)
			}
			acq.goWork = tc.declared(tree)
			acq.goToolchain = subjectGoToolchain{declared: "go1.22.1"}
			if _, ok := goWorkspace(context.Background(), acq, acq.buildDir); ok {
				t.Fatal("the declared go.work resolved; the fixture must make it fail")
			}

			resolved, unresolved, notes := dependencyInventory(context.Background(), acq)
			if len(notes) != 0 {
				t.Errorf("notes = %+v, want none", notes)
			}
			if len(resolved) != 0 {
				t.Errorf("resolved = %+v, want none: no module or stdlib version is known", resolved)
			}
			want := []report.Package{
				{Ecosystem: ecosystemGo, Name: "example.com/dep"},
				{Ecosystem: ecosystemGo, Name: goStdlibPackage},
			}
			if !reflect.DeepEqual(unresolved, want) {
				t.Errorf("unresolved = %+v, want %+v", unresolved, want)
			}
		})
	}
}
