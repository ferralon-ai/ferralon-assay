package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

// TestPolicyWorkSet_AdmitsTheRepositoryItself: a policy advisory against the scanned project's own
// package is admitted, judged as codebase_inventory judges it, even with no dependency inventory.
func TestPolicyWorkSet_AdmitsTheRepositoryItself(t *testing.T) {
	unrelated := corpusEntry{doc: goRecord("TEST-UNRELATED", "example.org/other")}
	cases := []struct {
		name    string
		acq     func(t *testing.T) *acquired
		entries []corpusEntry
		want    []string
	}{
		{
			name: "go module and a package path inside it",
			acq:  func(t *testing.T) *acquired { return goFixture(t, fixtureGoMod) },
			entries: []corpusEntry{
				unrelated,
				{doc: goRecord("TEST-ROOT-MODULE", "example.com/fixture")},
				{doc: goRecord("TEST-ROOT-PACKAGE", "example.com/fixture/internal/x")},
				{doc: goRecord("TEST-ROOT-V2", "example.com/fixture/v2")},
				{doc: goRecord("TEST-PREFIX-ONLY", "example.com/fixtures")},
				{doc: npmRecord("TEST-OTHER-ECOSYSTEM", "example.com/fixture")},
			},
			want: []string{"TEST-ROOT-MODULE", "TEST-ROOT-PACKAGE"},
		},
		{
			name: "npm package with no analyzer to inventory its dependencies",
			acq:  func(t *testing.T) *acquired { return jsFixture(t, `{"name":"next","version":"14.1.0"}`) },
			entries: []corpusEntry{
				unrelated,
				{doc: npmRecord("TEST-NEXT", "next")},
				{doc: npmRecord("TEST-NEXT-AUTH", "next-auth")},
			},
			want: []string{"TEST-NEXT"},
		},
		{
			name:    "private npm package",
			acq:     func(t *testing.T) *acquired { return jsFixture(t, `{"name":"next","private":true}`) },
			entries: []corpusEntry{{doc: npmRecord("TEST-NEXT", "next")}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			corpus := pipeline.NewBundleSource(writePolicyBundle(t, tc.entries))
			acq := tc.acq(t)
			ws := selectWorkSet(context.Background(), acq, corpus, corpus, "full", false, &fakeOSV{})
			if got := extraIDs(ws, len(acq.advisories)); !reflect.DeepEqual(got, tc.want) && (len(got) != 0 || len(tc.want) != 0) {
				t.Fatalf("admitted %v, want %v", got, tc.want)
			}
		})
	}
}

// TestOSVWorkSet_QueriesTheVersionedRoot: the OSV widening asks about the project's own package
// when its version is known, and never about an unversioned one.
func TestOSVWorkSet_QueriesTheVersionedRoot(t *testing.T) {
	for _, tc := range []struct {
		name     string
		manifest string
		want     bool
	}{
		{"versioned", `{"name":"next","version":"14.1.0"}`, true},
		{"unversioned", `{"name":"next"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acq := jsFixture(t, tc.manifest)
			osv := &fakeOSV{}
			resolveWorkSet(context.Background(), acq, osv, pipeline.NewTableSource())
			queried := false
			for _, p := range osv.seen {
				if p.Root && p.Name == "next" && p.Version == "14.1.0" && p.Ecosystem == ecosystemNPM {
					queried = true
				}
			}
			if queried != tc.want {
				t.Fatalf("root queried = %v, want %v (seen %+v)", queried, tc.want, osv.seen)
			}
		})
	}
}

func jsFixture(t *testing.T, packageJSON string) *acquired {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(packageJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	return &acquired{buildDir: dir, language: checkout.LangJS, repo: "example.com/js"}
}
