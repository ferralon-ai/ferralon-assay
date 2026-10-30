package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestWorkSet_GoModuleBelowCheckoutRoot: the work set reads the module checkout.FindGoModuleRoot
// picks — the root codebase_inventory analyzes — so a monorepo with no go.mod at the checkout root
// still gets OSV widening and policy admission instead of a no_manifest note.
func TestWorkSet_GoModuleBelowCheckoutRoot(t *testing.T) {
	gomod := func(module, dep string) string {
		return "module " + module + "\n\ngo 1.21.0\n\nrequire " + dep + " v0.30.0\n"
	}
	for _, tc := range []struct {
		name       string
		files      map[string]string
		wantModule string
		wantDep    string
	}{
		{
			name:       "single module below the root",
			files:      map[string]string{"services/api/go.mod": gomod("example.com/api", "golang.org/x/crypto")},
			wantModule: "example.com/api",
			wantDep:    "golang.org/x/crypto",
		},
		{
			name: "root go.work and no root go.mod",
			files: map[string]string{
				"go.work":             "go 1.21.0\n\nuse ./services/api\n",
				"services/api/go.mod": gomod("example.com/api", "golang.org/x/crypto"),
			},
			wantModule: "example.com/api",
			wantDep:    "golang.org/x/crypto",
		},
		{
			name: "two modules at one depth and no root",
			files: map[string]string{
				"b/go.mod": gomod("example.com/b", "golang.org/x/net"),
				"a/go.mod": gomod("example.com/a", "golang.org/x/crypto"),
			},
			wantModule: "example.com/a", // the lexically first at the shallowest depth
			wantDep:    "golang.org/x/crypto",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for rel, body := range tc.files {
				p := filepath.Join(dir, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			acq := &acquired{buildDir: dir, language: checkout.LangGo, repo: "example.com/mono", advisories: goAdvisoryCorpus(false)}

			osv := &fakeOSV{}
			ws := resolveWorkSet(context.Background(), acq, osv, pipeline.NewTableSource())
			for _, n := range ws.partiality {
				if n.Reason == plugin.PartialReasonNoManifest {
					t.Errorf("no_manifest disclosed for a module FindGoModuleRoot finds: %+v", n)
				}
			}
			queried := map[string]string{}
			for _, p := range osv.seen {
				queried[p.Name] = p.Version
			}
			if queried[tc.wantDep] != "v0.30.0" {
				t.Errorf("OSV queried %v, want %s@v0.30.0 from %s", queried, tc.wantDep, tc.wantModule)
			}
			if len(queried) != 2 { // the picked module's one require plus stdlib
				t.Errorf("OSV queried %v, want only the picked module's inventory", queried)
			}

			corpus := pipeline.NewBundleSource(writePolicyBundle(t, []corpusEntry{
				{doc: goRecord("TEST-PICKED", tc.wantModule)},
				{doc: goRecord("TEST-OTHER", "example.com/b")},
			}))
			pol := selectWorkSet(context.Background(), acq, corpus, corpus, "full", false, &fakeOSV{})
			if got, want := extraIDs(pol, len(acq.advisories)), []string{"TEST-PICKED"}; !reflect.DeepEqual(got, want) {
				t.Errorf("policy admitted %v, want %v", got, want)
			}
		})
	}
}

// TestWorkSet_GoNestedModuleRootQuery: the project's own module is queried at the version its
// prefixed tag names, which is read from the module FindGoModuleRoot picks, not the checkout root.
func TestWorkSet_GoNestedModuleRootQuery(t *testing.T) {
	dir := t.TempDir()
	writeT(t, filepath.Join(dir, "services", "api", "go.mod"), "module example.com/api\n\ngo 1.21.0\n")
	gitT(t, dir, "init", "-q")
	gitT(t, dir, "add", "-A")
	gitT(t, dir, "commit", "-q", "-m", "init")
	gitT(t, dir, "tag", "services/api/v1.2.3")

	acq := &acquired{buildDir: dir, language: checkout.LangGo, repo: "example.com/mono", advisories: goAdvisoryCorpus(false)}
	osv := &fakeOSV{}
	resolveWorkSet(context.Background(), acq, osv, pipeline.NewTableSource())
	for _, p := range osv.seen {
		if p.Root && p.Name == "example.com/api" && p.Version == "v1.2.3" && p.Ecosystem == ecosystemGo {
			return
		}
	}
	t.Fatalf("root module not queried at its tag; seen %+v", osv.seen)
}
