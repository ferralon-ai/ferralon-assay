package trigger

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

func launchTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestJSLaunchDigest: the digest moves with the scripts and bin of a first-party package.json and
// with nothing else.
func TestJSLaunchDigest(t *testing.T) {
	const root = `{"name": "app", "version": "1.0.0", "scripts": {"start": "node server.js", "build": "tsc"}, "bin": {"app": "cli.js"}}`
	base := map[string]string{"package.json": root}
	with := func(over map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range over {
			m[k] = v
		}
		return m
	}
	cases := []struct {
		name  string
		files map[string]string
		same  bool
	}{
		{"a script command changed", with(map[string]string{"package.json": `{"name": "app", "version": "1.0.0", "scripts": {"start": "node other.js", "build": "tsc"}, "bin": {"app": "cli.js"}}`}), false},
		{"a script added", with(map[string]string{"package.json": `{"name": "app", "version": "1.0.0", "scripts": {"start": "node server.js", "build": "tsc", "postinstall": "node setup.js"}, "bin": {"app": "cli.js"}}`}), false},
		{"a bin target changed", with(map[string]string{"package.json": `{"name": "app", "version": "1.0.0", "scripts": {"start": "node server.js", "build": "tsc"}, "bin": {"app": "bin/cli.js"}}`}), false},
		{"bin as a string", with(map[string]string{"package.json": `{"name": "app", "version": "1.0.0", "scripts": {"start": "node server.js", "build": "tsc"}, "bin": "cli.js"}`}), false},
		{"a workspace member's script changed", with(map[string]string{"packages/web/package.json": `{"scripts": {"start": "vite"}}`}), false},
		{"a first-party package.json moved", map[string]string{"sub/package.json": root}, false},
		{"unparsable package.json", with(map[string]string{"package.json": `{"scripts": {`}), false},
		{"keys reordered and reformatted", with(map[string]string{"package.json": "{\n  \"bin\": {\"app\": \"cli.js\"},\n  \"scripts\": {\"build\": \"tsc\", \"start\": \"node server.js\"},\n  \"version\": \"1.0.0\", \"name\": \"app\"\n}"}), true},
		{"a non-launch field changed", with(map[string]string{"package.json": `{"name": "app", "version": "2.0.0", "dependencies": {"left-pad": "^1.3.0"}, "scripts": {"start": "node server.js", "build": "tsc"}, "bin": {"app": "cli.js"}}`}), true},
		{"a node_modules package.json", with(map[string]string{"node_modules/left-pad/package.json": `{"scripts": {"install": "node evil.js"}}`}), true},
		{"a dot-directory package.json", with(map[string]string{".cache/x/package.json": `{"scripts": {"start": "x"}}`}), true},
		{"a file that is not package.json", with(map[string]string{"server.js": "console.log(1)"}), true},
	}
	want := jsLaunchDigest(launchTree(t, base))
	if want == "" {
		t.Fatal("digest of a tree with a package.json is empty")
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := jsLaunchDigest(launchTree(t, tc.files))
			if (got == want) != tc.same {
				t.Errorf("digest equal to the base tree's = %v, want %v", got == want, tc.same)
			}
		})
	}
	t.Run("no package.json", func(t *testing.T) {
		if got := jsLaunchDigest(launchTree(t, map[string]string{"go.mod": "module m\n"})); got != "" {
			t.Errorf("digest = %q, want empty", got)
		}
	})
	t.Run("only a node_modules package.json", func(t *testing.T) {
		if got := jsLaunchDigest(launchTree(t, map[string]string{"node_modules/x/package.json": `{"scripts": {"a": "b"}}`})); got != "" {
			t.Errorf("digest = %q, want empty", got)
		}
	})
	t.Run("no dir", func(t *testing.T) {
		if got := jsLaunchDigest(""); got != "" {
			t.Errorf("digest = %q, want empty", got)
		}
	})
}

// TestRelaunched_PRInherit: tracker#896. A PR that edits only package.json scripts or bin leaves
// the SBOM alone, so the package diff alone would inherit every row. The launch digest blocks the
// fast path, and in the re-analysis an npm row is assessed again while a row of another ecosystem,
// which no script or bin reaches, is kept.
func TestRelaunched_PRInherit(t *testing.T) {
	const before, after = "digest-before", "digest-after"
	t.Run("go row", func(t *testing.T) {
		for _, tc := range []struct {
			name      string
			head      string
			inherited bool
		}{
			{"launch changed", after, false},
			{"launch unchanged", before, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				pkg := wiringPkg
				baseline := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base-sha"}).
					AddPackage(pkg).
					SetJSLaunchDigest(report.SBOM{JSLaunchDigest: before}).
					NotExploitable(report.Advisory{ID: wiringAdvisory.ID, Source: wiringAdvisory.Source}, &pkg, "vulnerable_symbol_absent", baselineDetail).
					WithProvenance(report.Provenance{CommitSHA: "base-sha", AdvisoryCursor: wiringAdvisory.ID}).
					Build()
				store := &memStore{state: &statestore.State{Report: &baseline, SBOM: baseline.SBOM, Cursor: wiringAdvisory.ID}}
				head := baseline.SBOM
				head.JSLaunchDigest = tc.head
				res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
					Subject:       Subject{Repo: "r", ResolvedCommit: "pr-sha"},
					Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
					PRSBOM:        head,
					Advisories:    []assessment.VulnRef{wiringAdvisory},
					AssessOptions: wiringOptions(t, plugin.Complete()),
				})
				if err != nil {
					t.Fatalf("RunPRInherit: %v", err)
				}
				if res.Inherited != tc.inherited {
					t.Fatalf("Inherited = %v, want %v", res.Inherited, tc.inherited)
				}
				if got := rowDetail(t, res.Report); got != baselineDetail {
					t.Errorf("row detail = %q, want the baseline's kept", got)
				}
				if got := res.Report.SBOM.JSLaunchDigest; got != tc.head {
					t.Errorf("report js_launch_digest = %q, want the head's %q", got, tc.head)
				}
			})
		}
	})
	t.Run("npm row", func(t *testing.T) {
		lock := `{"name": "app", "lockfileVersion": 3, "packages": {
  "": {"name": "app", "version": "1.0.0"},
  "node_modules/left-pad": {"version": "1.4.0"},
  "node_modules/wrapper": {"version": "2.0.0"},
  "node_modules/wrapper/node_modules/left-pad": {"version": "1.5.0"}}}`
		advisory := assessment.VulnRef{ID: "FERRALON-JS-DEP-0001", Source: "corpus"}
		leftPad := func(v string) report.Package {
			return report.Package{Ecosystem: "npm", Name: "left-pad", Version: v, PURL: "pkg:npm/left-pad@" + v}
		}
		pkgs := []report.Package{leftPad("1.4.0"), leftPad("1.5.0"), {Ecosystem: "npm", Name: "wrapper", Version: "2.0.0", PURL: "pkg:npm/wrapper@2.0.0"}}
		for _, tc := range []struct {
			name  string
			head  string
			extra bool // the head also adds an unrelated package, so the run re-analyzes either way
			fresh bool
		}{
			{"launch changed", after, false, true},
			{"launch changed beside a package change", after, true, true},
			{"launch unchanged beside a package change", before, true, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				dir := launchTree(t, map[string]string{"package-lock.json": lock})
				rowPkg := report.Package{Ecosystem: "npm", Name: "left-pad"}
				baseline := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base-sha"}).
					AddPackages(pkgs...).
					SetJSLaunchDigest(report.SBOM{JSLaunchDigest: before}).
					NotExploitable(report.Advisory{ID: advisory.ID, Source: advisory.Source}, &rowPkg, "vulnerable_symbol_unreachable", baselineDetail).
					WithProvenance(report.Provenance{CommitSHA: "base-sha", AdvisoryCursor: advisory.ID}).
					Build()
				store := &memStore{state: &statestore.State{Report: &baseline, SBOM: baseline.SBOM, Cursor: advisory.ID}}
				head := report.SBOM{Packages: append([]report.Package(nil), pkgs...), JSLaunchDigest: tc.head}
				if tc.extra {
					head.Packages = append(head.Packages, report.Package{Ecosystem: "npm", Name: "unrelated", Version: "1.0.0", PURL: "pkg:npm/unrelated@1.0.0"})
				}
				res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
					Subject:    Subject{Repo: "r", ResolvedCommit: "pr-sha"},
					Codebase:   assessment.CodebaseRef{Repo: "r", Revision: "main"},
					PRSBOM:     head,
					Advisories: []assessment.VulnRef{advisory},
					AssessOptions: []pipeline.AssessOption{
						pipeline.WithCheckout(fixedCheckout{dir: dir, lang: "js"}),
						pipeline.WithPlugin(multiCopyJSPlugin{inventory: plugin.Complete()}),
					},
				})
				if err != nil {
					t.Fatalf("RunPRInherit: %v", err)
				}
				if res.Inherited {
					t.Fatal("took the inherit fast path")
				}
				var row *report.AdvisoryFinding
				for i := range res.Report.Advisories {
					if res.Report.Advisories[i].Advisory.ID == advisory.ID {
						row = &res.Report.Advisories[i]
					}
				}
				if row == nil {
					t.Fatalf("no %s row", advisory.ID)
				}
				if fresh := row.Evidence.Detail != baselineDetail; fresh != tc.fresh {
					t.Errorf("row %s (%q): fresh = %v, want %v", row.Verdict, row.Evidence.Detail, fresh, tc.fresh)
				}
			})
		}
	})
}

// TestOnJSLane: a row with no package may rest on any lane's entry points, the js lane's included.
func TestOnJSLane(t *testing.T) {
	for _, tc := range []struct {
		pkg  *report.Package
		want bool
	}{
		{nil, true},
		{&report.Package{Ecosystem: "npm", Name: "x"}, true},
		{&report.Package{Ecosystem: "Go", Name: "x"}, false},
		{&report.Package{Ecosystem: "PyPI", Name: "x"}, false},
	} {
		if got := onJSLane(tc.pkg); got != tc.want {
			t.Errorf("onJSLane(%+v) = %v, want %v", tc.pkg, got, tc.want)
		}
	}
}

// TestBaselineRecordsJSLaunchDigest: a baseline records its own tree's digest, which the next PR is
// compared against.
func TestBaselineRecordsJSLaunchDigest(t *testing.T) {
	dir := launchTree(t, map[string]string{
		"package.json":      `{"name": "app", "version": "1.0.0", "scripts": {"start": "node server.js"}}`,
		"package-lock.json": `{"name": "app", "lockfileVersion": 3, "packages": {"": {"name": "app", "version": "1.0.0"}, "node_modules/left-pad": {"version": "1.4.0"}}}`,
	})
	rep, err := buildBaselineReport(context.Background(), BaselineRequest{
		Subject:    Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
		Codebase:   assessment.CodebaseRef{Repo: "r", Revision: "main"},
		Advisories: []assessment.VulnRef{{ID: "FERRALON-JS-DEP-0001", Source: "corpus"}},
		AssessOptions: []pipeline.AssessOption{
			pipeline.WithCheckout(fixedCheckout{dir: dir, lang: "js"}),
			pipeline.WithPlugin(multiCopyJSPlugin{inventory: plugin.Complete()}),
		},
	})
	if err != nil {
		t.Fatalf("buildBaselineReport: %v", err)
	}
	if want := jsLaunchDigest(dir); want == "" || rep.SBOM.JSLaunchDigest != want {
		t.Fatalf("baseline js_launch_digest = %q, want %q", rep.SBOM.JSLaunchDigest, want)
	}
}
