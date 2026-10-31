package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/jsanalysis"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/pythonanalysis"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// inventoryAnalyzer is an unsearchingAnalyzer whose manifest declares deps. Match follows the
// plugin contract: a resolved declaration of the coordinate wins over an unresolved one, unless
// match decides the coordinate the way a reader does from copies outside All.
type inventoryAnalyzer struct {
	unsearchingAnalyzer
	deps  []plugin.ResolvedDependency
	match map[string]plugin.ResolvedDependency
	fail  map[string]bool // coordinates whose per-coordinate read fails
	miss  map[string]bool // coordinates the per-coordinate read doesn't find
}

func (a inventoryAnalyzer) ResolveDependencyVersions(_ context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	if a.fail[req.Coordinate] {
		return plugin.DependencyVersionResult{}, errors.New("reader failed")
	}
	res := plugin.DependencyVersionResult{Partiality: plugin.Complete(), All: a.deps}
	if a.miss[req.Coordinate] {
		return res, nil
	}
	if m, ok := a.match[req.Coordinate]; ok {
		res.Found, res.Match = true, m
		return res, nil
	}
	for _, d := range a.deps {
		if d.Coordinate != req.Coordinate {
			continue
		}
		if !res.Found || d.Resolved && !res.Match.Resolved {
			res.Found, res.Match = true, d
		}
	}
	return res, nil
}

// pythonInventory is the real Python lane's manifest reader behind the analyzer double.
type pythonInventory struct {
	unsearchingAnalyzer
}

func (pythonInventory) ResolveDependencyVersions(ctx context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	return pythonanalysis.ResolveDependencyVersions(ctx, req)
}

// jsInventory is the real JS lane's manifest reader behind the analyzer double.
type jsInventory struct {
	unsearchingAnalyzer
}

func (jsInventory) ResolveDependencyVersions(ctx context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	return jsanalysis.ResolveDependencyVersions(ctx, req)
}

func mavenRecord(id, coordinate string) map[string]any {
	return map[string]any{
		"schema_version":  "ferralon.normalized_advisory.v3",
		"vuln_id":         id,
		"coordinate":      coordinate,
		"purl":            "pkg:maven/" + strings.Replace(coordinate, ":", "/", 1),
		"version_scheme":  "maven",
		"affected_ranges": []map[string]string{{"introduced": "8.4.0", "fixed": "8.5.10"}},
	}
}

func pypiRecord(id, name string) map[string]any {
	return map[string]any{
		"schema_version":  "ferralon.normalized_advisory.v3",
		"vuln_id":         id,
		"coordinate":      name,
		"purl":            "pkg:pypi/" + name,
		"version_scheme":  "pypi",
		"affected_ranges": []map[string]string{{"introduced": "0", "fixed": "99.0.0"}},
	}
}

const (
	minioID  = "CVE-2025-59952"
	widgetID = "GHSA-wwww-wwww-wwww"
	flaskID  = "GHSA-ffff-ffff-ffff"
	minio    = "io.minio:minio"
	widget   = "com.example.lib:widget"
)

var (
	minioResolved   = plugin.ResolvedDependency{Coordinate: minio, Version: "8.5.4", Resolved: true}
	minioPatched    = plugin.ResolvedDependency{Coordinate: minio, Version: "8.5.11", Resolved: true}
	minioUnresolved = plugin.ResolvedDependency{Coordinate: minio, Constraint: "8.5.4"}
	widgetResolved  = plugin.ResolvedDependency{Coordinate: widget, Version: "1.0.0", Resolved: true}
)

// javaTree writes a Java source tree and returns an *acquired with an empty floor, so the work set
// is exactly what admission added.
func javaTree(t *testing.T, p plugin.LanguagePlugin) *acquired {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "App.java"), []byte("class App {}\n"), 0o600); err != nil {
		t.Fatalf("write App.java: %v", err)
	}
	return &acquired{buildDir: dir, language: checkout.LangJava, repo: "example.com/fixture", plugin: p}
}

// pythonTree writes a Python tree with requirements.txt and returns an *acquired over the real
// Python manifest reader.
func pythonTree(t *testing.T, requirements string) *acquired {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{"app.py": "x = 1\n", "requirements.txt": requirements} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return &acquired{
		buildDir: dir, language: checkout.LangPython, repo: "example.com/fixture",
		plugin: pythonInventory{unsearchingAnalyzer{language: checkout.LangPython}},
	}
}

// jsTree writes a JS tree with no lockfile, so the real JS reader seeds every package.json
// declaration as unresolved, and returns an *acquired over that reader.
func jsTree(t *testing.T) *acquired {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"index.js":     "module.exports = 1;\n",
		"package.json": `{"name":"app","dependencies":{"@acme/widget":"^1.0.0"}}`,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return &acquired{
		buildDir: dir, language: checkout.LangJS, repo: "example.com/fixture",
		plugin: jsInventory{unsearchingAnalyzer{language: checkout.LangJS}},
	}
}

func javaAnalyzer(deps ...plugin.ResolvedDependency) plugin.LanguagePlugin {
	return inventoryAnalyzer{unsearchingAnalyzer: unsearchingAnalyzer{language: checkout.LangJava}, deps: deps}
}

// javaDecided is javaAnalyzer whose reader decides minio's Match as m.
func javaDecided(m plugin.ResolvedDependency, deps ...plugin.ResolvedDependency) plugin.LanguagePlugin {
	return inventoryAnalyzer{unsearchingAnalyzer: unsearchingAnalyzer{language: checkout.LangJava}, deps: deps,
		match: map[string]plugin.ResolvedDependency{minio: m}}
}

// pythonToxTree is pythonTree plus a tox.ini that pins a second copy of a requirement.
func pythonToxTree(t *testing.T, requirements, tox string) *acquired {
	t.Helper()
	acq := pythonTree(t, requirements)
	if err := os.WriteFile(filepath.Join(acq.buildDir, "tox.ini"), []byte(tox), 0o600); err != nil {
		t.Fatalf("write tox.ini: %v", err)
	}
	return acq
}

func policyCorpus(t *testing.T) pipeline.AdvisorySource {
	t.Helper()
	return pipeline.NewBundleSource(writePolicyBundle(t, []corpusEntry{
		{doc: mavenRecord(minioID, minio)},
		{doc: mavenRecord(widgetID, widget)},
		{doc: pypiRecord(flaskID, "flask")},
	}))
}

func notesFor(notes []report.PartialityNote, reason string) []report.PartialityNote {
	var out []report.PartialityNote
	for _, n := range notes {
		if n.Reason == reason {
			out = append(out, n)
		}
	}
	return out
}

// TestWorkSet_UnresolvedDependency pins admission of a dependency that is declared but carries no
// resolved version. Unread is not absent: policy admission matches by name, so the advisory gets a
// row; the OSV query cannot ask without a version, so the skipped dependency is named. Any unresolved
// copy of a coordinate is named even beside a resolved copy, and every distinct resolved version is
// queried.
func TestWorkSet_UnresolvedDependency(t *testing.T) {
	tests := []struct {
		name        string
		acq         func(t *testing.T) *acquired
		policy      bool
		wantIDs     []string
		wantQueried []string          // name@version, in query order
		wantSkipped map[string]string // skipped coordinate -> the note's Package
		wantFailed  []string          // the Package of each work_set_dependency_unreadable note
		wantMissing []string          // the Package of each work_set_dependency_not_found note
		wantSummary []string          // substrings the terminal summary must carry
		wantSource  string
	}{
		{
			name:       "policy: mixed build admits the unresolved dependency's advisory",
			acq:        func(t *testing.T) *acquired { return javaTree(t, javaAnalyzer(widgetResolved, minioUnresolved)) },
			policy:     true,
			wantIDs:    []string{minioID, widgetID},
			wantSource: workSetSourceBuiltinUnionPolicy,
		},
		{
			name:       "policy: all-unresolved build is admitted, not an absent inventory",
			acq:        func(t *testing.T) *acquired { return javaTree(t, javaAnalyzer(minioUnresolved)) },
			policy:     true,
			wantIDs:    []string{minioID},
			wantSource: workSetSourceBuiltinUnionPolicy,
		},
		{
			name:       "policy: resolved control is unchanged",
			acq:        func(t *testing.T) *acquired { return javaTree(t, javaAnalyzer(widgetResolved, minioResolved)) },
			policy:     true,
			wantIDs:    []string{minioID, widgetID},
			wantSource: workSetSourceBuiltinUnionPolicy,
		},
		{
			name:       "policy: a coordinate declared both resolved and unresolved is admitted once",
			acq:        func(t *testing.T) *acquired { return javaTree(t, javaAnalyzer(minioUnresolved, minioResolved)) },
			policy:     true,
			wantIDs:    []string{minioID},
			wantSource: workSetSourceBuiltinUnionPolicy,
		},
		{
			name:        "osv: mixed build queries the resolved dependency and names the skipped one",
			acq:         func(t *testing.T) *acquired { return javaTree(t, javaAnalyzer(widgetResolved, minioUnresolved)) },
			wantQueried: []string{widget + "@1.0.0"},
			wantSkipped: map[string]string{minio: "pkg:maven/io.minio/minio"},
			wantSource:  workSetSourceBuiltinUnionOSV,
		},
		{
			name:        "osv: an unresolved copy beside a resolved one queries the version and names the coordinate",
			acq:         func(t *testing.T) *acquired { return javaTree(t, javaAnalyzer(minioUnresolved, minioResolved)) },
			wantQueried: []string{minio + "@8.5.4"},
			wantSkipped: map[string]string{minio: "pkg:maven/io.minio/minio"},
			wantSource:  workSetSourceBuiltinUnionOSV,
		},
		{
			name:        "osv: two resolved versions of one coordinate are each queried",
			acq:         func(t *testing.T) *acquired { return javaTree(t, javaAnalyzer(minioResolved, minioPatched)) },
			wantQueried: []string{minio + "@8.5.11", minio + "@8.5.4"},
			wantSource:  workSetSourceBuiltinUnionOSV,
		},
		{
			name: "osv: a coordinate whose read fails is its own state, not an unresolved version",
			acq: func(t *testing.T) *acquired {
				return javaTree(t, inventoryAnalyzer{unsearchingAnalyzer: unsearchingAnalyzer{language: checkout.LangJava},
					deps: []plugin.ResolvedDependency{widgetResolved, minioResolved}, fail: map[string]bool{minio: true}})
			},
			wantQueried: []string{widget + "@1.0.0"},
			wantFailed:  []string{"pkg:maven/io.minio/minio"},
			wantSummary: []string{"could not have their version read", minio},
			wantSource:  workSetSourceBuiltinUnionOSV,
		},
		{
			name: "osv: a build whose only read fails says OSV.dev was asked nothing and names it",
			acq: func(t *testing.T) *acquired {
				return javaTree(t, inventoryAnalyzer{unsearchingAnalyzer: unsearchingAnalyzer{language: checkout.LangJava},
					deps: []plugin.ResolvedDependency{minioResolved}, fail: map[string]bool{minio: true}})
			},
			wantFailed:  []string{"pkg:maven/io.minio/minio"},
			wantSummary: []string{"asked nothing", "could not have their version read", minio},
			wantSource:  report.WorkSetBuiltinLanguageSet,
		},
		{
			name: "policy: a coordinate whose read fails is still admitted by name",
			acq: func(t *testing.T) *acquired {
				return javaTree(t, inventoryAnalyzer{unsearchingAnalyzer: unsearchingAnalyzer{language: checkout.LangJava},
					deps: []plugin.ResolvedDependency{widgetResolved, minioResolved}, fail: map[string]bool{minio: true}})
			},
			policy:     true,
			wantIDs:    []string{minioID, widgetID},
			wantFailed: []string{"pkg:maven/io.minio/minio"},
			wantSource: workSetSourceBuiltinUnionPolicy,
		},
		{
			name: "osv: a pinned coordinate the reader doesn't find is its own state",
			acq: func(t *testing.T) *acquired {
				return javaTree(t, inventoryAnalyzer{unsearchingAnalyzer: unsearchingAnalyzer{language: checkout.LangJava},
					deps: []plugin.ResolvedDependency{widgetResolved, minioResolved}, miss: map[string]bool{minio: true}})
			},
			wantQueried: []string{widget + "@1.0.0"},
			wantMissing: []string{"pkg:maven/io.minio/minio"},
			wantSummary: []string{"the dependency reader does not find them", minio},
			wantSource:  workSetSourceBuiltinUnionOSV,
		},
		{
			name: "osv: a build whose only pin the reader doesn't find says OSV.dev was asked nothing and names it",
			acq: func(t *testing.T) *acquired {
				return javaTree(t, inventoryAnalyzer{unsearchingAnalyzer: unsearchingAnalyzer{language: checkout.LangJava},
					deps: []plugin.ResolvedDependency{minioResolved}, miss: map[string]bool{minio: true}})
			},
			wantMissing: []string{"pkg:maven/io.minio/minio"},
			wantSummary: []string{"asked nothing", "the dependency reader does not find them", minio},
			wantSource:  report.WorkSetBuiltinLanguageSet,
		},
		{
			name: "policy: a pinned coordinate the reader doesn't find is still admitted by name",
			acq: func(t *testing.T) *acquired {
				return javaTree(t, inventoryAnalyzer{unsearchingAnalyzer: unsearchingAnalyzer{language: checkout.LangJava},
					deps: []plugin.ResolvedDependency{widgetResolved, minioResolved}, miss: map[string]bool{minio: true}})
			},
			policy:      true,
			wantIDs:     []string{minioID, widgetID},
			wantMissing: []string{"pkg:maven/io.minio/minio"},
			wantSource:  workSetSourceBuiltinUnionPolicy,
		},
		{
			name: "osv: a coordinate whose Match withholds is named and none of its pins is queried",
			acq: func(t *testing.T) *acquired {
				return javaTree(t, javaDecided(minioUnresolved, widgetResolved, minioResolved))
			},
			wantQueried: []string{widget + "@1.0.0"},
			wantSkipped: map[string]string{minio: "pkg:maven/io.minio/minio"},
			wantSource:  workSetSourceBuiltinUnionOSV,
		},
		{
			name:        "osv: a version only the Match holds is queried too",
			acq:         func(t *testing.T) *acquired { return javaTree(t, javaDecided(minioPatched, minioResolved)) },
			wantQueried: []string{minio + "@8.5.11", minio + "@8.5.4"},
			wantSource:  workSetSourceBuiltinUnionOSV,
		},
		{
			name:        "osv: all-unresolved build names every skipped dependency",
			acq:         func(t *testing.T) *acquired { return javaTree(t, javaAnalyzer(minioUnresolved)) },
			wantSkipped: map[string]string{minio: "pkg:maven/io.minio/minio"},
			wantSource:  report.WorkSetBuiltinLanguageSet,
		},
		{
			name:        "osv: resolved control queries everything and names nothing",
			acq:         func(t *testing.T) *acquired { return javaTree(t, javaAnalyzer(widgetResolved, minioResolved)) },
			wantQueried: []string{widget + "@1.0.0", minio + "@8.5.4"},
			wantSource:  workSetSourceBuiltinUnionOSV,
		},
		{
			name:       "python policy: an unpinned requirement beside a pinned one is admitted",
			acq:        func(t *testing.T) *acquired { return pythonTree(t, "requests==2.31.0\nflask>=2.0\n") },
			policy:     true,
			wantIDs:    []string{flaskID},
			wantSource: workSetSourceBuiltinUnionPolicy,
		},
		{
			name:        "python osv: the unpinned requirement is named",
			acq:         func(t *testing.T) *acquired { return pythonTree(t, "requests==2.31.0\nflask>=2.0\n") },
			wantQueried: []string{"requests@2.31.0"},
			wantSkipped: map[string]string{"flask": "pkg:pypi/flask"},
			wantSource:  workSetSourceBuiltinUnionOSV,
		},
		{
			name: "python osv: pins the reader withholds over an unread tox.ini are named, not queried",
			acq: func(t *testing.T) *acquired {
				return pythonToxTree(t, "requests==2.31.0\njinja2==3.1.4\n", "[testenv]\ndeps =\n    jinja2==3.1.2\n")
			},
			wantSkipped: map[string]string{"jinja2": "pkg:pypi/jinja2", "requests": "pkg:pypi/requests"},
			wantSource:  report.WorkSetBuiltinLanguageSet,
		},
		{
			name:        "js osv: a scoped package declared with no lockfile is named",
			acq:         jsTree,
			wantSkipped: map[string]string{"@acme/widget": "pkg:npm/%40acme/widget"},
			wantSource:  report.WorkSetBuiltinLanguageSet,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acq := tt.acq(t)
			osv := &fakeOSV{}
			var ws workSet
			if tt.policy {
				corpus := policyCorpus(t)
				ws = selectWorkSet(context.Background(), acq, corpus, corpus, "full", false, osv)
			} else {
				ws = selectWorkSet(context.Background(), acq, nil, nil, "", true, osv)
			}

			if got := ids(ws.advisories); strings.Join(got, ",") != strings.Join(tt.wantIDs, ",") {
				t.Errorf("work set = %v, want %v", got, tt.wantIDs)
			}
			if ws.source != tt.wantSource {
				t.Errorf("source = %q, want %q", ws.source, tt.wantSource)
			}
			if hasReason(ws.partiality, reasonWorkSetNoInventory) {
				t.Errorf("work_set_no_inventory fired over a manifest that declares dependencies: %+v", ws.partiality)
			}

			var queried []string
			for _, p := range osv.seen {
				queried = append(queried, p.Name+"@"+p.Version)
				if p.Version == "" {
					t.Errorf("OSV was asked about %s with no version", p.Name)
				}
			}
			if strings.Join(queried, ",") != strings.Join(tt.wantQueried, ",") {
				t.Errorf("OSV queried %v, want %v", queried, tt.wantQueried)
			}

			var failed []string
			for _, n := range notesFor(ws.partiality, reasonWorkSetDependencyUnreadable) {
				failed = append(failed, n.Package)
			}
			if strings.Join(failed, ",") != strings.Join(tt.wantFailed, ",") {
				t.Errorf("%s notes for %v, want %v", reasonWorkSetDependencyUnreadable, failed, tt.wantFailed)
			}

			var missing []string
			for _, n := range notesFor(ws.partiality, reasonWorkSetDependencyNotFound) {
				missing = append(missing, n.Package)
			}
			if strings.Join(missing, ",") != strings.Join(tt.wantMissing, ",") {
				t.Errorf("%s notes for %v, want %v", reasonWorkSetDependencyNotFound, missing, tt.wantMissing)
			}

			for _, want := range tt.wantSummary {
				if !strings.Contains(ws.describe(), want) {
					t.Errorf("terminal summary does not carry %q:\n%s", want, ws.describe())
				}
			}

			skipped := notesFor(ws.partiality, reasonWorkSetDependencyUnresolved)
			if len(skipped) != len(tt.wantSkipped) {
				t.Fatalf("%d %s notes, want %d: %+v", len(skipped), reasonWorkSetDependencyUnresolved, len(tt.wantSkipped), ws.partiality)
			}
			for _, n := range skipped {
				coord := strings.SplitN(n.Detail, " ", 2)[0]
				want, ok := tt.wantSkipped[coord]
				if !ok {
					t.Errorf("note names %q, want one of %v: %+v", coord, tt.wantSkipped, n)
					continue
				}
				if n.Package != want {
					t.Errorf("note Package = %q, want %q", n.Package, want)
				}
				for _, q := range queried {
					if strings.HasPrefix(q, coord+"@") && !strings.Contains(n.Detail, "asked only about its pinned copies") {
						t.Errorf("OSV was asked about %s, but the note says it was not: %q", q, n.Detail)
					}
				}
				if !strings.Contains(ws.describe(), coord) {
					t.Errorf("terminal summary does not name %s:\n%s", coord, ws.describe())
				}
			}
		})
	}
}

// TestWorkSet_UnresolvedAdmissionIsUndetermined follows an admitted advisory through the baseline
// path. With no resolved version the version check fails open, so the row is undetermined and
// carries no package; the resolved control shows the double does deliver a version when there is one.
func TestWorkSet_UnresolvedAdmissionIsUndetermined(t *testing.T) {
	tests := []struct {
		name        string
		acq         func(t *testing.T) *acquired
		id          string
		wantVersion string
	}{
		{"java: unresolved minio", func(t *testing.T) *acquired { return javaTree(t, javaAnalyzer(widgetResolved, minioUnresolved)) }, minioID, ""},
		{"python: unpinned flask", func(t *testing.T) *acquired { return pythonTree(t, "requests==2.31.0\nflask>=2.0\n") }, flaskID, ""},
		{"java control: resolved minio", func(t *testing.T) *acquired { return javaTree(t, javaAnalyzer(widgetResolved, minioResolved)) }, minioID, "8.5.4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trapEgress(t)
			acq := tt.acq(t)
			corpus := policyCorpus(t)
			ws := selectWorkSet(context.Background(), acq, corpus, corpus, "full", false, &fakeOSV{})

			rep, err := trigger.RunBaseline(context.Background(), statestore.NewMemStore(), trigger.BaselineRequest{
				Subject: trigger.Subject{Repo: "specimen", Revision: "HEAD"},
				Codebase: assessment.CodebaseRef{
					Repo:        "specimen",
					Revision:    "HEAD",
					Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: acq.buildDir},
				},
				Advisories:    ws.advisories,
				WorkSetLimits: ws.partiality,
				AssessOptions: []pipeline.AssessOption{pipeline.WithPlugin(acq.plugin), pipeline.WithAdvisorySource(corpus)},
			})
			if err != nil {
				t.Fatalf("RunBaseline: %v", err)
			}

			var found *report.AdvisoryFinding
			for i := range rep.Advisories {
				if rep.Advisories[i].Advisory.ID == tt.id {
					found = &rep.Advisories[i]
				}
			}
			if found == nil {
				t.Fatalf("no row for %s: the advisory against a declared dependency left the work set", tt.id)
			}
			if tt.wantVersion != "" {
				if found.Package == nil || found.Package.Version != tt.wantVersion {
					t.Fatalf("control row package = %+v, want version %s", found.Package, tt.wantVersion)
				}
				return
			}
			if found.Verdict != report.VerdictUndetermined {
				t.Errorf("%s verdict = %q, want %q: an unresolved version cannot place the dependency out of range",
					tt.id, found.Verdict, report.VerdictUndetermined)
			}
			if found.Package != nil && found.Package.Version != "" {
				t.Errorf("%s carries version %q that nothing resolved", tt.id, found.Package.Version)
			}
		})
	}
}

// TestReviewGlobalVersionVetoMustReachOSVInventory is the ferralon-ai/tracker#238 repro: jinja2 is
// pinned in requirements.txt and tox.ini holds another copy, so the Python reader returns Found and
// unresolved. The inventory must list it unresolved, with no version, and keep it out of resolved.
func TestReviewGlobalVersionVetoMustReachOSVInventory(t *testing.T) {
	acq := pythonToxTree(t, "jinja2==3.1.4\n", "[testenv]\ndeps = jinja2==3.1.2\n")
	match, err := acq.plugin.ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: acq.buildDir, Coordinate: "jinja2"})
	if err != nil || !match.Found || match.Match.Resolved {
		t.Fatalf("fixture must be found/unresolved: %v %+v", err, match)
	}
	resolved, unresolved, notes := dependencyInventory(context.Background(), acq)
	if len(resolved) > 0 {
		t.Fatalf("OSV inventory calls unresolved jinja2 resolved: resolved=%+v unresolved=%+v notes=%+v", resolved, unresolved, notes)
	}
	if len(unresolved) != 1 || unresolved[0].Name != "jinja2" || unresolved[0].Version != "" {
		t.Fatalf("unresolved = %+v, want jinja2 with no version", unresolved)
	}
}

// A project only pixi's PyPI tables declare enters the inventory unresolved, so the work set
// discloses it rather than leaving it out unnamed. A conda dependency is not a PyPI project and
// stays out.
func TestInventory_PixiDeclaredNames(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"pyproject pixi table": {
			"pyproject.toml": "[project]\nname = \"app\"\ndependencies = [\"flask==3.0.0\"]\n\n" +
				"[tool.pixi.pypi-dependencies]\npyjwt = \"==2.10.0\"\n\n[tool.pixi.dependencies]\nnumpy = \"1.26.*\"\n",
		},
		"pixi.toml": {
			"pixi.toml": "[workspace]\nchannels = [\"conda-forge\"]\nplatforms = [\"linux-64\"]\n\n" +
				"[pypi-dependencies]\npyjwt = \"==2.10.0\"\n\n[dependencies]\nnumpy = \"1.26.*\"\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			files["requirements.txt"], files["app.py"] = "flask==3.0.0\n", "x = 1\n"
			for f, body := range files {
				if err := os.WriteFile(filepath.Join(dir, f), []byte(body), 0o600); err != nil {
					t.Fatalf("write %s: %v", f, err)
				}
			}
			acq := &acquired{
				buildDir: dir, language: checkout.LangPython, repo: "example.com/fixture",
				plugin: pythonInventory{unsearchingAnalyzer{language: checkout.LangPython}},
			}
			resolved, unresolved, notes := dependencyInventory(context.Background(), acq)
			names := map[string]string{}
			for _, p := range append(resolved, unresolved...) {
				names[p.Name] = p.Version
			}
			if v, ok := names["pyjwt"]; !ok || v != "" {
				t.Fatalf("pyjwt not in the inventory unresolved: resolved=%+v unresolved=%+v notes=%+v", resolved, unresolved, notes)
			}
			if _, ok := names["numpy"]; ok {
				t.Fatalf("conda numpy entered the PyPI inventory: resolved=%+v unresolved=%+v", resolved, unresolved)
			}
		})
	}
}
