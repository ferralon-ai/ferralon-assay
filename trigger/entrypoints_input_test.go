package trigger

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// requestEntrypointsPlugin is refutingGoPlugin with the lane recording the entry points it resolved
// from the request it was handed, as the go lane does. The refutation's detail names the statement it
// was reached under, so a row carries which statement it rests on.
type requestEntrypointsPlugin struct{ refutingGoPlugin }

func (p requestEntrypointsPlugin) Reachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	res, err := p.refutingGoPlugin.Reachability(ctx, req)
	if le := req.LibraryEntrypoints; le != nil {
		src := plugin.LibraryEntrypointsSourceAuto
		if le.Declared() {
			src = plugin.LibraryEntrypointsSourceDeclared
		}
		res.LibraryEntrypoints = &plugin.ResolvedLibraryEntrypoints{Ecosystem: "golang", Source: src, Input: le.String(), Packages: []string{}}
		if res.Refutation != nil {
			r := *res.Refutation
			r.Detail += " under " + le.String()
			res.Refutation = &r
		}
	}
	return res, err
}

func reportJSON(t *testing.T, r *report.Report) string {
	t.Helper()
	c := *r
	c.Provenance.Timestamp = time.Time{}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestEntrypointsInput_StateStore: a changed entrypoints value is treated as a changed
// library-entrypoints value. A re-analysis records the entry points of the value it ran with in place of
// the stored report's, and an unchanged value records the same set again; a value that differs from the
// stored one is re-analysed on the PR inherit fast path too, so no row stays under the old one.
// Whichever way the value is given, as
// library-entrypoints or as the clauses it stands for, the Report is byte-identical.
func TestEntrypointsInput_StateStore(t *testing.T) {
	stored := []plugin.ResolvedLibraryEntrypoints{{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "none", Packages: []string{}}}
	bumped := func(*report.Report) report.SBOM {
		return report.SBOM{Packages: []report.Package{{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.5"}}}
	}
	type run func(t *testing.T, opts []pipeline.AssessOption) *report.Report
	prReanalysis := func(t *testing.T, opts []pipeline.AssessOption) *report.Report {
		store, baseline := groundedBaseline()
		baseline.LibraryEntrypoints = stored
		res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
			Subject:       Subject{Repo: "r", ResolvedCommit: "pr-sha"},
			Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
			PRSBOM:        bumped(baseline),
			Advisories:    []assessment.VulnRef{wiringAdvisory},
			AssessOptions: opts,
		})
		if err != nil {
			t.Fatalf("RunPRInherit: %v", err)
		}
		return res.Report
	}
	fastPath := func(t *testing.T, opts []pipeline.AssessOption) *report.Report {
		store, baseline := groundedBaseline()
		baseline.LibraryEntrypoints = stored
		res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
			Subject:       Subject{Repo: "r", ResolvedCommit: "pr-sha"},
			Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
			PRSBOM:        baseline.SBOM,
			Advisories:    []assessment.VulnRef{wiringAdvisory},
			AssessOptions: opts,
		})
		if err != nil {
			t.Fatalf("RunPRInherit: %v", err)
		}
		return res.Report
	}
	cveWatch := func(t *testing.T, opts []pipeline.AssessOption) *report.Report {
		store, _ := seedBaseline(t)
		store.state.Report.LibraryEntrypoints = stored
		store.state.Cursor = ""
		osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{{ID: wiringAdvisory.ID, Package: wiringPkg}}}}
		res, err := RunCVEWatch(context.Background(), store, osv, CVEWatchRequest{
			Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
			Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
			AssessOptions: opts,
		})
		if err != nil {
			t.Fatalf("RunCVEWatch: %v", err)
		}
		if res.Report == nil {
			t.Fatal("CVE-watch ran no earnest pass")
		}
		return res.Report
	}
	cases := []struct {
		name  string
		run   run
		value string // library-entrypoints syntax
		want  string // the Input of the one recorded set
	}{
		{"PR re-analysis, value changed", prReanalysis, "pkg/api", "pkg/api"},
		{"PR re-analysis, value changed to auto", prReanalysis, "auto", "auto"},
		{"PR re-analysis, value unchanged", prReanalysis, "none", "none"},
		{"CVE-watch, value changed", cveWatch, "pkg/api,!pkg/api/x", "pkg/api,!pkg/api/x"},
		{"CVE-watch, value unchanged", cveWatch, "none", "none"},
		{"PR inherit fast path, value changed", fastPath, "pkg/api", "pkg/api"},
		{"PR inherit fast path, value unchanged", fastPath, "none", "none"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			le, err := plugin.ParseLibraryEntrypoints(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			overrides, err := plugin.ParseEntryOverrides(plugin.EntryOverrideForLibraryEntrypoints(le).Input)
			if err != nil {
				t.Fatal(err)
			}
			base := func(extra pipeline.AssessOption) []pipeline.AssessOption {
				return []pipeline.AssessOption{
					pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, wiringGoMod), lang: "go"}),
					pipeline.WithPlugin(requestEntrypointsPlugin{refutingGoPlugin{inventory: plugin.Complete()}}),
					extra,
				}
			}
			viaAlias := tc.run(t, base(pipeline.WithLibraryEntrypoints(le)))
			viaClauses := tc.run(t, base(pipeline.WithEntrypoints(overrides)))
			if len(viaAlias.LibraryEntrypoints) != 1 || viaAlias.LibraryEntrypoints[0].Input != tc.want {
				t.Errorf("library_entrypoints = %+v, want one set with input %q", viaAlias.LibraryEntrypoints, tc.want)
			}
			if !reflect.DeepEqual(viaClauses.LibraryEntrypoints, viaAlias.LibraryEntrypoints) {
				t.Errorf("via entrypoints: %+v, via library-entrypoints: %+v", viaClauses.LibraryEntrypoints, viaAlias.LibraryEntrypoints)
			}
			if a, c := reportJSON(t, viaAlias), reportJSON(t, viaClauses); a != c {
				t.Errorf("reports differ:\n via library-entrypoints %s\n via entrypoints         %s", a, c)
			}
		})
	}
}

// TestEntrypointsInput_Restated: reuse compares the go library statement. A run whose statement
// differs from the one the stored Report's refutations rest on assesses again instead of inheriting
// (the PR fast path, and a CVE-watch run with no new advisory); an equal one inherits; a stored Report
// that records no set reads as auto, so it equals only the default.
func TestEntrypointsInput_Restated(t *testing.T) {
	none := []plugin.ResolvedLibraryEntrypoints{{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "none", Packages: []string{}}}
	auto := []plugin.ResolvedLibraryEntrypoints{{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceAuto, Input: "auto", Packages: []string{}}}
	opts := func(t *testing.T, value string) []pipeline.AssessOption {
		t.Helper()
		le, err := plugin.ParseLibraryEntrypoints(value)
		if err != nil {
			t.Fatal(err)
		}
		o := []pipeline.AssessOption{
			pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, wiringGoMod), lang: "go"}),
			pipeline.WithPlugin(requestEntrypointsPlugin{refutingGoPlugin{inventory: plugin.Complete()}}),
		}
		if value != "" {
			o = append(o, pipeline.WithLibraryEntrypoints(le))
		}
		return o
	}
	cases := []struct {
		name   string
		stored []plugin.ResolvedLibraryEntrypoints
		value  string // library-entrypoints syntax; "" states nothing
		assess bool   // the run assesses again
	}{
		{"equal statement inherits", none, "none", false},
		{"changed statement assesses", none, "pkg/api", true},
		{"changed to the default assesses", none, "", true},
		{"changed to an explicit auto assesses", none, "auto", true},
		{"recorded auto, stated auto", auto, "auto", false},
		{"recorded auto, none stated", auto, "none", true},
		{"nothing recorded, nothing stated", nil, "", false},
		{"nothing recorded, auto stated", nil, "auto", false},
		{"nothing recorded, none stated", nil, "none", true},
		{"nothing recorded, a path stated", nil, "pkg/api", true},
	}
	for _, tc := range cases {
		t.Run("PR/"+tc.name, func(t *testing.T) {
			store, baseline := groundedBaseline()
			baseline.LibraryEntrypoints = tc.stored
			res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
				Subject:       Subject{Repo: "r", ResolvedCommit: "pr-sha"},
				Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
				PRSBOM:        baseline.SBOM,
				Advisories:    []assessment.VulnRef{wiringAdvisory},
				AssessOptions: opts(t, tc.value),
			})
			if err != nil {
				t.Fatalf("RunPRInherit: %v", err)
			}
			if res.Inherited == tc.assess {
				t.Errorf("Inherited = %v, want %v", res.Inherited, !tc.assess)
			}
			if tc.assess && wiringVerdict(t, res.Report) != report.VerdictNotExploitable {
				t.Errorf("assessed verdict = %v", wiringVerdict(t, res.Report))
			}
		})
		t.Run("CVE-watch/"+tc.name, func(t *testing.T) {
			store, _ := seedBaseline(t)
			store.state.Report.LibraryEntrypoints = tc.stored
			store.state.Cursor = wiringAdvisory.ID
			osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{{ID: wiringAdvisory.ID, Package: wiringPkg}}}}
			res, err := RunCVEWatch(context.Background(), store, osv, CVEWatchRequest{
				Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
				Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
				AssessOptions: opts(t, tc.value),
			})
			if err != nil {
				t.Fatalf("RunCVEWatch: %v", err)
			}
			if res.Heartbeat == tc.assess {
				t.Errorf("Heartbeat = %v, want %v", res.Heartbeat, !tc.assess)
			}
			if tc.assess && (res.Report == nil || len(res.Reassessed) != 1 || res.Reassessed[0] != wiringAdvisory.ID) {
				t.Errorf("Reassessed = %v, report nil = %v; want the stored row assessed again", res.Reassessed, res.Report == nil)
			}
		})
	}
}

func rowDetail(t *testing.T, rep *report.Report) string {
	t.Helper()
	for _, f := range rep.Advisories {
		if f.Advisory.ID == wiringAdvisory.ID {
			return f.Evidence.Detail
		}
	}
	t.Fatalf("no %s row in the report", wiringAdvisory.ID)
	return ""
}

// TestEntrypointsInput_SliceKeepsNoRowUnderOldStatement: a PR that changes a package the advisory does
// not touch re-analyses only the slice, and the slice keeps a baseline row only while the statement is
// the one the row was reached under. Under another statement the row is the fresh finding, which names
// the statement it rests on; under the same one the baseline's row stands.
func TestEntrypointsInput_SliceKeepsNoRowUnderOldStatement(t *testing.T) {
	stored := []plugin.ResolvedLibraryEntrypoints{{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "none", Packages: []string{}}}
	for _, tc := range []struct {
		name  string
		value string
		fresh bool
	}{
		{"statement changed", "pkg/api", true},
		{"statement unchanged", "none", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, baseline := groundedBaseline()
			baseline.LibraryEntrypoints = stored
			le, err := plugin.ParseLibraryEntrypoints(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			unrelated := report.SBOM{Packages: append(slices.Clone(baseline.SBOM.Packages), report.Package{Ecosystem: "Go", Name: "example.com/other", Version: "v1.0.0"})}
			res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
				Subject:    Subject{Repo: "r", ResolvedCommit: "pr-sha"},
				Codebase:   assessment.CodebaseRef{Repo: "r", Revision: "main"},
				PRSBOM:     unrelated,
				Advisories: []assessment.VulnRef{wiringAdvisory},
				AssessOptions: []pipeline.AssessOption{
					pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, wiringGoMod), lang: "go"}),
					pipeline.WithPlugin(requestEntrypointsPlugin{refutingGoPlugin{inventory: plugin.Complete()}}),
					pipeline.WithLibraryEntrypoints(le),
				},
			})
			if err != nil {
				t.Fatalf("RunPRInherit: %v", err)
			}
			if got := strings.Contains(rowDetail(t, res.Report), " under "+tc.value); got != tc.fresh {
				t.Errorf("row detail %q: fresh finding = %v, want %v", rowDetail(t, res.Report), got, tc.fresh)
			}
		})
	}
}

// TestEntrypointsInput_NonGoScanStatesNothing: a scan of another language ignores a go library
// clause, so however it is given it never reads as a restatement of what a go lane recorded.
func TestEntrypointsInput_NonGoScanStatesNothing(t *testing.T) {
	statements := map[string]pipeline.AssessOption{}
	for _, v := range []string{"none", "pkg/api", "auto"} {
		le, err := plugin.ParseLibraryEntrypoints(v)
		if err != nil {
			t.Fatal(err)
		}
		statements["library "+v] = pipeline.WithLibraryEntrypoints(le)
	}
	overrides, err := plugin.ParseEntryOverrides("go:library=none")
	if err != nil {
		t.Fatal(err)
	}
	statements["clause go:library=none"] = pipeline.WithEntrypoints(overrides)
	for name, opt := range statements {
		for _, lang := range []string{"java", "kotlin", "js", "python", "dotnet", "go"} {
			t.Run(name+"/"+lang, func(t *testing.T) {
				got := restated(&report.Report{}, []pipeline.AssessOption{pipeline.WithPlugin(fakeInventoryPlugin{lang: lang}), opt})
				if want := lang == "go" && name != "library auto"; got != want {
					t.Errorf("restated = %v, want %v", got, want)
				}
			})
		}
	}
}

// TestEntrypointsInput_RestatedEdges: a stored statement that does not parse is another statement,
// and the rows a restated CVE-watch run assesses again leave out the ones withheld as
// dependency_not_fetched.
func TestEntrypointsInput_RestatedEdges(t *testing.T) {
	garbled := &report.Report{LibraryEntrypoints: []plugin.ResolvedLibraryEntrypoints{{Ecosystem: "golang", Input: "none,auto"}}}
	if !restated(garbled, nil) {
		t.Error("an unparsable recorded statement read as unchanged")
	}
	row := func(id string, reason string) report.AdvisoryFinding {
		return report.AdvisoryFinding{Advisory: report.Advisory{ID: id, Source: "corpus"}, UndeterminedReason: reason}
	}
	prior := &report.Report{Advisories: []report.AdvisoryFinding{row("A", ""), row("B", report.ReasonDependencyNotFetched)}}
	got := restatedRetry(prior, nil, nil)
	if len(got) != 1 || got[0].Advisory.ID != "A" {
		t.Errorf("restatedRetry = %+v, want only A", got)
	}
}

// TestRestated_BaselineEntrypointsRecord: restated reads the statement from library_entrypoints
// alone. A baseline whose assessments judged no refutation (path-only rows, or a build whose cgo
// did not resolve) holds an entrypoints[] record of the Go lane but no library_entrypoints, and
// reads as auto: it inherits under auto and re-assesses under any other statement, whatever its
// entrypoints[] record says.
func TestRestated_BaselineEntrypointsRecord(t *testing.T) {
	record := func(input string) []plugin.EntryRootRecord {
		return []plugin.EntryRootRecord{{
			Lane: plugin.EntryLaneGo, Source: plugin.LibraryEntrypointsSourceDeclared, Input: input,
			Effective: map[string][]string{plugin.EntryKindLibrary: {"example.com/m/pkg/api"}},
			Inferred: map[string][]string{
				plugin.EntryKindLibrary: {"example.com/m/pkg/api", "example.com/m/pkg/lib"},
				plugin.EntryKindMain:    {"example.com/m/cmd/tool"},
			},
			Denied: []string{"!pkg/lib"},
		}}
	}
	cases := []struct {
		name     string
		baseline report.Report
		input    string
		want     bool
	}{
		{"path-only baseline, same statement", report.Report{Entrypoints: record("auto")}, "auto", false},
		{"path-only baseline, changed statement", report.Report{Entrypoints: record("auto")}, "!pkg/lib", true},
		{"path-only baseline, an entrypoints record of another statement does not restate auto", report.Report{Entrypoints: record("!pkg/lib")}, "auto", false},
		{"cgo-unresolved baseline, same statement", report.Report{Entrypoints: record("auto")}, "auto", false},
		{"cgo-unresolved baseline, changed statement", report.Report{Entrypoints: record("auto")}, "none", true},
		{"refutation baseline, same declared statement",
			report.Report{LibraryEntrypoints: []plugin.ResolvedLibraryEntrypoints{{Ecosystem: "golang", Input: "!pkg/lib"}}, Entrypoints: record("!pkg/lib")}, "!pkg/lib", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			le, err := plugin.ParseLibraryEntrypoints(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			opts := []pipeline.AssessOption{pipeline.WithPlugin(fakeInventoryPlugin{lang: "go"}), pipeline.WithLibraryEntrypoints(le)}
			if got := restated(&tc.baseline, opts); got != tc.want {
				t.Errorf("restated = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRestated_JSStatement: the js lane's statement is compared per lane. A run that states the same
// removal as the stored js record inherits, a changed or newly stated one re-assesses, and the go
// lane's comparison stands beside it unchanged.
func TestRestated_JSStatement(t *testing.T) {
	record := func(input string) *report.Report {
		return &report.Report{Entrypoints: []plugin.EntryRootRecord{{Lane: plugin.EntryLaneJS, Source: plugin.LibraryEntrypointsSourceDeclared, Input: input}}}
	}
	run := func(t *testing.T, lang, in string) []pipeline.AssessOption {
		m, err := plugin.ParseEntryOverrides(in)
		if err != nil {
			t.Fatal(err)
		}
		return []pipeline.AssessOption{pipeline.WithPlugin(fakeInventoryPlugin{lang: lang}), pipeline.WithEntrypoints(m)}
	}
	cases := []struct {
		name   string
		stored *report.Report
		lang   string
		in     string
		want   bool
	}{
		{"same removal", record("!js:bin=bin:a"), "js", "!js:bin=bin:a", false},
		{"same removal, order of denies", record("!js:bin=bin:a !js:bin=bin:b"), "js", "!js:bin=bin:b !js:bin=bin:a", false},
		{"changed removal", record("!js:bin=bin:a"), "js", "!js:bin=bin:b", true},
		{"removal added", &report.Report{}, "js", "!js:bin=bin:a", true},
		{"removal withdrawn", record("!js:bin=bin:a"), "js", "js:auto", true},
		{"nothing stated either side", &report.Report{}, "js", "js:auto", false},
		{"recorded auto, none stated", record("auto"), "js", "js:auto", false},
		{"unparsable record", record("!!"), "js", "!js:bin=bin:a", true},
		{"scan of another language states nothing for js", record("!js:bin=bin:a"), "go", "!js:bin=bin:a", true},
		{"a go scan ignores a js clause", &report.Report{}, "go", "!js:bin=bin:a", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := restated(tc.stored, run(t, tc.lang, tc.in)); got != tc.want {
				t.Errorf("restated = %v, want %v", got, tc.want)
			}
		})
	}
}
