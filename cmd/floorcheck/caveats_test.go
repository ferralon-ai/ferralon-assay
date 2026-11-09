package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// testCaveats is a small hand-written mapping, independent of the shipped file.
const testCaveats = `{"mappings":[
 {"reason":"relationship_unexpressed:uninspectable_package","language":"js","run_wide":true,"caveat":"JS-UNINSPECTABLE-RUNWIDE","defined_in":"plugin/plugin.go"},
 {"reason":"scan_cut_short","language":"any","run_wide":false,"caveat":"SCAN-CUT-SHORT","defined_in":"report/report.go"},
 {"reason":"dependency_not_in_build","language":"java","run_wide":false,"caveat":"JAVA-INSTALL-UNLISTED","defined_in":"internal/plugin/javaanalysis/graph.go"},
 {"reason":"other_tool_build","language":"java","run_wide":true,"caveat":"JAVA-OTHER-TOOL-BUILD","defined_in":"internal/plugin/javaanalysis/graph.go"},
 {"reason":"source_unpinned:git_ref","language":"js","run_wide":false,"caveat":"JS-GIT-PIN","defined_in":"plugin/plugin.go"}],
 "structural":[{"caveat":"JS-NO-CLEAR-GROUNDS","language":"js"}]}`

func mustCaveats(t *testing.T) Caveats {
	t.Helper()
	c, err := parseCaveats([]byte(testCaveats))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestParseCaveats(t *testing.T) {
	m := func(fields string) string {
		return `{"mappings":[{` + fields + `}]}`
	}
	ok := `"reason":"scan_cut_short","language":"any","run_wide":false,"caveat":"SCAN-CUT-SHORT","defined_in":"report/report.go"`
	for _, tc := range []struct {
		name, json, err string
	}{
		{"valid", testCaveats, ""},
		{"not JSON", `{"mappings":[`, "caveats:"},
		{"misspelt key", m(strings.Replace(ok, `"caveat"`, `"cavaet"`, 1)), "unknown field"},
		{"no mappings", `{"mappings":[]}`, "no mappings"},
		{"empty reason", m(strings.Replace(ok, `"scan_cut_short"`, `""`, 1)), "reason"},
		{"padded reason", m(strings.Replace(ok, `"scan_cut_short"`, `" scan_cut_short"`, 1)), "padded"},
		{"lowercase caveat", m(strings.Replace(ok, `"SCAN-CUT-SHORT"`, `"scan-cut-short"`, 1)), "caveat id"},
		{"unmapped as a caveat", m(strings.Replace(ok, `"SCAN-CUT-SHORT"`, `"unmapped:x"`, 1)), "caveat id"},
		{"unknown language", m(strings.Replace(ok, `"any"`, `"cobol"`, 1)), "language"},
		{"defined in a test file", m(strings.Replace(ok, `report/report.go`, `report/report_test.go`, 1)), "defined_in"},
		{"defined in no Go file", m(strings.Replace(ok, `report/report.go`, `report/`, 1)), "defined_in"},
		{"mapped twice", `{"mappings":[{` + ok + `},{` + ok + `}]}`, "twice"},
		{"structural without a language", `{"mappings":[{` + ok + `}],"structural":[{"caveat":"JS-NO-CLEAR-GROUNDS","language":"any"}]}`, "structural"},
		{"structural twice", `{"mappings":[{` + ok + `}],"structural":[{"caveat":"JS-X-Y","language":"js"},{"caveat":"JS-X-Y","language":"js"}]}`, "twice"},
		{"structural is a mapping's caveat", `{"mappings":[{` + strings.Replace(strings.Replace(ok, `"any"`, `"js"`, 1), `"SCAN-CUT-SHORT"`, `"JS-X-Y"`, 1) + `}],"structural":[{"caveat":"JS-X-Y","language":"js"}]}`, "also a mapping's caveat"},
		{"structural is an any mapping's caveat", `{"mappings":[{` + ok + `}],"structural":[{"caveat":"SCAN-CUT-SHORT","language":"go"}]}`, "also a mapping's caveat"},
		{"structural shares a caveat id with another language's mapping", `{"mappings":[{` + strings.Replace(strings.Replace(ok, `"any"`, `"python"`, 1), `"SCAN-CUT-SHORT"`, `"JS-X-Y"`, 1) + `}],"structural":[{"caveat":"JS-X-Y","language":"js"}]}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCaveats([]byte(tc.json))
			switch {
			case tc.err == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
				t.Fatalf("error = %v, want one containing %q", err, tc.err)
			}
		})
	}
}

func TestCaveatFor(t *testing.T) {
	c := mustCaveats(t)
	for _, tc := range []struct {
		reason, language string
		runWide          bool
		want             string
	}{
		{"relationship_unexpressed:uninspectable_package", "js", true, "JS-UNINSPECTABLE-RUNWIDE"},
		{"relationship_unexpressed:uninspectable_package", "js", false, "unmapped:relationship_unexpressed:uninspectable_package"},
		{"relationship_unexpressed:uninspectable_package", "python", true, "unmapped:relationship_unexpressed:uninspectable_package"},
		{"scan_cut_short", "go", true, "SCAN-CUT-SHORT"},
		{"scan_cut_short", "python", false, "SCAN-CUT-SHORT"},
		{"dependency_not_in_build", "java", false, "JAVA-INSTALL-UNLISTED"},
		{"dependency_not_in_build", "java", true, "JAVA-INSTALL-UNLISTED"},
		{"other_tool_build", "java", false, "unmapped:other_tool_build"},
		{"advisory_symbol_absent", "go", false, "unmapped:advisory_symbol_absent"},
	} {
		if got := c.caveatFor(tc.reason, tc.language, tc.runWide); got != tc.want {
			t.Errorf("caveatFor(%q, %s, run-wide %v) = %q, want %q", tc.reason, tc.language, tc.runWide, got, tc.want)
		}
	}
}

// Hand-written report members for the caveat tally.
const (
	dnrA          = `{"advisory":{"id":"JS-1","source":"osv"},"verdict":"undetermined","undetermined_reason":"analysis_did_not_run","evidence":{}}`
	dnrB          = `{"advisory":{"id":"JS-2","source":"osv"},"verdict":"undetermined","undetermined_reason":"analysis_did_not_run","evidence":{}}`
	pinnedGit     = `{"advisory":{"id":"JS-3","source":"osv"},"package":{"ecosystem":"npm","name":"left-pad","version":"1.0.0","direct":true,"partial_reason":"source_unpinned:git_ref"},"verdict":"reachable_candidate","evidence":{}}`
	uninspectRun  = `{"reason":"relationship_unexpressed:uninspectable_package","ecosystem":"npm"}`
	uninspectPkg  = `{"reason":"relationship_unexpressed:uninspectable_package","ecosystem":"npm","package":"pkg:npm/esbuild"}`
	reflectionRun = `{"reason":"reflection","class":"inherent_limit"}`
	notInBuild    = `{"reason":"dependency_not_in_build","ecosystem":"Maven","package":"pkg:maven/a/b","path":"a:b"}`
)

func TestRepoCaveats(t *testing.T) {
	c := mustCaveats(t)
	for _, tc := range []struct {
		name, language, advisories, partiality string
		want                                   []CaveatHit
	}{
		{name: "mapped run-wide reason holds the did-not-run rows", language: "js",
			advisories: dnrA + "," + dnrB, partiality: uninspectRun,
			want: []CaveatHit{
				{Caveat: "JS-UNINSPECTABLE-RUNWIDE", Findings: 2, RunWide: true, Reasons: []string{"relationship_unexpressed:uninspectable_package"}},
				{Caveat: "unmapped:analysis_did_not_run", Findings: 2, Reasons: []string{"analysis_did_not_run"}},
			}},
		{name: "the scoped form of a run-wide mapping stays unmapped", language: "js",
			partiality: uninspectPkg,
			want: []CaveatHit{
				{Caveat: "unmapped:relationship_unexpressed:uninspectable_package", Reasons: []string{"relationship_unexpressed:uninspectable_package"}},
			}},
		{name: "a note naming a package holds every did-not-run row too", language: "js",
			advisories: dnrA + "," + dnrB, partiality: uninspectPkg,
			want: []CaveatHit{
				{Caveat: "unmapped:analysis_did_not_run", Findings: 2, Reasons: []string{"analysis_did_not_run"}},
				{Caveat: "unmapped:relationship_unexpressed:uninspectable_package", Findings: 2, Reasons: []string{"relationship_unexpressed:uninspectable_package"}},
			}},
		{name: "mapped per-finding reason counts its rows once", language: "go",
			advisories: neGrounded + "," + cutShort, partiality: cutShortNote,
			want: []CaveatHit{
				{Caveat: "SCAN-CUT-SHORT", Findings: 1, RunWide: true, Reasons: []string{"scan_cut_short"}},
			}},
		{name: "mapped scoped reason", language: "java",
			partiality: notInBuild,
			want: []CaveatHit{
				{Caveat: "JAVA-INSTALL-UNLISTED", Reasons: []string{"dependency_not_in_build"}},
			}},
		{name: "a package's partial_reason affects its row", language: "js",
			advisories: pinnedGit,
			want: []CaveatHit{
				{Caveat: "JS-GIT-PIN", Findings: 1, Reasons: []string{"source_unpinned:git_ref"}},
			}},
		{name: "unmapped reasons are kept raw; an inherent limit affects no row", language: "go",
			advisories: undetA + "," + undetB + "," + dnrA, partiality: reflectionRun,
			want: []CaveatHit{
				{Caveat: "unmapped:advisory_symbol_absent", Findings: 2, Reasons: []string{"advisory_symbol_absent"}},
				{Caveat: "unmapped:analysis_did_not_run", Findings: 1, Reasons: []string{"analysis_did_not_run"}},
				{Caveat: "unmapped:reflection", RunWide: true, Reasons: []string{"reflection"}},
			}},
		{name: "a clean report fires nothing", language: "go", advisories: neGrounded, want: []CaveatHit{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := decodeReport([]byte(reportJSON(tc.advisories, tc.partiality)))
			if err != nil {
				t.Fatal(err)
			}
			got := repoCaveats(c, tc.language, r)
			if len(got) != len(tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			for i := range got {
				g, w := got[i], tc.want[i]
				if g.Caveat != w.Caveat || g.Findings != w.Findings || g.RunWide != w.RunWide ||
					strings.Join(g.Reasons, ",") != strings.Join(w.Reasons, ",") {
					t.Errorf("hit %d = %+v, want %+v", i, g, w)
				}
			}
		})
	}
}

// TestAddCaveats rolls caveats up per language, lists a structural caveat as always applying,
// renders the section, and leaves pass, failures and the alert as they were.
func TestAddCaveats(t *testing.T) {
	tg := Targets{Policy: "published-24h", Targets: []Target{
		{Repo: "o/web", Language: "js"}, {Repo: "o/api", Language: "js"}, {Repo: "o/svc", Language: "go"},
		{Repo: "o/gone", Language: "python"},
	}}
	results := map[string]*scanResult{
		"o/web": withReport(ok(), reportJSON(dnrA+","+dnrB, uninspectRun)),
		"o/api": withReport(ok(), reportJSON(dnrA+","+neUngrounded, uninspectRun+","+uninspectPkg)),
		"o/svc": withReport(ok(), reportJSON(neGrounded, "")),
	}
	s := summarize(tg, results, "", "")
	before, alertBefore := s.Pass, s.alert()
	failures := func() string {
		var out []string
		for _, r := range s.Repos {
			out = append(out, r.Repo+":"+strings.Join(kinds(r.Failures), ","))
		}
		return strings.Join(out, " ")
	}
	failuresBefore := failures()
	s.addCaveats(mustCaveats(t), nil, results)

	if s.Pass != before || s.alert() != alertBefore || failures() != failuresBefore {
		t.Fatalf("caveats changed the outcome: pass %v→%v, failures %q→%q", before, s.Pass, failuresBefore, failures())
	}
	if s.Pass || !strings.Contains(alertBefore, "api") {
		t.Fatalf("fixture: want o/api to fail on its own grounds, got pass %v alert %q", s.Pass, alertBefore)
	}
	if s.Repos[3].Caveats != nil {
		t.Errorf("a repo without a report got caveats %+v", s.Repos[3].Caveats)
	}
	if s.Repos[2].Caveats == nil || len(s.Repos[2].Caveats) != 0 {
		t.Errorf("a clean report: caveats %#v, want an empty list", s.Repos[2].Caveats)
	}

	var langs []string
	var js LanguageCaveats
	for _, lc := range s.Caveats {
		langs = append(langs, lc.Language)
		if lc.Language == "js" {
			js = lc
		}
	}
	if strings.Join(langs, ",") != "go,js,python" {
		t.Errorf("roll-up languages = %v, want go,js,python", langs)
	}
	want := []CaveatRollup{
		{Caveat: "JS-NO-CLEAR-GROUNDS", Repos: 2, AlwaysApplies: true},
		{Caveat: "JS-UNINSPECTABLE-RUNWIDE", Repos: 2, FiredOn: []string{"web", "api"}, Findings: 3},
		{Caveat: "unmapped:analysis_did_not_run", Repos: 2, FiredOn: []string{"web", "api"}, Findings: 3},
		{Caveat: "unmapped:relationship_unexpressed:uninspectable_package", Repos: 1, FiredOn: []string{"api"}, Findings: 1},
	}
	if len(js.Caveats) != len(want) {
		t.Fatalf("js roll-up = %+v, want %+v", js.Caveats, want)
	}
	for i, w := range want {
		g := js.Caveats[i]
		if g.Caveat != w.Caveat || g.Repos != w.Repos || g.Findings != w.Findings || g.AlwaysApplies != w.AlwaysApplies ||
			strings.Join(g.FiredOn, ",") != strings.Join(w.FiredOn, ",") {
			t.Errorf("js roll-up %d = %+v, want %+v", i, g, w)
		}
	}

	md := s.markdown()
	for _, w := range []string{
		"### Caveats by language", "#### js", "| `JS-NO-CLEAR-GROUNDS` | always applies | — |",
		"| `JS-UNINSPECTABLE-RUNWIDE` | 2 (web, api) | 3 |",
		"| `unmapped:relationship_unexpressed:uninspectable_package` | 1 (api) | 1 |",
		"#### go\n\nNo caveat fired.", "#### python\n\nNo caveat fired.",
		// The existing tables are unchanged.
		"| Repo | Language | Assay commit | Policy | Verdicts | Qualified (alias sets) | Top undetermined reasons | Truncated | Duration | Result |",
	} {
		if !strings.Contains(md, w) {
			t.Errorf("markdown lacks %q:\n%s", w, md)
		}
	}

	// A mapping that could not be read leaves every reason unmapped, says so, and fails nothing.
	s2 := summarize(tg, results, "", "")
	s2.addCaveats(Caveats{}, errBadMapping, results)
	if s2.Pass != before || s2.CaveatMappingError == "" || s2.Repos[0].Caveats[0].Caveat != "unmapped:analysis_did_not_run" {
		t.Errorf("without a mapping: pass %v, error %q, web caveats %+v", s2.Pass, s2.CaveatMappingError, s2.Repos[0].Caveats)
	}
	if !strings.Contains(s2.markdown(), "**The caveat mapping could not be read**") {
		t.Error("markdown does not say the mapping could not be read")
	}
}

var errBadMapping = func() error {
	_, err := parseCaveats([]byte(`{"mappings":[`))
	return err
}()

// TestShippedCaveats keeps floor/caveats.json valid: floorcheck reads it with the same parser.
func TestShippedCaveats(t *testing.T) {
	if _, err := loadCaveats(filepath.Join("..", "..", "floor", "caveats.json")); err != nil {
		t.Fatal(err)
	}
}

// TestShippedCaveatIDs keeps the shipped mapping to the caveat ids docs/floor.md lists under
// "Caveat ids", so a misspelt id fails here instead of reaching the summary.
func TestShippedCaveatIDs(t *testing.T) {
	root := filepath.Join("..", "..")
	c, err := loadCaveats(filepath.Join(root, "floor", "caveats.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(filepath.Join(root, "docs", "floor.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, section, found := strings.Cut(string(doc), "\n### Caveat ids\n")
	if !found {
		t.Fatal(`docs/floor.md has no "### Caveat ids" section`)
	}
	section, _, _ = strings.Cut(section, "\n#")
	listed := map[string]bool{}
	for _, line := range strings.Split(section, "\n") {
		if id, ok := strings.CutPrefix(line, "| `"); ok {
			if id, _, ok = strings.Cut(id, "`"); ok {
				listed[id] = true
			}
		}
	}
	if len(listed) == 0 {
		t.Fatal(`docs/floor.md "Caveat ids" lists no id`)
	}
	for _, m := range c.Mappings {
		if !listed[m.Caveat] {
			t.Errorf("mapping %s (%s): caveat %s is not listed under docs/floor.md \"Caveat ids\"", m.Reason, m.Language, m.Caveat)
		}
	}
	for _, s := range c.Structural {
		if !listed[s.Caveat] {
			t.Errorf("structural %s (%s) is not listed under docs/floor.md \"Caveat ids\"", s.Caveat, s.Language)
		}
	}
}

// TestShippedCaveatReasons keeps the shipped mapping from drifting off the code: every mapped
// reason must be the value of a string constant declared in its defined_in file. The constants
// are evaluated from source (literals, same-package names, plugin.X and report.X, and +), since
// most lane reasons are unexported and built as base + ":suffix".
func TestShippedCaveatReasons(t *testing.T) {
	root := filepath.Join("..", "..")
	c, err := loadCaveats(filepath.Join(root, "floor", "caveats.json"))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]bool{"plugin/plugin.go": true, "report/report.go": true}
	for _, m := range c.Mappings {
		files[m.DefinedIn] = true
	}
	byFile, err := stringConsts(root, sortedSet(files))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range c.Mappings {
		if !byFile[m.DefinedIn][m.Reason] {
			t.Errorf("%s (%s): %s declares no string constant with that value", m.Reason, m.Caveat, m.DefinedIn)
		}
	}
}

// stringConsts evaluates the string constants the given files declare and returns, per file, the
// set of values. A constant is resolved from string literals, names in the same package, a
// selector naming another parsed package (plugin.X, report.X), and concatenation.
func stringConsts(root string, files []string) (map[string]map[string]bool, error) {
	type decl struct {
		file, pkg, name string
		expr            ast.Expr
	}
	var decls []decl
	fset := token.NewFileSet()
	for _, f := range files {
		af, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(f)), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		for _, d := range af.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i < len(vs.Values) {
						decls = append(decls, decl{f, af.Name.Name, n.Name, vs.Values[i]})
					}
				}
			}
		}
	}
	values := map[string]map[string]string{} // package -> name -> value
	var eval func(pkg string, e ast.Expr) (string, bool)
	eval = func(pkg string, e ast.Expr) (string, bool) {
		switch e := e.(type) {
		case *ast.BasicLit:
			if e.Kind != token.STRING {
				return "", false
			}
			s, err := strconv.Unquote(e.Value)
			return s, err == nil
		case *ast.Ident:
			v, ok := values[pkg][e.Name]
			return v, ok
		case *ast.SelectorExpr:
			x, ok := e.X.(*ast.Ident)
			if !ok {
				return "", false
			}
			v, ok := values[x.Name][e.Sel.Name]
			return v, ok
		case *ast.ParenExpr:
			return eval(pkg, e.X)
		case *ast.BinaryExpr:
			if e.Op != token.ADD {
				return "", false
			}
			a, ok := eval(pkg, e.X)
			if !ok {
				return "", false
			}
			b, ok := eval(pkg, e.Y)
			return a + b, ok
		}
		return "", false
	}
	out := map[string]map[string]bool{}
	done := make([]bool, len(decls))
	for progress := true; progress; {
		progress = false
		for i, d := range decls {
			if done[i] {
				continue
			}
			v, ok := eval(d.pkg, d.expr)
			if !ok {
				continue
			}
			if values[d.pkg] == nil {
				values[d.pkg] = map[string]string{}
			}
			values[d.pkg][d.name] = v
			if out[d.file] == nil {
				out[d.file] = map[string]bool{}
			}
			out[d.file][v] = true
			done[i], progress = true, true
		}
	}
	return out, nil
}
