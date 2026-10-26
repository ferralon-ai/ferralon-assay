package trigger

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/intel"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// storedWithStalePriority is a stored Report whose rows carry Priority from some earlier run's
// signals file: CVE-2025-8110 with an old EPSS value, CVE-2021-38561 with none.
func storedWithStalePriority() *report.Report {
	stale := &report.Priority{EPSSScore: 0.5, EPSSAsOf: "2026-07-29"}
	r := report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "base"}).
		AddFinding(report.AdvisoryFinding{Advisory: report.Advisory{ID: "CVE-2025-8110", Source: "osv"}, Verdict: report.VerdictDisqualified, Priority: stale}).
		AddFinding(report.AdvisoryFinding{Advisory: report.Advisory{ID: "GO-2021-0113", Source: "osv", Aliases: []string{"CVE-2021-38561"}}, Verdict: report.VerdictDisqualified}).
		Build()
	return &r
}

// TestEveryPathRanksRowsByThisRunsSignals: the inherited fast path, the re-analysis merge and the
// CVE-watch merge all rank every row — inherited ones included — by THIS run's signals, so no row
// keeps a value from a signals file the run did not read, and a run with no signals carries no
// Priority on any row. The verdicts are untouched.
func TestEveryPathRanksRowsByThisRunsSignals(t *testing.T) {
	ctx := context.Background()
	sig := prioritySignals(t)
	subject := Subject{Repo: "github.com/example/widget", ResolvedCommit: "head"}
	paths := map[string]func(*testing.T, PRInheritRequest) *report.Report{
		"inherit": func(t *testing.T, req PRInheritRequest) *report.Report {
			rep, err := inheritBaseline(storedWithStalePriority(), req, &statestore.State{}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			return rep
		},
		"reanalyze": func(t *testing.T, req PRInheritRequest) *report.Report {
			rep, err := reanalyzeSlice(ctx, storedWithStalePriority(), req, &statestore.State{}, []string{"Go\x00example.com/changed"})
			if err != nil {
				t.Fatal(err)
			}
			return rep
		},
		"cve-watch": func(t *testing.T, req PRInheritRequest) *report.Report {
			rep, err := earnestRun(ctx, &statestore.State{Report: storedWithStalePriority()},
				CVEWatchRequest{Subject: req.Subject, Signals: req.Signals}, OSVResult{}, nil, "osv:next")
			if err != nil {
				t.Fatal(err)
			}
			return rep
		},
	}
	for name, run := range paths {
		t.Run(name+"/no signals", func(t *testing.T) {
			for _, f := range run(t, PRInheritRequest{Subject: subject}).Advisories {
				if f.Priority != nil {
					t.Errorf("%s kept Priority %+v with no signals", f.Advisory.ID, *f.Priority)
				}
			}
		})
		t.Run(name+"/signals", func(t *testing.T) {
			rep := run(t, PRInheritRequest{Subject: subject, Signals: sig})
			if err := rep.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			claims := new(intel.Claims)
			for _, f := range rep.Advisories {
				claims.Add(f.Advisory.ID, f.Advisory.Aliases...)
			}
			for _, f := range rep.Advisories {
				if f.Verdict != report.VerdictDisqualified {
					t.Errorf("%s verdict = %s; ranking must not touch it", f.Advisory.ID, f.Verdict)
				}
				want := priorityFor(f.Advisory, sig, claims)
				if f.Priority == nil || *f.Priority != *want {
					t.Errorf("%s Priority = %+v, want this run's %+v", f.Advisory.ID, f.Priority, want)
				}
			}
		})
	}
}

// TestNoVerdictCodeReadsPriority proves Priority is ranking context only (inv. 5): nothing that
// decides a verdict reads it, or the signals it comes from.
//
//   - The pipeline and verdict packages never import internal/intel and never name a Priority.
//   - In this package, no function reachable from findingInBuild — the verdict decision, including
//     every grounds.go helper it calls — names Priority, the signals, priorityFor or rankWith, and
//     neither does any function in grounds.go itself.
//
// The call graph is the static one over this package's own function and method names, which
// over-approximates what findingInBuild can reach; that is the safe direction for this check.
func TestNoVerdictCodeReadsPriority(t *testing.T) {
	fset := token.NewFileSet()
	parseDir := func(dir string) []*ast.File {
		t.Helper()
		paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		var files []*ast.File
		for _, p := range paths {
			if strings.HasSuffix(p, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
		}
		if len(files) == 0 {
			t.Fatalf("no Go source under %s: the check would be vacuous", dir)
		}
		return files
	}
	// forbidden names the identifiers that read priority or signals.
	forbidden := map[string]bool{"Priority": true, "WithPriority": true, "priorityFor": true, "rankWith": true, "Signals": true, "intel": true}
	reads := func(n ast.Node) string {
		hit := ""
		ast.Inspect(n, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && forbidden[id.Name] && hit == "" {
				hit = id.Name
			}
			return hit == ""
		})
		return hit
	}

	for _, dir := range []string{"../pipeline", "../verdict"} {
		for _, f := range parseDir(dir) {
			name := fset.Position(f.Package).Filename
			for _, imp := range f.Imports {
				if strings.Contains(imp.Path.Value, "/internal/intel") {
					t.Errorf("%s imports %s: verdict code must not see signals", name, imp.Path.Value)
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Priority" {
					t.Errorf("%s reads .Priority at %s", name, fset.Position(sel.Pos()))
				}
				return true
			})
		}
	}

	// This package: index every function by name, then walk the call graph from findingInBuild.
	funcs := map[string][]*ast.FuncDecl{}
	var grounds []*ast.FuncDecl
	for _, f := range parseDir(".") {
		isGrounds := filepath.Base(fset.Position(f.Package).Filename) == "grounds.go"
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				funcs[fd.Name.Name] = append(funcs[fd.Name.Name], fd)
				if isGrounds {
					grounds = append(grounds, fd)
				}
			}
		}
	}
	if len(grounds) == 0 {
		t.Fatal("found no functions in grounds.go: the check would be vacuous")
	}
	seen := map[*ast.FuncDecl]bool{}
	queue := append([]*ast.FuncDecl{}, funcs["findingInBuild"]...)
	queue = append(queue, grounds...)
	if len(funcs["findingInBuild"]) == 0 {
		t.Fatal("findingInBuild not found: the check would be vacuous")
	}
	for len(queue) > 0 {
		fd := queue[0]
		queue = queue[1:]
		if seen[fd] {
			continue
		}
		seen[fd] = true
		if hit := reads(fd.Body); hit != "" {
			t.Errorf("%s (reachable from the verdict decision) names %s", fd.Name.Name, hit)
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var callee string
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				callee = fn.Name
			case *ast.SelectorExpr:
				callee = fn.Sel.Name
			}
			queue = append(queue, funcs[callee]...)
			return true
		})
	}
	t.Logf("walked %d functions reachable from the verdict decision", len(seen))
	if len(seen) < 10 {
		t.Errorf("walked only %d functions from findingInBuild: the call-graph walk looks broken", len(seen))
	}

	// Positive control: the walk does flag a reader. priorityFor names Signals by construction.
	if hit := reads(funcs["priorityFor"][0]); hit == "" {
		t.Error("positive control: priorityFor should be flagged as reading signals")
	}
	if _, err := os.Stat("grounds.go"); err != nil {
		t.Fatalf("grounds.go: %v", err)
	}
}
