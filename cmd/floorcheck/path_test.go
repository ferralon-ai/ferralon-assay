package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
)

var testPath = []string{"app/x.Handler", "net/http.Server.Serve", "m/p.Parser.Parse"}

var testBound = BoundTo{Target: "app@c1", Component: "m@v1",
	Analysis: Analysis{AssayVersion: "v", CorpusRelease: "corpus-92d72057330c", GoVersion: "1.23.12"}}

const testBoundYAML = "{target: app@c1, component: m@v1, analysis: {assay_version: v, corpus_release: corpus-92d72057330c, go_version: 1.23.12}}"

// reviewYAML is a path_review block (and, with extra, further row keys) for the row ledgerRow writes.
func reviewYAML(status, extra string) string {
	pr := newPathReview(testPath, testBound)
	y := "    path_review:\n      path: [" + strings.Join(testPath, ", ") + "]\n      hops: 3\n      path_sha: " + pr.PathSHA + "\n      status: " + status + "\n"
	if status != StatusUnreviewed {
		y += "      by: Eric\n      date: 2026-11-16\n      note: read it\n      bound_to: " + testBoundYAML + "\n"
	}
	return y + extra
}

// adjudicate gives a row ledgerRow wrote a reviewer's conclusion.
func adjudicate(row string) string {
	return strings.Replace(row, "adjudicated: {status: unknown}",
		"adjudicated: {status: reachable, by: Eric, date: 2026-11-16, evidence: \"x.go:1\", bound_to: "+testBoundYAML+"}", 1)
}

func TestPathReviewRules(t *testing.T) {
	reach := ledgerRow("CVE-1", "m@v1", "reachable", "reachable_candidate", "", "")
	notReach := ledgerRow("CVE-2", "m@v1", "unknown", "undetermined", "x", "")
	for _, tc := range []struct {
		name, rows, want string // want is a substring of the error; empty means valid
	}{
		{"seeded unreviewed", reach + reviewYAML(StatusUnreviewed, ""), ""},
		{"missing block", reach, "no path_review block"},
		{"block on a row that is not reachable", notReach + reviewYAML(StatusUnreviewed, ""), "not reachable_candidate"},
		{"reviewed real and featured", adjudicate(reach) + reviewYAML(StatusReal, "    featured: true\n"), ""},
		{"featured while unreviewed", reach + reviewYAML(StatusUnreviewed, "    featured: true\n"), "only a real path may be featured"},
		{"featured while artifact", reach + reviewYAML(StatusArtifact, "    featured: true\n"), "only a real path may be featured"},
		{"featured without a block", adjudicate(notReach) + "    featured: true\n", "featured: true needs"},
		{"reviewed without bound_to", reach + strings.Replace(reviewYAML(StatusReal, ""), "      bound_to: "+testBoundYAML+"\n", "", 1), "needs a bound_to"},
		{"real without a reviewer", reach + strings.Replace(reviewYAML(StatusReal, ""), "      by: Eric\n", "", 1), "needs by, date and note"},
		{"unknown status", reach + reviewYAML("maybe", ""), "status \"maybe\""},
		{"hand-edited path", reach + strings.Replace(reviewYAML(StatusUnreviewed, ""), "m/p.Parser.Parse]", "m/p.Other]", 1), "does not hash the path"},
		{"wrong hop count", reach + strings.Replace(reviewYAML(StatusUnreviewed, ""), "hops: 3", "hops: 2", 1), "hops 2"},
		{"bad date", reach + strings.Replace(reviewYAML(StatusReal, ""), "2026-11-16", "yesterday", 1), "YYYY-MM-DD"},
	} {
		_, err := parseLedger([]byte(ledgerHeaderYAML + tc.rows))
		if (err == nil) != (tc.want == "") || (err != nil && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
	// seed -update reads a ledger from before path review existed.
	if _, err := parseLedgerFor([]byte(ledgerHeaderYAML+reach), false); err != nil {
		t.Errorf("lenient parse of a ledger without blocks: %v", err)
	}
}

func TestQualifiedHop(t *testing.T) {
	for _, tc := range []struct {
		symbol, hop, module string
		main                bool
	}{
		{"scip-go gomod code.gitea.io/gitea . code.gitea.io/gitea/routers/web/repo/UpdatePullRequestTarget().", "code.gitea.io/gitea/routers/web/repo.UpdatePullRequestTarget", "code.gitea.io/gitea", true},
		{"scip-go gomod stdlib v1.23.12 bytes/Buffer#ReadFrom().", "bytes.Buffer.ReadFrom", "stdlib", false},
		{"scip-go gomod golang.org/x/crypto v0.1.0 golang.org/x/crypto/ssh/extChannel#Read().", "golang.org/x/crypto/ssh.extChannel.Read", "golang.org/x/crypto", false},
		{"scip-go gomod stdlib v1.23.12 os/ReadDir().", "os.ReadDir", "stdlib", false},
		{"not a scip symbol", "not a scip symbol", "", false},
	} {
		hop, mod, isMain := qualifiedHop(tc.symbol)
		if hop != tc.hop || mod != tc.module || isMain != tc.main {
			t.Errorf("qualifiedHop(%q) = %q, %q, %v; want %q, %q, %v", tc.symbol, hop, mod, isMain, tc.hop, tc.module, tc.main)
		}
	}
}

func TestHopPackageAndDynamic(t *testing.T) {
	path := []string{"app/x.Handler", "io.Copy", "bytes.Buffer.ReadFrom", "golang.org/x/crypto/ssh.extChannel.Read", "net/url.Parse"}
	var pkgs []string
	var dyn []bool
	for i, h := range path {
		pkgs = append(pkgs, hopPackage(h, "app"))
		dyn = append(dyn, dynamicHop(path, i, "app"))
	}
	if want := []string{pkgTarget, pkgStdlib, pkgStdlib, pkgDependency, pkgStdlib}; !slices.Equal(pkgs, want) {
		t.Errorf("packages = %v, want %v", pkgs, want)
	}
	// ReadFrom is a generic interface method and calls back into a dependency; Copy is a plain call.
	if want := []bool{false, false, true, false, false}; !slices.Equal(dyn, want) {
		t.Errorf("dynamic = %v, want %v", dyn, want)
	}
}

func rcFinding(id string, frames ...string) report.AdvisoryFinding {
	f := finding(id, "m", "v1", report.VerdictReachableCandidate, "")
	for _, s := range frames {
		f.Evidence.CallPath = append(f.Evidence.CallPath, report.CallFrame{Symbol: s})
	}
	return f
}

func TestPathChangeAndSeed(t *testing.T) {
	a := "scip-go gomod app . app/x/Handler()."
	b := "scip-go gomod m v1 m/p/Parse()."
	c := "scip-go gomod m v1 m/p/Other()."
	row := LedgerRow{Advisory: []string{"A-1"}, Package: "m@v1", Target: "app", EngineExpected: Engine{Verdict: report.VerdictReachableCandidate}}
	row.PathReview = newPathReview([]string{"app/x.Handler", "m/p.Parse"}, testBound)
	l := Ledger{Header: LedgerHeader{Target: "app"}, Rows: []LedgerRow{row}}

	same := engineRows([]report.AdvisoryFinding{rcFinding("A-1", a, b)})
	if d := compareLedger(l, same).Lines; len(d) != 0 {
		t.Errorf("unchanged path differs: %v", d)
	}
	moved := engineRows([]report.AdvisoryFinding{rcFinding("A-1", a, c)})
	d := compareLedger(l, moved).Lines
	if len(d) != 1 || !strings.Contains(d[0], "path changed: A-1 | m@v1 | app") ||
		!strings.Contains(d[0], "app/x.Handler -> m/p.Parse") || !strings.Contains(d[0], "app/x.Handler -> m/p.Other") {
		t.Errorf("changed path lines = %q, want the row with its old and new path", d)
	}

	// Seeding keeps a review while the path holds and resets it, and the featured flag, when it moves.
	row.PathReview.Status, row.PathReview.By, row.PathReview.Date, row.PathReview.Note = StatusReal, "Eric", "2026-11-16", "ok"
	row.PathReview.BoundTo = &BoundTo{Target: "app@c1", Component: "m@v1", Symbol: "m/p.Parse", Analysis: testBound.Analysis}
	row.Featured, row.ComparatorObserved, row.Basis, row.Source = true, TruthReachable, "b", "s"
	row.Adjudicated = Adjudicated{Status: TruthReachable, By: "Eric", Date: "2026-11-16", Evidence: "x.go:1", BoundTo: row.PathReview.BoundTo}
	in := scanInputs{Commit: "c1", AssayVersion: "v", CorpusRelease: "corpus-92d72057330c", GoVersion: "1.23.12"}
	prior := Ledger{Rows: []LedgerRow{row}}
	kept := seedLedger(LedgerHeader{Target: "app"}, report.Report{Advisories: []report.AdvisoryFinding{rcFinding("A-1", a, b)}}, Evidence{}, &prior, in)
	if r := kept.Rows[0]; r.PathReview.Status != StatusReal || !r.Featured {
		t.Errorf("unchanged path lost its review: %+v featured=%v", r.PathReview, r.Featured)
	}
	reset := seedLedger(LedgerHeader{Target: "app"}, report.Report{Advisories: []report.AdvisoryFinding{rcFinding("A-1", a, c)}}, Evidence{}, &prior, in)
	if r := reset.Rows[0]; r.PathReview.Status != StatusUnreviewed || r.PathReview.By != "" || r.Featured || r.PathReview.Path[1] != "m/p.Other" {
		t.Errorf("changed path kept its review: %+v featured=%v", r.PathReview, r.Featured)
	}
	if err := reset.Rows[0].validatePathReview(true); err != nil {
		t.Errorf("seeded ledger invalid: %v", err)
	}
}

func TestReviewAid(t *testing.T) {
	row := LedgerRow{Advisory: []string{"A-1"}, Package: "m@v1", EngineExpected: Engine{Verdict: report.VerdictReachableCandidate},
		PathReview: newPathReview([]string{"app/x.Handler", "bytes.Buffer.ReadFrom", "example.com/m/p.Read"}, testBound)}
	skipped := LedgerRow{Advisory: []string{"A-2"}, Package: "m@v1", EngineExpected: Engine{Verdict: report.VerdictUndetermined}}
	var out bytes.Buffer
	reachable, dyn := writeReviewAid(&out, Ledger{Header: LedgerHeader{MainModule: "app"}, Rows: []LedgerRow{row, skipped}})
	if reachable != 1 || dyn != 1 {
		t.Errorf("reachable, dynamic = %d, %d; want 1, 1", reachable, dyn)
	}
	for _, want := range []string{"A-1 | m@v1", "status: unreviewed", " 1. [target    ] app/x.Handler", " 2. [stdlib    ] bytes.Buffer.ReadFrom  <- likely interface dispatch", " 3. [dependency] example.com/m/p.Read"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("aid lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "A-2") {
		t.Errorf("aid lists a row that is not reachable:\n%s", out.String())
	}
}
