package jsanalysis

// cve_watch_test.go — C4 scheduled CVE-watch for the JS lane (PLAN-165, §3.1). These tests drive the
// REAL exported trigger.RunCVEWatch over a baseline seeded by RunBaseline, with a faithful in-test
// OSV fake. RunCVEWatch queries OSV over the STORED SBOM's packages, diffs the returned advisory IDs
// against the stored cursor, and either heartbeats (no new IDs) or runs an earnest re-analysis (new
// IDs). §3-safe: no network, no package manager, no target code — the fake replaces OSV.dev and every
// dependency fact is read statically from committed lockfiles.

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// fakeOSVClient is a faithful stand-in for OSV.dev's querybatch: it returns a canned advisory ONLY
// when the advisory's package is among the packages actually queried — exactly the real endpoint's
// contract (querybatch reports advisories for the coordinates you POST, and only those). This
// faithfulness is what makes the "absent package" control meaningful: an advisory for a coordinate
// the SBOM never carried is never returned, so RunCVEWatch cannot manufacture a finding for it.
type fakeOSVClient struct {
	canned []trigger.OSVAdvisory
	calls  int
}

func (f *fakeOSVClient) QueryBatch(ctx context.Context, pkgs []report.Package) (trigger.OSVResult, error) {
	f.calls++
	queried := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		queried[p.Key()] = true
	}
	var out []trigger.OSVAdvisory
	for _, a := range f.canned {
		if queried[a.Package.Key()] {
			out = append(out, a)
		}
	}
	return trigger.OSVResult{Advisories: out}, nil
}

// toughCookie is the advisory-named transitive the CVE-2023-26136 yarn repro resolves (jsdom →
// tough-cookie@4.1.2); TestSBOM_JS_VulnerableTransitivePresent proves it reaches the SBOM. CVE-watch
// keys advisories on this coordinate.
var toughCookie = report.Package{
	Ecosystem: "npm",
	Name:      "tough-cookie",
	Version:   "4.1.2",
	PURL:      "pkg:npm/tough-cookie@4.1.2",
}

// TestCVEWatch_JS_NewAdvisoryOverStoredPackageFinding is the C4 positive: OSV reports a NEW advisory
// (absent from the empty stored cursor) whose package IS in the stored SBOM (tough-cookie@4.1.2). The
// overlap forces an earnest run — Heartbeat:false, the new ID in NewAdvisories, a non-nil Report.
//
// Non-vacuity: a watch that treated every pass as a heartbeat (never diffing new IDs into an earnest
// run) would return Heartbeat:true and fail.
func TestCVEWatch_JS_NewAdvisoryOverStoredPackageFinding(t *testing.T) {
	store := seedJSBaseline(t, yarnJsdomDir, "") // empty cursor: any returned ID is "new"

	osv := &fakeOSVClient{canned: []trigger.OSVAdvisory{
		{ID: "GHSA-72xf-g2v4-qvf3", Package: toughCookie}, // CVE-2023-26136, over a package IN the SBOM
	}}

	res, err := trigger.RunCVEWatch(context.Background(), store, osv, trigger.CVEWatchRequest{
		Subject:       trigger.Subject{Repo: "example.com/js-fixture", ResolvedCommit: "watch-sha"},
		Codebase:      jsCodebase(yarnJsdomDir),
		AssessOptions: jsAssessOpts(),
	})
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if res.Heartbeat {
		t.Fatalf("positive: a new advisory over a stored package must force an earnest run, got heartbeat")
	}
	if !containsStr(res.NewAdvisories, "GHSA-72xf-g2v4-qvf3") {
		t.Fatalf("positive: NewAdvisories must name the new advisory, got %q", res.NewAdvisories)
	}
	if res.Report == nil {
		t.Fatalf("positive: earnest run must produce a Report")
	}
	if osv.calls != 1 {
		t.Fatalf("positive: expected exactly one OSV querybatch, got %d", osv.calls)
	}
}

// TestCVEWatch_JS_AdvisoryAbsentPackageNoFinding is MANDATORY CONTROL 1: OSV holds an advisory for a
// package that is NOT in the stored SBOM. A faithful querybatch never returns it (that coordinate was
// never queried), so there is no new ID and the pass heartbeats — no earnest finding is manufactured.
//
// Non-vacuity: a watch that keyed on advisory existence alone (ignoring whether the coordinate is in
// the SBOM it queried) would earnest-run and fabricate a finding for a package the codebase does not
// carry — this asserts it does not.
func TestCVEWatch_JS_AdvisoryAbsentPackageNoFinding(t *testing.T) {
	store := seedJSBaseline(t, yarnJsdomDir, "")

	absent := report.Package{Ecosystem: "npm", Name: "not-in-this-sbom", Version: "9.9.9", PURL: "pkg:npm/not-in-this-sbom@9.9.9"}
	osv := &fakeOSVClient{canned: []trigger.OSVAdvisory{
		{ID: "GHSA-ffff-ffff-ffff", Package: absent}, // advisory for a coordinate the SBOM never carried
	}}

	res, err := trigger.RunCVEWatch(context.Background(), store, osv, trigger.CVEWatchRequest{
		Subject:       trigger.Subject{Repo: "example.com/js-fixture", ResolvedCommit: "watch-sha"},
		Codebase:      jsCodebase(yarnJsdomDir),
		AssessOptions: jsAssessOpts(),
	})
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if !res.Heartbeat {
		t.Fatalf("control-1: an advisory for a package absent from the SBOM must NOT earnest-run; got new=%q", res.NewAdvisories)
	}
	if len(res.NewAdvisories) != 0 {
		t.Fatalf("control-1: absent-package advisory must not surface as NewAdvisories, got %q", res.NewAdvisories)
	}
	if res.Report != nil {
		t.Fatalf("control-1: a heartbeat must not produce a new Report")
	}
}

// TestCVEWatch_JS_UnresolvedInventoryDeclaresPartiality is MANDATORY CONTROL 2 (§3.1): a watch over a
// baseline whose INVENTORY was partial must stay distinguishable from a clean "no newly affected"
// result — never infer safety from missing evidence.
//
// Investigation result (recorded so the assertion is honest about WHERE the distinction lives):
// RunCVEWatch's heartbeat path (trigger/trigger.go:340-347) writes only the cursor and returns a
// CVEWatchResult of {Heartbeat, Cursor} with Report=nil — so the RESULT object alone is byte-identical
// for a clean vs a partial baseline. The distinction is NOT masked, however: the heartbeat leaves
// state.Report untouched, so the baseline's scan-level inventory-partiality note (emitted by
// sbomFromInventory → inventoryPartialityNotes for a graph-partial inventory) survives in the
// STORED/inherited Report. This test asserts that surviving distinction on the stored state:
// the partial baseline's stored Report carries the alias_target partiality note after a heartbeat;
// the clean baseline's does not.
//
// Non-vacuity: a heartbeat that rebuilt the Report and dropped the baseline's partiality (making an
// unresolved scan render clean) would fail the "partial retains the note" assertion.
func TestCVEWatch_JS_UnresolvedInventoryDeclaresPartiality(t *testing.T) {
	// fakeOSVClient with no canned advisories → querybatch returns nothing → both baselines heartbeat.
	newOSV := func() *fakeOSVClient { return &fakeOSVClient{} }

	heartbeatThenReadPartiality := func(t *testing.T, dir string) []report.PartialityNote {
		t.Helper()
		store := seedJSBaseline(t, dir, "")
		res, err := trigger.RunCVEWatch(context.Background(), store, newOSV(), trigger.CVEWatchRequest{
			Subject:       trigger.Subject{Repo: "example.com/js-fixture", ResolvedCommit: "watch-sha"},
			Codebase:      jsCodebase(dir),
			AssessOptions: jsAssessOpts(),
		})
		if err != nil {
			t.Fatalf("RunCVEWatch(%s): %v", dir, err)
		}
		if !res.Heartbeat {
			t.Fatalf("%s: expected a heartbeat (OSV returned nothing new), got earnest run", dir)
		}
		state, err := store.Read(context.Background())
		if err != nil {
			t.Fatalf("read stored state after heartbeat: %v", err)
		}
		if state.Report == nil {
			t.Fatalf("%s: stored Report missing after heartbeat", dir)
		}
		return state.Report.Partiality
	}

	cleanNotes := heartbeatThenReadPartiality(t, filepath.Join(invDir, "cve", "clean"))
	partialNotes := heartbeatThenReadPartiality(t, filepath.Join(invDir, "cve", "partial"))

	if notesHaveReason(cleanNotes, plugin.PartialReasonAliasTargetAbsent) {
		t.Fatalf("control-2: the CLEAN baseline must not carry an inventory-partiality note; got %+v", cleanNotes)
	}
	if !notesHaveReason(partialNotes, plugin.PartialReasonAliasTargetAbsent) {
		t.Fatalf("control-2: the PARTIAL baseline's inventory-partiality note (%s) must SURVIVE the heartbeat in the stored Report — an unresolved inventory must stay distinguishable from clean; got %+v",
			plugin.PartialReasonAliasTargetAbsent, partialNotes)
	}
}

func notesHaveReason(notes []report.PartialityNote, reason string) bool {
	for _, n := range notes {
		if n.Reason == reason {
			return true
		}
	}
	return false
}
