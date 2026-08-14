package trigger_test

// PLAN-173 C5 — CVE-watch evaluates a newly-disclosed advisory against the STORED Python inventory.
// External test package (trigger_test): drives only exported RunBaseline / RunCVEWatch and reuses
// the C3 in-process Python-plugin adapter (pythonInventoryPlugin) + vendored fixture, so the stored
// SBOM is real pythonanalysis.ResolveInventory output over a native-captured pdm.lock (jinja2 ->
// markupsafe), never a hand-fabricated inventory.
//
// The criterion is a PAIRING, and either half alone is satisfiable by a broken implementation:
//   POSITIVE — markupsafe is in the resolved inventory but named by NO advisory in the corpus (the
//     "not in the advisory work set at scan time" distribution, verified in C3). An advisory
//     disclosed AFTER the scan against markupsafe MUST be evaluated. This can only happen if the
//     watch queries the WHOLE stored inventory, not the shrunken advisory work set.
//   NEGATIVE — an advisory against a distribution NOT in the stored inventory MUST NOT be evaluated.
//     The watch queries the stored inventory, so a distribution the inventory never contained is
//     never even queried, and no disclosure about it can force a run.
//
// The pairing distinguishes "watch reads the stored inventory" from "watch evaluates everything".

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// c5FakeOSV is a faithful OSVClient: OSV.dev only ever reports advisories for the coordinates it was
// asked about, so this fake returns an advisory IFF its distribution appears in the queried package
// set — i.e. IFF that distribution is in the STORED inventory RunCVEWatch built the query from. It
// records the queried names so a test can prove the query was scoped to the stored inventory (the
// stored inventory is what includes non-advisory-work-set markupsafe and excludes leftpad).
type c5FakeOSV struct {
	// disclose maps a distribution name to the advisory OSV.dev would newly report against it.
	disclose map[string]string
	// queried records every distribution name the watch actually queried OSV.dev for.
	queried map[string]bool
}

func (f *c5FakeOSV) QueryBatch(_ context.Context, pkgs []report.Package) (trigger.OSVResult, error) {
	if f.queried == nil {
		f.queried = map[string]bool{}
	}
	var out []trigger.OSVAdvisory
	for _, p := range pkgs {
		f.queried[p.Name] = true
		if id, ok := f.disclose[p.Name]; ok {
			out = append(out, trigger.OSVAdvisory{ID: id, Package: p})
		}
	}
	return trigger.OSVResult{Advisories: out}, nil
}

func c5Codebase(dir string) assessment.CodebaseRef {
	return assessment.CodebaseRef{
		Repo:        "example.com/pyapp",
		Revision:    "sha",
		Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: dir},
	}
}

func hasPyPI(sbom report.SBOM, name string) bool {
	for _, p := range sbom.Packages {
		if p.Ecosystem == "PyPI" && p.Name == name {
			return true
		}
	}
	return false
}

func hasFinding(rep *report.Report, id string) bool {
	if rep == nil {
		return false
	}
	for _, f := range rep.Advisories {
		if f.Advisory.ID == id {
			return true
		}
	}
	return false
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestC5_CVEWatchEvaluatesNewlyDisclosedAdvisoryAgainstStoredInventory is C5 end-to-end. A real
// baseline stores the resolved Python inventory (jinja2 -> markupsafe); the scan-time cursor names
// no markupsafe advisory. Then two advisories are "disclosed": one against markupsafe (in the stored
// inventory, absent from the work set) and one against leftpad (absent from the stored inventory).
// The watch must evaluate the first and never the second.
func TestC5_CVEWatchEvaluatesNewlyDisclosedAdvisoryAgainstStoredInventory(t *testing.T) {
	ctx := context.Background()

	// A real vendored inventory: jinja2 -> markupsafe (the C3 harness fixture). markupsafe is in the
	// resolved inventory and named by no advisory in the corpus (verified in the C3 test).
	dir, _ := vendoredPythonFixture(t)
	plugin := []pipeline.AssessOption{pipeline.WithPlugin(pythonInventoryPlugin{})}

	// The advisory work set at scan time (the cursor) — deliberately does NOT name markupsafe: at
	// scan time no advisory covered it, which is exactly the case C5 exists for.
	const scanTimeCursor = "PYSEC-2024-JINJA2-PLACEHOLDER"

	store := statestore.NewMemStore()
	if _, err := trigger.RunBaseline(ctx, store, trigger.BaselineRequest{
		Subject:       trigger.Subject{Repo: "example.com/pyapp", ResolvedCommit: "base-sha"},
		Codebase:      c5Codebase(dir),
		AssessOptions: plugin,
		Cursor:        scanTimeCursor,
	}); err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}

	// Guard the premise: the stored inventory really contains markupsafe (the positive distribution)
	// and really does not contain leftpad (the negative distribution). Without this, the pairing
	// below proves nothing.
	state, err := store.Read(ctx)
	if err != nil {
		t.Fatalf("read stored state: %v", err)
	}
	if !hasPyPI(state.SBOM, "markupsafe") {
		t.Fatalf("stored inventory is missing markupsafe — the positive distribution; SBOM = %+v", state.SBOM.Packages)
	}
	if hasPyPI(state.SBOM, "leftpad") {
		t.Fatal("stored inventory unexpectedly contains leftpad — the negative distribution is invalid")
	}

	const advMarkupsafe = "PYSEC-2026-MARKUPSAFE-0001" // disclosed AFTER the scan, against a stored distribution
	const advLeftpad = "PYSEC-2026-LEFTPAD-0001"       // disclosed AFTER the scan, against a NON-stored distribution
	osv := &c5FakeOSV{disclose: map[string]string{
		"markupsafe": advMarkupsafe,
		"leftpad":    advLeftpad,
	}}

	res, err := trigger.RunCVEWatch(ctx, store, osv, trigger.CVEWatchRequest{
		Subject:       trigger.Subject{Repo: "example.com/pyapp", ResolvedCommit: "base-sha"},
		Codebase:      c5Codebase(dir),
		AssessOptions: plugin,
	})
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}

	// POSITIVE — the markupsafe advisory IS evaluated: it forced an earnest run (not a heartbeat),
	// it appears in the newly-relevant set, and it is a finding in the re-analyzed Report.
	if res.Heartbeat {
		t.Fatal("watch heartbeat — a newly-disclosed advisory against a stored distribution was not evaluated")
	}
	if !contains(res.NewAdvisories, advMarkupsafe) {
		t.Errorf("markupsafe advisory not in NewAdvisories %v — a disclosure against a stored non-work-set distribution was not evaluated", res.NewAdvisories)
	}
	if !hasFinding(res.Report, advMarkupsafe) {
		t.Errorf("markupsafe advisory produced no finding in the re-analyzed report — it was not actually evaluated")
	}
	// The query was built from the stored inventory: markupsafe (in it) WAS queried. This is why the
	// disclosure could be caught at all — a watch keyed on the advisory work set would never have
	// queried markupsafe.
	if !osv.queried["markupsafe"] {
		t.Error("markupsafe was never queried — the watch did not key its query on the stored inventory")
	}

	// NEGATIVE — the leftpad advisory is NOT evaluated: leftpad is absent from the stored inventory,
	// so it was never queried and no disclosure about it could force a run. This is the half that
	// separates "watch reads the inventory" from "watch evaluates everything".
	if contains(res.NewAdvisories, advLeftpad) {
		t.Errorf("leftpad advisory in NewAdvisories %v — an advisory against a distribution absent from the stored inventory was evaluated", res.NewAdvisories)
	}
	if hasFinding(res.Report, advLeftpad) {
		t.Error("leftpad advisory produced a finding — a non-inventory distribution was evaluated")
	}
	if osv.queried["leftpad"] {
		t.Error("leftpad was queried despite being absent from the stored inventory — the query is not inventory-keyed")
	}
}
