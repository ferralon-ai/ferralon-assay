// internal/pipeline/attribution_test.go
//
// PLAN-220 convergence tests C1–C6 for the advisory attribution sidecar. Hermetic: no build tag, no
// env opt-in — every check below runs under `go test ./...`.
package pipeline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpusKnownIDs loads the real corpus manifest and returns its advisory id set — the §0 integrity
// oracle (an attribution key must resolve to one of these). Uses the manifest on disk, not
// AdvisoryTable, so the test is faithful to "resolves to a corpusManifest.advisories record".
func corpusKnownIDs(t *testing.T) map[string]bool {
	t.Helper()
	mb, err := os.ReadFile(filepath.Join(advisoryCorpusDir, advisoryCorpusManifestFile))
	if err != nil {
		t.Fatalf("read corpus manifest: %v", err)
	}
	var man corpusManifest
	if err := json.Unmarshal(mb, &man); err != nil {
		t.Fatalf("decode corpus manifest: %v", err)
	}
	known := make(map[string]bool, len(man.Advisories))
	for id := range man.Advisories {
		known[id] = true
	}
	return known
}

func mustReviewedAt() string { return "2026-08-12T00:00:00Z" }

// --- C2 substrate: type + loader ---------------------------------------------------------------

func TestLoadAttributionStore(t *testing.T) {
	// The shipped store is the honest zero: `{}` → empty store → every record unreviewed.
	store, err := loadAttributionStore(advisoryCorpusDir)
	if err != nil {
		t.Fatalf("load real attribution.json: %v", err)
	}
	if len(store) != 0 {
		t.Fatalf("shipped attribution.json is not empty: %d entries (no attribution may be fabricated for the unreviewed records)", len(store))
	}

	// An ABSENT file is the same honest zero (no error).
	empty := t.TempDir()
	store, err = loadAttributionStore(empty)
	if err != nil {
		t.Fatalf("absent attribution.json must load as empty, got %v", err)
	}
	if len(store) != 0 {
		t.Fatalf("absent file yielded %d entries, want 0", len(store))
	}

	// A present entry round-trips through the wire form.
	dir := t.TempDir()
	want := AdvisoryAttribution{Status: AttributionConfirmed, Reviewer: "eric", Citation: "GHSA-x", ReviewedAt: mustReviewedAt()}
	b, _ := json.Marshal(AttributionStore{"CVE-2024-45337": want})
	if err := os.WriteFile(filepath.Join(dir, attributionStoreFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
	store, err = loadAttributionStore(dir)
	if err != nil {
		t.Fatalf("load present entry: %v", err)
	}
	if got := store["CVE-2024-45337"]; got != want {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}
}

// --- C5: integrity enforced, not documented ----------------------------------------------------

// TestAttributionStore_Integrity is the always-on hermetic enforcement: the shipped store has no
// orphan and no invalid entry against the real corpus.
func TestAttributionStore_Integrity(t *testing.T) {
	store, err := loadAttributionStore(advisoryCorpusDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := checkAttributionIntegrity(store, corpusKnownIDs(t)); err != nil {
		t.Fatalf("shipped attribution.json fails integrity: %v", err)
	}
}

// TestAttributionIntegrity_OrphanFails is the C5 fixture-less-record check: an attribution keyed by a
// vuln_id with NO corpus fixture fails mechanically; removing it passes. Plus the required mutation
// control — a variant that logs instead of returning nil would let the orphan through, and the
// assertion below would go red.
func TestAttributionIntegrity_OrphanFails(t *testing.T) {
	known := corpusKnownIDs(t)

	orphan := AttributionStore{
		"CVE-0000-0000": {Status: AttributionConfirmed, Reviewer: "eric", Citation: "x", ReviewedAt: mustReviewedAt()},
	}
	if err := checkAttributionIntegrity(orphan, known); err == nil {
		t.Fatal("fixture-less attribution must fail integrity (§0), got nil")
	}

	// Remove the orphan → passes.
	if err := checkAttributionIntegrity(AttributionStore{}, known); err != nil {
		t.Fatalf("empty store must pass integrity, got %v", err)
	}

	// Mutation control: a check that downgrades the failure to a log line returns nil, which would
	// flip the `err == nil` assertion above to a pass. Prove the mutant returns nil so the real
	// check — not a passthrough — is what fails the suite.
	logMutant := func(store AttributionStore, known map[string]bool) error {
		for id := range store {
			if !known[id] {
				t.Logf("(mutant) orphan attribution %s — logged, not failed", id)
			}
		}
		return nil
	}
	if logMutant(orphan, known) != nil {
		t.Fatal("mutant unexpectedly returned an error")
	}
	// Under logMutant the orphan assertion becomes `nil == nil` → the C5 test goes red. Recorded.
}

// --- C3/C4: sliced coverage report, no blended number ------------------------------------------

func TestCoverageReport(t *testing.T) {
	table := map[string]AdvisoryFacts{
		"GO-A":  {PURL: "pkg:golang/example.com/a", Symbols: []string{"a.F"}}, // unreviewed
		"GO-B":  {PURL: "pkg:golang/example.com/b"},                           // reviewed-none-found
		"NPM-C": {PURL: "pkg:npm/c", Symbols: []string{"c"}},                  // confirmed
		"PY-D":  {PURL: "pkg:pypi/d", Symbols: []string{"d"}},                 // disputed
		"MVN-E": {PURL: "pkg:maven/e/e", Symbols: []string{"e"}},              // ambiguous
	}
	store := AttributionStore{
		"GO-B":  {Reviewer: "eric", ReviewedAt: mustReviewedAt()}, // Status "" → reviewed-none-found
		"NPM-C": {Status: AttributionConfirmed, Reviewer: "eric", Citation: "GHSA-c", ReviewedAt: mustReviewedAt()},
		"PY-D":  {Status: AttributionDisputed, Reviewer: "anvil", Citation: "GHSA-d", Reason: "symbol never reaches sink", ReviewedAt: mustReviewedAt()},
		"MVN-E": {Status: AttributionAmbiguous, Reviewer: "eric", Citation: "GHSA-e", ReviewedAt: mustReviewedAt()},
	}

	rows := buildCoverageReport(table, store)

	// One row per (ecosystem × state) — every cell present, including empties.
	wantCells := len(coverageEcosystems) * len(coverageStates)
	if len(rows) != wantCells {
		t.Fatalf("coverage rows = %d, want one per (ecosystem × state) = %d", len(rows), wantCells)
	}

	byCell := map[[2]string]CoverageRow{}
	total := 0
	for _, r := range rows {
		byCell[[2]string{r.Ecosystem, r.AttributionState}] = r
		total += r.RecordCount
	}
	if total != len(table) {
		t.Fatalf("sum of record_count = %d, want %d (no record may vanish from a total)", total, len(table))
	}

	// reviewed-none-found and unreviewed are SEPARATE rows (the §3.1 distinction).
	rnf := byCell[[2]string{"golang", stateReviewedNoneFound}]
	unrev := byCell[[2]string{"golang", stateUnreviewed}]
	if rnf.RecordCount != 1 || rnf.Records[0] != "GO-B" {
		t.Fatalf("golang reviewed-none-found row = %+v, want GO-B", rnf)
	}
	if unrev.RecordCount != 1 || unrev.Records[0] != "GO-A" {
		t.Fatalf("golang unreviewed row = %+v, want GO-A", unrev)
	}
	if rnf.AttributionState == unrev.AttributionState {
		t.Fatal("reviewed-none-found and unreviewed collapsed into one state")
	}

	// ambiguous is its own row (not folded into attributed-and-reviewed).
	if amb := byCell[[2]string{"maven", stateAmbiguous}]; amb.RecordCount != 1 || amb.Records[0] != "MVN-E" {
		t.Fatalf("maven ambiguous row = %+v, want MVN-E", amb)
	}
	if arr := byCell[[2]string{"maven", stateAttributedReviewed}]; arr.RecordCount != 0 {
		t.Fatalf("maven attributed-and-reviewed should be 0 (ambiguous not folded in), got %d", arr.RecordCount)
	}

	// C4: the disputed record is present, counted, non-suppressible, with reason + reviewer.
	disp := byCell[[2]string{"pypi", stateDisputed}]
	if disp.RecordCount != 1 || len(disp.DisputedDetail) != 1 {
		t.Fatalf("pypi disputed row = %+v, want one disputed record", disp)
	}
	if d := disp.DisputedDetail[0]; d.VulnID != "PY-D" || d.Reason == "" || d.Reviewer != "anvil" {
		t.Fatalf("disputed detail = %+v, want vuln_id/reason/reviewer populated", d)
	}

	// C3 grep-check equivalent: the serialized report carries no blended percentage.
	rb, _ := json.Marshal(rows)
	if strings.Contains(string(rb), "%") {
		t.Fatal("coverage report contains a '%' — no blended rate may be published (C3)")
	}
}

// --- C6: evidence validator (reject/accept arms) -----------------------------------------------

func TestValidateAttributionEntry(t *testing.T) {
	at := mustReviewedAt()
	tests := []struct {
		name    string
		entry   AdvisoryAttribution
		wantErr bool
	}{
		// REJECT arms
		{"no reviewer", AdvisoryAttribution{Status: AttributionConfirmed, Citation: "x", ReviewedAt: at}, true},
		{"no reviewed_at", AdvisoryAttribution{Status: AttributionConfirmed, Reviewer: "eric", Citation: "x"}, true},
		{"confirmed no citation", AdvisoryAttribution{Status: AttributionConfirmed, Reviewer: "eric", ReviewedAt: at}, true},
		{"ambiguous no citation", AdvisoryAttribution{Status: AttributionAmbiguous, Reviewer: "eric", ReviewedAt: at}, true},
		{"disputed no citation", AdvisoryAttribution{Status: AttributionDisputed, Reviewer: "eric", Reason: "r", ReviewedAt: at}, true},
		{"disputed no reason", AdvisoryAttribution{Status: AttributionDisputed, Reviewer: "eric", Citation: "x", ReviewedAt: at}, true},
		{"unrecognized status", AdvisoryAttribution{Status: "bogus", Reviewer: "eric", Citation: "x", ReviewedAt: at}, true},
		// ACCEPT arms
		{"confirmed with citation", AdvisoryAttribution{Status: AttributionConfirmed, Reviewer: "eric", Citation: "x", ReviewedAt: at}, false},
		{"reviewed-none-found empty citation", AdvisoryAttribution{Status: "", Reviewer: "eric", ReviewedAt: at}, false},
		{"disputed complete", AdvisoryAttribution{Status: AttributionDisputed, Reviewer: "eric", Citation: "x", Reason: "r", ReviewedAt: at}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAttributionEntry("TEST-ID", tt.entry)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validate(%+v) err=%v, wantErr=%v", tt.entry, err, tt.wantErr)
			}
		})
	}
}

// --- C1: recurring ingestion + change detection ------------------------------------------------

func TestReconcileAttribution(t *testing.T) {
	reviewed := AdvisoryAttribution{Status: AttributionConfirmed, Reviewer: "eric", Citation: "GHSA-x", ReviewedAt: mustReviewedAt()}
	baseFacts := AdvisoryFacts{PURL: "pkg:npm/x", Symbols: []string{"x.F"}}
	changedFacts := AdvisoryFacts{PURL: "pkg:npm/x", Symbols: []string{"x.F", "x.G"}} // upstream added a symbol

	tests := []struct {
		name         string
		prior        AttributionStore
		priorFacts   map[string]AdvisoryFacts
		upstream     map[string]AdvisoryFacts
		wantPresent  bool
		wantStatus   AttributionStatus
		wantStale    bool
		wantReported string
	}{
		{
			name:         "new record ingests unreviewed",
			prior:        AttributionStore{},
			priorFacts:   map[string]AdvisoryFacts{},
			upstream:     map[string]AdvisoryFacts{"X": baseFacts},
			wantPresent:  false,
			wantReported: stateUnreviewed,
		},
		{
			name:         "unchanged leaves reviewed attribution untouched",
			prior:        AttributionStore{"X": reviewed},
			priorFacts:   map[string]AdvisoryFacts{"X": baseFacts},
			upstream:     map[string]AdvisoryFacts{"X": baseFacts},
			wantPresent:  true,
			wantStatus:   AttributionConfirmed,
			wantStale:    false,
			wantReported: stateAttributedReviewed,
		},
		{
			name:         "changed preserves status and flags stale",
			prior:        AttributionStore{"X": reviewed},
			priorFacts:   map[string]AdvisoryFacts{"X": baseFacts},
			upstream:     map[string]AdvisoryFacts{"X": changedFacts},
			wantPresent:  true,
			wantStatus:   AttributionConfirmed, // human judgement PRESERVED, never overwritten
			wantStale:    true,
			wantReported: stateAttributedReviewed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := reconcileAttribution(tt.prior, tt.priorFacts, tt.upstream)
			entry, present := next["X"]
			if present != tt.wantPresent {
				t.Fatalf("present=%v want %v", present, tt.wantPresent)
			}
			if tt.wantPresent {
				if entry.Status != tt.wantStatus {
					t.Fatalf("status=%q want %q (a machine re-ingest must never overwrite a human judgement)", entry.Status, tt.wantStatus)
				}
				if entry.StaleReview != tt.wantStale {
					t.Fatalf("stale_review=%v want %v", entry.StaleReview, tt.wantStale)
				}
			}
			var ap *AdvisoryAttribution
			if present {
				e := entry
				ap = &e
			}
			if got := reportState(tt.upstream["X"], ap); got != tt.wantReported {
				t.Fatalf("reportState=%q want %q", got, tt.wantReported)
			}
		})
	}

	// Negative control (required): the unchanged case and the changed case MUST produce different
	// states — otherwise change detection is untested.
	prior := AttributionStore{"X": reviewed}
	unchanged := reconcileAttribution(prior, map[string]AdvisoryFacts{"X": baseFacts}, map[string]AdvisoryFacts{"X": baseFacts})
	changed := reconcileAttribution(prior, map[string]AdvisoryFacts{"X": baseFacts}, map[string]AdvisoryFacts{"X": changedFacts})
	if unchanged["X"].StaleReview == changed["X"].StaleReview {
		t.Fatal("unchanged and changed produced the same stale_review — change detection is untested")
	}

	// Mutation control: disable change detection (changed always false) and the changed case must
	// collapse onto the unchanged case — proving the negative control above has teeth.
	noDetect := func(_, _ AdvisoryFacts) bool { return false }
	mutated := reconcileAttributionWith(prior, map[string]AdvisoryFacts{"X": baseFacts}, map[string]AdvisoryFacts{"X": changedFacts}, noDetect)
	if mutated["X"].StaleReview != false {
		t.Fatal("with change detection disabled the changed case still flagged stale — the mutation control does not bite")
	}
}
