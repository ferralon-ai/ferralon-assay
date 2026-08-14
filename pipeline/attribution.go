// internal/pipeline/attribution.go
//
// PLAN-220 — the advisory attribution sidecar. The supported-ness marking for each corpus record
// lives here, in a committed sidecar store (corpus/testdata/advisories/attribution.json) keyed by
// vuln_id — NOT on the evidence record (§4.4.8 / stages.go:540-543) and NOT a PLAN-024 type. It
// USES the PLAN-024 AttributionStatus enum + attributionStatusRecognized validator; it does not
// fork them.
//
// Absence is the honest zero: a vuln_id with no entry is `unreviewed` (nobody looked). This is the
// 38/38 state today — attribution.json ships as `{}`. The store exists to keep three outcomes
// DISTINCT that a single boolean would collapse: absent (unreviewed), present-with-no-symbol
// (reviewed-none-found), and present-with-attribution (reviewed). Collapsing any pair is the §3.1
// violation PLAN-024's schema exists to prevent.
package pipeline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// attributionStoreFile is the sidecar's basename, committed alongside the evidence fixtures under
// corpus/testdata/advisories/. It is NOT one of the AdvisoryFacts fixtures (advisory_corpus_test.go
// skips it in the on-disk file-set check) and is NOT folded into corpusManifest.corpus_digest: a
// landed review touches ONLY this file, so the 38 evidence fixtures and their per-record digests
// never churn (field-contract §0 point 2). Its integrity is enforced by a hermetic test
// (TestAttributionStore_Integrity), not by the manifest digest.
const attributionStoreFile = "attribution.json"

// AdvisoryAttribution is one per-record review entry in attribution.json (PLAN-220). An ABSENT entry
// for a vuln_id means `unreviewed` (the honest zero — §3.1/§3.6: absence is never a silent default).
// A PRESENT entry means "a review touched this record"; presence IS the reviewed marker, so a present
// entry MUST carry Reviewer and ReviewedAt (else §4 rejects it — a present entry is never an accidental
// empty object). This type is NOT on the digest-pinned evidence record (§4.4.8) and is NOT a PLAN-024
// type; Status USES the PLAN-024 AttributionStatus enum, validated by attributionStatusRecognized.
//
// SEMANTIC GUARD (PLAN-024 Amendment-A, binding — keeps per-record from laundering partial review
// into full attribution): a record-level Status is a claim about the record's symbol set REVIEWED AS
// A UNIT; it does NOT assert per-symbol confirmation. A reviewer who confirms only SOME symbols of a
// multi-symbol record MUST NOT record record-level `confirmed` (that over-claims, §3.1) — they use
// `ambiguous`, or, when per-symbol precision is required, per-symbol entries via the reserved Symbol
// discriminator. While SymbolsTyped is nil corpus-wide, Symbol == "" (record-level) is the only form
// in use; (vuln_id, symbol) keying is an ADDITIVE migration when typed symbols emit, not a reshape.
type AdvisoryAttribution struct {
	Status      AttributionStatus `json:"status,omitempty"`       // PLAN-024 enum; "" on a PRESENT entry = reviewed-none-found (§3)
	Reviewer    string            `json:"reviewer,omitempty"`     // C6 identity; REQUIRED on any present entry
	Citation    string            `json:"citation,omitempty"`     // C6 upstream doc the JUDGEMENT was made against; REQUIRED when Status ∈ {confirmed,ambiguous,disputed}. NOT Provenance.Source.
	Reason      string            `json:"reason,omitempty"`       // C4 per-record reason; REQUIRED when Status == disputed
	ReviewedAt  string            `json:"reviewed_at,omitempty"`  // RFC3339; REQUIRED on any present entry (audit trail)
	StaleReview bool              `json:"stale_review,omitempty"` // C1: set when the upstream fact changed under a prior reviewed attribution → surfaces for re-review; status preserved
	Symbol      string            `json:"symbol,omitempty"`       // §4.4.8 forward-compat discriminator; "" = record-level (today). Amendment A.
}

// AttributionStore is the loaded sidecar: vuln_id → its review entry. A vuln_id absent from the map
// is `unreviewed`; the map never carries a synthetic "unreviewed" entry to represent absence.
type AttributionStore map[string]AdvisoryAttribution

// The five distinct report states (§3). reviewed-none-found and unreviewed are SEPARATE states —
// collapsing them is the §3.1 violation PLAN-024 exists to prevent — and `ambiguous` is its own row
// rather than folded into attributed-and-reviewed (folding is a §3.1-style collapse). Over-splitting
// never violates §3.1; collapsing does.
const (
	stateAttributedReviewed = "attributed-and-reviewed"
	stateAmbiguous          = "ambiguous"
	stateReviewedNoneFound  = "reviewed-none-found"
	stateUnreviewed         = "unreviewed"
	stateDisputed           = "disputed"
)

// parseAttributionStore decodes attribution.json bytes into a store. It does NOT validate entries or
// check integrity (see validateAttributionEntry / checkAttributionIntegrity) — decode is separated
// from enforcement so a caller can inspect a malformed store.
func parseAttributionStore(b []byte) (AttributionStore, error) {
	store := AttributionStore{}
	if err := json.Unmarshal(b, &store); err != nil {
		return nil, fmt.Errorf("decode attribution store: %w", err)
	}
	return store, nil
}

// loadAttributionStore reads attribution.json from dir. An ABSENT file yields an empty store (every
// record unreviewed) with no error — the honest-zero default before any review has run. A present
// but malformed file is an error.
func loadAttributionStore(dir string) (AttributionStore, error) {
	b, err := os.ReadFile(filepath.Join(dir, attributionStoreFile))
	if os.IsNotExist(err) {
		return AttributionStore{}, nil
	}
	if err != nil {
		return nil, err
	}
	return parseAttributionStore(b)
}

// validateAttributionEntry is the §4 evidence-enforcement rule for one PRESENT entry. It REJECTS an
// unevidenced or malformed reviewed attribution; it is never called on an absent entry (absence is
// always accepted — nobody reviewed). A present reviewed-none-found entry (Status == "" with the
// required Reviewer/ReviewedAt) is ACCEPTED with an empty Citation — the review attributed no symbol,
// so there is no per-symbol judgement to cite; the validator never fabricates one.
func validateAttributionEntry(id string, a AdvisoryAttribution) error {
	if a.Reviewer == "" {
		return fmt.Errorf("attribution %s: present entry with no reviewer identity (§4.1)", id)
	}
	if a.ReviewedAt == "" {
		return fmt.Errorf("attribution %s: present entry with no reviewed_at audit timestamp (§4.2)", id)
	}
	switch a.Status {
	case AttributionConfirmed, AttributionAmbiguous, AttributionDisputed:
		if a.Citation == "" {
			return fmt.Errorf("attribution %s: reviewed status %q with empty citation (§4.3)", id, a.Status)
		}
	}
	if a.Status == AttributionDisputed && a.Reason == "" {
		return fmt.Errorf("attribution %s: disputed with no per-record reason (§4.4)", id)
	}
	if !attributionStatusRecognized(string(a.Status)) {
		return fmt.Errorf("attribution %s: unrecognized status %q (§4.5)", id, a.Status)
	}
	return nil
}

// checkAttributionIntegrity enforces the §0 integrity rule plus §4 validation over the whole store:
// every key MUST resolve to a known corpus record (no orphan attributions), and every present entry
// MUST pass validateAttributionEntry. It returns a non-nil error on the FIRST violation — this is the
// mechanical fail C5 requires; a caller that logs the error instead of failing defeats the check.
func checkAttributionIntegrity(store AttributionStore, known map[string]bool) error {
	ids := make([]string, 0, len(store))
	for id := range store {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if !known[id] {
			return fmt.Errorf("attribution %s: orphan — no corpus record with this vuln_id (§0 integrity)", id)
		}
		if err := validateAttributionEntry(id, store[id]); err != nil {
			return err
		}
	}
	return nil
}

// reportState derives the §3 report state for record r given its attribution a (nil == absent). It is
// the ONLY place reviewed-none-found is produced (derived, not stored). r is carried for the frozen
// signature and future per-symbol derivation; today only a drives the state.
func reportState(r AdvisoryFacts, a *AdvisoryAttribution) string {
	_ = r
	if a == nil {
		return stateUnreviewed // honest absence
	}
	switch a.Status {
	case AttributionDisputed:
		return stateDisputed
	case AttributionConfirmed:
		return stateAttributedReviewed
	case AttributionAmbiguous:
		return stateAmbiguous
	case "":
		return stateReviewedNoneFound // reviewer looked, attributed nothing
	default:
		// Unrecognized (or the literal `unreviewed`) fails open, mirroring attributionStatusRecognized.
		return stateUnreviewed
	}
}

// symbolBearing is the D2 candidate-denominator predicate: the record carries at least one
// extractable vulnerable symbol. Reads only the committed Symbols field — no re-review.
func symbolBearing(r AdvisoryFacts) bool { return len(r.Symbols) > 0 }

// ecosystemToken is the D1 candidate-denominator key and the §3 coverage ecosystem column:
// purlEcosystem(r.PURL), or "(none)" for an empty/malformed PURL. Reads only the committed PURL.
func ecosystemToken(r AdvisoryFacts) string {
	e := purlEcosystem(r.PURL)
	if e == "" {
		return coverageNoEcosystem
	}
	return e
}

const coverageNoEcosystem = "(none)"

// coverageEcosystems is the frozen §3 ecosystem grid; coverageStates the five report states. Rows are
// emitted for every (ecosystem × state) cell — including empty cells (count 0) — so a missing lane is
// VISIBLE rather than absent. Any ecosystem observed beyond the grid is appended (sorted) so no record
// is dropped from the report.
var coverageEcosystems = []string{"golang", "maven", "npm", "pypi", "nuget", coverageNoEcosystem}

var coverageStates = []string{
	stateAttributedReviewed,
	stateAmbiguous,
	stateReviewedNoneFound,
	stateUnreviewed,
	stateDisputed,
}

// DisputedRecord is one non-suppressible disputed entry in a coverage row (C4): a disputed record
// MUST NOT vanish from any total or fold into unreviewed, and carries its reason + the reviewer who
// raised it.
type DisputedRecord struct {
	VulnID   string `json:"vuln_id"`
	Reason   string `json:"reason"`
	Reviewer string `json:"reviewer"`
}

// CoverageRow is one (ecosystem × attribution_state) cell of the §3 coverage report. Counts only —
// there is NO blended/aggregate percentage anywhere in this report (C3): a rate presented as THE
// coverage figure pre-empts Open Question 3's granularity half. symbol_bearing_count is a diagnostic
// subcount, NOT a rate.
type CoverageRow struct {
	Ecosystem          string           `json:"ecosystem"`
	AttributionState   string           `json:"attribution_state"`
	RecordCount        int              `json:"record_count"`
	SymbolBearingCount int              `json:"symbol_bearing_count"`
	Records            []string         `json:"records"`
	DisputedDetail     []DisputedRecord `json:"disputed_detail,omitempty"`
}

// buildCoverageReport produces the §3 sliced coverage report over the committed corpus: one row per
// (ecosystem × report-state), every cell present (empty cells count 0). It publishes NO blended
// percentage. The disputed rows carry non-suppressible per-record detail (C4).
func buildCoverageReport(table map[string]AdvisoryFacts, store AttributionStore) []CoverageRow {
	type cell struct{ eco, state string }

	ecoSet := map[string]bool{}
	for _, e := range coverageEcosystems {
		ecoSet[e] = true
	}
	for _, r := range table {
		ecoSet[ecosystemToken(r)] = true
	}
	ecos := orderedEcosystems(ecoSet)

	agg := make(map[cell]*CoverageRow, len(ecos)*len(coverageStates))
	for _, e := range ecos {
		for _, s := range coverageStates {
			agg[cell{e, s}] = &CoverageRow{Ecosystem: e, AttributionState: s, Records: []string{}}
		}
	}

	for id, r := range table {
		e := ecosystemToken(r)
		var ap *AdvisoryAttribution
		if a, ok := store[id]; ok {
			av := a
			ap = &av
		}
		s := reportState(r, ap)
		row := agg[cell{e, s}]
		row.RecordCount++
		row.Records = append(row.Records, id)
		if symbolBearing(r) {
			row.SymbolBearingCount++
		}
		if s == stateDisputed {
			var reason, reviewer string
			if ap != nil {
				reason, reviewer = ap.Reason, ap.Reviewer
			}
			row.DisputedDetail = append(row.DisputedDetail, DisputedRecord{VulnID: id, Reason: reason, Reviewer: reviewer})
		}
	}

	rows := make([]CoverageRow, 0, len(ecos)*len(coverageStates))
	for _, e := range ecos {
		for _, s := range coverageStates {
			row := agg[cell{e, s}]
			sort.Strings(row.Records)
			sort.Slice(row.DisputedDetail, func(i, j int) bool {
				return row.DisputedDetail[i].VulnID < row.DisputedDetail[j].VulnID
			})
			rows = append(rows, *row)
		}
	}
	return rows
}

// orderedEcosystems returns the grid ecosystems in their frozen order, followed by any observed
// ecosystem outside the grid, sorted — so an unexpected PURL type surfaces as its own rows rather
// than silently dropping its records.
func orderedEcosystems(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	inGrid := map[string]bool{}
	for _, e := range coverageEcosystems {
		out = append(out, e)
		inGrid[e] = true
	}
	extra := make([]string, 0)
	for e := range set {
		if !inGrid[e] {
			extra = append(extra, e)
		}
	}
	sort.Strings(extra)
	return append(out, extra...)
}

// factsChanged is the C1 change-detection predicate: two ingests of the same vuln_id differ when
// their normalized facts differ. Byte comparison over the deterministic JSON encoding — the same
// axis the corpus digest pins, so a change the digest would catch is a change this catches.
func factsChanged(a, b AdvisoryFacts) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return !bytes.Equal(ab, bb)
}

// reconcileAttribution runs ONE recurring-ingestion pass and returns the updated review store. It is
// the C1 mechanism: a machine re-ingest writes facts, never a human judgement. Rules:
//
//   - NEW record (in upstream, absent from priorFacts): no entry created — absence == unreviewed.
//   - UNCHANGED record: its prior attribution (if any) is returned untouched.
//   - CHANGED record: its prior attribution's Status and fields are PRESERVED and StaleReview is set
//     true, surfacing it for re-review. A machine change NEVER overwrites a human judgement with an
//     unreviewed one.
//   - No record is dropped: an id whose entry existed in prior is retained even if upstream removed
//     the fact.
//
// Change detection is injected (changed) so a mutation control can disable it and prove case (c)
// collapses onto case (b) — the negative control C1 requires.
func reconcileAttribution(prior AttributionStore, priorFacts, upstream map[string]AdvisoryFacts) AttributionStore {
	return reconcileAttributionWith(prior, priorFacts, upstream, factsChanged)
}

func reconcileAttributionWith(prior AttributionStore, priorFacts, upstream map[string]AdvisoryFacts, changed func(a, b AdvisoryFacts) bool) AttributionStore {
	next := make(AttributionStore, len(prior))
	for id, a := range prior {
		next[id] = a
	}
	for id, up := range upstream {
		old, existed := priorFacts[id]
		if !existed {
			continue // newly ingested → unreviewed (no entry)
		}
		if !changed(old, up) {
			continue // unchanged → prior attribution untouched
		}
		entry, hasEntry := next[id]
		if !hasEntry {
			continue // changed but never reviewed → still unreviewed (nothing to stale)
		}
		entry.StaleReview = true // status preserved; surfaced for re-review
		next[id] = entry
	}
	return next
}
