// migrate_test.go
//
// The tegron.report.v1 → v2 migration. Two properties matter more
// than the mechanics:
//
//  1. No stored report becomes unreadable. A v1 document written before the bump — the only kind a
//     pre-bump StateStore holds — must load, and must load as v2.
//  2. No advisory changes meaning across the migration. A v1 withheld id and a v2 undetermined row
//     say the same thing about the same advisory; the migration may move it, never restate it.
package report_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// v1WithheldJSON is a consumer-visible tegron.report.v1 report in the shape M2 shipped: one
// disqualified row, and four toolchain advisories withheld from advisories[] and named in one
// scan-level limit. It is written as literal JSON rather than built through the Builder on purpose —
// the Builder now produces v2, so only literal bytes can stand in for what is actually on a ref.
const v1WithheldJSON = `{
  "schema_version": "tegron.report.v1",
  "subject": {"repo": "github.com/example/widget", "revision": "main", "resolved_commit": "abc123"},
  "sbom": {"packages": [{"ecosystem": "Go", "name": "golang.org/x/text", "version": "v0.3.8"}]},
  "advisories": [
    {
      "advisory": {"id": "GO-2021-0113", "source": "osv"},
      "package": {"ecosystem": "Go", "name": "golang.org/x/text", "version": "v0.3.8"},
      "verdict": "disqualified",
      "evidence": {"basis": "version_not_in_affected_range", "detail": "resolved v0.3.8 is at or past the fix"}
    }
  ],
  "partiality": [
    {"reason": "no_manifest", "ecosystem": "npm"},
    {"reason": "go_toolchain_not_scanned", "ecosystem": "Go",
     "advisories": ["CVE-2023-39325", "CVE-2023-45283", "CVE-2024-24790", "GO-2021-0264"]}
  ],
  "provenance": {
    "commit_sha": "abc123", "analyzer_version": "ferralon-assay/1.x",
    "advisory_cursor": "osv:2026-07-30", "timestamp": "2026-07-30T12:00:00Z"
  }
}`

func decodeV1(t *testing.T) report.Report {
	t.Helper()
	var r report.Report
	if err := json.Unmarshal([]byte(v1WithheldJSON), &r); err != nil {
		t.Fatalf("decode v1 fixture: %v", err)
	}
	return r
}

// TestUpgrade_V1WithheldIDsBecomeUndeterminedRows is the migration's headline: the four ids a v1
// note carried are now four rows, and the count of advisories evaluated is readable off
// len(advisories) again — which is exactly what the withholding cost and the bump buys back.
func TestUpgrade_V1WithheldIDsBecomeUndeterminedRows(t *testing.T) {
	got, err := report.Upgrade(decodeV1(t))
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}

	if got.SchemaVersion != report.SchemaVersion {
		t.Errorf("schema_version = %q, want %q", got.SchemaVersion, report.SchemaVersion)
	}
	if len(got.Advisories) != 5 {
		t.Fatalf("advisories = %d rows, want 5 (the disqualified one plus four converted)", len(got.Advisories))
	}
	if err := got.Validate(); err != nil {
		t.Errorf("upgraded report fails Validate: %v", err)
	}

	byID := make(map[string]report.AdvisoryFinding, len(got.Advisories))
	for _, f := range got.Advisories {
		byID[f.Advisory.ID] = f
	}
	for _, id := range []string{"CVE-2023-39325", "CVE-2023-45283", "CVE-2024-24790", "GO-2021-0264"} {
		f, ok := byID[id]
		if !ok {
			t.Errorf("%s is missing from advisories[] — the migration dropped a withheld id", id)
			continue
		}
		if f.Verdict != report.VerdictUndetermined {
			t.Errorf("%s verdict = %q, want undetermined", id, f.Verdict)
		}
		if f.UndeterminedReason != report.ReasonGoToolchainNotScanned {
			t.Errorf("%s reason = %q, want the note's reason verbatim", id, f.UndeterminedReason)
		}
		if f.Evidence.Basis != verdict.BasisNone {
			t.Errorf("%s carries basis %q — a migrated non-verdict must not acquire grounds", id, f.Evidence.Basis)
		}
		// Source is honestly absent: a v1 note named the id alone, and naming a database it
		// might have come from would be a fabricated fact.
		if f.Advisory.Source != "" {
			t.Errorf("%s source = %q, want empty — a v1 note carried no source to migrate", id, f.Advisory.Source)
		}
		if f.Package != nil {
			t.Errorf("%s package = %+v, want nil", id, f.Package)
		}
	}

	// The finding that already had a verdict is untouched.
	if f := byID["GO-2021-0113"]; f.Verdict != report.VerdictDisqualified || f.Evidence.Basis != verdict.BasisVersionNotAffected {
		t.Errorf("the disqualified row changed under migration: %+v", f)
	}
}

// TestUpgrade_ConvertedNoteKeepsItsScopeAndLosesItsIDs pins the shape of what is left behind. The
// note survives because it is the only carrier of the limit's ECOSYSTEM (an undetermined row has no
// ecosystem field — its Package is nil, the Go toolchain not being an SBOM dependency), and its id
// list empties because the rows carry the ids now.
func TestUpgrade_ConvertedNoteKeepsItsScopeAndLosesItsIDs(t *testing.T) {
	got, err := report.Upgrade(decodeV1(t))
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}

	want := []report.PartialityNote{
		{Reason: report.ReasonGoToolchainNotScanned, Ecosystem: "Go"},
		{Reason: "no_manifest", Ecosystem: "npm"},
	}
	if len(got.Partiality) != len(want) {
		t.Fatalf("partiality = %+v, want %d notes", got.Partiality, len(want))
	}
	for _, w := range want {
		var found bool
		for _, n := range got.Partiality {
			if n.Reason == w.Reason {
				found = true
				if !reflect.DeepEqual(n, w) {
					t.Errorf("note %q = %+v, want %+v", w.Reason, n, w)
				}
			}
		}
		if !found {
			t.Errorf("note %q was dropped by the migration", w.Reason)
		}
	}
}

// TestUpgrade_UndeterminedRowsSortAboveTheRefutations pins that migration and production converge
// on ONE canonical order. If they did not, re-running a scan over a migrated baseline would rewrite
// report.json with identical content in a different order — every heartbeat writing new git objects.
func TestUpgrade_UndeterminedRowsSortAboveTheRefutations(t *testing.T) {
	got, err := report.Upgrade(decodeV1(t))
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}

	var sawRefutation bool
	for _, f := range got.Advisories {
		switch f.Verdict {
		case report.VerdictUndetermined:
			if sawRefutation {
				t.Errorf("undetermined %s sorts below a refutation — not assessed must rank above grounded-safe", f.Advisory.ID)
			}
		default:
			sawRefutation = true
		}
	}

	// And the same set built fresh through the Builder orders identically.
	b := report.NewBuilder(got.Subject)
	for i := range got.Advisories {
		b.AddFinding(got.Advisories[i])
	}
	rebuilt := b.Build()
	for i := range got.Advisories {
		if rebuilt.Advisories[i].Advisory.ID != got.Advisories[i].Advisory.ID {
			t.Fatalf("order diverges at %d: upgraded %q, rebuilt %q",
				i, got.Advisories[i].Advisory.ID, rebuilt.Advisories[i].Advisory.ID)
		}
	}
}

// TestUpgrade_DoesNotDuplicateAnIDThatIsAlreadyARow guards the one combination a v1 producer could
// not emit but another writer might: an id present as a row AND named in a limit. The row wins.
func TestUpgrade_DoesNotDuplicateAnIDThatIsAlreadyARow(t *testing.T) {
	r := decodeV1(t)
	for i := range r.Partiality {
		if r.Partiality[i].Reason == report.ReasonGoToolchainNotScanned {
			r.Partiality[i].Advisories = append(r.Partiality[i].Advisories, "GO-2021-0113")
		}
	}

	got, err := report.Upgrade(r)
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	var seen int
	for _, f := range got.Advisories {
		if f.Advisory.ID == "GO-2021-0113" {
			seen++
			if f.Verdict != report.VerdictDisqualified {
				t.Errorf("GO-2021-0113 verdict = %q, want the existing disqualified row to win", f.Verdict)
			}
		}
	}
	if seen != 1 {
		t.Errorf("GO-2021-0113 appears %d times, want 1", seen)
	}
}

// TestUpgrade_SchemaVersionHandling covers the versions Upgrade must accept, pass through, and
// refuse. Refusal is the contract's own rule for every reader: a document from a schema this code
// does not know may have changed the meaning of a field it does read.
func TestUpgrade_SchemaVersionHandling(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version string
		wantErr string
	}{
		{name: "current schema passes through", version: report.SchemaVersion},
		{name: "v1 upgrades", version: report.SchemaVersionV1},
		{name: "absent version is refused", version: "", wantErr: "no schema_version"},
		{name: "future version is refused", version: "tegron.report.v3", wantErr: "unrecognized schema_version"},
		{name: "another artifact's schema is refused", version: "tegron.inventory.v1", wantErr: "unrecognized schema_version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := decodeV1(t)
			r.SchemaVersion = tc.version

			got, err := report.Upgrade(r)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("Upgrade(%q) = nil error, want one mentioning %q", tc.version, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Upgrade(%q): %v", tc.version, err)
			}
			if got.SchemaVersion != report.SchemaVersion {
				t.Errorf("schema_version = %q, want %q", got.SchemaVersion, report.SchemaVersion)
			}
		})
	}
}

// TestUpgrade_IsIdempotent matters because upgrade-on-read has no write barrier: the same document
// can be read, upgraded, written, and read again, and a second pass must be a no-op. A pass that
// converted its own output would multiply rows on every read.
func TestUpgrade_IsIdempotent(t *testing.T) {
	once, err := report.Upgrade(decodeV1(t))
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	twice, err := report.Upgrade(once)
	if err != nil {
		t.Fatalf("Upgrade (second pass): %v", err)
	}
	if !reflect.DeepEqual(once, twice) {
		t.Errorf("second Upgrade changed the report:\n once = %+v\ntwice = %+v", once, twice)
	}
}

// TestUpgrade_RoundTripsThroughJSON is the serialization half: the upgraded document marshals,
// decodes, and validates, and the second decode needs no further upgrade. This is what a consumer
// reading the post-bump report.json actually does.
func TestUpgrade_RoundTripsThroughJSON(t *testing.T) {
	upgraded, err := report.Upgrade(decodeV1(t))
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}

	raw, err := json.Marshal(upgraded)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"undetermined_reason":"go_toolchain_not_scanned"`) {
		t.Errorf("serialized form does not carry the reason code:\n%s", raw)
	}

	var back report.Report
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(upgraded, back) {
		t.Errorf("round trip is lossy:\nwant %+v\ngot  %+v", upgraded, back)
	}
	again, err := report.Upgrade(back)
	if err != nil {
		t.Fatalf("Upgrade after round trip: %v", err)
	}
	if !reflect.DeepEqual(back, again) {
		t.Error("a decoded post-bump document still needed upgrading")
	}
}

// TestUpgrade_NoteWithNoReasonStillNamesItsAdvisories is the boundary case `upgradeV1` has to defend
// for the same reason it defends the duplicate-id case: this is a boundary over documents written by
// other versions, so the shape is checked rather than assumed.
//
// A v1 note whose own `reason` was empty still withheld real advisories. Copying that emptiness onto
// the rows produced a report that failed its own Validate — so the document decoded fine and then blew
// up at the next BuildValidated(), arbitrarily far from the ref holding the bad bytes. Dropping the
// ids instead would silently un-name the advisories, which is the failure the verdict exists to end.
func TestUpgrade_NoteWithNoReasonStillNamesItsAdvisories(t *testing.T) {
	r := decodeV1(t)
	r.Partiality = []report.PartialityNote{{
		Reason:     "", // the malformed shape
		Ecosystem:  "Go",
		Advisories: []string{"CVE-2023-39325", "GO-2021-0264"},
	}}

	got, err := report.Upgrade(r)
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	// The whole point: the upgraded document is VALID, so it cannot fail downstream.
	if err := got.Validate(); err != nil {
		t.Fatalf("upgraded report fails its own Validate: %v", err)
	}

	byID := make(map[string]report.AdvisoryFinding, len(got.Advisories))
	for _, f := range got.Advisories {
		byID[f.Advisory.ID] = f
	}
	for _, id := range []string{"CVE-2023-39325", "GO-2021-0264"} {
		f, ok := byID[id]
		if !ok {
			t.Errorf("%s was dropped — a nameless limit must not cost the advisory its name", id)
			continue
		}
		if f.Verdict != report.VerdictUndetermined {
			t.Errorf("%s verdict = %q, want undetermined", id, f.Verdict)
		}
		if f.UndeterminedReason != report.ReasonUnspecifiedLimit {
			t.Errorf("%s reason = %q, want %q", id, f.UndeterminedReason, report.ReasonUnspecifiedLimit)
		}
		// The detail must say the reason is unknown, not imply a specific limit.
		if f.Evidence.Detail == "" {
			t.Errorf("%s carries no detail", id)
		}
		for _, code := range []string{report.ReasonGoToolchainNotScanned, report.ReasonGoToolchainUnresolved} {
			if strings.Contains(f.Evidence.Detail, code) {
				t.Errorf("%s detail names %q, a limit the source document never claimed: %q", id, code, f.Evidence.Detail)
			}
		}
	}
}

// TestUpgrade_UnspecifiedLimitIsNotProducibleByTheBuilder pins the claim in ReasonUnspecifiedLimit's
// own doc comment — that a report this analyzer produced can never carry a reason-less note, so the
// substitution is genuinely migration-only. If AddPartiality ever stopped dropping those, this code
// path would start firing on our own output.
func TestUpgrade_UnspecifiedLimitIsNotProducibleByTheBuilder(t *testing.T) {
	r := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "c"}).
		AddPartiality(report.PartialityNote{Reason: "", Ecosystem: "Go", Advisories: []string{"CVE-2023-39325"}}).
		Build()

	if len(r.Partiality) != 0 {
		t.Errorf("Builder kept a reason-less note %+v; an unnamed limit renders as nothing and must be dropped", r.Partiality)
	}
}
