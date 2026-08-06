package statestore

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// v1StoredReport is a State holding the tegron.report.v1 document a pre-bump run committed: a real
// verdict, plus four toolchain advisories withheld from advisories[] and named in one limit. Written
// field-by-field rather than through the Builder because the Builder stamps the CURRENT schema, and
// the point of the test is a document stamped with the previous one.
func v1StoredReport(ts time.Time) *report.Report {
	pkg := report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.8"}
	return &report.Report{
		SchemaVersion: report.SchemaVersionV1,
		Subject:       report.Subject{Repo: "github.com/example/widget", Revision: "main", ResolvedCommit: "abc123"},
		SBOM:          report.SBOM{Packages: []report.Package{pkg}},
		Advisories: []report.AdvisoryFinding{{
			Advisory: report.Advisory{ID: "GO-2021-0113", Source: "osv"},
			Package:  &pkg,
			Verdict:  report.VerdictDisqualified,
			Evidence: report.EvidenceSummary{Basis: verdict.BasisVersionNotAffected, Detail: "past the fix"},
		}},
		Partiality: []report.PartialityNote{{
			Reason:     report.ReasonGoToolchainNotScanned,
			Ecosystem:  "Go",
			Advisories: []string{"CVE-2023-39325", "CVE-2023-45283", "CVE-2024-24790", "GO-2021-0264"},
		}},
		Provenance: report.Provenance{
			CommitSHA: "abc123", AnalyzerVersion: "test", AdvisoryCursor: "osv:2026-07-30", Timestamp: ts,
		},
	}
}

// TestStore_V1ReportRoundTripsPostBump is the migration requirement stated end to end: a report
// committed to the ref before the schema bump must still load, and must load as v2 with the withheld
// advisories as first-class rows. No rewrite pass runs — Read upgrades, and a later Write persists
// the upgraded form.
//
// This is the case that decides whether the bump is deployable. A v1 document that failed to load
// would brick every repo whose baseline predates the release, and one that loaded with the withheld
// ids still hidden in the note would leave those advisories invisible to every v2 consumer.
func TestStore_V1ReportRoundTripsPostBump(t *testing.T) {
	s := newTempStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

	// Commit the v1 document verbatim.
	if _, err := s.Write(ctx, &State{Report: v1StoredReport(ts), Cursor: "osv:2026-07-30"}); err != nil {
		t.Fatalf("write v1 state: %v", err)
	}

	got, err := s.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Report == nil {
		t.Fatal("read returned no report")
	}
	if got.Report.SchemaVersion != report.SchemaVersion {
		t.Errorf("schema_version = %q, want %q — Read must upgrade", got.Report.SchemaVersion, report.SchemaVersion)
	}
	if err := got.Report.Validate(); err != nil {
		t.Errorf("upgraded report fails Validate: %v", err)
	}

	byID := make(map[string]report.AdvisoryFinding, len(got.Report.Advisories))
	for _, f := range got.Report.Advisories {
		byID[f.Advisory.ID] = f
	}
	if len(byID) != 5 {
		t.Fatalf("advisories = %+v, want 5 rows (one disqualified plus four converted)", got.Report.Advisories)
	}
	for _, id := range []string{"CVE-2023-39325", "CVE-2023-45283", "CVE-2024-24790", "GO-2021-0264"} {
		f, ok := byID[id]
		if !ok {
			t.Errorf("%s did not survive the store round trip", id)
			continue
		}
		if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != report.ReasonGoToolchainNotScanned {
			t.Errorf("%s = {%q, %q}, want an undetermined row carrying the note's reason", id, f.Verdict, f.UndeterminedReason)
		}
	}
	if f := byID["GO-2021-0113"]; f.Verdict != report.VerdictDisqualified {
		t.Errorf("the pre-bump verdict changed: %+v", f)
	}
	for _, n := range got.Report.Partiality {
		if len(n.Advisories) > 0 {
			t.Errorf("limit %q still names %v after upgrade — the ids belong to the rows now", n.Reason, n.Advisories)
		}
	}

	// A subsequent write persists the upgraded form, so the ref converges on v2 without a
	// dedicated migration pass.
	if _, err := s.Write(ctx, got); err != nil {
		t.Fatalf("rewrite upgraded state: %v", err)
	}
	again, err := s.Read(ctx)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if again.Report.SchemaVersion != report.SchemaVersion {
		t.Errorf("after rewrite schema_version = %q, want %q", again.Report.SchemaVersion, report.SchemaVersion)
	}
	if len(again.Report.Advisories) != 5 {
		t.Errorf("after rewrite advisories = %d, want 5 — a second upgrade must not duplicate rows", len(again.Report.Advisories))
	}
}

// TestStore_UnrecognizedSchemaVersionIsRefused pins that a state ref written by a FUTURE tool is an
// error rather than a partial decode. The alternative is worse than failing: a newer schema may have
// changed the meaning of a field this code reads, and the object being decoded is a verdict document.
func TestStore_UnrecognizedSchemaVersionIsRefused(t *testing.T) {
	s := newTempStore(t)
	ctx := context.Background()

	future := v1StoredReport(time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC))
	future.SchemaVersion = "tegron.report.v9"
	if _, err := s.Write(ctx, &State{Report: future}); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := s.Read(ctx)
	if err == nil {
		t.Fatal("Read accepted an unrecognized schema_version")
	}
	if !strings.Contains(err.Error(), "unrecognized schema_version") {
		t.Errorf("error = %v, want it to name the unrecognized schema version", err)
	}
}

// TestMerge_MigratedRowDoesNotDuplicateAFreshFinding covers the CAS race across the bump. An
// upgraded v1 row carries no Source (a v1 note named the id alone), so it cannot key against the
// other side's fresh finding for the same advisory — and the union would carry both.
func TestMerge_MigratedRowDoesNotDuplicateAFreshFinding(t *testing.T) {
	older := time.Date(2026, 7, 30, 10, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)

	upgraded, err := report.Upgrade(*v1StoredReport(older))
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}

	fresh := report.NewBuilder(upgraded.Subject).
		WithProvenance(report.Provenance{CommitSHA: "abc123", Timestamp: newer}).
		Undetermined(report.Advisory{ID: "GO-2021-0264", Source: "osv"}, nil, report.ReasonGoToolchainNotScanned).
		Build()

	merged := Merge(&State{Report: &upgraded}, &State{Report: &fresh})

	var seen int
	for _, f := range merged.Report.Advisories {
		if f.Advisory.ID != "GO-2021-0264" {
			continue
		}
		seen++
		if f.Advisory.Source != "osv" {
			t.Errorf("GO-2021-0264 source = %q, want the freshly evaluated row to win", f.Advisory.Source)
		}
	}
	if seen != 1 {
		t.Errorf("GO-2021-0264 appears %d times in the merged report, want 1", seen)
	}
}

// TestStore_MalformedStoredReportIsRefusedAtTheBoundary covers the other half of the empty-reason
// gap: decodeReport now validates, so a stored document that no version of this tool could legally
// have written is refused where the bad bytes are, not at the next BuildValidated() somewhere else.
//
// The verdict case is the one that matters most. A stored `exploitable` is an inv.5 violation, and
// without this check it would decode cleanly and flow into every projector before anything noticed.
func TestStore_MalformedStoredReportIsRefusedAtTheBoundary(t *testing.T) {
	ts := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name    string
		mutate  func(*report.Report)
		wantErr string
	}{
		{
			name: "service-tier verdict (inv. 5)",
			mutate: func(r *report.Report) {
				r.SchemaVersion = report.SchemaVersion
				r.Advisories[0].Verdict = "exploitable"
			},
			wantErr: "non-deterministic verdict",
		},
		{
			name: "undetermined row with no reason",
			mutate: func(r *report.Report) {
				r.SchemaVersion = report.SchemaVersion
				r.Partiality = nil
				r.Advisories = []report.AdvisoryFinding{{
					Advisory: report.Advisory{ID: "GO-2021-0264", Source: "osv"},
					Verdict:  report.VerdictUndetermined,
				}}
			},
			wantErr: "no undetermined_reason",
		},
		{
			name: "undetermined row carrying a refutation basis",
			mutate: func(r *report.Report) {
				r.SchemaVersion = report.SchemaVersion
				r.Partiality = nil
				r.Advisories = []report.AdvisoryFinding{{
					Advisory:           report.Advisory{ID: "GO-2021-0264", Source: "osv"},
					Verdict:            report.VerdictUndetermined,
					UndeterminedReason: report.ReasonGoToolchainNotScanned,
					Evidence:           report.EvidenceSummary{Basis: verdict.BasisSymbolAbsent},
				}}
			},
			wantErr: "has no grounds",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTempStore(t)
			ctx := context.Background()

			bad := v1StoredReport(ts)
			tc.mutate(bad)
			if _, err := s.Write(ctx, &State{Report: bad}); err != nil {
				t.Fatalf("write: %v", err)
			}

			_, err := s.Read(ctx)
			if err == nil {
				t.Fatal("Read accepted a report that fails Validate")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestStore_V1NoteWithNoReasonLoads is the paired positive: the empty-reason document that used to
// upgrade into an invalid report now loads, because upgradeV1 substitutes an explicit code. Without
// that substitution the decodeReport validation added above would turn a readable-if-odd v1 document
// into an unreadable one — the two halves of this fix have to land together.
func TestStore_V1NoteWithNoReasonLoads(t *testing.T) {
	s := newTempStore(t)
	ctx := context.Background()

	stored := v1StoredReport(time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC))
	stored.Partiality = []report.PartialityNote{{Ecosystem: "Go", Advisories: []string{"GO-2021-0264"}}}
	if _, err := s.Write(ctx, &State{Report: stored}); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := s.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v — a v1 document with a nameless limit must still load", err)
	}
	var found bool
	for _, f := range got.Report.Advisories {
		if f.Advisory.ID != "GO-2021-0264" {
			continue
		}
		found = true
		if f.UndeterminedReason != report.ReasonUnspecifiedLimit {
			t.Errorf("reason = %q, want %q", f.UndeterminedReason, report.ReasonUnspecifiedLimit)
		}
	}
	if !found {
		t.Error("GO-2021-0264 did not survive the load")
	}
}
