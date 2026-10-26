// signals_digest_test.go — which signals file ranked a run is recorded once, by trigger.Run*; the
// command line's own intel block (stampIntel) keeps it and adds the entrypoint's disclosure.
package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// TestStampIntel: stampIntel replaces the Report's intel block with the entrypoint's, and carries the
// signals digest trigger recorded across it. The entrypoint's own block never names one — a digest it
// held would be a second stamp that could disagree with the first.
func TestStampIntel(t *testing.T) {
	const ranked = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	entry := report.IntelProvenance{WorkSetSource: report.WorkSetOSVQuery, WorkSetSize: 3, FactSource: report.FactSourceBuiltinTable, CorpusPolicy: "published-7d"}
	for _, c := range []struct {
		name string
		prev *report.IntelProvenance
		in   report.IntelProvenance
		want report.IntelProvenance
	}{
		{"ranked with signals", &report.IntelProvenance{SignalsDigest: ranked}, entry,
			report.IntelProvenance{WorkSetSource: entry.WorkSetSource, WorkSetSize: 3, FactSource: entry.FactSource, CorpusPolicy: "published-7d", SignalsDigest: ranked}},
		{"ranked with none", &report.IntelProvenance{}, entry, entry},
		{"no block from the run", nil, entry, entry},
		{"a stray digest in the entrypoint's block is dropped", nil,
			report.IntelProvenance{WorkSetSource: entry.WorkSetSource, SignalsDigest: "sha256:stray"},
			report.IntelProvenance{WorkSetSource: entry.WorkSetSource}},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep := &report.Report{Provenance: report.Provenance{Intel: c.prev}}
			stampIntel(rep, c.in)
			if rep.Provenance.Intel == nil || *rep.Provenance.Intel != c.want {
				t.Errorf("Provenance.Intel = %+v, want %+v", rep.Provenance.Intel, c.want)
			}
		})
	}
}

// TestIntelProvenanceNamesNoSignals: the entrypoint's block leaves the signals digest to trigger,
// whether or not the run loaded a signals file.
func TestIntelProvenanceNamesNoSignals(t *testing.T) {
	clearSignalsEnv(t)
	plain := writeSignalsFile(t, filepath.Join(t.TempDir(), "signals.json"), []byte(signalsDoc("2026-10-19")))
	for name, args := range map[string][]string{"signals": {"-advisory-signals", plain}, "none": nil} {
		f, err := resolvedFor(t, args...)
		if err != nil {
			t.Fatalf("%s: resolveSignals: %v", name, err)
		}
		if got := f.intelProvenance(workSet{}).SignalsDigest; got != "" {
			t.Errorf("%s: intelProvenance.SignalsDigest = %q, want the digest left to trigger.Run*", name, got)
		}
	}
}

// signalsFixtureReport is a baseline over a one-file Go tree ranked with a loaded signals file, then
// stamped the way a published report is, with the timestamp pinned. goldenSignalsReport is what it
// rendered before trigger.Run* recorded the signals digest and the command line stopped stamping it.
func signalsFixtureReport(t *testing.T) []byte {
	t.Helper()
	trapEgress(t)
	clearSignalsEnv(t)
	signalsPath := writeSignalsFile(t, filepath.Join(t.TempDir(), "signals.json"), []byte(signalsDoc("2026-10-19")))
	f, err := resolvedFor(t, "-advisory-signals", signalsPath)
	if err != nil || f.resolvedSignals == nil {
		t.Fatalf("resolveSignals = %v, %v", err, f.resolvedSignals)
	}

	dir := t.TempDir()
	file, content := languageFixture(t, "go")
	if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	// GO-2021-0113 aliases CVE-2021-38561 and CVE-2025-8110 is KEV-listed: both are in signalsDoc.
	advisories := []assessment.VulnRef{{ID: "GO-2021-0113", Source: "osv"}, {ID: "CVE-2025-8110", Source: "ghsa"}}
	rep, err := trigger.RunBaseline(context.Background(), statestore.NewMemStore(), trigger.BaselineRequest{
		Subject: trigger.Subject{Repo: "specimen", Revision: "HEAD", ResolvedCommit: "0123456789abcdef"},
		Codebase: assessment.CodebaseRef{
			Repo:        "specimen",
			Revision:    "HEAD",
			Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: dir},
		},
		Advisories:    advisories,
		AssessOptions: []pipeline.AssessOption{pipeline.WithPlugin(unsearchingAnalyzer{language: "go"})},
		Signals:       f.resolvedSignals,
	})
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	stampIntel(rep, f.intelProvenance(floorWorkSet(advisories)))
	rep.Provenance.Timestamp = time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	out, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

// TestPublishedReportIsUnchangedBySignalsStamp: the Report the command line publishes for a run with
// signals is byte-for-byte what it was when the command line did the stamping itself, and carries
// the verified digest once.
func TestPublishedReportIsUnchangedBySignalsStamp(t *testing.T) {
	got := signalsFixtureReport(t)
	want, err := os.ReadFile(filepath.Join("testdata", "signals_stamp_report.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("the published Report changed.\n--- got\n%s\n--- want\n%s", got, want)
	}
	var rep report.Report
	if err := json.Unmarshal(got, &rep); err != nil {
		t.Fatal(err)
	}
	if in := rep.Provenance.Intel; in == nil || in.SignalsDigest != digestOf(t, signalsDoc("2026-10-19")) {
		t.Errorf("Provenance.Intel = %+v, want the verified signals digest", in)
	}
	ranked := false
	for _, a := range rep.Advisories {
		ranked = ranked || a.Priority != nil
	}
	if !ranked {
		t.Error("no finding carries a Priority: the fixture ranks nothing, so its digest proves little")
	}
}
