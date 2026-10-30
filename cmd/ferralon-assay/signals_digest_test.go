// signals_digest_test.go — which signals file ranked a run is recorded once, by trigger.Run*; the
// command line's own intel block (stampIntel) keeps it and adds the entrypoint's disclosure.
package main

import (
	"context"
	"encoding/json"
	"flag"
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

// TestPublishedSignalsSummary: the run summary's signals line agrees with the Report as published.
// After a conflicting write the published Report is the merge, which may name no file or the other
// run's; the line then says so instead of reading as a ranking by this run's file.
func TestPublishedSignalsSummary(t *testing.T) {
	clearSignalsEnv(t)
	path := writeSignalsFile(t, filepath.Join(t.TempDir(), "signals.json"), []byte(signalsDoc("2026-10-19")))
	withFile, err := resolvedFor(t, "-advisory-signals", path)
	if err != nil || withFile.resolvedSignals == nil {
		t.Fatalf("resolveSignals = %v, %v", err, withFile.resolvedSignals)
	}
	none, err := resolvedFor(t)
	if err != nil || none.resolvedSignals != nil {
		t.Fatalf("resolveSignals = %v, %v; want no signals", err, none.resolvedSignals)
	}
	loaded := withFile.resolvedSignals.Digest
	const other = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	const noFile = "; merged with another run's rows on a conflicting write, so the published Report names no signals file"
	const otherFile = "; merged with another run's rows on a conflicting write, so the published Report names that run's signals file instead (" + other + ")"
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name      string
		f         *runFlags
		published *report.IntelProvenance
		ranked    bool   // the published Report keeps a finding with a Priority
		clause    string // appended to signalsSummary's line; "" when the two agree
		want      string // the whole line, when it is not signalsSummary's line plus clause
	}{
		{"the Report names the run's file", withFile, &report.IntelProvenance{WorkSetSource: report.WorkSetOSVQuery, SignalsDigest: loaded}, false, "", ""},
		{"no file, no intel block", none, nil, false, "", ""},
		{"no file, a block without a digest", none, &report.IntelProvenance{WorkSetSource: report.WorkSetOSVQuery}, false, "", ""},
		{"a merge cleared the run's file", withFile, &report.IntelProvenance{WorkSetSource: report.WorkSetOSVQuery}, false, noFile, ""},
		{"a merge cleared the run's file and the block", withFile, nil, false, noFile, ""},
		{"a merge kept another run's file", withFile, &report.IntelProvenance{SignalsDigest: other}, false, otherFile, ""},
		{"a merge kept another run's file over a run with none", none, &report.IntelProvenance{SignalsDigest: other}, false, "",
			"none — no signals source was provided (-advisory-signals, " + envAdvisorySignals + ", or an advisory corpus directory's signals.json)" + otherFile},
		{"a merge kept another run's ranked row over a run with none", none, nil, true, "",
			"none — no signals source was provided (-advisory-signals, " + envAdvisorySignals + ", or an advisory corpus directory's signals.json)" + noFile},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep := &report.Report{Provenance: report.Provenance{Intel: c.published}}
			if c.ranked {
				rep.Advisories = []report.AdvisoryFinding{{Advisory: report.Advisory{ID: "GO-2026-0001"}, Priority: &report.Priority{EPSSScore: 0.5, EPSSAsOf: "2026-10-19"}}}
			}
			want := c.want
			if want == "" {
				want = c.f.signalsSummary(now) + c.clause
			}
			if got := c.f.publishedSignalsSummary(rep, now); got != want {
				t.Errorf("summary line = %q\nwant         %q", got, want)
			}
		})
	}
}

// signalsFixtureReport is a baseline over a one-file Go tree ranked with a loaded signals file, then
// stamped the way a published report is, with the timestamp pinned. Its contract is pinned by signals_contract.golden.json.
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
	stampIntel(rep, f.intelProvenance(builtinWorkSet(advisories)))
	rep.Provenance.Timestamp = time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	out, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

var updateGolden = flag.Bool("update-golden", false, "rewrite signals_contract.golden.json")

// signalsContract is the part of a published Report this stamp is about: the provenance block, and
// each row's advisory id with its priority. Everything else in the Report belongs to other tests, and
// so does the analyzer version, which a release build stamps in (contractOf zeroes it).
type signalsContract struct {
	Provenance report.Provenance `json:"provenance"`
	Rows       []contractRow     `json:"rows"`
}

type contractRow struct {
	Advisory string           `json:"advisory"`
	Priority *report.Priority `json:"priority"`
}

func contractOf(t *testing.T, rep report.Report) []byte {
	t.Helper()
	c := signalsContract{Provenance: rep.Provenance}
	c.Provenance.AnalyzerVersion = ""
	for _, a := range rep.Advisories {
		c.Rows = append(c.Rows, contractRow{Advisory: a.Advisory.ID, Priority: a.Priority})
	}
	out, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

// TestPublishedReportCarriesSignalsContract: the Report the command line publishes for a run with
// signals has the provenance block and the per-row priorities it had when the command line did the
// stamping itself, and carries the verified digest once. Run with -update-golden to rewrite the golden.
func TestPublishedReportCarriesSignalsContract(t *testing.T) {
	golden, err := filepath.Abs(filepath.Join("testdata", "signals_contract.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	got := signalsFixtureReport(t)
	var rep report.Report
	if err := json.Unmarshal(got, &rep); err != nil {
		t.Fatal(err)
	}
	contract := contractOf(t, rep)
	if *updateGolden {
		if err := os.WriteFile(golden, contract, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(contract) != string(want) {
		t.Errorf("provenance or row priorities changed.\n--- got\n%s\n--- want\n%s", contract, want)
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
