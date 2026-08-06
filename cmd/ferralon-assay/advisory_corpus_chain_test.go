// advisory_corpus_chain_test.go
//
// The entrypoint half of I-17(a) and I-03: that a configured corpus SUPPLEMENTS the built-in
// advisory table rather than replacing it, that a missing-but-EXPECTED corpus fails the run, and
// that what the run resolved is recorded on the Report.
package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// sourceFrom extracts the AdvisorySource an AssessOption installs.
func sourceFrom(t *testing.T, opt pipeline.AssessOption) pipeline.AdvisorySource {
	t.Helper()
	if opt == nil {
		t.Fatal("expected a source-injecting option, got nil")
	}
	cfg := pipeline.AssessConfig{}
	opt(&cfg)
	if cfg.Source == nil {
		t.Fatal("option installed no AdvisorySource")
	}
	return cfg.Source
}

// TestAdvisoryCorpus_ChainsBehindTheBuiltinTable is the regression guard for the measured outage:
// installing a corpus must not cost a work-set id its facts. The fixture corpus carries none of the
// scan work set, which is the realistic case — the published corpus carries 5 of 16.
func TestAdvisoryCorpus_ChainsBehindTheBuiltinTable(t *testing.T) {
	validRoot := filepath.Join("..", "..", "pipeline", "testdata", "advisory_source")
	f := runFlagsFor(t, "-advisory-corpus", validRoot)
	t.Setenv(envAdvisoryCorpusDir, "")

	opt, err := f.advisoryCorpusOption()
	if err != nil {
		t.Fatalf("advisoryCorpusOption err = %v, want nil", err)
	}
	src := sourceFrom(t, opt)

	// Every id the built-in table backs must still resolve through the configured source.
	for _, id := range []string{
		"GO-2021-0113", "GO-2022-0322", "GO-2021-0264", "CVE-2024-55947", "CVE-2025-8110",
		"CVE-2024-45337", "CVE-2026-46595", "CVE-2026-39831", "CVE-2026-39821", "CVE-2020-36569",
		"TEGRON-JAVA-SSRF-0001", "TEGRON-JAVA-SPRING-SSRF-0001", "TEGRON-JAVA-DEP-0001",
		"TEGRON-JS-SSRF-0001", "TEGRON-JS-DEP-0001",
		"TEGRON-PY-AIRFLOW-EXPAPI-0001", "TEGRON-PY-DEP-0001",
	} {
		if _, ok := src.Lookup(id); !ok {
			t.Errorf("%s lost its facts when a corpus was configured — the corpus must supplement the table, not replace it", id)
		}
	}

	// And the corpus half is live: an id only the corpus carries resolves.
	if _, ok := src.Lookup("TEGRON-TEST-0001"); !ok {
		t.Error("a corpus-only id did not resolve — the corpus is not being consulted")
	}
}

// TestAdvisoryCorpus_RequiredButAbsentFailsTheRun covers I-03's sharp case: a corpus fetch that
// failed leaves an EMPTY corpus path, byte-identical to "no corpus configured". A run that declares
// it expects a corpus must fail rather than degrade to built-in intel and render as a clean scan.
func TestAdvisoryCorpus_RequiredButAbsentFailsTheRun(t *testing.T) {
	t.Run("required via flag", func(t *testing.T) {
		f := runFlagsFor(t, "-require-advisory-corpus")
		t.Setenv(envAdvisoryCorpusDir, "")
		t.Setenv(envAdvisoryCorpusRequired, "")
		opt, err := f.advisoryCorpusOption()
		if err == nil {
			t.Fatal("expected an error when a corpus is required but no path resolved")
		}
		if opt != nil {
			t.Fatal("expected nil option on the required-but-absent failure")
		}
		if !strings.Contains(err.Error(), envAdvisoryCorpusDir) {
			t.Errorf("error must name the env channel to fix; got %v", err)
		}
	})

	t.Run("required via env", func(t *testing.T) {
		f := runFlagsFor(t)
		t.Setenv(envAdvisoryCorpusDir, "")
		t.Setenv(envAdvisoryCorpusRequired, "1")
		if _, err := f.advisoryCorpusOption(); err == nil {
			t.Fatal("expected an error when the env declares a corpus is required but none resolved")
		}
	})

	t.Run("required and present → no error", func(t *testing.T) {
		f := runFlagsFor(t)
		t.Setenv(envAdvisoryCorpusDir, filepath.Join("..", "..", "pipeline", "testdata", "advisory_source"))
		t.Setenv(envAdvisoryCorpusRequired, "true")
		opt, err := f.advisoryCorpusOption()
		if err != nil {
			t.Fatalf("advisoryCorpusOption err = %v, want nil when the required corpus is present", err)
		}
		sourceFrom(t, opt)
	})
}

// TestAdvisoryCorpus_UnconfiguredRunStillWorks is the counterweight: the legitimate zero-config
// case — a user scanning with no corpus at all — must keep working, silently and with the built-in
// table.
func TestAdvisoryCorpus_UnconfiguredRunStillWorks(t *testing.T) {
	f := runFlagsFor(t)
	t.Setenv(envAdvisoryCorpusDir, "")
	t.Setenv(envAdvisoryCorpusRequired, "")

	opt, err := f.advisoryCorpusOption()
	if err != nil {
		t.Fatalf("advisoryCorpusOption err = %v, want nil — an unconfigured run is legitimate", err)
	}
	if opt != nil {
		t.Fatal("expected nil option (built-in table default) when nothing is configured")
	}
	if got := f.intelProvenance(floorWorkSet(make([]assessment.VulnRef, 16))); got.FactSource != report.FactSourceBuiltinTable {
		t.Errorf("FactSource = %q, want %q", got.FactSource, report.FactSourceBuiltinTable)
	}
}

// TestAdvisoryCorpus_UnparseableRequirementIsAnError proves the requirement gate cannot be disabled
// by a typo. Defaulting an unreadable value to "not required" would reintroduce the silent downgrade
// the gate exists to close.
func TestAdvisoryCorpus_UnparseableRequirementIsAnError(t *testing.T) {
	f := runFlagsFor(t)
	t.Setenv(envAdvisoryCorpusDir, filepath.Join("..", "..", "pipeline", "testdata", "advisory_source"))
	t.Setenv(envAdvisoryCorpusRequired, "yes-please")

	if _, err := f.advisoryCorpusOption(); err == nil {
		t.Fatal("expected an error for an unparseable requirement value, not a silent default")
	}
}

// TestAdvisoryCorpus_IntelProvenanceRecorded proves the Report can disclose what the run used: the
// work set's source and size, the fact source, and the corpus identity.
func TestAdvisoryCorpus_IntelProvenanceRecorded(t *testing.T) {
	validRoot := filepath.Join("..", "..", "pipeline", "testdata", "advisory_source")
	f := runFlagsFor(t, "-advisory-corpus", validRoot)
	t.Setenv(envAdvisoryCorpusDir, "")
	t.Setenv(envAdvisoryCorpusRequired, "")

	if _, err := f.advisoryCorpusOption(); err != nil {
		t.Fatalf("advisoryCorpusOption err = %v", err)
	}
	got := f.intelProvenance(floorWorkSet(make([]assessment.VulnRef, 16)))

	if got.FactSource != report.FactSourceCorpusThenBuiltinTable {
		t.Errorf("FactSource = %q, want %q", got.FactSource, report.FactSourceCorpusThenBuiltinTable)
	}
	if got.WorkSetSource != report.WorkSetBuiltinLanguageSet {
		t.Errorf("WorkSetSource = %q, want %q", got.WorkSetSource, report.WorkSetBuiltinLanguageSet)
	}
	if got.WorkSetSize != 16 {
		t.Errorf("WorkSetSize = %d, want 16", got.WorkSetSize)
	}
	if got.CorpusRecords == 0 {
		t.Error("CorpusRecords = 0, want the fixture corpus's record count")
	}
	// The corpus record count is a FACT-LOOKUP size, not the work set. Conflating them is what made
	// "72 records" read as "72 CVEs evaluated".
	if got.CorpusRecords == got.WorkSetSize {
		t.Log("note: fixture record count coincides with the work-set size; they are independent quantities")
	}
}
