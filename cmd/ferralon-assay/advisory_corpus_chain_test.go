// advisory_corpus_chain_test.go
//
// The entrypoint half of I-17(a) and I-03: that the opted-in house canaries chain behind a
// configured corpus, that a missing-but-EXPECTED corpus fails the run, and that what the run
// resolved is recorded on the Report.
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

// TestAdvisoryCorpus_ChainsCanariesBehindTheCorpus pins the fact source a corpus run resolves
// through: the corpus alone, with the house canaries behind it only when the run opted them in.
// Nothing else answers, so an id neither holds resolves nothing.
func TestAdvisoryCorpus_ChainsCanariesBehindTheCorpus(t *testing.T) {
	validRoot := filepath.Join("..", "..", "pipeline", "testdata", "advisory_source")
	canaries := []string{
		"FERRALON-APP-DOS-0001",
		"FERRALON-JAVA-SSRF-0001", "FERRALON-JAVA-SPRING-SSRF-0001", "FERRALON-JAVA-DEP-0001",
		"FERRALON-JS-SSRF-0001", "FERRALON-JS-DEP-0001",
		"FERRALON-PY-AIRFLOW-EXPAPI-0001", "FERRALON-PY-DEP-0001", "FERRALON-NET-DEP-0001",
	}
	for _, tc := range []struct {
		name        string
		args        []string
		wantCanary  bool
		wantSourced string
	}{
		{"canaries off", []string{"-advisory-corpus", validRoot}, false, report.FactSourceCorpus},
		{"canaries on", []string{"-advisory-corpus", validRoot, "-include-house-canaries"}, true, report.FactSourceCorpusThenHouseCanaries},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := runFlagsFor(t, tc.args...)
			t.Setenv(envAdvisoryCorpusDir, "")

			opt, err := f.advisoryCorpusOption()
			if err != nil {
				t.Fatalf("advisoryCorpusOption err = %v, want nil", err)
			}
			src := sourceFrom(t, opt)
			if f.resolvedFacts != tc.wantSourced {
				t.Errorf("FactSource = %q, want %q", f.resolvedFacts, tc.wantSourced)
			}
			if _, ok := src.Lookup("FERRALON-TEST-0001"); !ok {
				t.Error("a corpus-only id did not resolve — the corpus is not being consulted")
			}
			for _, id := range canaries {
				if _, ok := src.Lookup(id); ok != tc.wantCanary {
					t.Errorf("Lookup(%s) ok = %v, want %v", id, ok, tc.wantCanary)
				}
			}
			for _, id := range []string{"GO-2021-0113", "CVE-2024-45337", "CVE-2023-39325"} {
				if _, ok := src.Lookup(id); ok {
					t.Errorf("Lookup(%s) resolved facts neither the corpus nor the canaries hold", id)
				}
			}
		})
	}
}

// TestAdvisoryCorpus_RequiredButAbsentFailsTheRun covers I-03's sharp case: a corpus fetch that
// failed leaves an EMPTY corpus path, byte-identical to "no corpus configured". A run that declares
// it expects a corpus must fail rather than run without the facts it declared.
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

// TestAdvisoryCorpus_UnconfiguredRunHasNoFactSource pins the zero-config resolution: no corpus and
// no canaries is not itself an error here, but it installs no fact source at all, so the run halts
// later as given no work (or, in cve-watch, on errNoFactSource) rather than reading facts from
// anywhere else.
func TestAdvisoryCorpus_UnconfiguredRunHasNoFactSource(t *testing.T) {
	f := runFlagsFor(t)
	t.Setenv(envAdvisoryCorpusDir, "")
	t.Setenv(envAdvisoryCorpusRequired, "")

	opt, err := f.advisoryCorpusOption()
	if err != nil {
		t.Fatalf("advisoryCorpusOption err = %v, want nil", err)
	}
	if opt != nil {
		t.Fatal("expected no source-injecting option when nothing is configured")
	}
	if f.resolvedSource != nil {
		t.Fatalf("resolvedSource = %T, want nil: an unconfigured run has no fact source", f.resolvedSource)
	}
	if got := f.intelProvenance(floorWorkSet(nil)); got.FactSource != report.FactSourceNone || got.WorkSetSource != report.WorkSetNone {
		t.Errorf("provenance = %q/%q, want %q/%q", got.FactSource, got.WorkSetSource, report.FactSourceNone, report.WorkSetNone)
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

	if got.FactSource != report.FactSourceCorpus {
		t.Errorf("FactSource = %q, want %q", got.FactSource, report.FactSourceCorpus)
	}
	if got.WorkSetSource != report.WorkSetHouseCanaries {
		t.Errorf("WorkSetSource = %q, want %q", got.WorkSetSource, report.WorkSetHouseCanaries)
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
