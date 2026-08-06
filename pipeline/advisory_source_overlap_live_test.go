// advisory_source_overlap_live_test.go
//
// The I-17(a) acceptance measurement, against a REAL corpus rather than a fixture.
//
// It reproduces the overlap between the scan work set (the 16 compiled-in ids
// cmd/ferralon-assay/acquire.go evaluates) and a filesystem advisory corpus, three ways:
// corpus-only (what installing a corpus used to do), table-only (the pre-corpus baseline), and
// chained (what a run does now). The invariant it enforces is the acceptance criterion: THE CHAIN
// LOSES NO ID. Whatever resolved before a corpus was installed still resolves after.
//
// Opt-in — set OPEN_TEGRON_OVERLAP_CORPUS to a corpus root (a directory with manifest.json). It is
// skipped otherwise, so it never gates CI on an artifact the public module does not carry. Deliberately
// a separate env var from TEGRON_ADVISORY_CORPUS_DIR: pointing the CLI at a corpus must not silently
// turn a measurement on.
//
//	OPEN_TEGRON_OVERLAP_CORPUS=/path/to/vulnerability-corpus go test ./pipeline -run Overlap -v
package pipeline

import (
	"os"
	"testing"
)

// scanWorkSet is the set of advisory ids the scan path evaluates, copied from
// cmd/ferralon-assay/acquire.go (Go 10, Java 3, JS 2, Python 2). It is duplicated rather than imported
// because pipeline must not depend on the cmd package; TestOverlap_WorkSetIsFullyTableBacked pins the
// copy against the table so drift is caught.
var scanWorkSet = []string{
	"GO-2021-0113", "GO-2022-0322", "GO-2021-0264", "CVE-2024-55947", "CVE-2025-8110",
	"CVE-2024-45337", "CVE-2026-46595", "CVE-2026-39831", "CVE-2026-39821", "CVE-2020-36569",
	"TEGRON-JAVA-SSRF-0001", "TEGRON-JAVA-SPRING-SSRF-0001", "TEGRON-JAVA-DEP-0001",
	"TEGRON-JS-SSRF-0001", "TEGRON-JS-DEP-0001",
	"TEGRON-PY-AIRFLOW-EXPAPI-0001", "TEGRON-PY-DEP-0001",
}

// TestOverlap_WorkSetIsFullyTableBacked is the hermetic half: every id the scan path evaluates
// resolves from the built-in table. This is the baseline the chain must not fall below, and it fails
// loudly if the work set and the table drift apart.
func TestOverlap_WorkSetIsFullyTableBacked(t *testing.T) {
	tbl := NewTableSource()
	for _, id := range scanWorkSet {
		if _, ok := tbl.Lookup(id); !ok {
			t.Errorf("%s is in the scan work set but not in the built-in AdvisoryTable", id)
		}
	}
}

// TestOverlap_ChainLosesNoWorkSetID is the live acceptance measurement. It prints the per-id
// before/after table and fails if installing the corpus costs a single id its facts.
func TestOverlap_ChainLosesNoWorkSetID(t *testing.T) {
	root := os.Getenv("OPEN_TEGRON_OVERLAP_CORPUS")
	if root == "" {
		t.Skip("set OPEN_TEGRON_OVERLAP_CORPUS to a corpus root to run the live overlap measurement")
	}

	corpus := NewArtifactSource(root)
	table := NewTableSource()
	chain := NewChainSource(corpus, table)

	if d, ok := corpus.(CorpusDescriber); ok {
		if info, ok := d.Describe(); ok {
			t.Logf("corpus: %d records, digest %s", info.Records, info.Digest)
		}
	}

	var corpusHits, tableHits, chainHits int
	t.Logf("%-32s %-10s %-10s %-10s", "ID", "corpus", "table", "chain")
	for _, id := range scanWorkSet {
		_, cOK := corpus.Lookup(id)
		_, tOK := table.Lookup(id)
		_, chOK := chain.Lookup(id)
		if cOK {
			corpusHits++
		}
		if tOK {
			tableHits++
		}
		if chOK {
			chainHits++
		}
		t.Logf("%-32s %-10v %-10v %-10v", id, cOK, tOK, chOK)

		// THE ACCEPTANCE CRITERION: no id loses its facts.
		if tOK && !chOK {
			t.Errorf("%s resolved from the built-in table but NOT through the chain — installing the corpus cost this id its facts", id)
		}
		if cOK && !chOK {
			t.Errorf("%s resolved from the corpus but NOT through the chain", id)
		}
	}
	t.Logf("corpus-only %d/%d · table-only %d/%d · chained %d/%d",
		corpusHits, len(scanWorkSet), tableHits, len(scanWorkSet), chainHits, len(scanWorkSet))

	if chainHits < tableHits {
		t.Errorf("chain resolves %d of %d ids, fewer than the built-in table's %d — the corpus must SUPPLEMENT, never narrow",
			chainHits, len(scanWorkSet), tableHits)
	}
}
