// advisory_source_chain_test.go
//
// Covers chainSource: the corpus SUPPLEMENTS the built-in AdvisoryTable instead of replacing it.
//
// The regression these tests exist to prevent is measured, not hypothetical. Installing the
// 2026-07-23 published corpus as THE source (NewArtifactSource alone, which is what
// advisoryCorpusOption did) resolved 0 of the 16 ids the scan work set actually evaluates — every one
// of them fell to zero facts and failed open, taking Java, JS and Python from demo-quality to
// nothing. With the chain, every id that resolved before still resolves.
//
// The other half of the contract is the partial-fact rule: FIRST HIT WINS, WHOLE FACTS ONLY. A chain
// that topped up a thin corpus fact from the table would synthesize an advisory no producer asserted
// and no digest pins. TestChain_NeverMergesAcrossSources is the guard.
package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// writeCorpus materializes a one-record corpus at a fresh temp root: doc is written verbatim, its
// digest computed from the bytes on disk, and a valid manifest emitted alongside. Building the corpus
// from the exact bytes keeps the fixture honest — a test cannot accidentally pass on a digest that
// does not match what the reader will hash.
func writeCorpus(t *testing.T, docs map[string]string) string {
	t.Helper()
	root := t.TempDir()
	type entry struct {
		Identifier   string `json:"identifier"`
		Path         string `json:"path"`
		OutputDigest string `json:"output_digest"`
	}
	man := struct {
		ManifestVersion string  `json:"manifest_version"`
		SchemaVersion   string  `json:"schema_version"`
		RecordCount     int     `json:"record_count"`
		Records         []entry `json:"records"`
		CorpusDigest    string  `json:"corpus_digest"`
	}{ManifestVersion: "1.0.0", SchemaVersion: "ferralon.normalized_advisory.v3", CorpusDigest: "sha256:" + hex.EncodeToString(make([]byte, 32))}

	for id, body := range docs {
		name := id + ".json"
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		sum := sha256.Sum256([]byte(body))
		man.Records = append(man.Records, entry{Identifier: id, Path: name, OutputDigest: "sha256:" + hex.EncodeToString(sum[:])})
	}
	man.RecordCount = len(man.Records)

	blob, err := json.Marshal(man)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), blob, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return root
}

// TestChain_CorpusMissFallsBackToTable is THE regression test for the measured outage: an id the
// corpus does not carry must still resolve its built-in facts. Before the chain, installing a corpus
// made every such id return (zero, false).
func TestChain_CorpusMissFallsBackToTable(t *testing.T) {
	// A corpus that carries ONE id, none of them from the scan work set.
	root := writeCorpus(t, map[string]string{
		"CVE-TEST-ONLY-IN-CORPUS": `{"schema_version":"ferralon.normalized_advisory.v3","vuln_id":"CVE-TEST-ONLY-IN-CORPUS","version_scheme":"gomod","module":"example.com/only"}`,
	})
	chain := NewChainSource(NewArtifactSource(root), NewTableSource())

	// The full scan work set with the house canaries opted IN (cmd/ferralon-assay/acquire.go):
	// Go 11, Java 6, JS 5, Python 5, .NET 4. Every one of them must keep its facts through the
	// chain. The DEFAULT floors — the first rows of each language, the real published advisories —
	// matter most: they are what a customer scan evaluates, and a chain that dropped them would
	// empty the work set and halt the run.
	workSet := []string{
		// Go (10 default + the DOS canary on the opt-in)
		"GO-2021-0113", "GO-2022-0322", "GO-2021-0264", "CVE-2024-55947", "CVE-2025-8110",
		"CVE-2024-45337", "CVE-2026-46595", "CVE-2026-39831", "CVE-2026-39821", "CVE-2020-36569",
		"FERRALON-APP-DOS-0001",
		// Java / Maven
		"CVE-2019-14540", "CVE-2020-36518", "CVE-2024-22243",
		"TEGRON-JAVA-SSRF-0001", "TEGRON-JAVA-SPRING-SSRF-0001", "TEGRON-JAVA-DEP-0001",
		// JS / npm
		"CVE-2022-46175", "CVE-2023-26136", "CVE-2024-29041",
		"TEGRON-JS-SSRF-0001", "TEGRON-JS-DEP-0001",
		// Python / PyPI
		"CVE-2024-22195", "CVE-2024-23334", "CVE-2024-3772",
		"TEGRON-PY-AIRFLOW-EXPAPI-0001", "TEGRON-PY-DEP-0001",
		// .NET / NuGet
		"CVE-2019-0820", "CVE-2020-5234", "CVE-2024-21907",
		"TEGRON-NET-DEP-0001",
	}
	corpusOnly := NewArtifactSource(root)
	for _, id := range workSet {
		if _, ok := corpusOnly.Lookup(id); ok {
			t.Fatalf("fixture drift: %s must NOT be in the test corpus — the point is that the chain rescues it", id)
		}
		want, ok := NewTableSource().Lookup(id)
		if !ok {
			t.Fatalf("work-set id %s is not in the built-in AdvisoryTable — the work set and the table have drifted", id)
		}
		got, ok := chain.Lookup(id)
		if !ok {
			t.Fatalf("chain.Lookup(%s) ok=false — a corpus miss must fall through to the built-in table", id)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("chain.Lookup(%s) != table fact — the fallback must return the table's fact verbatim", id)
		}
	}

	// And the corpus half still works: the id only the corpus carries resolves.
	if facts, ok := chain.Lookup("CVE-TEST-ONLY-IN-CORPUS"); !ok || facts.Module != "example.com/only" {
		t.Errorf("chain.Lookup(corpus-only id) = %+v, %v — the corpus must SUPPLEMENT the table", facts, ok)
	}
}

// TestChain_CorpusHitWinsOverTable proves precedence: when both sources carry an id, the corpus fact
// is returned, unmodified.
func TestChain_CorpusHitWinsOverTable(t *testing.T) {
	root := writeCorpus(t, map[string]string{
		"GO-2021-0113": `{"schema_version":"ferralon.normalized_advisory.v3","vuln_id":"GO-2021-0113","version_scheme":"gomod","module":"golang.org/x/text","upper_exclusive":"v0.3.99","summary":"corpus narrative"}`,
	})
	chain := NewChainSource(NewArtifactSource(root), NewTableSource())

	got, ok := chain.Lookup("GO-2021-0113")
	if !ok {
		t.Fatal("chain.Lookup ok=false, want true")
	}
	if got.UpperExclusive != "v0.3.99" {
		t.Errorf("UpperExclusive = %q, want the CORPUS bound v0.3.99 — the corpus is consulted first", got.UpperExclusive)
	}
	if got.Summary != "corpus narrative" {
		t.Errorf("Summary = %q, want the corpus narrative", got.Summary)
	}
}

// TestChain_NeverMergesAcrossSources is the partial-fact guard. The corpus carries a DELIBERATELY
// THIN record for an id whose table entry is rich (aliases, symbols, cwes, fixed version). The chain
// must return the thin corpus fact EXACTLY — no field may be topped up from the table.
//
// A merged fact would be an advisory no producer ever asserted: a corpus version axis welded to a
// years-old table symbol axis, weighed downstream as one coherent, digest-pinned advisory. That is
// the laundering the AdvisorySource soundness note forbids.
func TestChain_NeverMergesAcrossSources(t *testing.T) {
	const thin = `{"schema_version":"ferralon.normalized_advisory.v3","vuln_id":"GO-2021-0113","version_scheme":"gomod","module":"golang.org/x/text"}`
	root := writeCorpus(t, map[string]string{"GO-2021-0113": thin})
	chain := NewChainSource(NewArtifactSource(root), NewTableSource())

	table, ok := NewTableSource().Lookup("GO-2021-0113")
	if !ok {
		t.Fatal("fixture drift: GO-2021-0113 must be in the built-in AdvisoryTable")
	}
	if len(table.Symbols) == 0 || len(table.Aliases) == 0 || table.FixedVersion == "" || table.Summary == "" {
		t.Fatal("fixture drift: the table entry must be RICHER than the thin corpus doc for this test to mean anything")
	}

	got, ok := chain.Lookup("GO-2021-0113")
	if !ok {
		t.Fatal("chain.Lookup ok=false, want true")
	}
	corpusOnly, _ := NewArtifactSource(root).Lookup("GO-2021-0113")
	if !reflect.DeepEqual(got, corpusOnly) {
		t.Fatalf("chain returned a fact the corpus did not assert:\n corpus = %+v\n chain  = %+v", corpusOnly, got)
	}
	if len(got.Symbols) != 0 {
		t.Errorf("Symbols = %v, want empty — the table's symbols must NOT be merged into a corpus hit", got.Symbols)
	}
	if len(got.Aliases) != 0 {
		t.Errorf("Aliases = %v, want empty — no field may be topped up across sources", got.Aliases)
	}
	if got.FixedVersion != "" {
		t.Errorf("FixedVersion = %q, want empty — no field may be topped up across sources", got.FixedVersion)
	}
	if got.Summary != "" {
		t.Errorf("Summary = %q, want empty — no field may be topped up across sources", got.Summary)
	}
	if got.Provenance.TrustTier != "" {
		t.Errorf("TrustTier = %q, want empty — the table's first-party tier must never vouch for corpus fields", got.Provenance.TrustTier)
	}
}

// TestChain_RejectedCorpusRecordFallsThroughWhole proves that a corpus record the reader REJECTS
// (bad digest, malformed body) is a miss, not a partial: the chain falls through and returns the
// table's whole fact, with nothing salvaged from the rejected document.
func TestChain_RejectedCorpusRecordFallsThroughWhole(t *testing.T) {
	fixtures := filepath.Join("testdata", "advisory_source")
	corpus := NewArtifactSource(fixtures)
	for _, id := range []string{"TEGRON-TEST-BADDIGEST", "TEGRON-TEST-MALFORMED"} {
		if _, ok := corpus.Lookup(id); ok {
			t.Fatalf("fixture drift: %s must be REJECTED by the reader", id)
		}
	}

	// Same shape with a work-set id: a corpus whose record for GO-2021-0113 fails the digest pin.
	root := t.TempDir()
	body := `{"schema_version":"ferralon.normalized_advisory.v3","vuln_id":"GO-2021-0113","version_scheme":"gomod","module":"golang.org/x/text","symbols":["attacker.controlled.Symbol"]}`
	if err := os.WriteFile(filepath.Join(root, "GO-2021-0113.json"), []byte(body), 0o644); err != nil {
		t.Fatalf("write doc: %v", err)
	}
	manifest := `{"manifest_version":"1.0.0","schema_version":"ferralon.normalized_advisory.v3","record_count":1,` +
		`"records":[{"identifier":"GO-2021-0113","path":"GO-2021-0113.json","output_digest":"sha256:` +
		hex.EncodeToString(make([]byte, 32)) + `"}],"corpus_digest":"sha256:00"}`
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	chain := NewChainSource(NewArtifactSource(root), NewTableSource())
	got, ok := chain.Lookup("GO-2021-0113")
	if !ok {
		t.Fatal("chain.Lookup ok=false — a digest-rejected corpus record must fall through to the table")
	}
	want, _ := NewTableSource().Lookup("GO-2021-0113")
	if !reflect.DeepEqual(got, want) {
		t.Error("chain returned something other than the table's whole fact after a digest rejection")
	}
	for _, s := range got.Symbols {
		if s == "attacker.controlled.Symbol" {
			t.Fatal("a field from the digest-REJECTED document reached the returned fact")
		}
	}
}

// TestChain_FailOpenPreserved proves the chain adds no new failure posture: an id no source carries,
// an empty chain, a chain of nils, and a chain over a wholly-missing corpus root all collapse to
// (zero, false) — byte-identical to today's map miss. No (zero, true), no panic, no error path.
func TestChain_FailOpenPreserved(t *testing.T) {
	missingRoot := filepath.Join(t.TempDir(), "does-not-exist")

	cases := []struct {
		name  string
		chain AdvisorySource
		id    string
	}{
		{"empty chain", NewChainSource(), "GO-2021-0113"},
		{"all-nil chain", NewChainSource(nil, nil), "GO-2021-0113"},
		{"unknown id in a full chain", NewChainSource(NewArtifactSource(missingRoot), NewTableSource()), "CVE-0000-NOSUCH"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts, ok := tc.chain.Lookup(tc.id)
			if ok {
				t.Fatalf("Lookup ok=true, want false")
			}
			if !reflect.DeepEqual(facts, AdvisoryFacts{}) {
				t.Errorf("Lookup facts = %+v, want the ZERO AdvisoryFacts", facts)
			}
		})
	}

	// A wholly-unreadable corpus must not take the table down with it: the run degrades to built-in
	// intel for LOOKUPS while advisoryCorpusOption's Validate preflight is what makes it LOUD.
	chain := NewChainSource(NewArtifactSource(missingRoot), nil, NewTableSource())
	if _, ok := chain.Lookup("GO-2021-0113"); !ok {
		t.Error("an unreadable corpus at the head of the chain must not suppress the table behind it")
	}
}

// TestChain_Describe proves the corpus identity used for Report provenance is read from the manifest
// and is fail-open: a corpus that cannot be read reports ok=false rather than a fabricated digest.
func TestChain_Describe(t *testing.T) {
	root := writeCorpus(t, map[string]string{
		"CVE-TEST-A": `{"schema_version":"ferralon.normalized_advisory.v3","vuln_id":"CVE-TEST-A","version_scheme":"gomod"}`,
		"CVE-TEST-B": `{"schema_version":"ferralon.normalized_advisory.v3","vuln_id":"CVE-TEST-B","version_scheme":"gomod"}`,
	})
	d, ok := NewArtifactSource(root).(CorpusDescriber)
	if !ok {
		t.Fatal("NewArtifactSource must satisfy CorpusDescriber")
	}
	info, ok := d.Describe()
	if !ok {
		t.Fatal("Describe ok=false on a valid corpus")
	}
	if info.Records != 2 {
		t.Errorf("Records = %d, want 2", info.Records)
	}
	if info.Digest == "" {
		t.Error("Digest is empty, want the manifest's corpus_digest")
	}

	missing, _ := NewArtifactSource(filepath.Join(t.TempDir(), "nope")).(CorpusDescriber)
	if info, ok := missing.Describe(); ok || info != (CorpusInfo{}) {
		t.Errorf("Describe on an unreadable corpus = %+v, %v; want the zero, false", info, ok)
	}
}
