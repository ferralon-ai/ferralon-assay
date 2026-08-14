// internal/pipeline/advisory_corpus_test.go
//
// U8b — the fixture advisory corpus. This file is BOTH the generator (regen mode) and the
// loader-facing validity contract (always-on) for the on-disk normalized_advisory.v2 corpus
// under ../corpus/testdata/advisories/. The corpus externalizes the AdvisoryTable facts to
// disk so U8a's artifactSource can read them; this slice ships DATA + this test only and
// changes NO pipeline logic.
//
// Layout (per the U8 quick-win spec §U8b): one JSON file per advisory named <VULN_ID>.json,
// each a pipeline.AdvisoryFacts serialized to the v2 shape, plus a manifest.json mapping
// vulnID -> {file, digest:"sha256:<hex>"} and carrying a whole-corpus "sha256:<hex>" over the
// sorted manifest body. The per-artifact digest is the tight pin surface artifactSource verifies
// on each Lookup; the whole-corpus digest is the outer schema-version+digest handle a published
// feed is pinned by. The digest string form mirrors artifact.Record.ContentHash
// ("sha256:<hex>").
//
// The advisories/ subdir does NOT collide with corpus.go's `//go:embed testdata/*.json` flat
// glob (that glob does not descend into subdirs), so it is a distinct consumer: artifactSource
// reads it from disk, the corpus loader never sees it.
//
// To regenerate after editing the fixtures below or an AdvisoryTable entry:
//
//	TEGRON_REGEN_ADVISORIES=1 go test ./pipeline/ -run TestAdvisoryCorpus_Regen
package pipeline

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	advisoryCorpusDir           = "../corpus/testdata/advisories"
	advisoryCorpusManifestFile  = "manifest.json"
	advisoryCorpusSchemaVersion = normalizedAdvisorySchemaVersion
)

// corpusManifestEntry pins one advisory file by its content digest.
type corpusManifestEntry struct {
	File   string `json:"file"`
	Digest string `json:"digest"` // "sha256:<hex>" over the exact file bytes
}

// corpusManifest is the corpus index: the schema handle, the per-advisory pins, and the
// whole-corpus digest over the sorted manifest body.
type corpusManifest struct {
	SchemaVersion string                         `json:"schema_version"`
	Advisories    map[string]corpusManifestEntry `json:"advisories"`
	CorpusDigest  string                         `json:"corpus_digest"`
}

// digestOf returns the "sha256:<hex>" digest of b, matching artifact.Record.ContentHash's form.
func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// marshalAdvisory serializes one AdvisoryFacts to the exact bytes written to disk: indented,
// trailing newline. Generator and validator share this so the on-disk digest is well-defined.
func marshalAdvisory(f AdvisoryFacts) ([]byte, error) {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// corpusDigest computes the whole-corpus "sha256:<hex>" over the sorted manifest body: the
// compact JSON of the per-advisory pins sorted by vuln id. It excludes the CorpusDigest field
// itself so the value is self-consistent (recomputable by the validator and by U8d).
func corpusDigest(advisories map[string]corpusManifestEntry) string {
	type row struct {
		ID     string `json:"id"`
		File   string `json:"file"`
		Digest string `json:"digest"`
	}
	ids := make([]string, 0, len(advisories))
	for id := range advisories {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rows := make([]row, 0, len(ids))
	for _, id := range ids {
		e := advisories[id]
		rows = append(rows, row{ID: id, File: e.File, Digest: e.Digest})
	}
	b, _ := json.Marshal(rows)
	return digestOf(b)
}

// advisoryCorpusEntries is the full corpus source of truth: every live AdvisoryTable entry,
// converted byte-faithfully to the v2 shape by round-tripping the struct, so the on-disk file can
// never drift from the table (TestAdvisoryCorpus_Valid asserts DeepEqual).
//
// It used to be the table PLUS twelve authored non-Go fixtures that existed only here. Those twelve
// were the real Maven/npm/PyPI/NuGet advisories the shipped scanner needed and never had: the table
// carried no non-Go facts at all, so the default advisory floor for four of the five supported
// languages was empty and every default Java/JS/Python/.NET scan halted on an empty work set. They
// were promoted into AdvisoryTable on 2026-08-05 (ranges re-verified against api.osv.dev on the
// way), which is why this function is now a straight copy. The corpus and the table are one set.
func advisoryCorpusEntries() map[string]AdvisoryFacts {
	entries := make(map[string]AdvisoryFacts, len(AdvisoryTable))
	for id, facts := range AdvisoryTable {
		entries[id] = facts
	}
	return entries
}

// TestAdvisoryCorpus_Regen regenerates the on-disk corpus (JSON files + manifest) from
// advisoryCorpusEntries. Opt-in (TEGRON_REGEN_ADVISORIES=1) so a normal test run never mutates
// checked-in fixtures; it is the executable definition of the digest scheme.
func TestAdvisoryCorpus_Regen(t *testing.T) {
	if os.Getenv("TEGRON_REGEN_ADVISORIES") == "" {
		t.Skip("set TEGRON_REGEN_ADVISORIES=1 to regenerate the advisory corpus")
	}
	if err := os.MkdirAll(advisoryCorpusDir, 0o755); err != nil {
		t.Fatal(err)
	}
	entries := advisoryCorpusEntries()
	man := corpusManifest{
		SchemaVersion: advisoryCorpusSchemaVersion,
		Advisories:    make(map[string]corpusManifestEntry, len(entries)),
	}
	for id, facts := range entries {
		b, err := marshalAdvisory(facts)
		if err != nil {
			t.Fatalf("marshal %s: %v", id, err)
		}
		file := id + ".json"
		if err := os.WriteFile(filepath.Join(advisoryCorpusDir, file), b, 0o644); err != nil {
			t.Fatalf("write %s: %v", file, err)
		}
		man.Advisories[id] = corpusManifestEntry{File: file, Digest: digestOf(b)}
	}
	man.CorpusDigest = corpusDigest(man.Advisories)
	mb, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(advisoryCorpusDir, advisoryCorpusManifestFile), append(mb, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("regenerated %d advisories + manifest under %s", len(entries), advisoryCorpusDir)
}

// TestAdvisoryCorpus_Valid is the loader-facing contract U8a's artifactSource relies on: every
// advisory file parses into AdvisoryFacts, its manifest digest matches sha256(file bytes), the
// whole-corpus digest is self-consistent, the manifest and the on-disk file set agree exactly,
// every advisory's on-disk bytes round-trip the declared AdvisoryFacts schema exactly (so a
// declared field ABSENT from the file fails, not only a present field that disagrees), and the
// gogs advisories stay non-version-disqualifiable.
func TestAdvisoryCorpus_Valid(t *testing.T) {
	mb, err := os.ReadFile(filepath.Join(advisoryCorpusDir, advisoryCorpusManifestFile))
	if err != nil {
		t.Fatalf("read manifest (run TEGRON_REGEN_ADVISORIES=1 go test -run TestAdvisoryCorpus_Regen first): %v", err)
	}
	var man corpusManifest
	if err := json.Unmarshal(mb, &man); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if man.SchemaVersion != advisoryCorpusSchemaVersion {
		t.Fatalf("manifest schema_version = %q, want %q", man.SchemaVersion, advisoryCorpusSchemaVersion)
	}

	// The manifest must list exactly the JSON files on disk (no orphan file, no dangling entry).
	dirents, err := os.ReadDir(advisoryCorpusDir)
	if err != nil {
		t.Fatal(err)
	}
	onDisk := map[string]bool{}
	for _, de := range dirents {
		if de.IsDir() || de.Name() == advisoryCorpusManifestFile || de.Name() == attributionStoreFile || !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		onDisk[de.Name()] = true
	}
	if len(onDisk) != len(man.Advisories) {
		t.Fatalf("on-disk advisory files (%d) != manifest entries (%d)", len(onDisk), len(man.Advisories))
	}

	decoded := make(map[string]AdvisoryFacts, len(man.Advisories))
	raw := make(map[string][]byte, len(man.Advisories))
	for id, entry := range man.Advisories {
		if !onDisk[entry.File] {
			t.Errorf("manifest names %s (id %s) but it is not on disk", entry.File, id)
			continue
		}
		b, err := os.ReadFile(filepath.Join(advisoryCorpusDir, entry.File))
		if err != nil {
			t.Errorf("read %s: %v", entry.File, err)
			continue
		}
		if got := digestOf(b); got != entry.Digest {
			t.Errorf("%s digest mismatch: file=%s manifest=%s", entry.File, got, entry.Digest)
		}
		var facts AdvisoryFacts
		if err := json.Unmarshal(b, &facts); err != nil {
			t.Errorf("%s does not decode into AdvisoryFacts: %v", entry.File, err)
			continue
		}
		decoded[id] = facts
		raw[id] = b
	}

	// Whole-corpus digest is self-consistent (recomputable — a published feed is pinned by this).
	if got := corpusDigest(man.Advisories); got != man.CorpusDigest {
		t.Errorf("corpus_digest mismatch: recomputed=%s manifest=%s", got, man.CorpusDigest)
	}

	// Count: the corpus is exactly the AdvisoryTable, one file per entry — no fixture may exist on
	// disk that the shipped table does not carry. A corpus-only advisory is one the scanner can
	// resolve facts for but will never put in a work set, which is how twelve real non-Go
	// advisories sat unreachable while the languages they cover could not complete a scan.
	if len(decoded) != len(AdvisoryTable) {
		t.Errorf("corpus has %d advisories, want %d (one per AdvisoryTable entry)",
			len(decoded), len(AdvisoryTable))
	}

	// SCHEMA ROUND-TRIP: every advisory's on-disk BYTES must be exactly what the generator
	// would write today.
	//
	// The predecessor of this check compared DECODED structs (reflect.DeepEqual of the parsed
	// facts against the live table) and could not see a field the corpus had fallen behind on:
	// an absent JSON key decodes to the same zero value the table holds, so absent and
	// present-and-zero are indistinguishable once the bytes are gone. That is precisely how the
	// corpus lost the whole normalized_advisory.v3 block (Withdrawn / Trigger / Fix /
	// PocSummary / AffectedPackages) while every assertion here stayed green. Comparing bytes
	// against marshalAdvisory — the generator's own encoder, so the comparison is a genuine
	// round-trip and not a restatement of the decode — makes an absent key fail.
	//
	// It also covers the old assertion strictly: byte equality implies struct equality, and the
	// entry set spans BOTH the converted AdvisoryTable entries and the authored fixtures.
	for id, want := range advisoryCorpusEntries() {
		b, ok := raw[id]
		if !ok {
			t.Errorf("advisory %s missing from corpus (expected an on-disk file for every table entry and fixture)", id)
			continue
		}
		wantBytes, err := marshalAdvisory(want)
		if err != nil {
			t.Errorf("marshal %s: %v", id, err)
			continue
		}
		if bytes.Equal(b, wantBytes) {
			continue
		}
		if missing := missingDeclaredKeys(wantBytes, b); len(missing) > 0 {
			t.Errorf("%s omits declared field(s) %v — the corpus no longer round-trips the schema it declares; regenerate with TEGRON_REGEN_ADVISORIES=1 go test ./pipeline/ -run TestAdvisoryCorpus_Regen",
				id, missing)
			continue
		}
		t.Errorf("%s on-disk bytes differ from the generated form (value drift from the live entry); regenerate with TEGRON_REGEN_ADVISORIES=1 go test ./pipeline/ -run TestAdvisoryCorpus_Regen", id)
	}

	// SOUNDNESS (inv.5): BOTH gogs advisories backing the honesty-guard fixtures must stay
	// non-version-disqualifiable — first-party, incomplete-patch, no sound upper bound. Each must
	// carry NO AffectedRanges, NO UpperExclusive, NO FixedVersion so the version axis fails OPEN
	// (extractAffectedRange returns rangeKnown=false on an empty range set). A sibling slice (U5)
	// regressed by making gogs version-disqualifiable; this guards the DATA against it.
	//
	// Both halves of the chain are covered, not just the predecessor: real fix versions exist for
	// each (0.13.1 and 0.13.4) and are recorded in GuardSufficiency, so the tempting-but-wrong
	// move is to promote them into a version axis the first-party scan can never resolve.
	for _, id := range []string{"CVE-2024-55947", "CVE-2025-8110"} {
		gogs, ok := decoded[id]
		if !ok {
			t.Errorf("gogs advisory %s missing from corpus", id)
			continue
		}
		if len(gogs.AffectedRanges) != 0 || gogs.UpperExclusive != "" || gogs.FixedVersion != "" {
			t.Errorf("gogs %s is version-disqualifiable (ranges=%d upper=%q fixed=%q); it MUST stay open (inv.5)",
				id, len(gogs.AffectedRanges), gogs.UpperExclusive, gogs.FixedVersion)
		}
	}

	// The real non-Go advisories must carry what Wave D's engines consume: a PURL whose ecosystem
	// scheme derives, and a version axis or a reachability axis (or both). This is what lets each
	// actually light an engine rather than only assert a fail-open — and since these twelve are now
	// the DEFAULT advisory floor for Java, JS, Python and .NET, it is also what stops that floor
	// from becoming membership that assesses nothing.
	for _, id := range realNonGoAdvisoryIDs() {
		f, ok := decoded[id]
		if !ok {
			t.Errorf("real non-Go advisory %s missing from corpus", id)
			continue
		}
		if purlEcosystem(f.PURL) == "" {
			t.Errorf("fixture %s: PURL %q yields no derivable ecosystem scheme", id, f.PURL)
		}
		if len(f.AffectedRanges) == 0 && len(f.Symbols) == 0 {
			t.Errorf("fixture %s carries neither AffectedRanges nor Symbols; it lights no engine", id)
		}
		for i, r := range f.AffectedRanges {
			if r.Fixed == "" && r.LastAffected == "" {
				t.Errorf("fixture %s range %d has neither Fixed nor LastAffected (unusable bound)", id, i)
			}
		}
	}
}

// missingDeclaredKeys returns the dotted paths of every JSON key present in want but absent from
// got, walking nested objects so a field lost inside Trigger/Fix/Provenance is named too. It exists
// only to turn a byte mismatch into a legible diagnosis — "this advisory omits a declared field" is
// the failure the round-trip check is really guarding against, and it is worth saying out loud
// rather than leaving the reader to diff 40 lines of JSON. Nil when got is not missing anything
// (the mismatch is then value drift, not schema drift).
func missingDeclaredKeys(want, got []byte) []string {
	var w, g any
	if json.Unmarshal(want, &w) != nil || json.Unmarshal(got, &g) != nil {
		return nil
	}
	var missing []string
	var walk func(prefix string, want, got any)
	walk = func(prefix string, want, got any) {
		wm, ok := want.(map[string]any)
		if !ok {
			return
		}
		gm, ok := got.(map[string]any)
		if !ok {
			return
		}
		keys := make([]string, 0, len(wm))
		for k := range wm {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			path := prefix + k
			gv, present := gm[k]
			if !present {
				missing = append(missing, path)
				continue
			}
			walk(path+".", wm[k], gv)
		}
	}
	walk("", w, g)
	return missing
}

// realNonGoAdvisoryIDs returns the sorted ids of every REAL Maven/npm/PyPI/NuGet advisory in the
// table — the default advisory floor for the four non-Go languages.
//
// It is derived rather than listed so an advisory added to that floor is covered by the properties
// below automatically. First-party synthetic ids are excluded: the TEGRON-*/FERRALON-* house
// canaries share those ecosystems but are gated off the default surface and are deliberately
// version-axis-only or reachability-only fixtures, so the "lights an engine" property does not
// apply to them.
func realNonGoAdvisoryIDs() []string {
	ids := make([]string, 0, len(AdvisoryTable))
	for id, facts := range AdvisoryTable {
		if strings.HasPrefix(id, "TEGRON-") || strings.HasPrefix(id, "FERRALON-") {
			continue
		}
		switch purlEcosystem(facts.PURL) {
		case "maven", "npm", "pypi", "nuget":
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}
