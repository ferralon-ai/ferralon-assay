// internal/pipeline/advisory_corpus_test.go
//
// The fixture advisory corpus under ../corpus/testdata/advisories/: the advisories pipeline tests
// (and tests in other packages, through internal/advisorytest) read when a stage needs a known
// advisory. The files ARE the source of truth; this file is their validity contract (always on)
// and their canonicalizer (regen mode).
//
// Layout: one JSON file per advisory named <VULN_ID>.json, each a pipeline.AdvisoryFacts
// serialized field for field, plus a manifest.json mapping vulnID -> {file, digest:"sha256:<hex>"}
// and carrying a whole-corpus "sha256:<hex>" over the sorted manifest body. The digest string form
// mirrors artifact.Record.ContentHash ("sha256:<hex>").
//
// The advisories/ subdir does NOT collide with corpus.go's `//go:embed testdata/*.json` flat glob
// (that glob does not descend into subdirs).
//
// After editing or adding a fixture file, canonicalize it and re-pin the manifest:
//
//	ASSAY_REGEN_ADVISORIES=1 go test ./pipeline/ -run TestAdvisoryCorpus_Regen
package pipeline

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/advisorytest"
)

// marshalAdvisory serializes one AdvisoryFacts to the exact bytes kept on disk: indented, trailing
// newline. Regen and the validity check share it so the on-disk digest is well-defined.
func marshalAdvisory(f AdvisoryFacts) ([]byte, error) {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// corpusDigest computes the whole-corpus "sha256:<hex>" over the sorted manifest body: the compact
// JSON of the per-advisory pins sorted by vuln id. It excludes the CorpusDigest field itself so the
// value is self-consistent.
func corpusDigest(advisories map[string]advisorytest.Entry) string {
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
	return advisorytest.Digest(b)
}

// advisoryFixtureFiles returns the advisory JSON files in the fixture dir, keyed by vuln id (the
// file name without .json). The manifest and the attribution store are not advisories.
func advisoryFixtureFiles(t *testing.T) map[string]string {
	t.Helper()
	dirents, err := os.ReadDir(advisorytest.Dir())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, de := range dirents {
		name := de.Name()
		if de.IsDir() || name == advisorytest.ManifestFile || name == attributionStoreFile || !strings.HasSuffix(name, ".json") {
			continue
		}
		out[strings.TrimSuffix(name, ".json")] = name
	}
	return out
}

// TestAdvisoryCorpus_Regen canonicalizes every fixture file (decode strictly, re-encode with
// marshalAdvisory) and rewrites the manifest pins. Opt-in (ASSAY_REGEN_ADVISORIES=1) so a normal
// test run never mutates checked-in fixtures; it is the executable definition of the digest scheme.
func TestAdvisoryCorpus_Regen(t *testing.T) {
	if os.Getenv("ASSAY_REGEN_ADVISORIES") == "" {
		t.Skip("set ASSAY_REGEN_ADVISORIES=1 to canonicalize the fixture advisories and re-pin the manifest")
	}
	dir := advisorytest.Dir()
	man := advisorytest.Manifest{
		SchemaVersion: normalizedAdvisorySchemaVersion,
		Advisories:    map[string]advisorytest.Entry{},
	}
	for id, file := range advisoryFixtureFiles(t) {
		path := filepath.Join(dir, file)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var facts AdvisoryFacts
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&facts); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		b, err := marshalAdvisory(facts)
		if err != nil {
			t.Fatalf("marshal %s: %v", id, err)
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatalf("write %s: %v", file, err)
		}
		man.Advisories[id] = advisorytest.Entry{File: file, Digest: advisorytest.Digest(b)}
	}
	man.CorpusDigest = corpusDigest(man.Advisories)
	mb, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, advisorytest.ManifestFile), append(mb, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("canonicalized %d advisories and re-pinned the manifest under %s", len(man.Advisories), dir)
}

// TestAdvisoryCorpus_Valid is the fixture corpus contract: the manifest lists exactly the advisory
// files on disk, every pin and the whole-corpus digest verify, every file decodes strictly into
// AdvisoryFacts and is byte-identical to its canonical encoding (so a declared field ABSENT from
// the file fails, not only a present field that disagrees), the house canaries the scanner ships
// match their fixtures, and the data properties other tests lean on hold.
func TestAdvisoryCorpus_Valid(t *testing.T) {
	man, err := advisorytest.ReadManifest()
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if man.SchemaVersion != normalizedAdvisorySchemaVersion {
		t.Fatalf("manifest schema_version = %q, want %q", man.SchemaVersion, normalizedAdvisorySchemaVersion)
	}

	onDisk := advisoryFixtureFiles(t)
	if len(onDisk) != len(man.Advisories) {
		t.Fatalf("on-disk advisory files (%d) != manifest entries (%d)", len(onDisk), len(man.Advisories))
	}
	for id, entry := range man.Advisories {
		if onDisk[id] != entry.File {
			t.Errorf("manifest names %s for id %s, but the file on disk for that id is %q", entry.File, id, onDisk[id])
		}
	}
	if got := corpusDigest(man.Advisories); got != man.CorpusDigest {
		t.Errorf("corpus_digest mismatch: recomputed=%s manifest=%s", got, man.CorpusDigest)
	}

	// Load verifies every pin and decodes strictly.
	decoded, err := advisorytest.Load[AdvisoryFacts]()
	if err != nil {
		t.Fatalf("load fixtures: %v", err)
	}

	// SCHEMA ROUND-TRIP: every file's bytes must be exactly what marshalAdvisory writes for the
	// facts it decodes to. Comparing decoded structs cannot see a field the file has fallen behind
	// on (an absent key decodes to the same zero value), so the comparison is on bytes.
	for id, facts := range decoded {
		raw, err := os.ReadFile(filepath.Join(advisorytest.Dir(), man.Advisories[id].File))
		if err != nil {
			t.Fatal(err)
		}
		want, err := marshalAdvisory(facts)
		if err != nil {
			t.Fatalf("marshal %s: %v", id, err)
		}
		if bytes.Equal(raw, want) {
			continue
		}
		if missing := missingDeclaredKeys(want, raw); len(missing) > 0 {
			t.Errorf("%s omits declared field(s) %v; canonicalize with ASSAY_REGEN_ADVISORIES=1 go test ./pipeline/ -run TestAdvisoryCorpus_Regen", id, missing)
			continue
		}
		t.Errorf("%s is not in canonical form; canonicalize with ASSAY_REGEN_ADVISORIES=1 go test ./pipeline/ -run TestAdvisoryCorpus_Regen", id)
	}

	// The house canaries the scanner ships and their fixtures are one set of facts: a test that
	// reads a canary from the fixtures sees exactly what an opted-in scan resolves.
	for id, want := range houseCanaryFacts {
		got, ok := decoded[id]
		if !ok {
			t.Errorf("house canary %s has no fixture", id)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("house canary %s fixture drifted from houseCanaryFacts:\n fixture %+v\n shipped %+v", id, got, want)
		}
	}

	// SOUNDNESS (inv.5): BOTH gogs advisories backing the honesty-guard fixtures must stay
	// non-version-disqualifiable — first-party, incomplete-patch, no sound upper bound. Each must
	// carry NO AffectedRanges, NO UpperExclusive, NO FixedVersion so the version axis fails OPEN
	// (extractAffectedRange returns rangeKnown=false on an empty range set). Real fix versions exist
	// for each (0.13.1 and 0.13.4) and are recorded in GuardSufficiency, so the tempting-but-wrong
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

	// The real non-Go fixtures must carry what the non-Go engines consume: a PURL whose ecosystem
	// scheme derives, and a version axis or a reachability axis (or both), so each lights an engine
	// rather than only asserting a fail-open.
	for _, id := range realNonGoAdvisoryIDs(decoded) {
		f := decoded[id]
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
// got, walking nested objects so a field lost inside Trigger/Fix/Provenance is named too. It turns
// a byte mismatch into a legible diagnosis; nil when got is not missing anything (the mismatch is
// then formatting or value drift, not schema drift).
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

// realNonGoAdvisoryIDs returns the sorted ids of every real (non-FERRALON-*) Maven/npm/PyPI/NuGet
// fixture. It is derived rather than listed so a fixture added in those ecosystems is covered by
// the properties above automatically. The FERRALON-* house canaries are deliberately
// version-axis-only or reachability-only fixtures, so the "lights an engine" property does not
// apply to them.
func realNonGoAdvisoryIDs(fixtures map[string]AdvisoryFacts) []string {
	ids := make([]string, 0, len(fixtures))
	for id, facts := range fixtures {
		if strings.HasPrefix(id, "FERRALON-") {
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
