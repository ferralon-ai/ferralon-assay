// advisory_bundle_source_test.go
//
// Hermetic tests for bundleSource: the compressed corpus-bundle AdvisorySource. Synthetic bundles are
// built IN-CODE (no committed binary fixture) so each failure mode — digest mismatch, malformed
// record, corrupt gzip, duplicate identifier — can be constructed precisely. Valid records reuse a
// real committed fixture (testdata/advisory_source/FERRALON-TEST-0001.json) so toFacts is guaranteed to
// accept them rather than a hand-guessed envelope.
//
// Every bundleSource failure path must fail OPEN — (zero AdvisoryFacts, false) — never a partial or
// laundered fact (inv.5), exactly like artifactSource.
package pipeline

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

// validRecordBytes reads the committed FERRALON-TEST-0001 fixture and rewrites its vuln_id to id,
// returning the record file bytes. Reusing a real fixture guarantees the document is toFacts-valid;
// rewriting vuln_id lets a single fixture seed many distinct, valid records. Re-marshaling produces
// compact bytes; the caller computes output_digest over exactly these bytes.
func validRecordBytes(t *testing.T, id string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(advisoryFixtureRoot, "FERRALON-TEST-0001.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	m["vuln_id"] = id
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return out
}

// entryFor builds a bundleEntry with a CORRECT output_digest for recordJSON. digestOf is the shared
// "sha256:<hex>" helper (advisory_corpus_test.go) — the same recipe the reader and intel producer use.
func entryFor(id string, recordJSON []byte) bundleEntry {
	return bundleEntry{
		Identifier:   id,
		Path:         "2099/01/" + id + ".json",
		OutputDigest: digestOf(recordJSON),
		Bytes:        string(recordJSON),
	}
}

// writeBundle marshals entries as newline-delimited JSON (HTML-escaping disabled, mirroring the
// producer so recovered bytes hash correctly), gzips the whole stream as ONE deterministic member,
// and writes it to a t.TempDir() file. Entries are written in the given order — callers that care
// about the sorted-by-identifier invariant pre-sort; the duplicate-id case deliberately does not.
func writeBundle(t *testing.T, entries []bundleEntry) string {
	t.Helper()
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetEscapeHTML(false)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			t.Fatalf("encode entry: %v", err)
		}
	}
	return writeGzipBundle(t, body.Bytes())
}

// writeGzipBundle gzips raw bytes into a fresh .gz file under t.TempDir() and returns the path.
func writeGzipBundle(t *testing.T, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.jsonl.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create bundle file: %v", err)
	}
	defer f.Close()
	zw, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		t.Fatalf("gzip writer: %v", err)
	}
	if _, err := zw.Write(raw); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return path
}

// TestBundleSource_LookupCases covers the in-bundle content paths that share shape: a valid record
// resolves; every corruption of a single record fails OPEN to the zero fact.
func TestBundleSource_LookupCases(t *testing.T) {
	valid := validRecordBytes(t, "FERRALON-TEST-0001")

	// A record carrying the RETIRED `tegron.` schema tag (vs the shipped `ferralon.` base): decodes
	// as JSON but toFacts rejects the unrecognized schema_version → fail open.
	oldTag := validRecordBytes(t, "FERRALON-TEST-OLDTAG")
	oldTag = bytes.Replace(oldTag,
		[]byte(`"ferralon.normalized_advisory.v2"`),
		[]byte(`"tegron.normalized_advisory.v2"`), 1)

	tests := []struct {
		name   string
		entry  bundleEntry
		lookup string
		wantOK bool
	}{
		{
			name:   "valid record resolves",
			entry:  entryFor("FERRALON-TEST-0001", valid),
			lookup: "FERRALON-TEST-0001",
			wantOK: true,
		},
		{
			name: "digest mismatch fails open",
			entry: bundleEntry{
				Identifier:   "FERRALON-TEST-0001",
				Path:         "2099/01/x.json",
				OutputDigest: "sha256:" + hex.EncodeToString(make([]byte, 32)), // wrong digest
				Bytes:        string(valid),
			},
			lookup: "FERRALON-TEST-0001",
			wantOK: false,
		},
		{
			name:   "malformed record bytes fail open",
			entry:  entryFor("FERRALON-TEST-BAD", []byte(`{not valid json`)),
			lookup: "FERRALON-TEST-BAD",
			wantOK: false,
		},
		{
			name:   "retired schema tag fails open",
			entry:  entryFor("FERRALON-TEST-OLDTAG", oldTag),
			lookup: "FERRALON-TEST-OLDTAG",
			wantOK: false,
		},
		{
			name:   "unknown id fails open",
			entry:  entryFor("FERRALON-TEST-0001", valid),
			lookup: "FERRALON-TEST-NOPE",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeBundle(t, []bundleEntry{tc.entry})
			src := NewBundleSource(path)
			facts, ok := src.Lookup(tc.lookup)
			if ok != tc.wantOK {
				t.Fatalf("Lookup(%q) ok=%v, want %v", tc.lookup, ok, tc.wantOK)
			}
			if tc.wantOK {
				if facts.Coordinate != "com.example.lib:widget" || facts.UpperExclusive != "1.4.0" {
					t.Errorf("populated facts wrong: %+v", facts)
				}
			} else if !reflect.DeepEqual(facts, AdvisoryFacts{}) {
				// inv.5: a failed lookup must return the ZERO fact, never a laundered partial.
				t.Errorf("fail-open returned non-zero facts: %+v", facts)
			}
		})
	}
}

// TestBundleSource_MissingFile: an absent bundle fails OPEN on Lookup and LOUD on Validate.
func TestBundleSource_MissingFile(t *testing.T) {
	src := NewBundleSource(filepath.Join(t.TempDir(), "does-not-exist.jsonl.gz"))
	if facts, ok := src.Lookup("FERRALON-TEST-0001"); ok || !reflect.DeepEqual(facts, AdvisoryFacts{}) {
		t.Errorf("Lookup on missing bundle = (%+v, %v), want (zero, false)", facts, ok)
	}
	if err := src.(CorpusValidator).Validate(); err == nil {
		t.Error("Validate on missing bundle returned nil, want error")
	}
}

// TestBundleSource_CorruptGzip: random bytes that are not a gzip stream fail OPEN on Lookup and LOUD
// on Validate.
func TestBundleSource_CorruptGzip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.jsonl.gz")
	if err := os.WriteFile(path, []byte("this is not gzip at all, just bytes"), 0o644); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}
	src := NewBundleSource(path)
	if facts, ok := src.Lookup("FERRALON-TEST-0001"); ok || !reflect.DeepEqual(facts, AdvisoryFacts{}) {
		t.Errorf("Lookup on corrupt gzip = (%+v, %v), want (zero, false)", facts, ok)
	}
	if err := src.(CorpusValidator).Validate(); err == nil {
		t.Error("Validate on corrupt gzip returned nil, want error")
	}
}

// TestBundleSource_DuplicateIdentifier: two JSONL lines with the same identifier make the bundle
// unusable — Validate errors, Lookup fails open.
func TestBundleSource_DuplicateIdentifier(t *testing.T) {
	rec := validRecordBytes(t, "FERRALON-TEST-0001")
	path := writeBundle(t, []bundleEntry{
		entryFor("FERRALON-TEST-0001", rec),
		entryFor("FERRALON-TEST-0001", rec),
	})
	src := NewBundleSource(path)
	if err := src.(CorpusValidator).Validate(); err == nil {
		t.Error("Validate on duplicate-id bundle returned nil, want error")
	}
	if facts, ok := src.Lookup("FERRALON-TEST-0001"); ok || !reflect.DeepEqual(facts, AdvisoryFacts{}) {
		t.Errorf("Lookup on duplicate-id bundle = (%+v, %v), want (zero, false)", facts, ok)
	}
}

// TestBundleSource_EnumerateAndDescribe: KnownIDs returns the sorted identifier set and Describe
// reports Records == len with a sha256 file-digest handle.
func TestBundleSource_EnumerateAndDescribe(t *testing.T) {
	ids := []string{"FERRALON-TEST-0003", "FERRALON-TEST-0001", "FERRALON-TEST-0002"}
	var entries []bundleEntry
	for _, id := range ids {
		entries = append(entries, entryFor(id, validRecordBytes(t, id)))
	}
	path := writeBundle(t, entries)
	src := NewBundleSource(path)

	enum, ok := src.(AdvisoryEnumerator)
	if !ok {
		t.Fatal("bundleSource does not satisfy AdvisoryEnumerator")
	}
	got := enum.KnownIDs()
	want := []string{"FERRALON-TEST-0001", "FERRALON-TEST-0002", "FERRALON-TEST-0003"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("KnownIDs() = %v, want %v (sorted)", got, want)
	}

	info, ok := src.(CorpusDescriber).Describe()
	if !ok {
		t.Fatal("Describe() ok=false, want true")
	}
	if info.Records != len(ids) {
		t.Errorf("Describe().Records = %d, want %d", info.Records, len(ids))
	}
	if len(info.Digest) != len("sha256:")+64 || info.Digest[:7] != "sha256:" {
		t.Errorf("Describe().Digest = %q, want sha256:<64 hex>", info.Digest)
	}

	// A validated bundle Validate()s clean.
	if err := src.(CorpusValidator).Validate(); err != nil {
		t.Errorf("Validate() on good bundle = %v, want nil", err)
	}
	// Enumeration on an unusable bundle yields an empty slice, never an error path.
	bad := NewBundleSource(filepath.Join(t.TempDir(), "nope.jsonl.gz")).(AdvisoryEnumerator)
	if kn := bad.KnownIDs(); len(kn) != 0 {
		t.Errorf("KnownIDs() on missing bundle = %v, want empty", kn)
	}
}

// TestBundleSource_ConcurrentLookup fires many parallel reads (Lookup + KnownIDs + Describe) at one
// source; the sync.Once load followed by a read-only index must be race-clean under -race.
func TestBundleSource_ConcurrentLookup(t *testing.T) {
	ids := []string{"FERRALON-TEST-0001", "FERRALON-TEST-0002", "FERRALON-TEST-0003", "FERRALON-TEST-0004"}
	var entries []bundleEntry
	for _, id := range ids {
		entries = append(entries, entryFor(id, validRecordBytes(t, id)))
	}
	src := NewBundleSource(writeBundle(t, entries))

	const workers = 64
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			id := ids[i%len(ids)]
			facts, ok := src.Lookup(id)
			if !ok || facts.Coordinate != "com.example.lib:widget" {
				t.Errorf("concurrent Lookup(%q) = (%+v, %v)", id, facts, ok)
			}
			_ = src.(AdvisoryEnumerator).KnownIDs()
			_, _ = src.(CorpusDescriber).Describe()
		}(i)
	}
	wg.Wait()
}
