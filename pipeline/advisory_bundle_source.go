// advisory_bundle_source.go
//
// bundleSource: a memory-resident, digest-pinned AdvisorySource that consumes ONE compressed corpus
// bundle (`<policy>.jsonl.gz`) instead of a 128k-file on-disk tree. Where artifactSource does one
// os.ReadFile per advisory against its indexed manifest, this reader holds every record in memory:
// decompress-once / index-once / verify-per-lookup.
//
// LIFECYCLE — decompress-once, index-once, verify-per-lookup:
//   - NewBundleSource stores the path and does NO work (mirrors NewArtifactSource): cheap, no error.
//   - The first Lookup/Validate/Describe/KnownIDs triggers a sync.Once load: open the .gz, wrap it in
//     a stdlib gzip.NewReader, stream-decode each JSONL line into an in-memory
//     map[identifier]bundleRecord, and record the .gz file's own sha256 as the corpus identity. The
//     index is READ-ONLY after the Once returns, so every subsequent read is lock-free and
//     concurrency-safe (the set-before-spawn contract, advisory_source.go's defaultAdvisorySourceVar).
//   - Verification is per Lookup, NOT at build: only ids that are actually looked up are hashed
//     (digestMatches over rec.bytes), never the whole ~109.6k set at load. The index is immutable so
//     no memoization/locking is needed; re-hashing a repeat lookup (~1 KB–68 KB) is negligible.
//
// SOUNDNESS (inv.5) — fail-closed fidelity is the whole point. EVERY failure mode collapses to
// (zero AdvisoryFacts, false) on Lookup: unreadable bundle, corrupt gzip, bad JSON line, duplicate
// identifier, digest mismatch, unknown id, malformed record. A source NEVER returns a partial or
// laundered fact. This mirrors artifactSource exactly. The split between the loud path and the
// fail-open path is the same as artifactSource's: Validate surfaces the LOAD error (the bundle
// container is unopenable/undecompressible/unparseable/has duplicate ids) for a boot-time preflight;
// Lookup swallows it to (zero, false). A single bad *record* is NOT a load error — it is a
// per-lookup fail-open concern; Validate gates the container, Lookup gates each document.
//
// MEMORY BUDGET: the worst-case `full` bundle is ≈ 134.9 MB of raw record bytes (109,590 records) →
// ≈ 200–250 MB resident once the map, id keys, and digest strings are added. Trivial on the 16 GB
// fire VM / 7 GB Action budget; no spill-to-disk.
//
// TRUST BOUNDARY: the inline output_digest proves each `bytes` matches the bundle's OWN claim — the
// direct analog of artifactSource pinning each record against its manifest entry. The OUTER pin (is
// this the right bundle? — the .gz hash vs the trusted `corpus-<12hex>` release tag) is the
// fetcher/provisioning layer's job, exactly as artifactSource trusts the root it was handed. A
// wholesale-substituted bundle is not caught by this reader alone; that is the fetch pin's job.
package pipeline

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
)

// bundleEntry is one JSONL line of a `<policy>.jsonl.gz` bundle: the cross-repo wire shape emitted by
// the intel producer (internal/policy/public/bundle.go BundleEntry). `Bytes` is the record file
// VERBATIM as a JSON string — the producer disables HTML-escaping when writing it so the recovered
// bytes hash back to OutputDigest. `Path` is informational (the record's <YYYY>/<MM>/<id>.json stem);
// this reader keys purely on Identifier and never uses Path to locate anything, so no safeRelPath
// guard is needed (there is no filesystem read per record).
type bundleEntry struct {
	Identifier   string `json:"identifier"`
	Path         string `json:"path"`          // informational only; NOT used to locate anything
	OutputDigest string `json:"output_digest"` // "sha256:<hex>" over the UTF-8 bytes of Bytes
	Bytes        string `json:"bytes"`         // the record file verbatim, as a JSON string
}

// bundleRecord is one indexed advisory: the inline per-record pin plus the verbatim record bytes.
// bytes is stored as []byte (not string) so the per-lookup digestMatches/json.Unmarshal read it with
// no re-allocation. The index map is built once and never mutated, so a bundleRecord value is
// safe to read concurrently.
type bundleRecord struct {
	outputDigest string
	bytes        []byte
}

// bundleSource is a digest-pinned reader over one compressed corpus bundle. It holds the .gz path and
// a sync.Once-guarded lazily-built index; the Once also records the load error (if any) and the .gz
// file's own sha256 (the corpus identity handle Describe reports). After the Once, index/loadErr/
// fileDigest are read-only.
//
// CONCURRENCY CONTRACT — same set-before-spawn precedent as defaultAdvisorySourceVar
// (advisory_source.go): a bundleSource is built once at boot and read concurrently thereafter. The
// sync.Once makes the single lazy load happen-before every subsequent read, and the built index is
// never mutated, so reads take no lock.
type bundleSource struct {
	path string

	once       sync.Once
	index      map[string]bundleRecord
	loadErr    error
	fileDigest string // "sha256:<hex>" over the raw .gz file bytes; the corpus identity for Describe
}

// NewBundleSource constructs a digest-pinned bundle-backed AdvisorySource over the compressed bundle
// at path. It is CHEAP and does NO work — no open, no decompress, no error return — mirroring
// NewArtifactSource: the first Lookup/Validate/Describe/KnownIDs triggers the one-time load. The
// returned value also satisfies CorpusValidator, CorpusDescriber, and AdvisoryEnumerator, so an
// entrypoint can preflight, record provenance, and derive the work set from it.
//
// Set-before-spawn only (see bundleSource's concurrency contract): build it at boot, before any
// pipeline goroutine reads through it.
func NewBundleSource(path string) AdvisorySource { return &bundleSource{path: path} }

// load performs the one-time decompress + index build, guarded by s.once. It opens the .gz, computes
// the raw file digest as the bytes stream past (via io.TeeReader, so the file is read exactly once),
// gzip-decompresses, and stream-decodes each JSONL object into s.index keyed by identifier. A
// duplicate identifier FAILS the load (mirrors the manifest's duplicate-identifier rule): a bundle
// that cannot account for its own id set cannot be trusted to name the right bytes for any id. Any
// open/decompress/parse/duplicate error is recorded in s.loadErr and leaves s.index nil; callers read
// s.loadErr to distinguish the loud (Validate) path from the fail-open (Lookup) path.
func (s *bundleSource) load() {
	s.once.Do(func() {
		f, err := os.Open(s.path)
		if err != nil {
			s.loadErr = fmt.Errorf("open advisory bundle %s: %w", s.path, err)
			return
		}
		defer f.Close()

		// Hash the raw .gz bytes as they are read for decompression: TeeReader feeds every byte the
		// gzip reader consumes into the file-digest hasher, so the corpus identity is computed in the
		// single pass, no second read of the file.
		hasher := sha256.New()
		tee := io.TeeReader(f, hasher)

		gz, err := gzip.NewReader(tee)
		if err != nil {
			s.loadErr = fmt.Errorf("open gzip stream %s: %w", s.path, err)
			return
		}
		defer gz.Close()

		index := make(map[string]bundleRecord)
		dec := json.NewDecoder(gz)
		for {
			var entry bundleEntry
			if err := dec.Decode(&entry); err != nil {
				if err == io.EOF {
					break
				}
				s.loadErr = fmt.Errorf("parse advisory bundle %s: %w", s.path, err)
				return
			}
			if _, dup := index[entry.Identifier]; dup {
				s.loadErr = fmt.Errorf("advisory bundle %s: duplicate identifier %q", s.path, entry.Identifier)
				return
			}
			index[entry.Identifier] = bundleRecord{
				outputDigest: entry.OutputDigest,
				bytes:        []byte(entry.Bytes),
			}
		}

		// Drain any trailing bytes of the gzip member so the TeeReader hashes the WHOLE file — a
		// json.Decoder stops at the last decoded object and may leave the final newline / gzip
		// trailer unread, which would make fileDigest hash a prefix of the file. Reading to EOF also
		// surfaces a corrupt gzip trailer as a load error rather than a silently-truncated read.
		if _, err := io.Copy(io.Discard, gz); err != nil {
			s.loadErr = fmt.Errorf("read advisory bundle %s: %w", s.path, err)
			return
		}

		s.index = index
		s.fileDigest = "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	})
}

// Lookup resolves the pinned facts for vulnID through the bundle. It triggers the load, then fails
// open (zero, false) on: a load error (unusable bundle), an unknown id, a per-record digest mismatch,
// a record that will not decode, or any toFacts shape-validation failure. It NEVER returns a partial
// or laundered fact (inv.5). Verification is per-lookup and identical in discipline to
// artifactSource.Lookup: digest pin → json.Unmarshal → toFacts.
func (s *bundleSource) Lookup(vulnID string) (AdvisoryFacts, bool) {
	s.load()
	if s.loadErr != nil {
		return AdvisoryFacts{}, false
	}
	rec, ok := s.index[vulnID]
	if !ok {
		return AdvisoryFacts{}, false
	}
	// Digest pin: a record whose bytes do not match its inline output_digest cannot silently poison
	// S1. Mismatch → fail open, never pass the bytes through.
	if !digestMatches(rec.bytes, rec.outputDigest) {
		return AdvisoryFacts{}, false
	}
	var doc advisoryDoc
	if err := json.Unmarshal(rec.bytes, &doc); err != nil {
		return AdvisoryFacts{}, false
	}
	return doc.toFacts(vulnID)
}

// Validate is the STARTUP-ONLY bundle preflight (implements CorpusValidator). It triggers the load
// and returns the load error VERBATIM: a bundle that cannot be opened, decompressed, parsed as JSONL,
// or that carries a duplicate identifier is WHOLLY unusable, and an entrypoint hard-fails loudly on
// it before serving — never silently degrades to stale built-in intel.
//
// inv.5 SPLIT: Validate is SEPARATE from Lookup and never runs inside it. It gates the bundle
// CONTAINER (openable, decompressible, parseable, unique ids), NOT each document — a single
// digest-mismatched or malformed RECORD is a per-lookup fail-open concern (Lookup's job), not a
// corpus-unusable one, so it is not a Validate error.
func (s *bundleSource) Validate() error {
	s.load()
	return s.loadErr
}

// Describe reports the corpus identity for provenance recording ONLY (implements CorpusDescriber); it
// never participates in a Lookup and cannot change a verdict. The bundle carries no corpus_digest, so
// the sha256 of the raw .gz file bytes (computed during load) is the natural corpus identity handle.
// ok=false when the bundle cannot be loaded at all — the same fail-open shape as artifactSource.
func (s *bundleSource) Describe() (CorpusInfo, bool) {
	s.load()
	if s.loadErr != nil {
		return CorpusInfo{}, false
	}
	return CorpusInfo{Digest: s.fileDigest, Records: len(s.index)}, true
}

// KnownIDs returns the bundle's full identifier set, sorted ascending (implements
// AdvisoryEnumerator). It is the corpus-native work-set source (#301). An unusable bundle yields an
// empty slice, never an error — enumeration is metadata, never a Lookup path (inv.5).
func (s *bundleSource) KnownIDs() []string {
	s.load()
	if s.loadErr != nil {
		return nil
	}
	ids := make([]string, 0, len(s.index))
	for id := range s.index {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// interface assertions: bundleSource satisfies the core seam plus the three optional interfaces.
var (
	_ AdvisorySource     = (*bundleSource)(nil)
	_ CorpusValidator    = (*bundleSource)(nil)
	_ CorpusDescriber    = (*bundleSource)(nil)
	_ AdvisoryEnumerator = (*bundleSource)(nil)
)
