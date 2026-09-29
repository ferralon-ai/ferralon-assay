// advisory_corpus_bundle_test.go
//
// -advisory-corpus accepts either shape of on-disk corpus: a directory tree (manifest.json +
// per-advisory JSON) or a compressed corpus bundle file (<policy>.jsonl.gz). These tests prove the
// bundle path reaches the SAME entrypoint contract the directory path already has: preflight
// hard-fail on a broken corpus, chain in front of the built-in table, provenance on the Report, and
// the work-set widener admitting against the real fact source.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// bundleOnlyID is carried by the test bundle and by nothing else: not the built-in table, not the
// fixture directory corpus. A hit on it proves the bundle is being consulted.
const bundleOnlyID = "TEGRON-TEST-BUNDLE-0001"

// writeTestBundle writes a one-gzip-stream JSONL corpus bundle in the producer's wire shape
// ({identifier, path, output_digest, bytes}) holding one valid record per id, each derived from the
// committed TEGRON-TEST-0001 fixture with its vuln_id rewritten. Returns the bundle path and the
// "sha256:<hex>" of the .gz bytes, which is what Describe reports as the corpus identity.
func writeTestBundle(t *testing.T, ids ...string) (string, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "pipeline", "testdata", "advisory_source", "TEGRON-TEST-0001.json"))
	if err != nil {
		t.Fatalf("read fixture record: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode fixture record: %v", err)
	}

	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetEscapeHTML(false)
	for _, id := range ids {
		doc["vuln_id"] = id
		rec, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("encode record: %v", err)
		}
		sum := sha256.Sum256(rec)
		if err := enc.Encode(map[string]string{
			"identifier":    id,
			"path":          "2099/01/" + id + ".json",
			"output_digest": "sha256:" + hex.EncodeToString(sum[:]),
			"bytes":         string(rec),
		}); err != nil {
			t.Fatalf("encode entry: %v", err)
		}
	}

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(body.Bytes()); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	path := filepath.Join(t.TempDir(), "published-7d.jsonl.gz")
	if err := os.WriteFile(path, gz.Bytes(), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	sum := sha256.Sum256(gz.Bytes())
	return path, "sha256:" + hex.EncodeToString(sum[:])
}

// TestAdvisoryCorpusOption_DirectoryOrBundle is the shape table: what -advisory-corpus resolves for
// a directory, a bundle, nothing, and each way a bundle can be broken.
func TestAdvisoryCorpusOption_DirectoryOrBundle(t *testing.T) {
	dirRoot := filepath.Join("..", "..", "pipeline", "testdata", "advisory_source")
	bundle, bundleDigest := writeTestBundle(t, bundleOnlyID, "TEGRON-TEST-BUNDLE-0002")

	notGzip := filepath.Join(t.TempDir(), "corpus.jsonl.gz")
	if err := os.WriteFile(notGzip, []byte("this is not a gzip stream\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	truncated := filepath.Join(t.TempDir(), "truncated.jsonl.gz")
	full, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(truncated, full[:len(full)/2], 0o644); err != nil {
		t.Fatal(err)
	}
	missingBundle := filepath.Join(t.TempDir(), "absent.jsonl.gz")

	cases := []struct {
		name        string
		path        string
		required    bool
		wantErr     string // substring; "" = no error
		wantOption  bool
		wantDigest  string // "" = don't check
		wantRecords int    // 0 = don't check
		hitID       string // an id that must resolve through the installed source
	}{
		{name: "directory → tree reader", path: dirRoot, wantOption: true, hitID: "TEGRON-TEST-0001"},
		{name: "bundle file → bundle reader", path: bundle, wantOption: true, wantDigest: bundleDigest, wantRecords: 2, hitID: bundleOnlyID},
		{name: "bundle file, required → bundle reader", path: bundle, required: true, wantOption: true, wantRecords: 2, hitID: bundleOnlyID},
		{name: "neither set → built-in table", path: ""},
		{name: "neither set, required → hard-fail", path: "", required: true, wantErr: "no corpus path resolved"},
		{name: "bundle not gzip → hard-fail", path: notGzip, wantErr: "is unusable"},
		{name: "bundle truncated → hard-fail", path: truncated, wantErr: "is unusable"},
		{name: "bundle missing → hard-fail through the bundle reader", path: missingBundle, wantErr: "open advisory bundle"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var args []string
			if tc.path != "" {
				args = append(args, "-advisory-corpus", tc.path)
			}
			if tc.required {
				args = append(args, "-require-advisory-corpus")
			}
			f := runFlagsFor(t, args...)
			t.Setenv(envAdvisoryCorpusDir, "")
			t.Setenv(envAdvisoryCorpusRequired, "")

			opt, err := f.advisoryCorpusOption()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				if opt != nil {
					t.Fatal("a failed preflight must install no source")
				}
				return
			}
			if err != nil {
				t.Fatalf("advisoryCorpusOption err = %v", err)
			}
			if (opt != nil) != tc.wantOption {
				t.Fatalf("option installed = %v, want %v", opt != nil, tc.wantOption)
			}
			if !tc.wantOption {
				if f.resolvedFacts != report.FactSourceBuiltinTable {
					t.Errorf("FactSource = %q, want %q", f.resolvedFacts, report.FactSourceBuiltinTable)
				}
				return
			}

			src := sourceFrom(t, opt)
			if _, ok := src.Lookup(tc.hitID); !ok {
				t.Errorf("%s did not resolve through the installed source", tc.hitID)
			}
			// Chain semantics are shape-independent: the table still answers behind the corpus.
			if _, ok := src.Lookup("GO-2021-0113"); !ok {
				t.Error("built-in table id lost its facts behind the corpus — it must supplement, not replace")
			}
			// The widener admits against f.resolvedSource; it must see the corpus the pass reads.
			if _, ok := f.resolvedSource.Lookup(tc.hitID); !ok {
				t.Errorf("resolvedSource cannot resolve %s; the work-set widener would admit against a different source than the pass reads", tc.hitID)
			}

			got := f.intelProvenance(floorWorkSet(nil))
			if got.FactSource != report.FactSourceCorpusThenBuiltinTable {
				t.Errorf("FactSource = %q, want %q", got.FactSource, report.FactSourceCorpusThenBuiltinTable)
			}
			if tc.wantDigest != "" && got.CorpusDigest != tc.wantDigest {
				t.Errorf("CorpusDigest = %q, want the .gz sha256 %q", got.CorpusDigest, tc.wantDigest)
			}
			if tc.wantRecords != 0 && got.CorpusRecords != tc.wantRecords {
				t.Errorf("CorpusRecords = %d, want %d", got.CorpusRecords, tc.wantRecords)
			}
		})
	}
}

// TestAdvisoryCorpusOption_BundleFromEnv proves the env channel carries a bundle path exactly as it
// carries a directory — the Action forwards the flag, but an orchestrator may set only the env.
func TestAdvisoryCorpusOption_BundleFromEnv(t *testing.T) {
	bundle, _ := writeTestBundle(t, bundleOnlyID)
	f := runFlagsFor(t)
	t.Setenv(envAdvisoryCorpusDir, bundle)
	t.Setenv(envAdvisoryCorpusRequired, "1")

	opt, err := f.advisoryCorpusOption()
	if err != nil {
		t.Fatalf("advisoryCorpusOption err = %v", err)
	}
	if _, ok := sourceFrom(t, opt).Lookup(bundleOnlyID); !ok {
		t.Error("env-supplied bundle is not being consulted")
	}
}

// TestAdvisoryCorpusOption_EmptyBundleUnderRequirement: a bundle that decodes to zero records is a
// fetch that "succeeded" and delivered nothing — the same failure as an absent corpus when the run
// declared it needs one.
func TestAdvisoryCorpusOption_EmptyBundleUnderRequirement(t *testing.T) {
	empty, _ := writeTestBundle(t)
	f := runFlagsFor(t, "-advisory-corpus", empty, "-require-advisory-corpus")
	t.Setenv(envAdvisoryCorpusDir, "")
	t.Setenv(envAdvisoryCorpusRequired, "")
	if _, err := f.advisoryCorpusOption(); err == nil || !strings.Contains(err.Error(), "zero records") {
		t.Fatalf("err = %v, want the zero-records requirement failure", err)
	}
}

// TestAdvisoryCorpus_WidenerAdmitsBundleOnlyIDs proves the work-set widener sees the bundle: an OSV
// id only the bundle carries is admitted through f.resolvedSource, and would be unresolvable against
// the table alone.
func TestAdvisoryCorpus_WidenerAdmitsBundleOnlyIDs(t *testing.T) {
	bundle, _ := writeTestBundle(t, bundleOnlyID)
	f := runFlagsFor(t, "-advisory-corpus", bundle)
	t.Setenv(envAdvisoryCorpusDir, "")
	t.Setenv(envAdvisoryCorpusRequired, "")
	if _, err := f.advisoryCorpusOption(); err != nil {
		t.Fatalf("advisoryCorpusOption err = %v", err)
	}

	added, unresolved := admitByFacts([]string{bundleOnlyID}, nil, f.resolvedSource)
	if len(added) != 1 || added[0].ID != bundleOnlyID || len(unresolved) != 0 {
		t.Fatalf("admitByFacts via resolvedSource = (%v, %v), want %s admitted", added, unresolved, bundleOnlyID)
	}
	if _, unresolved := admitByFacts([]string{bundleOnlyID}, nil, pipeline.NewTableSource()); len(unresolved) != 1 {
		t.Fatal("control: the table alone should not resolve the bundle-only id")
	}
}

// TestCorpusSourceFor pins the routing rule itself.
func TestCorpusSourceFor(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "corpus.bin") // any regular file is a bundle, whatever its name
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	bundleType := fmt.Sprintf("%T", pipeline.NewBundleSource(""))
	treeType := fmt.Sprintf("%T", pipeline.NewArtifactSource(""))

	cases := []struct {
		path string
		want string
	}{
		{dir, treeType},
		{file, bundleType},
		{filepath.Join(dir, "missing.jsonl.gz"), bundleType},
		{filepath.Join(dir, "missing-tree"), treeType},
	}
	for _, tc := range cases {
		if got := fmt.Sprintf("%T", corpusSourceFor(tc.path)); got != tc.want {
			t.Errorf("corpusSourceFor(%q) = %s, want %s", tc.path, got, tc.want)
		}
	}
}
