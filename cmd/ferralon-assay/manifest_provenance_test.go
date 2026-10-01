package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// writeDirCorpus writes a one-record corpus directory whose manifest carries provenance verbatim
// as its "provenance" member, or no member at all when provenance is empty.
func writeDirCorpus(t *testing.T, provenance string) string {
	t.Helper()
	root := t.TempDir()
	const id = "CVE-TEST-A"
	doc := []byte(`{"schema_version":"ferralon.normalized_advisory.v3","vuln_id":"CVE-TEST-A","version_scheme":"gomod"}`)
	if err := os.WriteFile(filepath.Join(root, id+".json"), doc, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(doc)
	man := `{"manifest_version":"1.1.0","schema_version":"ferralon.normalized_advisory.v3","record_count":1,` +
		`"records":[{"identifier":"` + id + `","path":"` + id + `.json","output_digest":"sha256:` + hex.EncodeToString(sum[:]) + `"}],` +
		`"corpus_digest":"sha256:` + strings.Repeat("0", 64) + `"`
	if provenance != "" {
		man += `,"provenance":` + provenance
	}
	man += `}`
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), []byte(man), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestIntelProvenance_CorpusManifest: the corpus manifest's provenance block reaches the Report's
// intel disclosure as written, and is left off entirely when the corpus carries none.
func TestIntelProvenance_CorpusManifest(t *testing.T) {
	cases := []struct {
		name       string
		provenance string
		want       *report.CorpusManifestProvenance
	}{
		{
			name: "present",
			provenance: `{"generated_at":"2026-10-01T17:16:23Z","generator":"ferralon-intel/enrichment","policy_id":"published-7d",` +
				`"policy_query":"published within 7d","source_corpus_digest":"sha256:aa","selection_index_digest":"sha256:bb"}`,
			want: &report.CorpusManifestProvenance{
				GeneratedAt:          "2026-10-01T17:16:23Z",
				Generator:            "ferralon-intel/enrichment",
				PolicyID:             "published-7d",
				PolicyQuery:          "published within 7d",
				SourceCorpusDigest:   "sha256:aa",
				SelectionIndexDigest: "sha256:bb",
			},
		},
		{
			name:       "partial",
			provenance: `{"policy_id":"kev"}`,
			want:       &report.CorpusManifestProvenance{PolicyID: "kev"},
		},
		{name: "absent"},
		{name: "empty object", provenance: `{}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := runFlagsFor(t, "-advisory-corpus", writeDirCorpus(t, tc.provenance))
			t.Setenv(envAdvisoryCorpusDir, "")
			t.Setenv(envAdvisoryCorpusRequired, "")
			t.Setenv(envAdvisoryCorpusPolicy, "")
			if _, err := f.advisoryCorpusOption(); err != nil {
				t.Fatalf("advisoryCorpusOption err = %v", err)
			}

			got := f.intelProvenance(floorWorkSet(nil))
			if got.CorpusDigest == "" {
				t.Fatal("CorpusDigest empty; the corpus did not resolve")
			}
			switch {
			case tc.want == nil && got.CorpusManifest != nil:
				t.Errorf("CorpusManifest = %+v, want nil", *got.CorpusManifest)
			case tc.want != nil && (got.CorpusManifest == nil || *got.CorpusManifest != *tc.want):
				t.Errorf("CorpusManifest = %+v, want %+v", got.CorpusManifest, *tc.want)
			}

			blob, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if has := strings.Contains(string(blob), `"corpus_manifest"`); has != (tc.want != nil) {
				t.Errorf("serialized intel %s: corpus_manifest present = %v, want %v", blob, has, tc.want != nil)
			}
		})
	}
}

// TestIntelProvenance_CorpusManifestNoCorpus: with no corpus there is no manifest to describe.
func TestIntelProvenance_CorpusManifestNoCorpus(t *testing.T) {
	f := runFlagsFor(t)
	t.Setenv(envAdvisoryCorpusDir, "")
	t.Setenv(envAdvisoryCorpusRequired, "")
	t.Setenv(envAdvisoryCorpusPolicy, "")
	if _, err := f.advisoryCorpusOption(); err != nil {
		t.Fatalf("advisoryCorpusOption err = %v", err)
	}
	if got := f.intelProvenance(floorWorkSet(nil)); got.CorpusManifest != nil {
		t.Errorf("CorpusManifest = %+v, want nil with no corpus", *got.CorpusManifest)
	}
}

// TestIntelProvenance_CorpusManifestBundle: a bundle file carries no manifest, so it reports none.
func TestIntelProvenance_CorpusManifestBundle(t *testing.T) {
	bundle, _ := writeTestBundle(t, bundleOnlyID)
	f := runFlagsFor(t, "-advisory-corpus", bundle)
	t.Setenv(envAdvisoryCorpusDir, "")
	t.Setenv(envAdvisoryCorpusRequired, "")
	t.Setenv(envAdvisoryCorpusPolicy, "")
	if _, err := f.advisoryCorpusOption(); err != nil {
		t.Fatalf("advisoryCorpusOption err = %v", err)
	}
	got := f.intelProvenance(floorWorkSet(nil))
	if got.CorpusDigest == "" {
		t.Fatal("CorpusDigest empty; the bundle did not resolve")
	}
	if got.CorpusManifest != nil {
		t.Errorf("CorpusManifest = %+v, want nil for a bundle", *got.CorpusManifest)
	}
}
