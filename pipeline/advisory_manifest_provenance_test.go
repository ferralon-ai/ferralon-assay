package pipeline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// withManifestProvenance rewrites root/manifest.json with raw spliced in as its "provenance" member.
// An empty raw leaves the manifest without the member.
func withManifestProvenance(t *testing.T, root, raw string) {
	t.Helper()
	path := filepath.Join(root, "manifest.json")
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var man map[string]json.RawMessage
	if err := json.Unmarshal(blob, &man); err != nil {
		t.Fatal(err)
	}
	if raw == "" {
		delete(man, "provenance")
	} else {
		man["provenance"] = json.RawMessage(raw)
	}
	out, err := json.Marshal(man)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestArtifactSource_ManifestProvenance: the manifest-level provenance block is decoded and carried
// through Describe as written, and an absent, partial, or malformed block never makes the corpus
// unusable or changes what a Lookup resolves.
func TestArtifactSource_ManifestProvenance(t *testing.T) {
	const doc = `{"schema_version":"ferralon.normalized_advisory.v3","vuln_id":"CVE-TEST-A","version_scheme":"gomod","provenance":{"source":"osv","trust_tier":"third_party"}}`
	cases := []struct {
		name string
		raw  string
		want ManifestProvenance
	}{
		{
			name: "present",
			raw: `{"generated_at":"2026-10-01T17:16:23Z","generator":"ferralon-intel/enrichment","policy_id":"published-24h",` +
				`"policy_query":"published within 24h","source_corpus_digest":"sha256:aa","selection_index_digest":"sha256:bb"}`,
			want: ManifestProvenance{
				GeneratedAt:          "2026-10-01T17:16:23Z",
				Generator:            "ferralon-intel/enrichment",
				PolicyID:             "published-24h",
				PolicyQuery:          "published within 24h",
				SourceCorpusDigest:   "sha256:aa",
				SelectionIndexDigest: "sha256:bb",
			},
		},
		{name: "absent", raw: ""},
		{name: "null", raw: `null`},
		{name: "empty object", raw: `{}`},
		{
			name: "partial",
			raw:  `{"policy_id":"kev","source_corpus_digest":"sha256:aa"}`,
			want: ManifestProvenance{PolicyID: "kev", SourceCorpusDigest: "sha256:aa"},
		},
		{
			name: "unknown members ignored",
			raw:  `{"policy_id":"full","future_field":{"x":1}}`,
			want: ManifestProvenance{PolicyID: "full"},
		},
		{
			name: "wrong-typed member stays zero, the rest decode",
			raw:  `{"policy_id":7,"generator":"ferralon-intel/enrichment"}`,
			want: ManifestProvenance{Generator: "ferralon-intel/enrichment"},
		},
		{name: "not an object", raw: `"standard-30d"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeCorpus(t, map[string]string{"CVE-TEST-A": doc})
			withManifestProvenance(t, root, tc.raw)
			src := NewArtifactSource(root)

			if err := src.(CorpusValidator).Validate(); err != nil {
				t.Fatalf("Validate = %v; the manifest provenance block must never make a corpus unusable", err)
			}
			info, ok := src.(CorpusDescriber).Describe()
			if !ok {
				t.Fatal("Describe ok=false on a valid corpus")
			}
			if info.Manifest != tc.want {
				t.Errorf("Describe().Manifest = %+v, want %+v", info.Manifest, tc.want)
			}
			if info.Records != 1 || info.Digest == "" {
				t.Errorf("Describe() = %+v; digest and record count must be unaffected", info)
			}
			facts, ok := src.Lookup("CVE-TEST-A")
			if !ok {
				t.Fatal("Lookup failed; the manifest provenance block must not affect resolution")
			}
			if facts.Provenance.TrustTier != TrustThirdParty {
				t.Errorf("document trust tier = %q, want third_party; the manifest block must not shadow the per-document one", facts.Provenance.TrustTier)
			}
		})
	}
}
