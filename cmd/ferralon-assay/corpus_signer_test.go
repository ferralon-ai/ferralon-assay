package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestIntelProvenance_CorpusSigner: the signer the Action's bundle route verified reaches the Report's
// intel disclosure as corpus_signer, and is ABSENT (no key at all, never an empty object) when the
// route verified nothing or no corpus was read. Half a signer is refused rather than recorded.
func TestIntelProvenance_CorpusSigner(t *testing.T) {
	const (
		id     = "publisher@acme.iam.example.com"
		issuer = "https://accounts.example.com"
	)
	cases := []struct {
		name     string
		corpus   bool // a bundle corpus is configured
		identity string
		issuer   string
		want     *report.CorpusSigner
		wantErr  string
	}{
		{name: "verified bundle", corpus: true, identity: id, issuer: issuer, want: &report.CorpusSigner{Identity: id, Issuer: issuer}},
		{name: "route verified nothing", corpus: true},
		{name: "no corpus read", identity: id, issuer: issuer},
		{name: "identity without issuer", corpus: true, identity: id, wantErr: "must be set together"},
		{name: "issuer without identity", corpus: true, issuer: issuer, wantErr: "must be set together"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var args []string
			if tc.corpus {
				bundle, _ := writeTestBundle(t, bundleOnlyID)
				args = []string{"-advisory-corpus", bundle}
			}
			f := runFlagsFor(t, args...)
			t.Setenv(envAdvisoryCorpusDir, "")
			t.Setenv(envAdvisoryCorpusRequired, "")
			t.Setenv(envAdvisoryCorpusPolicy, "")
			t.Setenv(envAdvisoryCorpusSignerIdentity, tc.identity)
			t.Setenv(envAdvisoryCorpusSignerIssuer, tc.issuer)

			_, err := f.advisoryCorpusOption()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("advisoryCorpusOption err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("advisoryCorpusOption err = %v", err)
			}

			got := f.intelProvenance(floorWorkSet(nil))
			switch {
			case tc.want == nil && got.CorpusSigner != nil:
				t.Errorf("CorpusSigner = %+v, want nil", *got.CorpusSigner)
			case tc.want != nil && (got.CorpusSigner == nil || *got.CorpusSigner != *tc.want):
				t.Errorf("CorpusSigner = %+v, want %+v", got.CorpusSigner, *tc.want)
			}

			blob, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if has := strings.Contains(string(blob), `"corpus_signer"`); has != (tc.want != nil) {
				t.Errorf("serialized intel %s: corpus_signer present = %v, want %v", blob, has, tc.want != nil)
			}
			if tc.want != nil && !strings.Contains(string(blob), `"corpus_signer":{"identity":"`+id+`","issuer":"`+issuer+`"}`) {
				t.Errorf("serialized intel %s lacks the signer's identity and issuer", blob)
			}
		})
	}
}
