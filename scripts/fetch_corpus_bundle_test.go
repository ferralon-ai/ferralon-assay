// Hermetic self-test for fetch-corpus-bundle.sh, the Action's corpus-bundle fetch + pin. It builds a
// fake corpus release on the local filesystem — a git repository with a corpus-<12hex> tag, the
// release assets, and the raw policy manifest — points the script at it through file:// URLs, and
// checks that every link of the pin fails closed. No network.
package scripts

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	fakeRepo   = "acme/corpus"
	fakeTag    = "corpus-0123456789ab"
	fakePolicy = "published-7d"
)

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

type fakeRecord struct{ id, body string }

// fakeCorpus is one release's worth of inputs; each test case mutates a copy before it is written.
type fakeCorpus struct {
	manifestRecords []fakeRecord // what the policy manifest in git pins
	bundleRecords   []fakeRecord // what the .jsonl.gz carries
	corpusDigest    string
	policyID        string
	assetName       string
	omitPolicy      bool // bundles.json lists no bundle for the policy (manifest-only)
	gzDigest        func(real string) string
	manifestDigest  func(real string) string
}

func defaultCorpus() fakeCorpus {
	recs := []fakeRecord{
		{"CVE-2099-0001", "{\n  \"vuln_id\": \"CVE-2099-0001\"\n}\n"},
		{"CVE-2099-0002", "{\n  \"vuln_id\": \"CVE-2099-0002\"\n}\n"},
	}
	return fakeCorpus{
		manifestRecords: recs,
		bundleRecords:   recs,
		corpusDigest:    "sha256:" + strings.TrimPrefix(fakeTag, "corpus-") + strings.Repeat("f", 52),
		policyID:        fakePolicy,
		assetName:       fakePolicy + ".jsonl.gz",
		gzDigest:        func(real string) string { return real },
		manifestDigest:  func(real string) string { return real },
	}
}

func run(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

// write lays the fake release out under root and returns the CORPUS_GITHUB and CORPUS_RAW bases.
func (c fakeCorpus) write(t *testing.T, root string) (ghBase, rawBase string) {
	t.Helper()

	type entry struct {
		Identifier   string `json:"identifier"`
		Path         string `json:"path"`
		OutputDigest string `json:"output_digest"`
	}
	var mrecs []entry
	for _, r := range c.manifestRecords {
		mrecs = append(mrecs, entry{r.id, "2099/01/" + r.id + ".json", sha([]byte(r.body))})
	}
	manifest, err := json.MarshalIndent(map[string]any{
		"manifest_version": "1.1.0",
		"schema_version":   "ferralon.normalized_advisory.v3",
		"record_count":     len(mrecs),
		"records":          mrecs,
		"corpus_digest":    c.corpusDigest,
		"provenance":       map[string]any{"policy_id": c.policyID},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	// git: the tag the release is named by, pointing at a commit carrying the policy manifest.
	src := filepath.Join(root, "src")
	mdir := filepath.Join(src, "policies", fakePolicy)
	if err := os.MkdirAll(mdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mdir, "manifest.json"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, src, "git", "init", "-q")
	run(t, src, "git", "add", ".")
	run(t, src, "git", "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "corpus")
	run(t, src, "git", "tag", fakeTag)
	out, err := exec.Command("git", "-C", src, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	commit := strings.TrimSpace(string(out))
	gh := filepath.Join(root, "gh")
	if err := os.MkdirAll(filepath.Join(gh, "acme"), 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, root, "git", "clone", "-q", "--bare", src, filepath.Join(gh, "acme", "corpus.git"))

	// raw: the manifest at the commit.
	raw := filepath.Join(root, "raw")
	rdir := filepath.Join(raw, fakeRepo, commit, "policies", fakePolicy)
	if err := os.MkdirAll(rdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rdir, "manifest.json"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}

	// release assets.
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetEscapeHTML(false)
	for _, r := range c.bundleRecords {
		if err := enc.Encode(map[string]string{
			"identifier": r.id, "path": "2099/01/" + r.id + ".json", "output_digest": sha([]byte(r.body)), "bytes": r.body,
		}); err != nil {
			t.Fatal(err)
		}
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	bundles := []map[string]any{{
		"policy_id":       "full",
		"path":            "full.jsonl.gz",
		"members":         0,
		"digest":          "sha256:" + strings.Repeat("0", 64),
		"manifest_digest": "sha256:" + strings.Repeat("0", 64),
	}}
	if !c.omitPolicy {
		bundles = append(bundles, map[string]any{
			"policy_id":       fakePolicy,
			"path":            c.assetName,
			"members":         len(c.bundleRecords),
			"digest":          c.gzDigest(sha(gz.Bytes())),
			"manifest_digest": c.manifestDigest(sha(manifest)),
		})
	}
	sidecar, err := json.Marshal(map[string]any{"bundle_version": "1.0.0", "format": "jsonl+gzip", "bundles": bundles})
	if err != nil {
		t.Fatal(err)
	}
	rel := filepath.Join(gh, fakeRepo, "releases", "download", fakeTag)
	if err := os.MkdirAll(rel, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rel, "bundles.json"), sidecar, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rel, c.assetName), gz.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return "file://" + gh, "file://" + raw
}

func TestFetchCorpusBundle(t *testing.T) {
	for _, tool := range []string{"bash", "curl", "git", "jq", "gzip"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH", tool)
		}
	}
	script, err := filepath.Abs("fetch-corpus-bundle.sh")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		ref       string
		policy    string
		mutate    func(*fakeCorpus)
		wantRoute string // "" = the script must fail
		wantRef   string
		wantErr   string
	}{
		{name: "verified bundle", ref: fakeTag, wantRoute: "bundle", wantRef: fakeTag},
		{name: "manifest-only policy falls back to git at the tag", ref: fakeTag,
			mutate: func(c *fakeCorpus) { c.omitPolicy = true }, wantRoute: "git", wantRef: fakeTag},
		{name: "branch or SHA ref names no release", ref: "0123456789abcdef0123456789abcdef01234567",
			wantRoute: "git", wantRef: "0123456789abcdef0123456789abcdef01234567"},
		{name: "gz does not match its bundles.json digest", ref: fakeTag,
			mutate:  func(c *fakeCorpus) { c.gzDigest = func(string) string { return "sha256:" + strings.Repeat("a", 64) } },
			wantErr: "but bundles.json says"},
		{name: "manifest in git does not match manifest_digest", ref: fakeTag,
			mutate: func(c *fakeCorpus) {
				c.manifestDigest = func(string) string { return "sha256:" + strings.Repeat("b", 64) }
			},
			wantErr: "manifest.json at"},
		{name: "consistent sidecar + bundle whose members differ from the git manifest", ref: fakeTag,
			mutate: func(c *fakeCorpus) {
				c.bundleRecords = []fakeRecord{c.manifestRecords[0], {"CVE-2099-0002", "{\"vuln_id\":\"CVE-2099-0002\",\"tampered\":true}"}}
			},
			wantErr: "does not carry exactly the members"},
		{name: "bundle drops a manifest member", ref: fakeTag,
			mutate:  func(c *fakeCorpus) { c.bundleRecords = c.manifestRecords[:1] },
			wantErr: "does not carry exactly the members"},
		{name: "manifest belongs to another corpus", ref: fakeTag,
			mutate:  func(c *fakeCorpus) { c.corpusDigest = "sha256:" + strings.Repeat("9", 64) },
			wantErr: "does not belong to"},
		{name: "manifest names another policy", ref: fakeTag,
			mutate:  func(c *fakeCorpus) { c.policyID = "published-30d" },
			wantErr: "does not belong to"},
		{name: "sidecar steers the download to another asset", ref: fakeTag,
			mutate:  func(c *fakeCorpus) { c.assetName = "../evil.jsonl.gz" },
			wantErr: "want 'published-7d.jsonl.gz'"},
		{name: "release tag absent from git", ref: "corpus-ffffffffffff", wantErr: "has no git tag"},
		{name: "policy id that is not a policy id", ref: fakeTag, policy: "../x", wantErr: "is not a policy id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := defaultCorpus()
			if tc.mutate != nil {
				tc.mutate(&c)
			}
			root := t.TempDir()
			gh, raw := c.write(t, root)
			policy := tc.policy
			if policy == "" {
				policy = fakePolicy
			}
			dest := filepath.Join(root, "dest")
			outFile := filepath.Join(root, "github_output")

			cmd := exec.Command("bash", script)
			cmd.Env = append(os.Environ(),
				"CORPUS_REPO="+fakeRepo, "CORPUS_REF="+tc.ref, "CORPUS_POLICY="+policy, "DEST="+dest,
				"CORPUS_GITHUB="+gh, "CORPUS_RAW="+raw, "GITHUB_OUTPUT="+outFile,
				"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
			out, err := cmd.CombinedOutput()
			bundle := filepath.Join(dest, fakePolicy+".jsonl.gz")
			_, statErr := os.Stat(bundle)

			if tc.wantRoute == "" {
				if err == nil {
					t.Fatalf("script succeeded, want failure containing %q\n%s", tc.wantErr, out)
				}
				if !strings.Contains(string(out), tc.wantErr) {
					t.Fatalf("output lacks %q:\n%s", tc.wantErr, out)
				}
				if statErr == nil {
					t.Fatal("a failed pin left a bundle where the scan step would pick it up")
				}
				return
			}
			if err != nil {
				t.Fatalf("script failed: %v\n%s", err, out)
			}
			got, _ := os.ReadFile(outFile)
			if !strings.Contains(string(got), "route="+tc.wantRoute+"\n") || !strings.Contains(string(got), "git-ref="+tc.wantRef+"\n") {
				t.Fatalf("GITHUB_OUTPUT = %q, want route=%s git-ref=%s", got, tc.wantRoute, tc.wantRef)
			}
			if (statErr == nil) != (tc.wantRoute == "bundle") {
				t.Fatalf("bundle present = %v, want %v (route=%s)", statErr == nil, tc.wantRoute == "bundle", tc.wantRoute)
			}
		})
	}
}
