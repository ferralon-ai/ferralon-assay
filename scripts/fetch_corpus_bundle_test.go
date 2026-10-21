// Hermetic self-test for fetch-corpus-bundle.sh, the Action's corpus-bundle fetch + pin. It builds a
// fake corpus release on the local filesystem — a git repository with a corpus-<12hex> tag, the
// release assets, and the raw policy manifest — points the script at it through file:// URLs, and
// checks that every link of the pin fails closed. No network.
package scripts

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/gittest"
)

const (
	fakeRepo   = "acme/corpus"
	fakeTag    = "corpus-0123456789ab"
	fakePolicy = "published-7d"

	fakeSignerID     = "publisher@acme.iam.example.com"
	fakeSignerIssuer = "https://accounts.example.com"
	fakeSigstore     = `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`

	fakeSignalsDigest = "sha256:5d1e000000000000000000000000000000000000000000000000000000000001"
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
	omitSigstore    bool // the release carries no bundles.json.sigstore.json
	bundleVersion   string
	omitSignals     bool // bundles.json carries no `signals` object
	omitSignalsGz   bool // the release carries no signals.json.gz
	signalsAsset    string
	// looseGit writes the bare repository's tag and commit as loose objects instead of running git,
	// which keeps a case that needs only `git ls-remote` fast.
	looseGit       bool
	gzDigest       func(real string) string
	manifestDigest func(real string) string
	signalsSHA     func(real string) string // bare hex, as bundles.json's signals object carries it
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
		bundleVersion:   "1.1.0",
		signalsAsset:    "signals.json.gz",
		signalsSHA:      func(real string) string { return real },
	}
}

// fakeSignalsGz is the release's signals.json.gz. The script pins its bytes and never decompresses
// it, so a small stand-in for the corpus's signals.json is enough.
func fakeSignalsGz(t *testing.T) []byte {
	t.Helper()
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write([]byte(`{"signals_version":"1.0.0","signals_digest":"` + fakeSignalsDigest + `","records":[]}`)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return gz.Bytes()
}

func run(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(gittest.Env(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
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

	gh := filepath.Join(root, "gh")
	var commit string
	if c.looseGit {
		commit = writeLooseBareRepo(t, filepath.Join(gh, "acme", "corpus.git"), fakeTag)
	} else {
		commit = c.writeGit(t, root, manifest)
	}

	// raw: the manifest at the commit.
	raw := filepath.Join(root, "raw")
	rdir := filepath.Join(raw, fakeRepo, commit, "policies", fakePolicy)
	if err := os.MkdirAll(rdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rdir, "manifest.json"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	c.writeAssets(t, gh, manifest)
	return "file://" + gh, "file://" + raw
}

// writeGit makes the bare repository with git itself: the tag the release is named by, pointing at a
// commit carrying the policy manifest. It returns the commit.
func (c fakeCorpus) writeGit(t *testing.T, root string, manifest []byte) string {
	t.Helper()
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
	run(t, src, "git", "commit", "-q", "-m", "corpus")
	run(t, src, "git", "tag", fakeTag)
	out, err := gittest.Command("-C", src, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	commit := strings.TrimSpace(string(out))
	gh := filepath.Join(root, "gh")
	if err := os.MkdirAll(filepath.Join(gh, "acme"), 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, root, "git", "clone", "-q", "--bare", src, filepath.Join(gh, "acme", "corpus.git"))
	return commit
}

// writeAssets lays out the release assets under the gh base.
func (c fakeCorpus) writeAssets(t *testing.T, gh string, manifest []byte) {
	t.Helper()
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
	signalsGz := fakeSignalsGz(t)
	index := map[string]any{"bundle_version": c.bundleVersion, "format": "jsonl+gzip", "bundles": bundles}
	if !c.omitSignals {
		index["signals"] = map[string]any{
			"asset":          c.signalsAsset,
			"sha256":         c.signalsSHA(strings.TrimPrefix(sha(signalsGz), "sha256:")),
			"signals_digest": fakeSignalsDigest,
		}
	}
	sidecar, err := json.Marshal(index)
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
	if !c.omitSigstore {
		if err := os.WriteFile(filepath.Join(rel, "bundles.json.sigstore.json"), []byte(fakeSigstore), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if !c.omitSignalsGz {
		if err := os.WriteFile(filepath.Join(rel, "signals.json.gz"), signalsGz, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// writeLooseBareRepo writes a bare repository holding one empty-tree commit and a lightweight tag on
// it, as loose objects, without running git. The script only asks it for the tag (`git ls-remote`);
// the manifest itself is served from the raw base. It returns the commit.
func writeLooseBareRepo(t *testing.T, dir, tag string) string {
	t.Helper()
	put := func(kind string, body []byte) string {
		obj := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(body))), body...)
		sum := sha1.Sum(obj)
		id := hex.EncodeToString(sum[:])
		var z bytes.Buffer
		zw := zlib.NewWriter(&z)
		if _, err := zw.Write(obj); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		odir := filepath.Join(dir, "objects", id[:2])
		if err := os.MkdirAll(odir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(odir, id[2:]), z.Bytes(), 0o444); err != nil {
			t.Fatal(err)
		}
		return id
	}
	tree := put("tree", nil)
	commit := put("commit", []byte("tree "+tree+"\nauthor a <a@example.com> 0 +0000\ncommitter a <a@example.com> 0 +0000\n\ncorpus\n"))
	for _, d := range []string{"refs/heads", "refs/tags"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"HEAD":             "ref: refs/heads/main\n",
		"config":           "[core]\n\trepositoryformatversion = 0\n\tbare = true\n",
		"refs/tags/" + tag: commit + "\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return commit
}

// stubCosign returns the directory holding testdata/cosign-stub/cosign, for the front of PATH. The
// stub records its arguments one per line in $COSIGN_STUB_LOG, then the files present beside its last
// argument (the blob) when it ran, and exits with $COSIGN_STUB_EXIT (default 0).
func stubCosign(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("testdata", "cosign-stub"))
	if err != nil {
		t.Fatal(err)
	}
	return dir
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
		noSignals bool // a successful run that read no release, so has no signals to hand over
	}{
		{name: "verified bundle", ref: fakeTag, wantRoute: "bundle", wantRef: fakeTag},
		{name: "manifest-only policy falls back to git at the tag", ref: fakeTag,
			mutate: func(c *fakeCorpus) { c.omitPolicy = true }, wantRoute: "git", wantRef: fakeTag},
		{name: "branch or SHA ref names no release", ref: "0123456789abcdef0123456789abcdef01234567",
			wantRoute: "git", wantRef: "0123456789abcdef0123456789abcdef01234567", noSignals: true},
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
				"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
				"CORPUS_SIGNER_IDENTITY="+fakeSignerID, "CORPUS_SIGNER_ISSUER="+fakeSignerIssuer,
				"PATH="+stubCosign(t)+string(os.PathListSeparator)+os.Getenv("PATH"),
				"COSIGN_STUB_LOG="+filepath.Join(root, "cosign.log"))
			out, err := cmd.CombinedOutput()
			bundle := filepath.Join(dest, fakePolicy+".jsonl.gz")
			_, statErr := os.Stat(bundle)
			signals := filepath.Join(dest, "signals.json.gz")
			_, sigErr := os.Stat(signals)
			got, _ := os.ReadFile(outFile)

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
				if strings.Contains(string(got), "signals-path=") {
					t.Fatalf("a failed pin emitted a signals path: %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("script failed: %v\n%s", err, out)
			}
			if !strings.Contains(string(got), "route="+tc.wantRoute+"\n") || !strings.Contains(string(got), "git-ref="+tc.wantRef+"\n") {
				t.Fatalf("GITHUB_OUTPUT = %q, want route=%s git-ref=%s", got, tc.wantRoute, tc.wantRef)
			}
			if (statErr == nil) != (tc.wantRoute == "bundle") {
				t.Fatalf("bundle present = %v, want %v (route=%s)", statErr == nil, tc.wantRoute == "bundle", tc.wantRoute)
			}
			hasPath := strings.Contains(string(got), "signals-path="+signals+"\n")
			if hasPath != !tc.noSignals || (sigErr == nil) != !tc.noSignals {
				t.Fatalf("signals-path emitted = %v, file present = %v, want both %v\nGITHUB_OUTPUT = %q",
					hasPath, sigErr == nil, !tc.noSignals, got)
			}
		})
	}
}

// signedRun is one fetch-corpus-bundle.sh run against a fake release for a corpus-<12hex> ref, with
// the signer inputs set and the stub cosign first on PATH; env entries override those defaults.
type signedRun struct {
	out     string // combined stdout + stderr
	err     error
	outputs string // what the script appended to $GITHUB_OUTPUT
	cosign  string // what the stub recorded; "" when it never ran
	bundle  bool   // a bundle was left where the scan step would pick it up
	signals string // the signals.json.gz left in DEST, "" when none was
	dest    string
}

func runSigned(t *testing.T, c *fakeCorpus, env ...string) signedRun {
	t.Helper()
	for _, tool := range []string{"bash", "curl", "git", "jq", "gzip"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH", tool)
		}
	}
	script, err := filepath.Abs("fetch-corpus-bundle.sh")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	gh, raw := "file://"+filepath.Join(root, "no-release"), "file://"+filepath.Join(root, "no-raw")
	if c != nil {
		c.looseGit = true
		gh, raw = c.write(t, root)
	}
	dest := filepath.Join(root, "dest")
	outFile := filepath.Join(root, "github_output")
	logFile := filepath.Join(root, "cosign.log")

	cmd := exec.Command("bash", script)
	cmd.Env = append(os.Environ(),
		"CORPUS_REPO="+fakeRepo, "CORPUS_REF="+fakeTag, "CORPUS_POLICY="+fakePolicy, "DEST="+dest,
		"CORPUS_GITHUB="+gh, "CORPUS_RAW="+raw, "GITHUB_OUTPUT="+outFile,
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"CORPUS_SIGNER_IDENTITY="+fakeSignerID, "CORPUS_SIGNER_ISSUER="+fakeSignerIssuer,
		"PATH="+stubCosign(t)+string(os.PathListSeparator)+os.Getenv("PATH"),
		"COSIGN_STUB_LOG="+logFile)
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	r := signedRun{out: string(out), err: err}
	got, _ := os.ReadFile(outFile)
	r.outputs = string(got)
	got, _ = os.ReadFile(logFile)
	r.cosign = string(got)
	_, statErr := os.Stat(filepath.Join(dest, fakePolicy+".jsonl.gz"))
	r.bundle = statErr == nil
	if _, err := os.Stat(filepath.Join(dest, "signals.json.gz")); err == nil {
		r.signals = filepath.Join(dest, "signals.json.gz")
	}
	r.dest = dest
	return r
}

// failedClosed asserts a run failed with wantErr in its output and accepted nothing: no bundle or
// signals on disk, and no bundle route, signer or signals path in the step outputs.
func (r signedRun) failedClosed(t *testing.T, wantErr string) {
	t.Helper()
	if r.err == nil {
		t.Fatalf("script succeeded, want failure containing %q\n%s", wantErr, r.out)
	}
	if !strings.Contains(r.out, wantErr) {
		t.Fatalf("output lacks %q:\n%s", wantErr, r.out)
	}
	if r.bundle {
		t.Fatal("a failed signature check left a bundle where the scan step would pick it up")
	}
	if r.signals != "" {
		t.Fatal("a failed run left signals.json.gz where the scan step would be handed it")
	}
	if strings.Contains(r.outputs, "route=bundle") || strings.Contains(r.outputs, "corpus-signer") || strings.Contains(r.outputs, "signals-path") {
		t.Fatalf("a failed run emitted %q", r.outputs)
	}
}

// pathWithout returns a PATH directory holding links to the tools the script needs before it looks
// for cosign, and no cosign: the runner's own PATH may carry one.
func pathWithout(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, tool := range []string{"bash", "curl", "git", "jq", "gzip", "mktemp", "rm", "mkdir", "awk", "head", "tr", "cut"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			continue
		}
		if err := os.Symlink(p, filepath.Join(dir, tool)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestFetchCorpusBundleSignature_Verified: on a release, cosign verifies bundles.json with exactly the
// caller's identity and issuer while bundles.json and its signature are the only release files on
// disk (no bundle or signals.json.gz downloaded, no digest compared yet), and only then is the bundle
// accepted and the verified signer emitted.
func TestFetchCorpusBundleSignature_Verified(t *testing.T) {
	c := defaultCorpus()
	r := runSigned(t, &c)
	if r.err != nil {
		t.Fatalf("script failed: %v\n%s", r.err, r.out)
	}
	// The stub's log: its eight arguments, a marker, then the files beside the blob.
	lines := strings.Split(strings.TrimSpace(r.cosign), "\n")
	if len(lines) < 9 {
		t.Fatalf("cosign stub log = %q, want its arguments and the work dir", r.cosign)
	}
	args := append([]string(nil), lines[:8]...)
	if filepath.Dir(args[2]) != filepath.Dir(args[7]) {
		t.Fatalf("signature %s and blob %s are not the downloaded pair", args[2], args[7])
	}
	args[2], args[7] = filepath.Base(args[2]), filepath.Base(args[7])
	want := []string{"verify-blob", "--bundle", "bundles.json.sigstore.json", "--certificate-identity", fakeSignerID,
		"--certificate-oidc-issuer", fakeSignerIssuer, "bundles.json"}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("cosign args = %q, want %q", args, want)
	}
	if beside := strings.Join(lines[9:], " "); lines[8] != "--- beside the blob:" || beside != "bundles.json bundles.json.sigstore.json" {
		t.Fatalf("when cosign ran the work dir held %q, want only bundles.json and its signature", lines[8:])
	}
	if !r.bundle {
		t.Fatal("verified run left no bundle")
	}
	for _, kv := range []string{"route=bundle", "corpus-signer-identity=" + fakeSignerID, "corpus-signer-issuer=" + fakeSignerIssuer} {
		if !strings.Contains(r.outputs, kv+"\n") {
			t.Errorf("GITHUB_OUTPUT = %q, want %s", r.outputs, kv)
		}
	}
}

// TestFetchCorpusBundleSignature_RequiresSignerAndCosign: a release is never read without a signer
// to verify it against and a cosign to verify with; each refusal comes before any download.
func TestFetchCorpusBundleSignature_RequiresSignerAndCosign(t *testing.T) {
	cases := []struct {
		name    string
		env     []string
		wantErr string
	}{
		{"identity unset", []string{"CORPUS_SIGNER_IDENTITY="}, "corpus-signer-identity is not set"},
		{"issuer unset", []string{"CORPUS_SIGNER_ISSUER="}, "corpus-signer-issuer is not set"},
		{"identity smuggles a second output line", []string{"CORPUS_SIGNER_IDENTITY=" + fakeSignerID + "\nroute=bundle"}, "must each be one line"},
		{"cosign missing", []string{"PATH=" + pathWithout(t)}, "cosign is required to verify the corpus release signature and was not found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := runSigned(t, nil, tc.env...)
			r.failedClosed(t, tc.wantErr)
			if r.cosign != "" {
				t.Fatalf("cosign ran: %q", r.cosign)
			}
		})
	}
}

// TestFetchCorpusBundleSignature_MissingSignature: a release without bundles.json.sigstore.json is
// refused as unsigned, before cosign or any digest.
func TestFetchCorpusBundleSignature_MissingSignature(t *testing.T) {
	c := defaultCorpus()
	c.omitSigstore = true
	r := runSigned(t, &c)
	r.failedClosed(t, "has no bundles.json.sigstore.json signature; refusing an unsigned corpus release")
	if r.cosign != "" {
		t.Fatalf("cosign ran without a signature: %q", r.cosign)
	}
}

// badDigestCorpus is a release whose bundle disagrees with its bundles.json digest, so the digest
// check fails whenever it is reached.
func badDigestCorpus() *fakeCorpus {
	c := defaultCorpus()
	c.gzDigest = func(string) string { return "sha256:" + strings.Repeat("a", 64) }
	return &c
}

const digestErr = "but bundles.json says"

// TestFetchCorpusBundleSignature_RejectedBeforeDigest: when cosign does not verify (a bad signature,
// the wrong identity or issuer, a tampered bundles.json all exit non-zero), the run fails closed on
// the signature. The release's bundle also fails its digest check (the control below shows it), and
// the signature error is the one reported, because the digest check never runs.
func TestFetchCorpusBundleSignature_RejectedBeforeDigest(t *testing.T) {
	r := runSigned(t, badDigestCorpus(), "COSIGN_STUB_EXIT=1")
	r.failedClosed(t, "bundles.json of "+fakeTag+" is not signed by '"+fakeSignerID+"' (issuer '"+fakeSignerIssuer+"')")
	if r.cosign == "" {
		t.Fatal("cosign never ran")
	}
	if strings.Contains(r.out, digestErr) {
		t.Fatalf("the digest check ran after the signature failed:\n%s", r.out)
	}
}

// TestFetchCorpusBundleSignature_DigestControl is the positive control for the test above: the same
// release with a signature that verifies fails on its digest.
func TestFetchCorpusBundleSignature_DigestControl(t *testing.T) {
	runSigned(t, badDigestCorpus()).failedClosed(t, digestErr)
}

// TestFetchCorpusBundleSignals_Verified: the release's signals.json.gz is downloaded after the
// signature check, matches the sha256 the signed bundles.json names, and its path is emitted for the
// scan step.
func TestFetchCorpusBundleSignals_Verified(t *testing.T) {
	c := defaultCorpus()
	r := runSigned(t, &c)
	if r.err != nil {
		t.Fatalf("script failed: %v\n%s", r.err, r.out)
	}
	if r.signals == "" {
		t.Fatalf("verified run left no signals.json.gz in DEST\n%s", r.out)
	}
	if !strings.Contains(r.outputs, "signals-path="+r.signals+"\n") || !filepath.IsAbs(r.signals) {
		t.Fatalf("GITHUB_OUTPUT = %q, want signals-path=%s", r.outputs, r.signals)
	}
	got, err := os.ReadFile(r.signals)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, fakeSignalsGz(t)) {
		t.Fatal("signals.json.gz in DEST is not the release's asset")
	}
	if r.cosign == "" || !strings.Contains(r.out, "signals_digest "+fakeSignalsDigest) {
		t.Fatalf("cosign ran = %v; output lacks the verified signals_digest:\n%s", r.cosign != "", r.out)
	}
}

// TestFetchCorpusBundleSignals_FailClosed: a release that cannot hand over verified signals fails
// the run, with no signals path emitted and nothing accepted.
func TestFetchCorpusBundleSignals_FailClosed(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*fakeCorpus)
		wantErr string
	}{
		{"no signals object at 1.1.0", func(c *fakeCorpus) { c.omitSignals = true },
			"(bundle_version 1.1.0) has no signals object"},
		{"signals asset missing from the release", func(c *fakeCorpus) { c.omitSignalsGz = true },
			"could not download signals.json.gz from release " + fakeTag},
		{"signals sha256 mismatch", func(c *fakeCorpus) { c.signalsSHA = func(string) string { return strings.Repeat("c", 64) } },
			"but bundles.json's signals object says " + strings.Repeat("c", 64)},
		{"pre-signals bundle_version 1.0.x", func(c *fakeCorpus) { c.bundleVersion, c.omitSignals = "1.0.3", true },
			"is bundle_version 1.0.3, which predates the signals asset (1.1.0)"},
		{"pre-signals release for a manifest-only policy", func(c *fakeCorpus) {
			c.omitPolicy, c.bundleVersion, c.omitSignals = true, "1.0.0", true
		}, "is bundle_version 1.0.0, which predates the signals asset (1.1.0)"},
		{"sidecar steers the signals download to another asset", func(c *fakeCorpus) { c.signalsAsset = "../evil.json.gz" },
			"names '../evil.json.gz' as the signals asset, want 'signals.json.gz'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := defaultCorpus()
			tc.mutate(&c)
			r := runSigned(t, &c)
			r.failedClosed(t, tc.wantErr)
			if r.cosign == "" {
				t.Fatal("the signals check ran without the signature check before it")
			}
		})
	}
}

// TestFetchCorpusBundleSignals_SignatureFirst: when the signature does not verify, the signals are
// never checked or trusted: a release whose signals.json.gz would fail its sha256 reports the
// signature error and no signals error.
func TestFetchCorpusBundleSignals_SignatureFirst(t *testing.T) {
	c := defaultCorpus()
	c.signalsSHA = func(string) string { return strings.Repeat("c", 64) }
	r := runSigned(t, &c, "COSIGN_STUB_EXIT=1")
	r.failedClosed(t, "bundles.json of "+fakeTag+" is not signed by")
	if strings.Contains(r.out, "signals") {
		t.Fatalf("the signals were looked at after the signature failed:\n%s", r.out)
	}
}

// TestInstallCosign_RefusesUnpinnedBytes: install-cosign.sh installs nothing unless the downloaded
// binary hashes to the pinned sha256, and nothing when there is no download; a cosign left in DEST
// by an earlier run is removed first, so a failed install never leaves one to run.
func TestInstallCosign_RefusesUnpinnedBytes(t *testing.T) {
	for _, tool := range []string{"bash", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH", tool)
		}
	}
	script, err := filepath.Abs("install-cosign.sh")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		serve   bool
		wantErr string
	}{
		{"binary does not match the pinned sha256", true, "not the pinned 4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71; refusing to run it"},
		{"release asset missing", false, "could not download cosign v3.1.3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.serve {
				rel := filepath.Join(root, "gh", "sigstore", "cosign", "releases", "download", "v3.1.3")
				if err := os.MkdirAll(rel, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(rel, "cosign-linux-amd64"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			dest := filepath.Join(root, "bin")
			if err := os.MkdirAll(dest, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dest, "cosign"), []byte("stale"), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", script)
			cmd.Env = append(os.Environ(), "DEST="+dest, "COSIGN_GITHUB=file://"+filepath.Join(root, "gh"))
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("install succeeded, want failure containing %q\n%s", tc.wantErr, out)
			}
			if !strings.Contains(string(out), tc.wantErr) {
				t.Fatalf("output lacks %q:\n%s", tc.wantErr, out)
			}
			if _, err := os.Stat(filepath.Join(dest, "cosign")); err == nil {
				t.Fatal("a failed install left a cosign in DEST")
			}
		})
	}
}
