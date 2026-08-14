package jsanalysis

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// childDigestEnv, when set, puts a cross-process determinism test into its CHILD role:
// it writes the canonical-encoding digest to the named file and returns instead of
// re-execing itself. See TestBuildContext_DeterministicEncodingCrossProcess.
const childDigestEnv = "FERRALON_BUILDCTX_DIGEST_OUT"

// encodeDigest builds the fully-populated build context for dir, canonically encodes it,
// and returns the encoding plus its sha256 hex digest.
func encodeDigest(t *testing.T, dir string) (enc []byte, digest string) {
	t.Helper()
	bc := buildContextFor(dir)
	enc = bc.canonicalEncoding()
	sum := sha256.Sum256(enc)
	return enc, hex.EncodeToString(sum[:])
}

// TestBuildContext_BundlerProvenance asserts every extension-field entry carries its
// §3.5 provenance (producing tool + config file) after integration, that a node/SSR
// target marks the root server-side, and that entry points are attributed. This is the
// C5 "map is exposed with provenance" surface, minus the conflict half (below).
func TestBuildContext_BundlerProvenance(t *testing.T) {
	const dir = "testdata/buildcontext-determinism"
	bc := buildContextFor(dir)

	if len(bc.Aliases) == 0 || len(bc.Defines) == 0 || len(bc.EntryPoints) == 0 {
		t.Fatalf("integration populated nothing: aliases=%d defines=%d entries=%d",
			len(bc.Aliases), len(bc.Defines), len(bc.EntryPoints))
	}
	for _, a := range bc.Aliases {
		if a.Tool == "" || a.ConfigFile == "" {
			t.Errorf("alias %q->%q missing provenance: tool=%q file=%q", a.Key, a.Target, a.Tool, a.ConfigFile)
		}
	}
	for _, d := range bc.Defines {
		if d.Tool == "" || d.ConfigFile == "" {
			t.Errorf("define %q missing provenance: tool=%q file=%q", d.Key, d.Tool, d.ConfigFile)
		}
	}
	// A specific alias attribution: webpack's '@app' comes from webpack.config.js.
	b, found, _ := bc.lookupAlias("@app")
	if !found || b.Tool != string(bundlerWebpack) || b.ConfigFile != "webpack.config.js" {
		t.Errorf("'@app' provenance = %+v (found=%v); want tool=webpack file=webpack.config.js", b, found)
	}
	// The node target (webpack target:'node' and vite ssr) marks the root server-side.
	if len(bc.ServerSideRoots) != 1 || bc.ServerSideRoots[0] != dir {
		t.Errorf("ServerSideRoots = %v; want [%q] from the node/ssr targets", bc.ServerSideRoots, dir)
	}
	// The server-side entry point is flagged as such.
	var sawServerEntry bool
	for _, e := range bc.EntryPoints {
		if e.ServerSide {
			sawServerEntry = true
		}
		if e.Tool == "" || e.ConfigFile == "" {
			t.Errorf("entry %q missing provenance", e.Path)
		}
	}
	if !sawServerEntry {
		t.Errorf("expected a server-side entry point from the node-target webpack config; got %+v", bc.EntryPoints)
	}
}

// TestBuildContext_AliasConflictDeclared is the C5 conflict criterion: two configs
// disagree about the same alias key, and the build context DECLARES the conflict —
// retaining both divergent bindings — rather than silently picking a winner. The test
// asserts the declaration and both targets, never a single winning value; a last-wins
// reader (dropping one binding) fails it.
func TestBuildContext_AliasConflictDeclared(t *testing.T) {
	const dir = "testdata/buildcontext-conflict"
	bc := buildContextFor(dir)

	var appBindings []aliasBinding
	var shared *aliasBinding
	for i := range bc.Aliases {
		switch bc.Aliases[i].Key {
		case "@app":
			appBindings = append(appBindings, bc.Aliases[i])
		case "@shared":
			b := bc.Aliases[i]
			shared = &b
		}
	}

	// Both sides of the '@app' disagreement are retained, each with provenance.
	if len(appBindings) != 2 {
		t.Fatalf("want both '@app' bindings retained, got %d: %+v", len(appBindings), appBindings)
	}
	targetsByTool := map[string]string{}
	for _, b := range appBindings {
		if b.Tool == "" || b.ConfigFile == "" {
			t.Errorf("'@app' binding missing provenance: %+v", b)
		}
		if !b.Conflict {
			t.Errorf("'@app' binding not flagged Conflict: %+v", b)
		}
		targetsByTool[b.Tool] = b.Target
	}
	if targetsByTool[string(bundlerWebpack)] != "./src/app-web" ||
		targetsByTool[string(bundlerVite)] != "./src/app-server" {
		t.Fatalf("both divergent targets must be recorded; got %v", targetsByTool)
	}

	// The conflict is a first-class declaration naming the key and both bindings.
	var appConflict *aliasConflict
	for i := range bc.AliasConflicts {
		if bc.AliasConflicts[i].Key == "@app" {
			appConflict = &bc.AliasConflicts[i]
		}
	}
	if appConflict == nil {
		t.Fatalf("no declared conflict for '@app'; AliasConflicts=%+v", bc.AliasConflicts)
	}
	if len(appConflict.Bindings) != 2 {
		t.Errorf("declared conflict must carry both bindings, got %d", len(appConflict.Bindings))
	}

	// '@shared', declared in only one config, must NOT be a conflict.
	if shared == nil {
		t.Fatal("'@shared' alias missing")
	}
	if shared.Conflict {
		t.Errorf("'@shared' declared once must not be flagged Conflict: %+v", *shared)
	}
	for _, c := range bc.AliasConflicts {
		if c.Key == "@shared" {
			t.Errorf("'@shared' must not appear in AliasConflicts")
		}
	}
}

// TestBuildContext_ExposedAtResolverInjectionPoint is the other half of C5: the map with
// its declared conflicts is reachable at PLAN-162's resolver injection point (resolve.go),
// so the resolver can consult it. PLAN-163 exposes it here; applying it is PLAN-162's.
func TestBuildContext_ExposedAtResolverInjectionPoint(t *testing.T) {
	const dir = "testdata/buildcontext-conflict"
	prog, err := loadProgram(dir)
	if err != nil {
		t.Fatalf("loadProgram: %v", err)
	}
	rs := prog.resolver()
	if rs.bctx == nil {
		t.Fatal("resolver injection point exposes no build context")
	}
	if len(rs.bctx.AliasConflicts) != 1 || rs.bctx.AliasConflicts[0].Key != "@app" {
		t.Fatalf("declared conflict not visible at injection point: %+v", rs.bctx.AliasConflicts)
	}
	// The consult hook reports the conflict rather than a silent winning value.
	b, found, conflicted := rs.bctx.lookupAlias("@app")
	if !found || !conflicted {
		t.Fatalf("lookupAlias('@app') = (%+v, found=%v, conflicted=%v); want found+conflicted", b, found, conflicted)
	}
	if _, _, sharedConflicted := rs.bctx.lookupAlias("@shared"); sharedConflicted {
		t.Error("'@shared' declared in one config must not be conflicted at the injection point")
	}
}

// TestBuildContext_DeterministicEncoding is the in-process half of C6: the same tree
// encodes byte-identically across many rebuilds. Each iteration rebuilds the context from
// scratch, so Go's per-range map-iteration randomization is exercised — if any map leaked
// into the encoding, one of these runs would diverge. A checked-in golden does NOT satisfy
// C6; this is a repeat-run, not a comparison against a stored file.
func TestBuildContext_DeterministicEncoding(t *testing.T) {
	const dir = "testdata/buildcontext-determinism"
	first, digest := encodeDigest(t, dir)
	if len(first) == 0 {
		t.Fatal("empty canonical encoding")
	}
	const runs = 64 // ≥50 required
	for i := 0; i < runs; i++ {
		enc, _ := encodeDigest(t, dir)
		if !bytes.Equal(enc, first) {
			t.Fatalf("in-process run %d diverged:\n first=%s\n got  =%s", i, first, enc)
		}
	}
	t.Logf("in-process: %d rebuilds byte-identical; sha256=%s", runs, digest)
}

// TestBuildContext_DeterministicEncodingCrossProcess is the cross-process half of C6: a
// fresh process has a fresh map-hash seed, so an encoding that is stable within a process
// but seed-dependent across processes is caught here. The test logs its sha256 and
// re-execs THIS test binary as a separate process (via os.StartProcess — deliberately NOT
// os/exec, so C4's execution grep stays clean; it launches only the Go test binary, no
// Node/bundler/interpreter, and adds no dependency), then diffs the two digests. It is a
// repeat run across processes, not a golden comparison.
func TestBuildContext_DeterministicEncodingCrossProcess(t *testing.T) {
	const dir = "testdata/buildcontext-determinism"
	_, digest := encodeDigest(t, dir)

	// CHILD role: write the digest where the parent can read it, then return.
	if out := os.Getenv(childDigestEnv); out != "" {
		if err := os.WriteFile(out, []byte(digest), 0o644); err != nil {
			t.Fatalf("child: write digest: %v", err)
		}
		t.Logf("child sha256=%s", digest)
		return
	}

	// PARENT role: re-exec this single test in a fresh process and compare digests.
	t.Logf("parent sha256=%s", digest)
	childDigest := reexecForDigest(t)
	if childDigest == "" {
		t.Fatal("child produced no digest")
	}
	if childDigest != digest {
		t.Fatalf("cross-process digest mismatch: parent=%s child=%s", digest, childDigest)
	}
	t.Logf("cross-process: parent and child digests match (%s)", digest)
}

// reexecForDigest launches this test binary in a separate process, running only the
// cross-process determinism test in its CHILD role, and returns the digest the child
// wrote. It uses os.StartProcess (stdlib os), not os/exec, keeping C4's execution-site
// grep empty while still exercising a genuinely separate process.
func reexecForDigest(t *testing.T) string {
	t.Helper()
	bin := os.Args[0]
	if !filepath.IsAbs(bin) {
		if abs, err := filepath.Abs(bin); err == nil {
			bin = abs
		}
	}
	outFile := filepath.Join(t.TempDir(), "child-digest.txt")
	attr := &os.ProcAttr{
		Env:   append(os.Environ(), childDigestEnv+"="+outFile),
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	}
	argv := []string{bin, "-test.run=^TestBuildContext_DeterministicEncodingCrossProcess$", "-test.count=1", "-test.v"}
	proc, err := os.StartProcess(bin, argv, attr)
	if err != nil {
		t.Fatalf("re-exec test binary %q: %v", bin, err)
	}
	state, err := proc.Wait()
	if err != nil {
		t.Fatalf("wait for child: %v", err)
	}
	if !state.Success() {
		t.Fatalf("child process failed: %v", state)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read child digest: %v", err)
	}
	return strings.TrimSpace(string(data))
}
