//go:build live

// This file is OPT-IN: it is excluded from the default `go test ./...` run by the
// `live` build tag. Run it with `go test -tags live ./internal/plugin/...`.
//
// Unlike the hermetic java_client_test.go (which re-execs the test binary with a
// canned helper), this test builds the REAL cmd/tegron-plugin-java binary to a
// temp dir, points a javaPlugin at it, and drives IndexSymbols end-to-end over
// exec + JSON/stdio against the offline javaanalysis/testdata/fixturejar source
// tree. It proves the full transport + subprocess dispatch + real Java parser
// path works together. It needs no JVM, no network, and no external tools — the
// indexer is a pure-Go source parser — but it does invoke `go build`, so it stays
// out of the default suite.

package plugin

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func buildJavaPluginBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "tegron-plugin-java")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/ferralon-ai/ferralon-assay/cmd/tegron-plugin-java")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build tegron-plugin-java: %v\n%s", err, out)
	}
	return bin
}

// javaFixtureDir resolves javaanalysis/testdata/fixturejar in the sibling
// javaanalysis package's testdata tree.
func javaFixtureDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	pkgDir := filepath.Dir(thisFile) // .../internal/plugin
	return filepath.Join(pkgDir, "javaanalysis", "testdata", "fixturejar")
}

func newLiveJavaPlugin(t *testing.T) *javaPlugin {
	t.Helper()
	p, err := NewJavaPlugin(WithJavaBinaryPath(buildJavaPluginBinary(t)))
	if err != nil {
		t.Fatalf("NewJavaPlugin: %v", err)
	}
	return p.(*javaPlugin)
}

func TestLiveJava_IndexSymbols(t *testing.T) {
	p := newLiveJavaPlugin(t)
	res, err := p.IndexSymbols(context.Background(), IndexSymbolsRequest{BuildDir: javaFixtureDir(t)})
	if err != nil {
		t.Fatalf("IndexSymbols: %v", err)
	}
	if len(res.Symbols) == 0 {
		t.Fatal("want some indexed symbols from the fixture, got none")
	}
	var sawForward, sawService bool
	for _, s := range res.Symbols {
		if s.SCIP == "" {
			t.Errorf("symbol with empty SCIP id: %+v", s)
		}
		if s.DisplayName == "Sink.forward(1)" {
			sawForward = true
		}
		if s.DisplayName == "Service" {
			sawService = true
		}
	}
	if !sawForward {
		t.Errorf("expected the fixture's Sink.forward(1) symbol over the wire; got %d symbols", len(res.Symbols))
	}
	if !sawService {
		t.Errorf("expected the fixture's Service type over the wire; got %d symbols", len(res.Symbols))
	}
}

// TestLiveJava_ResolveDependencyVersions proves the Java Increment-2 version op end-to-end over
// the real subprocess: the pure-Go pom resolver reads the patched repro's declared
// com.example.lib:widget version (1.4.0) across exec + JSON/stdio. No JVM, no network.
func TestLiveJava_ResolveDependencyVersions(t *testing.T) {
	p := newLiveJavaPlugin(t)
	_, thisFile, _, _ := runtime.Caller(0)
	repro := filepath.Join(filepath.Dir(thisFile), "..", "corpus", "testdata", "repros", "TEGRON-JAVA-DEP-0001-patched")
	res, err := p.ResolveDependencyVersions(context.Background(), ResolveVersionsRequest{
		BuildDir:   repro,
		Coordinate: "com.example.lib:widget",
	})
	if err != nil {
		t.Fatalf("ResolveDependencyVersions: %v", err)
	}
	if !res.Found || !res.Match.Resolved || res.Match.Version != "1.4.0" {
		t.Fatalf("want widget resolved 1.4.0 over the wire, got %+v", res.Match)
	}
}

// TestLiveJava_UnimplementedOpDeclaresUnsupported proves the honesty-guard seam: an
// op the Java plugin does NOT implement must declare itself partial with reason
// "unsupported_phase1" rather than returning Complete:true (a false "nothing found"
// would be a soundness hole, per inv.5). The subject has walked forward as ops land:
// call_graph (Increment 1) and reachability/compute_taint (M1 seams) are now live,
// so this test retargets to generate_harness — a genuine remaining stub, because
// Java's effect proof rides the repro-runtime sandbox, not a plugin-generated
// harness.
func TestLiveJava_UnimplementedOpDeclaresUnsupported(t *testing.T) {
	p := newLiveJavaPlugin(t)
	// call_graph is now implemented (Java Increment 1) — assert it returns Complete
	// so regressions in that direction are caught too.
	cgRes, err := p.CallGraph(context.Background(), CallGraphRequest{BuildDir: javaFixtureDir(t)})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if !cgRes.Partiality.Complete {
		t.Errorf("call_graph (Increment-1 live op) should return Complete, got %+v", cgRes.Partiality)
	}

	// reachability is now a live op (M1 first-party call-graph BFS). It must NO
	// LONGER declare unsupported_phase1: it returns a real (possibly Partial for
	// honesty) result over the wire.
	rRes, err := p.Reachability(context.Background(), ReachabilityRequest{
		BuildDir: javaFixtureDir(t),
		VulnID:   "CVE-0000-0000",
		Symbols:  []string{"java example/Sink#forward()."},
	})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	for _, r := range rRes.Partiality.Reasons {
		if r == PartialReasonUnsupported {
			t.Errorf("reachability is now a live op; it must not declare unsupported_phase1, got %v", rRes.Partiality.Reasons)
		}
	}

	// generate_harness remains a genuine stub. It must declare-partial with
	// unsupported_phase1, never return Complete:true.
	hRes, err := p.GenerateHarness(context.Background(), GenerateHarnessRequest{
		Sink: "java example/Sink#forward().",
		Kind: "unit",
	})
	if err != nil {
		t.Fatalf("GenerateHarness: %v", err)
	}
	if hRes.Partiality.Complete {
		t.Errorf("want declared-partial (Unsupported) for the unimplemented generate_harness op, got %+v", hRes.Partiality)
	}
	var sawUnsupported bool
	for _, r := range hRes.Partiality.Reasons {
		if r == PartialReasonUnsupported {
			sawUnsupported = true
		}
	}
	if !sawUnsupported {
		t.Errorf("expected the unsupported_phase1 reason code, got %v", hRes.Partiality.Reasons)
	}
}
