//go:build live

// This file is OPT-IN: it is excluded from the default `go test ./...` run by the `live`
// build tag. Run it with `go test -tags live ./internal/plugin/...`.
//
// Unlike the hermetic client_test.go (which re-execs the test binary with a canned
// helper), this test builds the REAL cmd/tegron-plugin-go binary to a temp dir, points a
// goPlugin at it, and drives IndexSymbols + CallGraph end-to-end over exec + JSON/stdio
// against the offline, stdlib-only testdata/fixturemod fixture. It proves the full
// transport + subprocess dispatch + real go/packages + x/tools analysis path works
// together. It needs no network (the fixture is stdlib-only) but does invoke `go build`
// and the heavy analysis, so it stays out of the default suite.

package plugin

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildPluginBinary compiles cmd/tegron-plugin-go into a temp dir and returns its path.
func buildPluginBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "tegron-plugin-go")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/ferralon-ai/ferralon-assay/cmd/tegron-plugin-go")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build tegron-plugin-go: %v\n%s", err, out)
	}
	return bin
}

// fixtureDir resolves the absolute path to goanalysis/testdata/fixturemod, which lives in
// the sibling goanalysis package's testdata tree.
func fixtureDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	pkgDir := filepath.Dir(thisFile) // .../internal/plugin
	return filepath.Join(pkgDir, "goanalysis", "testdata", "fixturemod")
}

func newLivePlugin(t *testing.T) *goPlugin {
	t.Helper()
	p, err := NewGoPlugin(WithBinaryPath(buildPluginBinary(t)))
	if err != nil {
		t.Fatalf("NewGoPlugin: %v", err)
	}
	return p.(*goPlugin)
}

func TestLive_IndexSymbols(t *testing.T) {
	p := newLivePlugin(t)
	res, err := p.IndexSymbols(context.Background(), IndexSymbolsRequest{BuildDir: fixtureDir(t)})
	if err != nil {
		t.Fatalf("IndexSymbols: %v", err)
	}
	if len(res.Symbols) == 0 {
		t.Fatal("want some indexed symbols from the fixture module, got none")
	}
	var sawHandle bool
	for _, s := range res.Symbols {
		if strings.Contains(s.DisplayName, "Handle") {
			sawHandle = true
		}
		if s.SCIP == "" {
			t.Errorf("symbol with empty SCIP id: %+v", s)
		}
	}
	if !sawHandle {
		t.Errorf("expected the fixture's Handle symbol in the index; got %d symbols", len(res.Symbols))
	}
}

func TestLive_CallGraph(t *testing.T) {
	p := newLivePlugin(t)
	res, err := p.CallGraph(context.Background(), CallGraphRequest{BuildDir: fixtureDir(t)})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if res.Algorithm != "vta" {
		t.Errorf("default algorithm should be vta, got %q", res.Algorithm)
	}
	var sawChain bool
	for _, e := range res.Edges {
		if strings.Contains(e.Caller, "Handle") && strings.Contains(e.Callee, "Sink") {
			sawChain = true
		}
	}
	if !sawChain {
		t.Errorf("expected edge (*Service).Handle -> util.Sink over the wire; got %d edges", len(res.Edges))
	}
	if len(res.Roots) == 0 {
		t.Error("expected at least one root (main) over the wire")
	}
}
