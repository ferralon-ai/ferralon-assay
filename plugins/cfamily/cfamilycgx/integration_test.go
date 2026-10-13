package cfamilycgx

import (
	"context"
	"io"
	"os"
	"reflect"
	"runtime/debug"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// The integration test runs the real cgx engine over testdata/c and testdata/cpp. It needs the
// wasm module built from the pinned cgx commit and its sha256:
//
//	ASSAY_CFAMILY_CGX_WASM=/abs/path/cgx.wasm ASSAY_CFAMILY_CGX_WASM_SHA256=<hex> go test ./cfamilycgx
//
// and skips when either is unset. A test binary records no dependency list in its build info,
// so the SDK-version half of the pin is checked against go.mod (TestPinnedSDKVersion_MatchesGoMod)
// and the build info is stood in for here; the module half is checked against the real file.
var (
	envIntegrationWasm   = brand.EnvPrefix + "_CFAMILY_CGX_WASM"
	envIntegrationSHA256 = brand.EnvPrefix + "_CFAMILY_CGX_WASM_SHA256"
)

func sdkLane(t *testing.T) *Lane {
	t.Helper()
	wasm, sum := os.Getenv(envIntegrationWasm), os.Getenv(envIntegrationSHA256)
	if wasm == "" || sum == "" {
		t.Skipf("%s and %s unset", envIntegrationWasm, envIntegrationSHA256)
	}
	if bi, ok := debug.ReadBuildInfo(); ok && len(bi.Deps) == 0 {
		withBuildInfo(t, &debug.BuildInfo{Deps: []*debug.Module{{Path: SDKModule, Version: PinnedSDKVersion}}}, true)
	}
	l := NewSDK(Config{Transport: TransportWasm, WasmModule: wasm, WasmModuleSHA256: sum, CacheDir: t.TempDir(), MinConfidence: DefaultMinConfidence})
	if l.unavailable != nil {
		t.Fatalf("engine unavailable: %v", l.unavailable)
	}
	l.stderr = io.Discard
	return l
}

func TestIntegration_C(t *testing.T) {
	l := sdkLane(t)
	ctx := context.Background()
	dir := copyFixture(t, "c")

	cg, err := l.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := edgesOf(cg), [][2]string{{"apply", "parse"}, {"main", "apply"}, {"parse", "scan"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("edges = %v, want %v", got, want)
	}
	for _, r := range []string{plugin.PartialReasonNoManifest, reasonFnPtr, reasonMacro, reasonLinkPrefix + "memcpy"} {
		if !hasReason(cg.Partiality, r) {
			t.Errorf("partiality %v lacks %s", cg.Partiality.Reasons, r)
		}
	}
	for _, r := range []string{reasonEmptyTU, reasonUnparsed} {
		if hasReason(cg.Partiality, r) {
			t.Errorf("partiality %v declares %s", cg.Partiality.Reasons, r)
		}
	}

	in, err := l.FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ingressesOf(in), map[string]string{"main": IngressMain, "apply": IngressExported, "parse": IngressExported, "unused_export": IngressExported}; !reflect.DeepEqual(got, want) {
		t.Errorf("ingresses = %v, want %v", got, want)
	}

	re, err := l.Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{"scan"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(re.Paths) != 1 {
		t.Errorf("reachability = %+v, want a path to scan", re.Paths)
	}
}

func TestIntegration_CXX(t *testing.T) {
	l := sdkLane(t)
	ctx := context.Background()
	dir := copyFixture(t, "cpp")

	cg, err := l.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range [][2]string{{"main", "codec::checksum"}, {"main", "run"}, {"codec::Inflate::decode", "codec::checksum"}} {
		found := false
		for _, g := range edgesOf(cg) {
			found = found || g == e
		}
		if !found {
			t.Errorf("edges %v lack %v", edgesOf(cg), e)
		}
	}
	if !hasReason(cg.Partiality, reasonVtable) || hasReason(cg.Partiality, reasonUnparsed) {
		t.Errorf("partiality %v: want %s and not %s", cg.Partiality.Reasons, reasonVtable, reasonUnparsed)
	}

	// codec::checksum has a header prototype; it resolves to one merged symbol and is reached.
	res, err := l.ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{BuildDir: dir, AdvisorySymbols: []string{"codec::checksum"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Resolved) != 1 || res.Resolved[0].SCIP != "codec::checksum" {
		t.Errorf("resolve = %+v", res)
	}
	ta, err := l.ComputeTaint(ctx, plugin.ComputeTaintRequest{BuildDir: dir, Sinks: []string{"codec::checksum"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ta.Paths) != 1 {
		t.Errorf("taint = %+v, want a path to codec::checksum", ta.Paths)
	}
}

// The real engine over the unresolved-symbol probes: the vulnerable function is never resolved,
// and its absence is declared cgx_sink_unresolved rather than read as safe.
func TestIntegration_UnresolvedProbes(t *testing.T) {
	l := sdkLane(t)
	ctx := context.Background()
	for _, p := range unresolvedProbes {
		t.Run(p.name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"main.c": p.src})
			res, err := l.ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{BuildDir: dir, AdvisorySymbols: p.advisory})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Resolved) != 0 || !hasReason(res.Partiality, reasonSinkUnresolved) || hasReason(res.Partiality, reasonUnparsed) {
				t.Errorf("resolve %v: %+v, want nothing resolved and %s", p.advisory, res, reasonSinkUnresolved)
			}
		})
	}
}
