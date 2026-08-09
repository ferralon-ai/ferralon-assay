package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fakeCgx writes a stub cgx binary (a POSIX shell script) that dispatches on its
// first argument and echoes canned JSON. It ignores the trailing --repo/--format
// flags the client appends, so tests exercise the real client + generators
// without the real cgx binary or an index.
func fakeCgx(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fake-cgx")
	script := `#!/bin/sh
case "$1" in
doctor)
  printf '%s' '{"node_count":10,"edge_count":20,"call_edge_count":18,"confidence":{"certain":1,"probable":2,"possible":15},"trust":"high","unresolved_rate":0.0}'
  ;;
symbols)
  printf '%s' '[{"file":"hostmatch/matcher.go","fqn":"hostmatch::New","kind":"function","line":84,"in_degree":3,"out_degree":1,"inbound":{"by_condition":{"always":3},"by_confidence":{"possible":3},"by_family":{"calls":3},"total":3},"outbound":{"by_condition":{},"by_confidence":{},"by_family":{},"total":0}},{"file":"vendor/x/impl.go","fqn":"impl::Pointer","kind":"type","line":1,"in_degree":99,"out_degree":0,"inbound":{"by_condition":{},"by_confidence":{"possible":99},"by_family":{"calls":99},"total":99},"outbound":{"by_condition":{},"by_confidence":{},"by_family":{},"total":0}}]'
  ;;
search)
  # search --all and search PAT both land here; return one first-party symbol.
  printf '%s' '[{"file":"hostmatch/matcher.go","fqn":"hostmatch::New","kind":"function","line":84},{"file":"hostmatch/matcher.go","fqn":"hostmatch::(*Matcher)::Allows","kind":"method","line":170},{"file":"hostmatch/matcher_test.go","fqn":"hostmatch::TestNew","kind":"function","line":9},{"file":"hostmatch/matcher.go","fqn":"hostmatch::New::x#0","kind":"variable","line":85}]'
  ;;
explain)
  printf '%s' '{"symbol":"hostmatch::New","file":"hostmatch/matcher.go","line":84,"kind":"function","callers_count":1,"callees_count":2,"edges":[{"condition":"always","confidence":"possible","direction":"incoming","peer":"caller::X","peer_file":"a.go","peer_line":1,"resolution_source":null,"rule":"name-fn","site":{"file":"a.go","line":1},"tier":"scope_graph"}]}'
  ;;
callers)
  printf '%s' '{"approximation":{"direction":"over_under","reasons":[{"code":"depth-limit","detail":"stopped at 3","direction":"under"}]},"count":2,"results":[{"condition":"always","confidence":"possible","depth":1,"file":"a.go","fqn":"caller::X","kind":"function","line":1},{"condition":"always","confidence":"possible","depth":2,"file":"a_test.go","fqn":"caller::TestX","kind":"function","line":2}]}'
  ;;
unused)
  printf '%s' '{"approximation":{"direction":"under","reasons":[{"code":"unresolved-external-calls","detail":"42 calls resolved to no in-repo target","direction":"under"}]},"count":3,"results":[{"file":"hostmatch/matcher.go","fqn":"hostmatch::ExportedDead","kind":"function","line":10},{"file":"hostmatch/matcher.go","fqn":"hostmatch::privateDead","kind":"function","line":20},{"file":"vendor/x/y.go","fqn":"x::Vendored","kind":"function","line":1}],"vacuous":false}'
  ;;
query)
  printf '%s' '{"approximation":{"direction":"exact","reasons":[]},"columns":["a.fqn","b.fqn"],"count":0,"rows":[],"vacuous":false}'
  ;;
diff)
  printf '%s' '{"added_edges":[],"removed_edges":[],"changed_edges":[],"added_nodes":[],"removed_nodes":[]}'
  ;;
*)
  echo "fake-cgx: unknown subcommand $1" >&2
  exit 2
  ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake cgx: %v", err)
	}
	return path
}

func TestResolveCgxBin(t *testing.T) {
	if got, err := resolveCgxBin("/explicit/cgx"); err != nil || got != "/explicit/cgx" {
		t.Fatalf("explicit flag: got %q err %v", got, err)
	}
	// Empty flag + empty PATH => LookPath fails => error names the fallback.
	t.Setenv("PATH", "")
	_, err := resolveCgxBin("")
	if err == nil {
		t.Fatal("expected error when cgx not on PATH")
	}
	if !strings.Contains(err.Error(), fallbackCgxPath) {
		t.Fatalf("error should name fallback path, got: %v", err)
	}
}

func TestCgxClientDecoders(t *testing.T) {
	c := &cgxClient{bin: fakeCgx(t), repo: "."}
	ctx := context.Background()

	rows, err := c.symbols(ctx, "inbound", 300)
	if err != nil || len(rows) != 2 {
		t.Fatalf("symbols: %v rows=%d", err, len(rows))
	}
	if rows[0].Inbound.ByConfidence["possible"] != 3 {
		t.Fatalf("symbols by_confidence not decoded: %+v", rows[0].Inbound)
	}

	ex, err := c.explain(ctx, "hostmatch::New")
	if err != nil || ex.Kind != "function" || len(ex.Edges) != 1 {
		t.Fatalf("explain: %v %+v", err, ex)
	}
	if ex.Edges[0].Confidence != "possible" {
		t.Fatalf("explain per-edge confidence missing: %+v", ex.Edges[0])
	}

	fr, err := c.callers(ctx, "hostmatch::New", 3)
	if err != nil || fr.Count != 2 {
		t.Fatalf("callers: %v count=%d", err, fr.Count)
	}
	if len(fr.Approximation) == 0 {
		t.Fatal("callers approximation not captured")
	}
}

func TestDiscoverPkgSymbolsFiltersNoise(t *testing.T) {
	c := &cgxClient{bin: fakeCgx(t), repo: "."}
	syms, err := discoverPkgSymbols(context.Background(), c, "hostmatch")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	// Keeps New + (*Matcher)::Allows; drops the _test.go symbol and the value node (#0).
	if len(syms) != 2 {
		t.Fatalf("want 2 symbols, got %d: %+v", len(syms), syms)
	}
	for _, s := range syms {
		if strings.Contains(s.Fqn, "#") || strings.HasSuffix(s.File, "_test.go") {
			t.Fatalf("noise leaked through: %s (%s)", s.Fqn, s.File)
		}
	}
}

// TestEnvelopePreservation asserts the approximation envelope reaches the written
// artifact byte-for-byte-equivalent (semantically identical) to what cgx emitted.
func TestEnvelopePreservation(t *testing.T) {
	dir := t.TempDir()
	c := &cgxClient{bin: fakeCgx(t), repo: "."}
	b := &bundle{dir: dir}

	if _, err := genDeadCode(context.Background(), c, b); err != nil {
		t.Fatalf("genDeadCode: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, fileDeadCode))
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	var art struct {
		Approximation  json.RawMessage `json:"approximation"`
		ExportedUnused []unusedRow     `json:"exported_but_unused"`
		Unexported     []unusedRow     `json:"unexported_no_ref"`
	}
	if err := json.Unmarshal(raw, &art); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}

	wantEnv := `{"direction":"under","reasons":[{"code":"unresolved-external-calls","detail":"42 calls resolved to no in-repo target","direction":"under"}]}`
	if !jsonEqual(t, art.Approximation, []byte(wantEnv)) {
		t.Fatalf("envelope not preserved verbatim:\n got %s\nwant %s", art.Approximation, wantEnv)
	}
	// First-party split: ExportedDead exported; privateDead not; vendored dropped.
	if len(art.ExportedUnused) != 1 || art.ExportedUnused[0].Fqn != "hostmatch::ExportedDead" {
		t.Fatalf("exported split wrong: %+v", art.ExportedUnused)
	}
	if len(art.Unexported) != 1 || art.Unexported[0].Fqn != "hostmatch::privateDead" {
		t.Fatalf("unexported split wrong: %+v", art.Unexported)
	}
}

// TestDataFlowEmptySemantics: an empty DATA_FLOW result must be marked "not proven
// absent", never silently dropped.
func TestDataFlowEmptySemantics(t *testing.T) {
	dir := t.TempDir()
	c := &cgxClient{bin: fakeCgx(t), repo: "."}
	b := &bundle{dir: dir}
	if _, err := genDataFlow(context.Background(), c, b, "hostmatch"); err != nil {
		t.Fatalf("genDataFlow: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, fileDataFlow))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(raw), "NOT proof") {
		t.Fatalf("empty-result honesty note missing:\n%s", raw)
	}
	if !strings.Contains(string(raw), "STRUCTURAL") {
		t.Fatalf("structural-not-taint label missing")
	}
}

func TestManifestShape(t *testing.T) {
	live := map[int]*genResult{
		1:  {files: []string{"atlas.json"}, itemCount: 5, bytes: 400},
		2:  {files: []string{"symbols/hostmatch/New.json"}, itemCount: 1, bytes: 200},
		3:  {files: []string{"blast-radius/hostmatch/New.json"}, itemCount: 1, bytes: 200},
		6:  {files: []string{"dead-code.json"}, itemCount: 2, bytes: 300},
		9:  {files: []string{"data-flow.json"}, itemCount: 0, bytes: 250},
		10: {files: []string{"pr-diff.json"}, itemCount: 0, bytes: 250},
	}
	man := buildManifest(options{repo: "."}, "/bin/cgx", json.RawMessage(`{"trust":"high"}`), live)
	if len(man.LeaveBehinds) != 10 {
		t.Fatalf("want 10 leave-behinds, got %d", len(man.LeaveBehinds))
	}
	if len(man.GraphHonesty) == 0 {
		t.Fatal("graph_honesty header missing")
	}
	var liveN, stubN int
	seen := map[int]bool{}
	for _, e := range man.LeaveBehinds {
		if seen[e.ID] {
			t.Fatalf("duplicate id %d", e.ID)
		}
		seen[e.ID] = true
		switch e.Status {
		case "live":
			liveN++
			if len(e.Files) == 0 || e.TokenCostEst == "" {
				t.Fatalf("live entry %d missing files/token-cost", e.ID)
			}
		case "stub":
			stubN++
			if len(e.Files) == 0 || e.CgxCommand == "" {
				t.Fatalf("stub entry %d missing intended files/command", e.ID)
			}
		default:
			t.Fatalf("entry %d has bad status %q", e.ID, e.Status)
		}
	}
	if liveN != 6 || stubN != 4 {
		t.Fatalf("want 6 live + 4 stub, got %d live %d stub", liveN, stubN)
	}
}

func TestCardName(t *testing.T) {
	cases := []struct{ fqn, want string }{
		{"hostmatch::New", "New.json"},
		{"hostmatch::(*Matcher)::Allows", "Matcher.Allows.json"},
		{"hostmatch::(*node)::match", "node.match.json"},
	}
	for _, tc := range cases {
		if got := cardName("hostmatch", tc.fqn); got != tc.want {
			t.Errorf("cardName(%q) = %q, want %q", tc.fqn, got, tc.want)
		}
	}
}

func TestClassifiers(t *testing.T) {
	if !isFirstParty("hostmatch/matcher.go") || isFirstParty("vendor/x/y.go") || isFirstParty("corpus/testdata/z.go") {
		t.Fatal("isFirstParty misclassified")
	}
	if !isExportedGo("hostmatch::Exported") || isExportedGo("hostmatch::private") {
		t.Fatal("isExportedGo misclassified")
	}
	if !isExportedGo("hostmatch::(*Matcher)::Allows") {
		t.Fatal("isExportedGo should see through receiver wrapper")
	}
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		t.Fatalf("unmarshal a: %v", err)
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		t.Fatalf("unmarshal b: %v", err)
	}
	return reflect.DeepEqual(av, bv)
}
