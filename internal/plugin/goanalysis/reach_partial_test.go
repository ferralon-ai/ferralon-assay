package goanalysis

import (
	"context"
	"encoding/json"
	"errors"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestGovulncheckOrPartial pins when a govulncheck failure is answered by a partial run: only a
// settled failure on a run the caller lets settle, computed once per tree and environment in a scan,
// and never again once it could not be made. Anything else returns the failure as it was.
func TestGovulncheckOrPartial(t *testing.T) {
	const buildDir = "/src"
	env := []string{"GOWORK=off"}
	cause := errors.New("loading packages: olm/olm.h file not found")
	partialStream := []byte(`{"config":{}}` + "\n")
	record, err := partialRunRecord(buildDir,
		[]packages.Error{{Pos: "/mod/c/c.go:3:8", Msg: "could not import C"}},
		func() ([]listedPackage, error) {
			return []listedPackage{
				{ImportPath: "example.com/m/a", Imports: []string{"example.com/c"}},
				{ImportPath: "example.com/m/b"},
				{ImportPath: "example.com/c", Dir: "/mod/c", DepOnly: true},
			}, nil
		},
		func([]string) ([]byte, error) { return partialStream, nil })
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name         string
		cacheDir     bool
		settle       bool
		outcome      string // "stream", "settled", "unsettled"
		partialFails bool
		wantStreams  int
		wantPartials int
		wantPartial  bool
	}{
		{name: "settled failure answered by one partial run", cacheDir: true, settle: true, outcome: "settled", wantStreams: 1, wantPartials: 1, wantPartial: true},
		{name: "transient failure is re-run by every call and never gets a partial run", cacheDir: true, settle: true, outcome: "unsettled", wantStreams: 3},
		{name: "retryable run is re-run by every call and never gets a partial run", cacheDir: true, settle: false, outcome: "settled", wantStreams: 3},
		{name: "partial run that cannot be made is not retried", cacheDir: true, settle: true, outcome: "settled", partialFails: true, wantStreams: 1, wantPartials: 1},
		{name: "no cache dir", cacheDir: false, settle: true, outcome: "settled", wantStreams: 3, wantPartials: 3, wantPartial: true},
		{name: "a stream needs no partial run", cacheDir: true, settle: true, outcome: "stream", wantStreams: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := ""
			if tt.cacheDir {
				dir = t.TempDir()
			}
			ctx := WithRunCacheDir(context.Background(), dir)
			streams, partials := 0, 0
			stream := func() ([]byte, error) {
				streams++
				if tt.outcome == "stream" {
					return []byte(`{"config":{"full":true}}` + "\n"), nil
				}
				return nil, &govulncheckError{buildDir: buildDir, cause: cause, settled: tt.outcome == "settled"}
			}
			partial := func(failure error) ([]byte, error) {
				partials++
				var failed *govulncheckError
				if !errors.As(failure, &failed) || !failed.settled {
					t.Errorf("partial run made from %v, want the settled failure", failure)
				}
				if tt.partialFails {
					return nil, errors.New("every root imports the package")
				}
				return record, nil
			}
			for i := range 3 {
				out, run, err := govulncheckOrPartial(ctx, buildDir, env, tt.settle, stream, partial)
				switch {
				case tt.outcome == "stream":
					if err != nil || run != nil {
						t.Fatalf("call %d: run %v, err %v; want the full stream", i, run, err)
					}
				case tt.wantPartial:
					if err != nil || run == nil || string(out) != string(partialStream) {
						t.Fatalf("call %d: out %q, run %v, err %v; want the partial run", i, out, run, err)
					}
					if !slices.Equal(run.Excluded, []string{"example.com/m/a"}) || !slices.Equal(run.Unloadable, []string{"example.com/c"}) {
						t.Errorf("call %d: run excludes %v for %v", i, run.Excluded, run.Unloadable)
					}
				default:
					var failed *govulncheckError
					if !errors.As(err, &failed) || run != nil || out != nil {
						t.Fatalf("call %d: out %q, run %v, err %v; want the govulncheck failure", i, out, run, err)
					}
					if tt.partialFails && !strings.Contains(err.Error(), "every root imports the package") {
						t.Errorf("call %d: %v does not say why no partial run was made", i, err)
					}
				}
			}
			if streams != tt.wantStreams || partials != tt.wantPartials {
				t.Errorf("govulncheck ran %d times and the partial run %d, want %d and %d", streams, partials, tt.wantStreams, tt.wantPartials)
			}
		})
	}
}

// TestPartialRunRecord pins how the partial run is bounded: P is the packages the load errors name,
// the run covers every root of ./... whose imports never reach P, and it is not made when an error
// names no listed package or no root is left.
func TestPartialRunRecord(t *testing.T) {
	graph := []listedPackage{
		{ImportPath: "example.com/m/cmd/a", Imports: []string{"example.com/m/lib"}},
		{ImportPath: "example.com/m/cmd/b", Imports: []string{"fmt", "C"}},
		{ImportPath: "example.com/m/lib", Imports: []string{"example.com/dep/olm"}},
		{ImportPath: "example.com/dep/olm", Dir: "/mod/dep/olm", DepOnly: true, Imports: []string{"C", "fmt"}, Module: &listedModule{Path: "example.com/dep"}},
		{ImportPath: "example.com/dep/other", Dir: "/mod/dep/other", DepOnly: true},
		{ImportPath: "fmt", Dir: "/goroot/src/fmt", DepOnly: true},
	}
	withModules := slices.Clone(graph)
	for i := range withModules {
		switch {
		case strings.HasPrefix(withModules[i].ImportPath, "example.com/m/"):
			withModules[i].Module = &listedModule{Path: "example.com/m", Main: true}
		case withModules[i].Module == nil && !strings.Contains(withModules[i].ImportPath, "."):
			withModules[i].Standard = true
		}
	}
	cgoListError := packages.Error{Kind: packages.ListError, Msg: "# example.com/dep/olm\n/mod/dep/olm/e.go:4:11: fatal error: 'olm/olm.h' file not found"}
	typeError := packages.Error{Kind: packages.TypeError, Pos: "/mod/dep/olm/a.go:5:8", Msg: "could not import C (no metadata for C)"}
	cases := []struct {
		name         string
		perrs        []packages.Error
		graph        []listedPackage
		wantErr      bool
		wantRun      []string
		wantExcluded []string
		wantP        []string
		wantModules  map[string]string
		wantHeld     []heldModule
	}{
		{name: "an error named by position", perrs: []packages.Error{typeError}, graph: graph,
			wantRun: []string{"example.com/m/cmd/b"}, wantExcluded: []string{"example.com/m/cmd/a", "example.com/m/lib"}, wantP: []string{"example.com/dep/olm"},
			wantModules: map[string]string{"example.com/dep/olm": "pkg:golang/example.com/dep"}},
		{name: "H recorded", perrs: []packages.Error{typeError}, graph: withModules,
			wantRun: []string{"example.com/m/cmd/b"}, wantExcluded: []string{"example.com/m/cmd/a", "example.com/m/lib"}, wantP: []string{"example.com/dep/olm"},
			wantHeld: []heldModule{{}, {Path: "example.com/dep"}, {Path: "example.com/m", Main: true}}},
		{name: "an error named by the go command's heading", perrs: []packages.Error{cgoListError}, graph: graph,
			wantRun: []string{"example.com/m/cmd/b"}, wantExcluded: []string{"example.com/m/cmd/a", "example.com/m/lib"}, wantP: []string{"example.com/dep/olm"}},
		{name: "both errors of a failed cgo package", perrs: []packages.Error{cgoListError, typeError}, graph: graph,
			wantRun: []string{"example.com/m/cmd/b"}, wantExcluded: []string{"example.com/m/cmd/a", "example.com/m/lib"}, wantP: []string{"example.com/dep/olm"}},
		{name: "a root that fails itself", perrs: []packages.Error{{Pos: "/src/cmd/b/b.go:1:1", Msg: "x"}},
			graph:   append(slices.Clone(graph[:1]), listedPackage{ImportPath: "example.com/m/cmd/b", Dir: "/src/cmd/b", Module: &listedModule{Path: "example.com/m", Main: true}}, graph[2], graph[3], graph[5]),
			wantRun: []string{"example.com/m/cmd/a", "example.com/m/lib"}, wantExcluded: []string{"example.com/m/cmd/b"}, wantP: []string{"example.com/m/cmd/b"},
			wantModules: map[string]string{"example.com/m/cmd/b": ""}},
		{name: "a position relative to the build", perrs: []packages.Error{{Pos: "cmd/b/b.go:1:1", Msg: "x"}},
			graph:   append(slices.Clone(graph[:1]), listedPackage{ImportPath: "example.com/m/cmd/b", Dir: "/src/cmd/b"}, graph[2], graph[3], graph[5]),
			wantRun: []string{"example.com/m/cmd/a", "example.com/m/lib"}, wantExcluded: []string{"example.com/m/cmd/b"}, wantP: []string{"example.com/m/cmd/b"}},
		{name: "a kept root that is a wildcard pattern", perrs: []packages.Error{typeError},
			graph: append(slices.Clone(graph), listedPackage{ImportPath: "example.com/m/a...b"}), wantErr: true},
		{name: "a kept root that is a flag", perrs: []packages.Error{typeError},
			graph: append(slices.Clone(graph), listedPackage{ImportPath: "-json"}), wantErr: true},
		{name: "every root reaches P", perrs: []packages.Error{typeError}, graph: []listedPackage{graph[0], graph[2], graph[3]}, wantErr: true},
		{name: "an error at a position no listed package holds", perrs: []packages.Error{typeError, {Pos: "/elsewhere/x.go:1:1", Msg: "x"}}, graph: graph, wantErr: true},
		{name: "an error with no position and no heading", perrs: []packages.Error{{Msg: "something failed"}}, graph: graph, wantErr: true},
		{name: "a heading naming an unlisted package", perrs: []packages.Error{{Msg: "# example.com/nowhere\nfailed"}}, graph: graph, wantErr: true},
		{name: "a replayed failure carries no package errors", perrs: nil, graph: graph, wantErr: true},
		{name: "a heading under a position that does not parse", perrs: []packages.Error{{Pos: "garbled", Msg: cgoListError.Msg}}, graph: graph, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ran []string
			b, err := partialRunRecord("/src", tc.perrs, func() ([]listedPackage, error) { return tc.graph, nil }, func(patterns []string) ([]byte, error) {
				ran = patterns
				return []byte("{}\n"), nil
			})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("made a partial run over %v", ran)
				}
				if ran != nil {
					t.Errorf("govulncheck ran over %v for a partial run that cannot be made", ran)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			run := decodePartialRun(b)
			if run == nil {
				t.Fatalf("record %s does not decode", b)
			}
			if !slices.Equal(ran, tc.wantRun) || !slices.Equal(run.Excluded, tc.wantExcluded) || !slices.Equal(run.Unloadable, tc.wantP) {
				t.Errorf("ran over %v excluding %v for P %v; want %v excluding %v for %v", ran, run.Excluded, run.Unloadable, tc.wantRun, tc.wantExcluded, tc.wantP)
			}
			if tc.wantModules != nil && !maps.Equal(run.Modules, tc.wantModules) {
				t.Errorf("modules %v, want %v", run.Modules, tc.wantModules)
			}
			if tc.wantHeld != nil && !slices.Equal(run.Held, tc.wantHeld) {
				t.Errorf("held %+v, want %+v", run.Held, tc.wantHeld)
			}
		})
	}
}

// TestWithholdForPartialRun pins the result a partial run supports: a symbol finding stands; a
// refutation and silence about the advisory stand only when H is known and no module they name has
// a package in it, and are otherwise withheld as tool_failure; every result names what the run left
// out, bounded to H's modules when H is known. A run over the whole build is left as it was.
func TestWithholdForPartialRun(t *testing.T) {
	run := &partialRun{Unloadable: []string{"example.com/dep/olm"}, Modules: map[string]string{"example.com/dep/olm": "pkg:golang/example.com/dep"}, Excluded: []string{"example.com/m/cmd/a"}}
	held := *run
	held.Held = []heldModule{{}, {Path: "example.com/dep"}, {Path: "example.com/m", Main: true}}
	noStdlib := held
	noStdlib.Held = []heldModule{{Path: "example.com/dep"}, {Path: "example.com/m", Main: true}}
	replaced := *run
	replaced.Held = heldModules([]listedPackage{
		{ImportPath: "example.com/m/cmd/a", Imports: []string{"example.com/dep/olm", "example.com/orig/x"}, Module: &listedModule{Path: "example.com/m", Main: true}},
		{ImportPath: "example.com/dep/olm", DepOnly: true, Module: &listedModule{Path: "example.com/dep"}},
		{ImportPath: "example.com/orig/x", DepOnly: true, Module: &listedModule{Path: "example.com/orig", Replace: &struct{ Path, Version, Dir string }{Path: "example.com/fork", Version: "v1.0.0"}}},
	}, run.Excluded)
	if len(replaced.Held) == 0 {
		t.Fatal("no H for the replaced fixture")
	}
	forkFinding := []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/fork", Version: "v1.0.0", Package: "example.com/orig/x"}}}}
	outsideFinding := []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/out", Version: "v1.0.0", Package: "example.com/out/x"}}}}
	cgoLimit := plugin.ScopedReason{Reason: plugin.PartialReasonCgo, Package: "pkg:golang/example.com/other", Path: "example.com/other"}
	moduleFinding := []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/dep", Version: "v1.0.0", Package: "example.com/dep/x"}}}}
	symbolFinding := []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{
		{Module: "example.com/dep", Version: "v1.0.0", Package: "example.com/dep/x", Function: "Bad"},
		{Module: "example.com/m", Package: "example.com/m/cmd/b", Function: "main"},
	}}}
	cases := []struct {
		name          string
		findings      []vulnFinding
		partial       *partialRun
		wantRefuted   bool
		wantPaths     bool
		wantReason    string
		wantNoReason  string
		wantDisclosed bool
		wantBounded   bool
		cgScoped      []plugin.ScopedReason
		admitted      string
		imports       map[string][]string
		wholeModule   map[string]bool
		osvAbsent     bool
	}{
		{name: "refutation withheld", findings: moduleFinding, partial: run, wantReason: plugin.PartialReasonToolFailure, wantDisclosed: true},
		{name: "silence is a tool failure", partial: run, wantReason: plugin.PartialReasonToolFailure, wantNoReason: plugin.PartialReasonAdvisoryUnknownToAnalyzer, wantDisclosed: true, cgScoped: []plugin.ScopedReason{cgoLimit}},
		{name: "symbol finding stands", findings: symbolFinding, partial: run, wantPaths: true, wantNoReason: plugin.PartialReasonToolFailure, wantDisclosed: true},
		{name: "full run: refutation stands", findings: moduleFinding, wantRefuted: true, wantNoReason: plugin.PartialReasonToolFailure},
		{name: "full run: silence stays unknown to the analyzer", wantReason: plugin.PartialReasonAdvisoryUnknownToAnalyzer, wantNoReason: plugin.PartialReasonToolFailure},
		{name: "H unknown: silence about a module outside the build withheld", partial: run, admitted: "pkg:golang/example.com/out@v1.0.0",
			wantReason: plugin.PartialReasonToolFailure, wantNoReason: plugin.PartialReasonAdvisoryUnknownToAnalyzer, wantDisclosed: true},
		{name: "H unknown: refutation of a module outside the build withheld", findings: outsideFinding, partial: run, admitted: "pkg:golang/example.com/out@v1.0.0",
			wantReason: plugin.PartialReasonToolFailure, wantDisclosed: true},
		{name: "silence about a module outside H stands", partial: &held, admitted: "pkg:golang/example.com/out@v1.0.0",
			wantReason: plugin.PartialReasonAdvisoryUnknownToAnalyzer, wantNoReason: plugin.PartialReasonToolFailure, wantDisclosed: true, wantBounded: true},
		{name: "refutation of a module outside H stands", findings: outsideFinding, partial: &held, admitted: "pkg:golang/example.com/out@v1.0.0",
			wantRefuted: true, wantNoReason: plugin.PartialReasonToolFailure, wantDisclosed: true, wantBounded: true},
		{name: "silence about a module with a package in H withheld", partial: &held, admitted: "pkg:golang/example.com/dep@v1.0.0",
			wantReason: plugin.PartialReasonToolFailure, wantNoReason: plugin.PartialReasonAdvisoryUnknownToAnalyzer, wantDisclosed: true, wantBounded: true},
		{name: "silence about a module nested under one in H withheld", partial: &held, admitted: "pkg:golang/example.com/dep/sub@v1.0.0",
			wantReason: plugin.PartialReasonToolFailure, wantDisclosed: true, wantBounded: true},
		{name: "silence about a module holding one in H withheld", partial: &held, admitted: "pkg:golang/EXAMPLE.com@v1.0.0",
			wantReason: plugin.PartialReasonToolFailure, wantDisclosed: true, wantBounded: true},
		{name: "silence about the module under analysis withheld", partial: &held, admitted: "pkg:golang/example.com/m@v0.0.0",
			wantReason: plugin.PartialReasonToolFailure, wantDisclosed: true, wantBounded: true},
		{name: "refutation of a module in H for an admitted module outside it withheld", findings: moduleFinding, partial: &held, admitted: "pkg:golang/example.com/out@v1.0.0",
			wantReason: plugin.PartialReasonToolFailure, wantDisclosed: true, wantBounded: true},
		{name: "silence about an advisory that also names a module in H withheld", partial: &held, admitted: "pkg:golang/example.com/out@v1.0.0",
			imports: map[string][]string{"example.com/dep": {"example.com/dep/x"}}, wantReason: plugin.PartialReasonToolFailure, wantDisclosed: true, wantBounded: true},
		{name: "stdlib silence withheld with the standard library in H", partial: &held, admitted: "pkg:golang/stdlib@go1.25.0",
			wantReason: plugin.PartialReasonToolFailure, wantDisclosed: true, wantBounded: true},
		{name: "toolchain silence withheld with the standard library in H", partial: &held, admitted: "pkg:golang/toolchain@go1.25.0",
			wantReason: plugin.PartialReasonToolFailure, wantDisclosed: true, wantBounded: true},
		{name: "stdlib silence stands with no standard library package in H", partial: &noStdlib, admitted: "pkg:golang/stdlib@go1.25.0",
			wantNoReason: plugin.PartialReasonToolFailure, wantDisclosed: true, wantBounded: true},
		{name: "no admitted package withheld", partial: &held,
			wantReason: plugin.PartialReasonToolFailure, wantDisclosed: true, wantBounded: true},
		{name: "a non-Go admitted package withheld", partial: &held, admitted: "pkg:npm/example@1.0.0",
			wantReason: plugin.PartialReasonToolFailure, wantDisclosed: true, wantBounded: true},
		{name: "silence about an advisory that names a whole module in H withheld", partial: &held, admitted: "pkg:golang/example.com/out@v1.0.0",
			wholeModule: map[string]bool{"example.com/dep": true}, wantReason: plugin.PartialReasonToolFailure, wantDisclosed: true, wantBounded: true},
		{name: "silence about an advisory absent from the stream withheld", partial: &held, admitted: "pkg:golang/example.com/out@v1.0.0", osvAbsent: true,
			wantReason: plugin.PartialReasonToolFailure, wantNoReason: plugin.PartialReasonAdvisoryUnknownToAnalyzer, wantDisclosed: true, wantBounded: true},
		{name: "refutation of a module outside H for an advisory absent from the stream withheld", findings: outsideFinding, partial: &held, admitted: "pkg:golang/example.com/out@v1.0.0", osvAbsent: true,
			wantReason: plugin.PartialReasonToolFailure, wantDisclosed: true, wantBounded: true},
		{name: "silence about a replaced module used only from H withheld", partial: &replaced, admitted: "pkg:golang/example.com/fork@v1.0.0",
			wantReason: plugin.PartialReasonToolFailure, wantDisclosed: true, wantBounded: true},
		{name: "refutation of a replaced module used only from H withheld", findings: forkFinding, partial: &replaced, admitted: "pkg:golang/example.com/fork@v1.0.0",
			wantReason: plugin.PartialReasonToolFailure, wantDisclosed: true, wantBounded: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scanned := vulnScan{findings: tc.findings, partial: tc.partial, admitted: tc.admitted, imports: tc.imports, wholeModule: tc.wholeModule, osvListed: !tc.osvAbsent}
			cg := plugin.CallGraphResult{Partiality: plugin.Complete()}
			if tc.cgScoped != nil {
				cg.Partiality = plugin.Partial()
				cg.Partiality.Scoped = tc.cgScoped
			}
			res := withholdForPartialRun(evidenceResult(tc.findings, cg, nil), scanned)
			for _, want := range tc.cgScoped {
				if !slices.ContainsFunc(res.Partiality.Scoped, func(s plugin.ScopedReason) bool {
					return s.Reason == want.Reason && s.Package == want.Package && s.Path == want.Path
				}) {
					t.Errorf("scoped %+v lost %+v", res.Partiality.Scoped, want)
				}
			}
			if (res.Refutation != nil) != tc.wantRefuted {
				t.Errorf("refutation %+v, want refuted=%v", res.Refutation, tc.wantRefuted)
			}
			if (len(res.Paths) > 0) != tc.wantPaths {
				t.Errorf("paths %v, want some=%v", res.Paths, tc.wantPaths)
			}
			if tc.wantReason != "" && !slices.Contains(res.Partiality.Reasons, tc.wantReason) {
				t.Errorf("reasons %v, want %s", res.Partiality.Reasons, tc.wantReason)
			}
			if tc.wantNoReason != "" && slices.Contains(res.Partiality.Reasons, tc.wantNoReason) {
				t.Errorf("reasons %v, want no %s", res.Partiality.Reasons, tc.wantNoReason)
			}
			disclosed := slices.ContainsFunc(res.Partiality.Scoped, func(s plugin.ScopedReason) bool {
				return s.Reason == plugin.PartialReasonToolFailure && (len(s.Targets) > 0) == tc.wantBounded && s.Package == "pkg:golang/example.com/dep" &&
					strings.Contains(s.Path, "example.com/dep/olm") && strings.Contains(s.Path, "example.com/m/cmd/a")
			})
			if disclosed != tc.wantDisclosed {
				t.Errorf("scoped %+v, want the excluded roots disclosed=%v", res.Partiality.Scoped, tc.wantDisclosed)
			}
			if tc.partial != nil && res.Partiality.Complete {
				t.Error("a partial run's result is complete")
			}
		})
	}
}

// TestHeldModules pins H's modules: the modules of every package the excluded roots reach through
// their imports, the standard library as "", and no answer when an import is not listed or a
// package is in neither a module nor the standard library.
func TestHeldModules(t *testing.T) {
	main := &listedModule{Path: "example.com/m", Main: true}
	graph := []listedPackage{
		{ImportPath: "example.com/m/cmd/a", Imports: []string{"example.com/dep/olm"}, Module: main},
		{ImportPath: "example.com/m/cmd/b", Imports: []string{"example.com/other"}, Module: main},
		{ImportPath: "example.com/dep/olm", DepOnly: true, Imports: []string{"C", "fmt"}, Module: &listedModule{Path: "example.com/dep"}},
		{ImportPath: "example.com/other", DepOnly: true, Module: &listedModule{Path: "example.com/other"}},
		{ImportPath: "fmt", DepOnly: true, Standard: true},
	}
	cases := []struct {
		name     string
		graph    []listedPackage
		excluded []string
		want     []heldModule
	}{
		{name: "closure of the excluded roots", graph: graph, excluded: []string{"example.com/m/cmd/a"},
			want: []heldModule{{}, {Path: "example.com/dep"}, {Path: "example.com/m", Main: true}}},
		{name: "an import the graph does not list", graph: append(slices.Clone(graph[1:]), listedPackage{ImportPath: "example.com/m/cmd/a", Imports: []string{"example.com/gone"}, Module: main}),
			excluded: []string{"example.com/m/cmd/a"}},
		{name: "a package in no module and not standard", graph: append(slices.Clone(graph[:4]), listedPackage{ImportPath: "fmt", DepOnly: true}),
			excluded: []string{"example.com/m/cmd/a"}},
		{name: "a replaced module held under both paths", graph: withPackage(graph, 2, func(p *listedPackage) {
			p.Module = &listedModule{Path: "example.com/dep", Replace: &struct{ Path, Version, Dir string }{Path: "example.com/fork", Version: "v1.0.0"}}
		}), excluded: []string{"example.com/m/cmd/a"},
			want: []heldModule{{}, {Path: "example.com/dep"}, {Path: "example.com/fork"}, {Path: "example.com/m", Main: true}}},
		{name: "a package go list could not read", graph: withPackage(graph, 4, func(p *listedPackage) { p.Error = &struct{ Err string }{Err: "expected 'STRING'"} }),
			excluded: []string{"example.com/m/cmd/a"}},
		{name: "a package with a dependency go list could not read", graph: withPackage(graph, 2, func(p *listedPackage) { p.DepsErrors = []*struct{ Err string }{{Err: "x"}} }),
			excluded: []string{"example.com/m/cmd/a"}},
		{name: "an incomplete package", graph: withPackage(graph, 0, func(p *listedPackage) { p.Incomplete = true }),
			excluded: []string{"example.com/m/cmd/a"}},
		{name: "a package go list could not read outside H", graph: withPackage(graph, 3, func(p *listedPackage) { p.Error = &struct{ Err string }{Err: "x"} }),
			excluded: []string{"example.com/m/cmd/a"}, want: []heldModule{{}, {Path: "example.com/dep"}, {Path: "example.com/m", Main: true}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := heldModules(tc.graph, tc.excluded); !slices.Equal(got, tc.want) {
				t.Errorf("held %+v, want %+v", got, tc.want)
			}
		})
	}
}

// withPackage returns a copy of graph with its i'th package changed by edit.
func withPackage(graph []listedPackage, i int, edit func(*listedPackage)) []listedPackage {
	out := slices.Clone(graph)
	edit(&out[i])
	return out
}

// TestHeldModulesUnparseableImports pins, against go list itself, that H is unknown when a package
// in it has an import block go list cannot parse, and known when the same build parses.
func TestHeldModulesUnparseableImports(t *testing.T) {
	files := map[string]string{
		"go.mod":        "module example.com/m\n\ngo 1.22\n",
		"cmd/a/main.go": "package main\n\nimport (\n\t_ \"example.com/m/olm\"\n\t_ \"example.com/m/bad\"\n)\n\nfunc main() {}\n",
		"olm/olm.go":    "package olm\n",
		"bad/bad.go":    "package bad\n\nimport (\n\t\"fmt\"\n",
		"cmd/b/main.go": "package main\n\nfunc main() {}\n",
	}
	for _, tc := range []struct {
		name      string
		bad       string
		wantKnown bool
	}{
		{name: "an H package with an unparseable import block", bad: files["bad/bad.go"]},
		{name: "the same build parsed", bad: "package bad\n", wantKnown: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := maps.Clone(files)
			tree["bad/bad.go"] = tc.bad
			dir := writeTree(t, tree)
			graph, err := listBuildPackages(context.Background(), dir, append(os.Environ(), "GOWORK=off"))
			if err != nil {
				t.Fatal(err)
			}
			if held := heldModules(graph, []string{"example.com/m/cmd/a"}); (len(held) > 0) != tc.wantKnown {
				t.Errorf("held %+v, want known=%v", held, tc.wantKnown)
			}
		})
	}
}

// TestPartialRunAdvisoryModules pins that a partial run supports a verdict only on an advisory
// whose own OSV entry is in the stream: one absent from it (the run fetched advisories only for the
// modules it loaded) or reached only through an alias may name a module only H holds.
func TestPartialRunAdvisoryModules(t *testing.T) {
	const stream = `{"osv":{"id":"GO-1","aliases":["CVE-1"],"affected":[{"package":{"name":"example.com/out"}}]}}
{"osv":{"id":"GO-3","affected":[{"package":{"name":"example.com/out"}},{"package":{"name":"example.com/dep"}}]}}
`
	run := &partialRun{Unloadable: []string{"example.com/dep/olm"}, Modules: map[string]string{"example.com/dep/olm": "pkg:golang/example.com/dep"},
		Excluded: []string{"example.com/m/cmd/a"}, Held: []heldModule{{}, {Path: "example.com/dep"}, {Path: "example.com/m", Main: true}}}
	for _, tc := range []struct {
		name     string
		vulnID   string
		wantKept bool
	}{
		{name: "an advisory in the stream naming only modules outside H", vulnID: "GO-1", wantKept: true},
		{name: "a multi-module advisory absent from the stream", vulnID: "GO-2"},
		{name: "a multi-module advisory in the stream naming a module in H", vulnID: "GO-3"},
		{name: "an advisory reached through an alias", vulnID: "CVE-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scanned, err := parseFindings([]byte(stream), tc.vulnID)
			if err != nil {
				t.Fatal(err)
			}
			scanned.partial, scanned.admitted = run, "pkg:golang/example.com/out@v1.0.0"
			res := withholdForPartialRun(evidenceResult(scanned.findings, plugin.CallGraphResult{Partiality: plugin.Complete()}, nil), scanned)
			if failed := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonToolFailure); failed == tc.wantKept {
				t.Errorf("reasons %v, want kept=%v", res.Partiality.Reasons, tc.wantKept)
			}
		})
	}
}

// TestHeldTargets pins the targets a bounded disclosure names for H's modules.
func TestHeldTargets(t *testing.T) {
	got := heldTargets([]heldModule{{Path: "example.com/m", Main: true}, {}, {Path: "example.com/dep"}})
	want := []string{"", "pkg:golang/cmd", "pkg:golang/example.com/dep", "pkg:golang/stdlib", "pkg:golang/toolchain"}
	if !slices.Equal(got, want) {
		t.Errorf("targets %q, want %q", got, want)
	}
	if got := heldTargets(nil); got != nil {
		t.Errorf("targets %q for unknown H, want none", got)
	}
}

// TestIncompleteLoadExempt pins that incompleteLoad passes over exactly the exempt packages, each
// only when it is the one loaded package with its path, and that a partial run exempts P only for a
// module it supports a verdict on.
func TestIncompleteLoadExempt(t *testing.T) {
	failed := func(path string) *packages.Package {
		return &packages.Package{ID: path, PkgPath: path, Errors: []packages.Error{{Msg: "could not import C"}}}
	}
	ok := func(path string, imports ...*packages.Package) *packages.Package {
		p := &packages.Package{ID: path, PkgPath: path, Types: types.NewPackage(path, "x"), Imports: map[string]*packages.Package{}}
		for _, imp := range imports {
			p.Imports[imp.PkgPath] = imp
		}
		return p
	}
	olm := failed("example.com/dep/olm")
	twin := failed("example.com/dep/olm")
	twin.ID = "example.com/dep/olm [example.com/dep/olm.test]"
	cases := []struct {
		name   string
		pkgs   []*packages.Package
		exempt []string
		want   bool
	}{
		{name: "complete", pkgs: []*packages.Package{ok("example.com/m")}, want: false},
		{name: "a failed package, none exempt", pkgs: []*packages.Package{ok("example.com/m", olm)}, want: true},
		{name: "the failed package exempt", pkgs: []*packages.Package{ok("example.com/m", olm)}, exempt: []string{"example.com/dep/olm"}, want: false},
		{name: "another failed package", pkgs: []*packages.Package{ok("example.com/m", olm, failed("example.com/dep/x"))}, exempt: []string{"example.com/dep/olm"}, want: true},
		{name: "two loaded packages share the exempt path", pkgs: []*packages.Package{ok("example.com/m", olm), ok("example.com/m2", twin)}, exempt: []string{"example.com/dep/olm"}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := incompleteLoad(tc.pkgs, tc.exempt); got != tc.want {
				t.Errorf("incomplete=%v, want %v", got, tc.want)
			}
		})
	}
	run := &partialRun{Unloadable: []string{"example.com/dep/olm"}, Held: []heldModule{{}, {Path: "example.com/dep"}}}
	for _, tc := range []struct {
		name   string
		run    *partialRun
		module string
		want   []string
	}{
		{name: "a full run exempts nothing", module: "example.com/out"},
		{name: "a module outside H exempts P", run: run, module: "example.com/out", want: run.Unloadable},
		{name: "a module in H exempts nothing", run: run, module: "example.com/dep"},
		{name: "stdlib in H exempts nothing", run: run, module: "stdlib"},
		{name: "H unknown exempts nothing", run: &partialRun{Unloadable: run.Unloadable}, module: "example.com/out"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.run.loadExempt(tc.module); !slices.Equal(got, tc.want) {
				t.Errorf("exempt %v, want %v", got, tc.want)
			}
		})
	}
}

// TestReconciledResult_PartialRunWithholdsRefutation pins that a partial run reaches the result: the
// stream runGovulncheck answers a settled failure with carries the partial run and the request's
// package into reconciledResult, which withholds a refutation every other gate lets stand unless the
// run supports it. The run cache is seeded, so no govulncheck runs: under one key a settled failure
// and the partial run that answers it, under the other the same stream as a full run.
func TestReconciledResult_PartialRunWithholdsRefutation(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"go.mod":              "module example.com/m\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n\nreplace example.com/vulnmod => ./_vulnmod\n",
		"main.go":             "package main\n\nimport \"example.com/vulnmod\"\n\nfunc main() { vulnmod.Safe() }\n",
		"_vulnmod/go.mod":     "module example.com/vulnmod\n\ngo 1.22\n",
		"_vulnmod/vulnmod.go": "package vulnmod\n\nfunc Safe() {}\n\nfunc Bad() {}\n",
	})
	load, err := LoadProgram(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "GOWORK=off")
	key := append([]string{dir}, env...)
	stream := []byte(`{"osv":{"id":"GO-1","affected":[{"package":{"name":"example.com/vulnmod"}}]}}` + "\n" +
		`{"finding":{"osv":"GO-1","trace":[{"module":"example.com/vulnmod","version":"v0.0.0","package":"example.com/vulnmod"}]}}` + "\n")
	seed := func(t *testing.T, cache, kind string, v any) {
		t.Helper()
		b, ok := v.([]byte)
		if !ok {
			var err error
			if b, err = json.Marshal(v); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(runCachePath(cache, kind, key), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outside := []heldModule{{}, {Path: "example.com/m", Main: true}}
	cases := []struct {
		name     string
		partial  bool
		held     []heldModule
		pkg      string
		wantKept bool
	}{
		{name: "full run", pkg: "pkg:golang/example.com/vulnmod@v0.0.0", wantKept: true},
		{name: "partial run, H unknown", partial: true, pkg: "pkg:golang/example.com/vulnmod@v0.0.0"},
		{name: "partial run, module in H", partial: true, held: append(slices.Clone(outside), heldModule{Path: "example.com/vulnmod"}), pkg: "pkg:golang/example.com/vulnmod@v0.0.0"},
		{name: "partial run, module outside H", partial: true, held: outside, pkg: "pkg:golang/example.com/vulnmod@v0.0.0", wantKept: true},
		{name: "partial run, no admitted package", partial: true, held: outside},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cache := t.TempDir()
			if tc.partial {
				seed(t, cache, govulncheckFailureKind, govulncheckFailureRecord{Marker: govulncheckFailureMarker, Cause: "exit status 1", Stderr: "could not import C"})
				seed(t, cache, govulncheckPartialKind, partialRun{Marker: govulncheckPartialMarker, Unloadable: []string{"example.com/m/c"}, Excluded: []string{"example.com/m/cmd/a"}, Held: tc.held, Stream: stream})
			} else {
				seed(t, cache, "govulncheck", stream)
			}
			ctx := WithRunCacheDir(context.Background(), cache)
			scanned, err := runGovulncheck(ctx, plugin.ReachabilityRequest{BuildDir: dir, VulnID: "GO-1", Package: tc.pkg}, env, true)
			if err != nil {
				t.Fatal(err)
			}
			res, err := reconciledResult(ctx, scanned, dir, env, func() (*LoadResult, error) { return load, nil }, plugin.LibraryEntrypoints{})
			if err != nil {
				t.Fatal(err)
			}
			if refuted := res.Refutation != nil; refuted != tc.wantKept {
				t.Errorf("refutation %+v (%v), want kept=%v", res.Refutation, res.Partiality.Reasons, tc.wantKept)
			}
			if failed := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonToolFailure); failed == tc.wantKept {
				t.Errorf("reasons %v, want tool_failure=%v", res.Partiality.Reasons, !tc.wantKept)
			}
		})
	}
}

// TestListBuildPackages pins that the listing holds the build's dependencies as well as its roots,
// so an unloadable package outside the main module still names a package.
func TestListBuildPackages(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"go.mod":      "module example.com/m\n\ngo 1.22\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => ./_dep\n",
		"main.go":     "package main\n\nimport \"example.com/dep\"\n\nfunc main() { dep.F() }\n",
		"_dep/go.mod": "module example.com/dep\n\ngo 1.22\n",
		"_dep/dep.go": "package dep\n\nfunc F() {}\n",
	})
	graph, err := listBuildPackages(context.Background(), dir, append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod"))
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(graph, func(p listedPackage) bool { return p.ImportPath == "example.com/dep" })
	if i < 0 {
		t.Fatalf("graph %+v does not list the dependency", graph)
	}
	if dep := graph[i]; !dep.DepOnly || dep.purl() != "pkg:golang/example.com/dep" {
		t.Errorf("dependency listed as %+v (%s)", dep, dep.purl())
	}
}

// TestUnloadablePackagesResolvesSymlinks pins that an error position and a listed directory that
// spell one directory two ways (macOS's /var and /private/var) name the same package.
func TestUnloadablePackagesResolvesSymlinks(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	graph := []listedPackage{{ImportPath: "example.com/c", Dir: real, DepOnly: true}}
	got, err := unloadablePackages(root, []packages.Error{{Pos: filepath.Join(link, "c.go") + ":4:8", Msg: "could not import C"}}, graph)
	if err != nil || !slices.Equal(got, []string{"example.com/c"}) {
		t.Errorf("got %v, %v; want example.com/c", got, err)
	}
}

// TestWithholdForPartialRunNeverComplete pins that a partial run's result is never complete, even
// when the paths it stands on are fully corroborated.
func TestWithholdForPartialRunNeverComplete(t *testing.T) {
	run := &partialRun{Unloadable: []string{"example.com/dep/olm"}, Excluded: []string{"example.com/m/cmd/a"}}
	finding := []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/dep", Package: "example.com/dep/x", Function: "Bad"}}}}
	res := withholdForPartialRun(plugin.ReachabilityResult{Paths: []plugin.ReachPath{{}}, Partiality: plugin.Complete()}, vulnScan{findings: finding, partial: run})
	if res.Partiality.Complete {
		t.Errorf("partiality %+v is complete", res.Partiality)
	}
}

// TestDecodePartialRun pins that only a marked record naming what it could not load and what it
// left out is a partial run.
func TestDecodePartialRun(t *testing.T) {
	cases := []struct {
		name string
		run  partialRun
		want bool
	}{
		{name: "a whole record", run: partialRun{Marker: govulncheckPartialMarker, Unloadable: []string{"p"}, Excluded: []string{"r"}}, want: true},
		{name: "no marker", run: partialRun{Unloadable: []string{"p"}, Excluded: []string{"r"}}},
		{name: "nothing excluded", run: partialRun{Marker: govulncheckPartialMarker, Unloadable: []string{"p"}}},
		{name: "nothing unloadable", run: partialRun{Marker: govulncheckPartialMarker, Excluded: []string{"r"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.run)
			if err != nil {
				t.Fatal(err)
			}
			if got := decodePartialRun(b) != nil; got != tc.want {
				t.Errorf("decoded=%v, want %v", got, tc.want)
			}
		})
	}
}
