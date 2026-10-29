package goanalysis

import (
	"context"
	"encoding/json"
	"errors"
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
	record, err := partialRunRecord(
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
		{name: "transient failure never re-runs", cacheDir: true, settle: true, outcome: "unsettled", wantStreams: 3},
		{name: "retryable run never re-runs", cacheDir: true, settle: false, outcome: "settled", wantStreams: 3},
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
		{ImportPath: "example.com/dep/olm", Dir: "/mod/dep/olm", DepOnly: true, Imports: []string{"C", "fmt"}},
		{ImportPath: "example.com/dep/other", Dir: "/mod/dep/other", DepOnly: true},
		{ImportPath: "fmt", Dir: "/goroot/src/fmt", DepOnly: true},
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
	}{
		{name: "an error named by position", perrs: []packages.Error{typeError}, graph: graph,
			wantRun: []string{"example.com/m/cmd/b"}, wantExcluded: []string{"example.com/m/cmd/a", "example.com/m/lib"}, wantP: []string{"example.com/dep/olm"}},
		{name: "an error named by the go command's heading", perrs: []packages.Error{cgoListError}, graph: graph,
			wantRun: []string{"example.com/m/cmd/b"}, wantExcluded: []string{"example.com/m/cmd/a", "example.com/m/lib"}, wantP: []string{"example.com/dep/olm"}},
		{name: "both errors of a failed cgo package", perrs: []packages.Error{cgoListError, typeError}, graph: graph,
			wantRun: []string{"example.com/m/cmd/b"}, wantExcluded: []string{"example.com/m/cmd/a", "example.com/m/lib"}, wantP: []string{"example.com/dep/olm"}},
		{name: "a root that fails itself", perrs: []packages.Error{{Pos: "/src/cmd/b/b.go:1:1", Msg: "x"}},
			graph:   append(slices.Clone(graph[:1]), listedPackage{ImportPath: "example.com/m/cmd/b", Dir: "/src/cmd/b"}, graph[2], graph[3], graph[5]),
			wantRun: []string{"example.com/m/cmd/a", "example.com/m/lib"}, wantExcluded: []string{"example.com/m/cmd/b"}, wantP: []string{"example.com/m/cmd/b"}},
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
			b, err := partialRunRecord(tc.perrs, func() ([]listedPackage, error) { return tc.graph, nil }, func(patterns []string) ([]byte, error) {
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
		})
	}
}

// TestWithholdForPartialRun pins the result a partial run supports: a symbol finding stands, a
// refutation and silence about the advisory are withheld as tool_failure, and every result names
// what the run left out. A run over the whole build is left as it was.
func TestWithholdForPartialRun(t *testing.T) {
	run := &partialRun{Unloadable: []string{"example.com/dep/olm"}, Excluded: []string{"example.com/m/cmd/a"}}
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
	}{
		{name: "refutation withheld", findings: moduleFinding, partial: run, wantReason: plugin.PartialReasonToolFailure, wantDisclosed: true},
		{name: "silence is a tool failure", partial: run, wantReason: plugin.PartialReasonToolFailure, wantNoReason: plugin.PartialReasonAdvisoryUnknownToAnalyzer, wantDisclosed: true},
		{name: "symbol finding stands", findings: symbolFinding, partial: run, wantPaths: true, wantNoReason: plugin.PartialReasonToolFailure, wantDisclosed: true},
		{name: "full run: refutation stands", findings: moduleFinding, wantRefuted: true, wantNoReason: plugin.PartialReasonToolFailure},
		{name: "full run: silence stays unknown to the analyzer", wantReason: plugin.PartialReasonAdvisoryUnknownToAnalyzer, wantNoReason: plugin.PartialReasonToolFailure},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scanned := vulnScan{findings: tc.findings, partial: tc.partial}
			res := withholdForPartialRun(evidenceResult(tc.findings, plugin.CallGraphResult{Partiality: plugin.Complete()}, nil), scanned)
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
				return s.Reason == plugin.PartialReasonToolFailure && len(s.Targets) == 0 &&
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

// TestReconciledResult_PartialRunWithholdsRefutation pins that reconciledResult applies the partial
// run's shape: a refutation every other gate lets stand is withheld when the stream is partial.
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
	finding := []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/vulnmod", Version: "v0.0.0", Package: "example.com/vulnmod"}}}}
	for _, partial := range []*partialRun{nil, {Unloadable: []string{"example.com/c"}, Excluded: []string{"example.com/m/cmd/a"}}} {
		res, err := reconciledResult(context.Background(), vulnScan{findings: finding, partial: partial}, dir, append(os.Environ(), "GOWORK=off"), func() (*LoadResult, error) { return load, nil }, plugin.LibraryEntrypoints{})
		if err != nil {
			t.Fatal(err)
		}
		if refuted := res.Refutation != nil; refuted != (partial == nil) {
			t.Errorf("partial=%v: refutation %+v (%v)", partial != nil, res.Refutation, res.Partiality.Reasons)
		}
		if failed := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonToolFailure); failed != (partial != nil) {
			t.Errorf("partial=%v: reasons %v", partial != nil, res.Partiality.Reasons)
		}
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
	got, err := unloadablePackages([]packages.Error{{Pos: filepath.Join(link, "c.go") + ":4:8", Msg: "could not import C"}}, graph)
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
