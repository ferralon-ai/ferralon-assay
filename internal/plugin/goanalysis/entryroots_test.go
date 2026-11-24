package goanalysis

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestReconciledResult_EntryRootsOnEveryAssessment: a Go advisory the call graph reaches holds no
// refutation candidate, and its result still records the resolved set and the inferred and denied
// entry points, as an advisory with a refutation does. library_entrypoints keeps its shape. The build
// ships cmd/tool, so auto reads it as an application: its library packages are inferred but not entry
// points.
func TestReconciledResult_EntryRootsOnEveryAssessment(t *testing.T) {
	files := map[string]string{
		"go.mod":              "module example.com/m\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n\nreplace example.com/vulnmod => ./_vulnmod\n",
		"_vulnmod/go.mod":     "module example.com/vulnmod\n\ngo 1.22\n",
		"_vulnmod/vulnmod.go": "package vulnmod\n\nfunc Bad() {}\n",
		"cmd/tool/main.go":    "package main\n\nimport \"example.com/vulnmod\"\n\nfunc main() { vulnmod.Bad() }\n",
		"examples/ex/main.go": "package main\n\nfunc main() {}\n",
		"pkg/api/api.go":      "package api\n\nfunc One() int { return 1 }\n",
		"pkg/lib/lib.go":      "package lib\n\nfunc Two() int { return 2 }\n",
		"test/helpers/h.go":   "package helpers\n\nfunc H() {}\n",
	}
	reached := vulnScan{findings: []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{
		{Module: "example.com/vulnmod", Version: "v0.0.0", Package: "example.com/vulnmod", Function: "Bad"},
		{Module: "example.com/m", Package: "example.com/m/cmd/tool", Function: "main"},
	}}}}
	module := vulnScan{findings: []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/vulnmod", Version: "v0.0.0", Package: "example.com/vulnmod"}}}}}
	inferred := map[string][]string{
		plugin.EntryKindLibrary: {"example.com/m/pkg/api", "example.com/m/pkg/lib"},
		plugin.EntryKindMain:    {"example.com/m/cmd/tool", "example.com/m/examples/ex"},
	}
	cases := []struct {
		name      string
		input     string
		scanned   vulnScan
		refuted   bool
		source    string
		effective []string
		denied    []string
		unmatched []string
	}{
		{"a reachable path, auto", "auto", reached, false, plugin.LibraryEntrypointsSourceMains, []string{}, nil, nil},
		{"a reachable path, a declared deny", "!pkg/lib", reached, false, plugin.LibraryEntrypointsSourceDeclared,
			[]string{"example.com/m/pkg/api"}, []string{"!pkg/lib"}, nil},
		{"a reachable path, a deny that removes nothing inferred", "!test", reached, false, plugin.LibraryEntrypointsSourceDeclared,
			[]string{"example.com/m/pkg/api", "example.com/m/pkg/lib"}, nil, nil},
		{"a reachable path, a deny of a path the build does not hold", "!nope", reached, false, plugin.LibraryEntrypointsSourceDeclared,
			[]string{"example.com/m/pkg/api", "example.com/m/pkg/lib"}, nil, []string{"!nope"}},
		{"a reachable path, none", "none", reached, false, plugin.LibraryEntrypointsSourceDeclared, []string{}, nil, nil},
		{"a refutation candidate, auto", "auto", module, true, plugin.LibraryEntrypointsSourceMains, []string{}, nil, nil},
		{"a refutation candidate, a declared deny", "!pkg/lib", module, true, plugin.LibraryEntrypointsSourceDeclared,
			[]string{"example.com/m/pkg/api"}, []string{"!pkg/lib"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry, err := plugin.ParseLibraryEntrypoints(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			dir := writeTree(t, files)
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			env := append(os.Environ(), "GOWORK=off")
			res, err := reconciledResult(context.Background(), tc.scanned, dir, env, func() (*LoadResult, error) { return load, nil }, entry)
			if err != nil {
				t.Fatal(err)
			}
			if tc.refuted != (res.Refutation != nil) {
				t.Fatalf("refutation = %+v, want one: %v", res.Refutation, tc.refuted)
			}
			lib, rec := res.LibraryEntrypoints, res.EntryRoots
			if rec == nil {
				t.Fatal("entry roots not recorded")
			}
			// library_entrypoints stays what it was: a set only where a refutation was judged.
			if tc.refuted != (lib != nil) {
				t.Fatalf("library_entrypoints = %+v, want one: %v", lib, tc.refuted)
			}
			if lib != nil && (lib.Source != tc.source || !slices.Equal(lib.Packages, tc.effective) || !slices.Equal(lib.Unmatched, tc.unmatched)) {
				t.Errorf("library_entrypoints = %+v, want source %q packages %q unmatched %q", lib, tc.source, tc.effective, tc.unmatched)
			}
			if rec.Lane != plugin.EntryLaneGo || rec.Source != tc.source || rec.Input != entry.String() {
				t.Errorf("record lane, source, input = %q, %q, %q", rec.Lane, rec.Source, rec.Input)
			}
			if !reflect.DeepEqual(rec.Effective, map[string][]string{plugin.EntryKindLibrary: tc.effective}) {
				t.Errorf("effective = %v, want library %q", rec.Effective, tc.effective)
			}
			if !reflect.DeepEqual(rec.Inferred, inferred) {
				t.Errorf("inferred = %v, want %v", rec.Inferred, inferred)
			}
			if !slices.Equal(rec.Denied, tc.denied) || !slices.Equal(rec.Unmatched, tc.unmatched) {
				t.Errorf("denied, unmatched = %q, %q, want %q, %q", rec.Denied, rec.Unmatched, tc.denied, tc.unmatched)
			}
		})
	}
}

// TestWithoutLoad: an assessment that holds no refutation records the entry points through the run
// cache, loading the build for the first assessment of a tree only, and a load that fails records
// nothing and changes nothing else of the result.
func TestWithoutLoad(t *testing.T) {
	files := map[string]string{
		"go.mod":         "module example.com/m\n\ngo 1.22\n",
		"pkg/api/api.go": "package api\n\nfunc One() int { return 1 }\n",
		"cmd/t/main.go":  "package main\n\nfunc main() {}\n",
	}
	dir := writeTree(t, files)
	cached := WithRunCacheDir(context.Background(), t.TempDir())
	base := plugin.ReachabilityResult{Partiality: plugin.Complete()}
	entry := plugin.LibraryEntrypoints{Mode: plugin.LibraryEntrypointsAuto}

	loads := 0
	counting := func() (*LoadResult, error) {
		loads++
		return LoadProgram(context.Background(), dir)
	}
	failing := func() (*LoadResult, error) { return nil, errors.New("go list failed") }

	first := withoutLoad(cached, base, dir, entry, counting)
	second := withoutLoad(cached, base, dir, entry, counting)
	if loads != 1 {
		t.Errorf("loads over two assessments of one tree = %d, want 1", loads)
	}
	if first.EntryRoots == nil || !reflect.DeepEqual(first.EntryRoots, second.EntryRoots) || !reflect.DeepEqual(first.LibraryEntrypoints, second.LibraryEntrypoints) {
		t.Errorf("records differ across a cache hit: %+v vs %+v", first.EntryRoots, second.EntryRoots)
	}
	if got := first.EntryRoots.Inferred[plugin.EntryKindMain]; !slices.Equal(got, []string{"example.com/m/cmd/t"}) {
		t.Errorf("inferred mains = %q", got)
	}

	// A statement the cache has not seen resolves again, and a failed load is never cached.
	other := plugin.LibraryEntrypoints{Mode: plugin.LibraryEntrypointsNone}
	if res := withoutLoad(cached, base, dir, other, failing); !reflect.DeepEqual(res, base) {
		t.Errorf("a failed load changed the result: %+v", res)
	}
	if res := withoutLoad(context.Background(), base, dir, entry, failing); !reflect.DeepEqual(res, base) {
		t.Errorf("a failed load with no run cache changed the result: %+v", res)
	}
	if res := withoutLoad(cached, base, dir, other, counting); res.EntryRoots == nil || loads != 2 {
		t.Errorf("a new statement did not resolve: roots %+v, loads %d", res.EntryRoots, loads)
	}

	// Statements that differ only in Base, or only in mode, are distinct keys: each resolves and
	// records its own set.
	nominated := plugin.LibraryEntrypoints{Mode: plugin.LibraryEntrypointsPaths, Include: []string{"pkg"}, Base: dir}
	rebased := nominated
	rebased.Base = filepath.Join(dir, "pkg")
	added := nominated
	added.Mode = plugin.LibraryEntrypointsAuto
	var recs []*plugin.EntryRootRecord
	for _, e := range []plugin.LibraryEntrypoints{nominated, rebased, added} {
		recs = append(recs, withoutLoad(cached, base, dir, e, counting).EntryRoots)
	}
	if loads != 5 {
		t.Errorf("loads after three statements differing in base or mode = %d, want 5", loads)
	}
	for i := range recs {
		for j := i + 1; j < len(recs); j++ {
			if recs[i] == nil || recs[j] == nil || reflect.DeepEqual(recs[i], recs[j]) {
				t.Errorf("statements %d and %d share a record: %+v, %+v", i, j, recs[i], recs[j])
			}
		}
	}
}
