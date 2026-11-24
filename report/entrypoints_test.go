package report

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestBuilderEntrypoints: the lane's resolved library set is rendered as an entrypoints[] record.
func TestBuilderEntrypoints(t *testing.T) {
	tests := []struct {
		name string
		in   []plugin.ResolvedLibraryEntrypoints
		want []plugin.EntryRootRecord
	}{
		{
			name: "go scan, auto",
			in: []plugin.ResolvedLibraryEntrypoints{{
				Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceAuto, Input: "auto",
				Packages: []string{"example.com/m/api", "example.com/m/lib"},
			}},
			want: []plugin.EntryRootRecord{{
				Lane: "go", Source: plugin.LibraryEntrypointsSourceAuto, Input: "auto",
				Effective: map[string][]string{plugin.EntryKindLibrary: {"example.com/m/api", "example.com/m/lib"}},
			}},
		},
		{
			name: "go scan, declared none",
			in: []plugin.ResolvedLibraryEntrypoints{{
				Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "none",
			}},
			want: []plugin.EntryRootRecord{{
				Lane: "go", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "none",
				Effective: map[string][]string{plugin.EntryKindLibrary: {}},
			}},
		},
		{
			name: "go scan, declared paths with an unmatched selector",
			in: []plugin.ResolvedLibraryEntrypoints{{
				Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "pkg/api,!pkg/gone",
				Packages: []string{"example.com/m/pkg/api"}, Unmatched: []string{"!pkg/gone"},
			}},
			want: []plugin.EntryRootRecord{{
				Lane: "go", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "pkg/api,!pkg/gone",
				Effective: map[string][]string{plugin.EntryKindLibrary: {"example.com/m/pkg/api"}},
				Unmatched: []string{"!pkg/gone"},
			}},
		},
		{
			name: "a lane that reports no set yet states nothing",
			in: []plugin.ResolvedLibraryEntrypoints{{
				Ecosystem: "maven", Source: plugin.LibraryEntrypointsSourceAuto, Input: "auto", Packages: []string{"com.example:lib"},
			}},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewBuilder(Subject{ResolvedCommit: "c"}).WithLibraryEntrypoints(tt.in...).Build()
			if !reflect.DeepEqual(r.Entrypoints, tt.want) {
				t.Errorf("Entrypoints = %+v, want %+v", r.Entrypoints, tt.want)
			}
			if !reflect.DeepEqual(r.LibraryEntrypoints, tt.in) {
				t.Errorf("LibraryEntrypoints = %+v, want %+v unchanged", r.LibraryEntrypoints, tt.in)
			}
		})
	}
}

// TestEntrypointsCannotDriftFromLibraryEntrypoints: both fields are rendered from the one recorded
// set, through every route a set reaches a report (recorded, inherited from a stored report, merged
// from several), and survive the JSON round trip with the same packages.
func TestEntrypointsCannotDriftFromLibraryEntrypoints(t *testing.T) {
	first := plugin.ResolvedLibraryEntrypoints{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "pkg/api", Packages: []string{"example.com/m/pkg/api"}}
	second := plugin.ResolvedLibraryEntrypoints{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceAuto, Input: "auto", Packages: []string{"example.com/m/other"}}
	stored := NewBuilder(Subject{ResolvedCommit: "c"}).WithLibraryEntrypoints(first).Build()

	for name, r := range map[string]Report{
		"recorded":  NewBuilder(Subject{ResolvedCommit: "c"}).WithLibraryEntrypoints(first, second).Build(),
		"inherited": NewBuilder(Subject{ResolvedCommit: "c"}).WithLibraryEntrypoints(stored.LibraryEntrypoints...).WithLibraryEntrypoints(second).Build(),
		"merged":    NewBuilder(Subject{ResolvedCommit: "c"}).WithLibraryEntrypoints(first).WithLibraryEntrypoints(second).Build(),
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			var back struct {
				Library []plugin.ResolvedLibraryEntrypoints `json:"library_entrypoints"`
				Entries []plugin.EntryRootRecord            `json:"entrypoints"`
			}
			if err := json.Unmarshal(raw, &back); err != nil {
				t.Fatal(err)
			}
			if len(back.Library) != 1 || len(back.Entries) != 1 {
				t.Fatalf("library_entrypoints %+v, entrypoints %+v: want one record each", back.Library, back.Entries)
			}
			lib, rec := back.Library[0], back.Entries[0]
			if !slices.Equal(rec.Effective[plugin.EntryKindLibrary], lib.Packages) || rec.Source != lib.Source || rec.Input != lib.Input ||
				!slices.Equal(rec.Unmatched, lib.Unmatched) {
				t.Errorf("entrypoints %+v drifted from library_entrypoints %+v", rec, lib)
			}
			if want, ok := plugin.EntryRootRecordOf(lib); !ok || !reflect.DeepEqual(rec, want) {
				t.Errorf("entrypoints %+v is not the rendering of library_entrypoints %+v (%+v)", rec, lib, want)
			}
		})
	}
}

// TestEntrypointsDoNotAliasLibraryEntrypoints: editing one rendering of the set never edits the other.
func TestEntrypointsDoNotAliasLibraryEntrypoints(t *testing.T) {
	r := NewBuilder(Subject{ResolvedCommit: "c"}).WithLibraryEntrypoints(plugin.ResolvedLibraryEntrypoints{
		Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceAuto, Input: "auto", Packages: []string{"example.com/m/a"},
	}).Build()
	r.Entrypoints[0].Effective[plugin.EntryKindLibrary][0] = "changed"
	if got := r.LibraryEntrypoints[0].Packages[0]; got != "example.com/m/a" {
		t.Errorf("library_entrypoints packages = %q after editing entrypoints", got)
	}
}

// TestUpgradeDerivesEntrypointsFromStoredLibraryEntrypoints: a stored report that carries
// library_entrypoints and no entrypoints reads, and so exports, with both, equal to a fresh build.
func TestUpgradeDerivesEntrypointsFromStoredLibraryEntrypoints(t *testing.T) {
	set := plugin.ResolvedLibraryEntrypoints{
		Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "pkg/api,!pkg/gone",
		Packages: []string{"example.com/m/pkg/api"}, Unmatched: []string{"!pkg/gone"},
	}
	fresh := NewBuilder(Subject{ResolvedCommit: "c"}).WithLibraryEntrypoints(set).Build()

	stored := fresh
	stored.Entrypoints = nil
	raw, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	var read Report
	if err := json.Unmarshal(raw, &read); err != nil {
		t.Fatal(err)
	}
	if read.Entrypoints != nil {
		t.Fatalf("stored document should carry no entrypoints, got %+v", read.Entrypoints)
	}
	got, err := Upgrade(read)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Entrypoints, fresh.Entrypoints) || !reflect.DeepEqual(got.LibraryEntrypoints, fresh.LibraryEntrypoints) {
		t.Errorf("upgraded entrypoints %+v / library_entrypoints %+v, want fresh %+v / %+v",
			got.Entrypoints, got.LibraryEntrypoints, fresh.Entrypoints, fresh.LibraryEntrypoints)
	}
	exported, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if string(exported) != string(want) {
		t.Errorf("export differs from a fresh build:\n got %s\nwant %s", exported, want)
	}

	// A report that already states entrypoints keeps them, and one with no set states none.
	if again, _ := Upgrade(got); !reflect.DeepEqual(again, got) {
		t.Errorf("Upgrade is not idempotent: %+v vs %+v", again, got)
	}
	bare := NewBuilder(Subject{ResolvedCommit: "c"}).Build()
	if up, _ := Upgrade(bare); up.Entrypoints != nil {
		t.Errorf("no library set, got entrypoints %+v", up.Entrypoints)
	}
}

// TestEntrypointRecordsSortedByLane: records are ordered by lane, not by the ecosystem order the
// sets arrive in.
func TestEntrypointRecordsSortedByLane(t *testing.T) {
	recs := []plugin.EntryRootRecord{{Lane: "js"}, {Lane: "go"}, {Lane: "dotnet"}, {Lane: "java"}}
	sortRecordsByLane(recs)
	var lanes []string
	for _, r := range recs {
		lanes = append(lanes, r.Lane)
	}
	if want := []string{"dotnet", "go", "java", "js"}; !slices.Equal(lanes, want) {
		t.Errorf("lanes = %v, want %v", lanes, want)
	}
}

// TestEntryRootsCarryInferredAndDenied: a lane's own record, with what it inferred and what the
// caller denied, stands in entrypoints[] while it states the set library_entrypoints does, through
// every route a set reaches a report; library_entrypoints keeps its shape; a record of another set
// is dropped rather than drift.
func TestEntryRootsCarryInferredAndDenied(t *testing.T) {
	lib := plugin.ResolvedLibraryEntrypoints{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "!pkg/lib", Packages: []string{"example.com/m/pkg/api"}}
	rec, _ := plugin.EntryRootRecordOf(lib)
	rec.Inferred = map[string][]string{
		plugin.EntryKindLibrary: {"example.com/m/pkg/api", "example.com/m/pkg/lib"},
		plugin.EntryKindMain:    {"example.com/m/cmd/tool"},
	}
	rec.Denied = []string{"!pkg/lib"}
	derived, _ := plugin.EntryRootRecordOf(lib)
	other := plugin.ResolvedLibraryEntrypoints{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceAuto, Input: "auto", Packages: []string{"example.com/m/other"}}

	plain := NewBuilder(Subject{ResolvedCommit: "c"}).WithLibraryEntrypoints(lib).Build()
	recorded := NewBuilder(Subject{ResolvedCommit: "c"}).WithLibraryEntrypoints(lib).WithEntryRoots(rec).Build()
	for name, tc := range map[string]struct {
		r    Report
		want plugin.EntryRootRecord
	}{
		"no record: derived from the library set": {plain, derived},
		"recorded": {recorded, rec},
		"merged, the first record stands": {NewBuilder(Subject{ResolvedCommit: "c"}).WithLibraryEntrypoints(lib).
			WithEntryRoots(rec).WithEntryRoots(derived).Build(), rec},
		"a record of another set is dropped": {NewBuilder(Subject{ResolvedCommit: "c"}).WithLibraryEntrypoints(other).WithEntryRoots(rec).Build(),
			func() plugin.EntryRootRecord { r, _ := plugin.EntryRootRecordOf(other); return r }()},
	} {
		t.Run(name, func(t *testing.T) {
			if len(tc.r.Entrypoints) != 1 || !reflect.DeepEqual(tc.r.Entrypoints[0], tc.want) {
				t.Errorf("Entrypoints = %+v, want [%+v]", tc.r.Entrypoints, tc.want)
			}
		})
	}
	// library_entrypoints is the same bytes with or without the record.
	a, _ := json.Marshal(plain.LibraryEntrypoints)
	b, _ := json.Marshal(recorded.LibraryEntrypoints)
	if string(a) != string(b) || string(a) != `[{"ecosystem":"golang","source":"declared","input":"!pkg/lib","packages":["example.com/m/pkg/api"]}]` {
		t.Errorf("library_entrypoints = %s / %s", a, b)
	}

	// The stored report round trips with the record, and a re-read report feeds the next one with no drift.
	raw, err := json.Marshal(recorded)
	if err != nil {
		t.Fatal(err)
	}
	var read Report
	if err := json.Unmarshal(raw, &read); err != nil {
		t.Fatal(err)
	}
	next := NewBuilder(Subject{ResolvedCommit: "d"}).WithLibraryEntrypoints(read.LibraryEntrypoints...).WithEntryRoots(read.Entrypoints...).Build()
	if !reflect.DeepEqual(next.Entrypoints, recorded.Entrypoints) {
		t.Errorf("inherited entrypoints %+v, want %+v", next.Entrypoints, recorded.Entrypoints)
	}
	if got, err := Upgrade(read); err != nil || !reflect.DeepEqual(got.Entrypoints, recorded.Entrypoints) {
		t.Errorf("Upgrade dropped the record: %+v (%v)", got.Entrypoints, err)
	}
}
