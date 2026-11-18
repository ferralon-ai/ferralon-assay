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
