package report

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/jsanalysis"
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

// TestEntryRootsCarryApplicationMains: read as an application, the go record names the mains the
// reading rests on beside a library set that cannot state them, and keeps them through a stored
// report's round trip, an inheriting builder and Upgrade.
func TestEntryRootsCarryApplicationMains(t *testing.T) {
	lib := plugin.ResolvedLibraryEntrypoints{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceMains, Input: "auto", Packages: []string{}}
	rec, _ := plugin.EntryRootRecordOf(lib)
	rec.Effective[plugin.EntryKindMain] = []string{"example.com/m/cmd/app"}
	rec.Inferred = map[string][]string{
		plugin.EntryKindLibrary: {"example.com/m/pkg/api"},
		plugin.EntryKindMain:    {"example.com/m/cmd/app"},
	}
	recorded := NewBuilder(Subject{ResolvedCommit: "c"}).WithLibraryEntrypoints(lib).WithEntryRoots(rec).Build()
	if len(recorded.Entrypoints) != 1 || !reflect.DeepEqual(recorded.Entrypoints[0], rec) {
		t.Fatalf("Entrypoints = %+v, want [%+v]", recorded.Entrypoints, rec)
	}
	// Against a literal, not rec: rec shares its maps with what the builder was handed.
	if got := recorded.Entrypoints[0].Effective[plugin.EntryKindMain]; !reflect.DeepEqual(got, []string{"example.com/m/cmd/app"}) {
		t.Fatalf("effective.main = %v, want [example.com/m/cmd/app]", got)
	}
	// Another application's mains are another set's record.
	other := rec
	other.Effective = map[string][]string{plugin.EntryKindLibrary: {"example.com/m/pkg/api"}, plugin.EntryKindMain: {"example.com/m/cmd/app"}}
	derived, _ := plugin.EntryRootRecordOf(lib)
	if got := NewBuilder(Subject{ResolvedCommit: "c"}).WithLibraryEntrypoints(lib).WithEntryRoots(other).Build().Entrypoints; len(got) != 1 || !reflect.DeepEqual(got[0], derived) {
		t.Errorf("a record of another library set: Entrypoints = %+v, want [%+v]", got, derived)
	}
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
		t.Errorf("Upgrade dropped the mains: %+v (%v)", got.Entrypoints, err)
	}
}

// TestJSEntryRootsDoNotDrift: the js lane's record has no library_entrypoints twin to derive it
// from, so it is kept as recorded: through the builder, a stored report's round trip, an inheriting
// builder and beside the go lane's record, in lane order.
func TestJSEntryRootsDoNotDrift(t *testing.T) {
	js := plugin.EntryRootRecord{
		Lane: plugin.EntryLaneJS, Source: plugin.LibraryEntrypointsSourceDeclared, Input: "!js:bin=bin:storybook",
		Effective: map[string][]string{plugin.EntryKindBin: {}, plugin.EntryKindScript: {"npm:tool/index.js"}},
		Inferred:  map[string][]string{plugin.EntryKindBin: {"bin:storybook"}, plugin.EntryKindScript: {"npm:tool/index.js"}},
		Denied:    []string{"!bin:storybook"},
	}
	lib := plugin.ResolvedLibraryEntrypoints{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceAuto, Input: "auto", Packages: []string{"example.com/m/api"}}
	goRec, _ := plugin.EntryRootRecordOf(lib)

	recorded := NewBuilder(Subject{ResolvedCommit: "c"}).WithEntryRoots(js).Build()
	both := NewBuilder(Subject{ResolvedCommit: "c"}).WithLibraryEntrypoints(lib).WithEntryRoots(js).Build()
	for name, tc := range map[string]struct {
		r    Report
		want []plugin.EntryRootRecord
	}{
		"js alone":       {recorded, []plugin.EntryRootRecord{js}},
		"beside the go":  {both, []plugin.EntryRootRecord{goRec, js}},
		"recorded twice": {NewBuilder(Subject{ResolvedCommit: "c"}).WithEntryRoots(js).WithEntryRoots(js).Build(), []plugin.EntryRootRecord{js}},
	} {
		t.Run(name, func(t *testing.T) {
			if !reflect.DeepEqual(tc.r.Entrypoints, tc.want) {
				t.Errorf("Entrypoints = %+v, want %+v", tc.r.Entrypoints, tc.want)
			}
		})
	}

	raw, err := json.Marshal(both)
	if err != nil {
		t.Fatal(err)
	}
	var read Report
	if err := json.Unmarshal(raw, &read); err != nil {
		t.Fatal(err)
	}
	next := NewBuilder(Subject{ResolvedCommit: "d"}).WithLibraryEntrypoints(read.LibraryEntrypoints...).WithEntryRoots(read.Entrypoints...).Build()
	if !reflect.DeepEqual(next.Entrypoints, both.Entrypoints) {
		t.Errorf("inherited entrypoints %+v, want %+v", next.Entrypoints, both.Entrypoints)
	}
	if got, err := Upgrade(read); err != nil || !reflect.DeepEqual(got.Entrypoints, both.Entrypoints) {
		t.Errorf("Upgrade changed the records: %+v (%v)", got.Entrypoints, err)
	}
}

// laneUnlistedRecord is the js record a run that read no closure emits, as the lane builds it and a
// stored report returns it: a removing override and no dependency cache.
func laneUnlistedRecord(t *testing.T, input string) plugin.EntryRootRecord {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"index.js":     "console.log('x');\n",
		"package.json": `{"name":"app","version":"1.0.0","scripts":{"start":"tool --serve"}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var o *plugin.EntryOverride
	if input != "" {
		m, err := plugin.ParseEntryOverrides(input)
		if err != nil {
			t.Fatal(err)
		}
		js := m[plugin.EntryLaneJS]
		o = &js
	}
	res, err := jsanalysis.Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{"npm:idle@1.0.0#bad"}, EntryOverride: o})
	if err != nil || res.EntryRoots == nil {
		t.Fatalf("Reachability: record %+v, err %v", res.EntryRoots, err)
	}
	b, err := json.Marshal(res.EntryRoots)
	if err != nil {
		t.Fatal(err)
	}
	var rec plugin.EntryRootRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

// TestEntrypointRecords_FullJSRecordBeatsUnlisted: of two js records offered under one statement, the
// one that reports what the lane inferred stands over one from a run that read no closure, in either
// order, and a record of another statement never displaces it: its Input would be on this report.
// A record whose Input does not parse never displaces one that does. Of two full records the first stands, and the same clauses in another order are one statement.
func TestEntrypointRecords_FullJSRecordBeatsUnlisted(t *testing.T) {
	const in = "!js:bin=bin:storybook"
	unlisted := laneUnlistedRecord(t, in)
	if len(unlisted.Inferred) != 0 {
		t.Fatalf("the lane's unlisted record reports a guess: %+v", unlisted.Inferred)
	}
	full := unlisted
	full.Effective = map[string][]string{plugin.EntryKindBin: {}, plugin.EntryKindScript: {}}
	full.Inferred = map[string][]string{plugin.EntryKindBin: {"bin:storybook"}, plugin.EntryKindScript: {}}
	full.Denied = []string{"!bin:storybook"}
	other := full
	other.Input = "!js:bin=bin:other"
	other.Denied = []string{"!bin:other"}

	fullLater := full
	fullLater.Inferred = map[string][]string{plugin.EntryKindBin: {"bin:storybook", "bin:later"}, plugin.EntryKindScript: {}}
	ab := laneUnlistedRecord(t, "!js:bin=bin:a,!js:bin=bin:b")
	abFull := ab
	abFull.Input = "!js:bin=bin:b,!js:bin=bin:a"
	abFull.Inferred = map[string][]string{plugin.EntryKindBin: {"bin:a", "bin:b"}, plugin.EntryKindScript: {}}

	unparsable := full
	unparsable.Input = "::bad"

	for name, tc := range map[string]struct {
		roots []plugin.EntryRootRecord
		want  plugin.EntryRootRecord
	}{
		"an unparsable statement does not displace": {[]plugin.EntryRootRecord{unlisted, unparsable}, unlisted},
		"two full records, the first stands":        {[]plugin.EntryRootRecord{full, fullLater}, full},
		"reordered clauses are one statement":       {[]plugin.EntryRootRecord{ab, abFull}, abFull},
		"unlisted first":                            {[]plugin.EntryRootRecord{unlisted, full}, full},
		"full first":                                {[]plugin.EntryRootRecord{full, unlisted}, full},
		"another statement does not displace":       {[]plugin.EntryRootRecord{unlisted, other}, unlisted},
		"another statement, other order":            {[]plugin.EntryRootRecord{other, unlisted}, other},
	} {
		t.Run(name, func(t *testing.T) {
			r := NewBuilder(Subject{ResolvedCommit: "c"}).WithEntryRoots(tc.roots...).Build()
			if len(r.Entrypoints) != 1 || !reflect.DeepEqual(r.Entrypoints[0], tc.want) {
				t.Errorf("Entrypoints = %+v, want [%+v]", r.Entrypoints, tc.want)
			}
		})
	}
}

// TestEntrypointRecords_WithdrawnRemovalThenFailedRead: the removal that the stored report was
// resolved from is withdrawn, and the run's dependency read then fails. The lane still records the
// default statement, so the stored removal is not the one the report states.
func TestEntrypointRecords_WithdrawnRemovalThenFailedRead(t *testing.T) {
	stored := laneUnlistedRecord(t, "!js:bin=bin:storybook")
	stored.Effective = map[string][]string{plugin.EntryKindBin: {}, plugin.EntryKindScript: {}}
	stored.Inferred = map[string][]string{plugin.EntryKindBin: {"bin:storybook"}, plugin.EntryKindScript: {}}
	stored.Denied = []string{"!bin:storybook"}
	head := laneUnlistedRecord(t, "")
	if head.Input != plugin.LibraryEntrypointsAuto || len(head.Inferred)+len(head.Denied)+len(head.Unmatched) != 0 {
		t.Fatalf("the lane's default record = %+v, want auto with nothing inferred, denied or unmatched", head)
	}
	// The head's records are offered before the baseline's (trigger/state.go).
	r := NewBuilder(Subject{ResolvedCommit: "c"}).WithEntryRoots(head, stored).Build()
	if len(r.Entrypoints) != 1 || r.Entrypoints[0].Input != plugin.LibraryEntrypointsAuto {
		t.Errorf("Entrypoints = %+v, want the run's own default statement", r.Entrypoints)
	}
}
