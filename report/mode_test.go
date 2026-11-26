package report

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func TestModeJSONShape(t *testing.T) {
	rep := NewBuilder(Subject{ResolvedCommit: "c"}).WithMode(Mode{Strictness: StrictnessStrict, Source: ModeSourceConfig}).Build()
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Mode json.RawMessage `json:"mode"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if want := `{"strictness":"strict","source":"ferralon.yml"}`; string(got.Mode) != want {
		t.Errorf("mode = %s, want %s", got.Mode, want)
	}
}

func TestModeOf(t *testing.T) {
	tests := []struct {
		name string
		mode *Mode
		want string
	}{
		{name: "legacy report", want: StrictnessPractical},
		{name: "empty strictness", mode: &Mode{Source: ModeSourceDefault}, want: StrictnessPractical},
		{name: "practical", mode: &Mode{Strictness: StrictnessPractical}, want: StrictnessPractical},
		{name: "strict", mode: &Mode{Strictness: StrictnessStrict}, want: StrictnessStrict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (Report{Mode: tt.mode}).ModeOf(); got != tt.want {
				t.Errorf("ModeOf = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAssumptionsOf(t *testing.T) {
	nested := func(path string) PartialityNote {
		return PartialityNote{Reason: plugin.PartialReasonNestedModule, Path: path}
	}
	tests := []struct {
		name string
		r    Report
		want RunAssumptions
	}{
		{name: "empty report", r: Report{Subject: Subject{ResolvedCommit: "c"}}, want: RunAssumptions{Build: RunBuild{ResolvedCommit: "c"}}},
		{
			name: "stances, build and skipped targets",
			r: Report{
				Subject: Subject{ResolvedCommit: "c"},
				SBOM:    SBOM{GoMainModule: "example.com/app", GoWorkspaceModules: []string{"example.com/app"}},
				Entrypoints: []plugin.EntryRootRecord{
					{Lane: plugin.EntryLaneJS, Source: plugin.LibraryEntrypointsSourceMains, Effective: map[string][]string{"main": {"a", "b", "c", "d", "e", "f", "g"}, "handler": {"h"}}},
					{Lane: "go", Source: plugin.LibraryEntrypointsSourceDeclared},
					{Lane: "py", Source: "auto"},
				},
				SubjectToolchain: &SubjectToolchain{Version: "go1.21.3", Bound: "exact", Source: "ci_observed"},
				BuildGraph:       &BuildGraph{Source: "gradle"},
				DependencyCode:   &DependencyCode{Source: "registry"},
				Partiality:       []PartialityNote{nested("b/mod"), nested("a/mod"), nested("a/mod"), {Reason: "other", Path: "x"}, {Reason: plugin.PartialReasonNoPlugin, Detail: "rust"}},
			},
			want: RunAssumptions{
				Entrypoints: []EntryStance{{Lane: plugin.EntryLaneJS, Stance: StanceApplication, Source: plugin.LibraryEntrypointsSourceMains, Roots: []EntryRoots{
					{Kind: "handler", Count: 1, First: []string{"h"}},
					{Kind: "main", Count: 7, First: []string{"a", "b", "c", "d", "e"}},
				}}, {Lane: "go", Stance: StanceDeclared, Source: plugin.LibraryEntrypointsSourceDeclared}, {Lane: "py", Stance: StanceLibrary, Source: "auto"}},
				Build: RunBuild{
					ResolvedCommit: "c", GoMainModule: "example.com/app", GoWorkspaceModules: []string{"example.com/app"},
					Toolchain:        &SubjectToolchain{Version: "go1.21.3", Bound: "exact", Source: "ci_observed"},
					BuildGraphSource: "gradle", DependencyCodeSource: "registry",
				},
				SkippedTargets: []SkippedTarget{{Kind: SkippedLane, Reason: plugin.PartialReasonNoPlugin, Detail: "rust"}, {Kind: SkippedModule, Path: "a/mod", Reason: plugin.PartialReasonNestedModule}, {Kind: SkippedModule, Path: "b/mod", Reason: plugin.PartialReasonNestedModule}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AssumptionsOf(tt.r); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AssumptionsOf = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestWithSubjectToolchainKeepsFirstResolved(t *testing.T) {
	fresh := &SubjectToolchain{Version: "go1.22.0", Bound: "exact", Source: "ci_observed"}
	stored := &SubjectToolchain{Version: "go1.20.0", Bound: "minimum", Source: "go_directive"}
	unresolved := &SubjectToolchain{Bound: "none", Source: ToolchainSourceUnresolved}
	tests := []struct {
		name  string
		calls []*SubjectToolchain
		want  *SubjectToolchain
	}{
		{name: "none", want: nil},
		{name: "fresh outranks stored", calls: []*SubjectToolchain{fresh, stored}, want: fresh},
		{name: "stored fills when nothing fresh", calls: []*SubjectToolchain{nil, stored}, want: stored},
		{name: "fresh unresolved outranks stored", calls: []*SubjectToolchain{unresolved, stored}, want: unresolved},
		{name: "unresolved kept when nothing else", calls: []*SubjectToolchain{unresolved}, want: unresolved},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBuilder(Subject{ResolvedCommit: "c"})
			for _, c := range tt.calls {
				b.WithSubjectToolchain(c)
			}
			if got := b.Build().SubjectToolchain; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SubjectToolchain = %+v, want %+v", got, tt.want)
			}
		})
	}
}
