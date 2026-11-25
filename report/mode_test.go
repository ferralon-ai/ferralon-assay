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
					{Lane: plugin.EntryLaneJS, Source: plugin.LibraryEntrypointsSourceMains},
					{Lane: "go", Source: plugin.LibraryEntrypointsSourceDeclared},
					{Lane: "py", Source: "auto"},
				},
				BuildGraph:     &BuildGraph{Source: "gradle"},
				DependencyCode: &DependencyCode{Source: "registry"},
				Partiality:     []PartialityNote{nested("b/mod"), nested("a/mod"), nested("a/mod"), {Reason: "other", Path: "x"}},
			},
			want: RunAssumptions{
				Entrypoints: []EntryStance{{Lane: plugin.EntryLaneJS, Stance: StanceApplication}, {Lane: "go", Stance: StanceDeclared}, {Lane: "py", Stance: StanceLibrary}},
				Build: RunBuild{
					ResolvedCommit: "c", GoMainModule: "example.com/app", GoWorkspaceModules: []string{"example.com/app"},
					BuildGraphSource: "gradle", DependencyCodeSource: "registry",
				},
				SkippedTargets: []SkippedTarget{{Path: "a/mod", Reason: plugin.PartialReasonNestedModule}, {Path: "b/mod", Reason: plugin.PartialReasonNestedModule}},
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
