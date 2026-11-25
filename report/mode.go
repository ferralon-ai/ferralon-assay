package report

import (
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Strictness values.
const (
	// StrictnessPractical is the default: a row may clear under an assumption when the row names it.
	StrictnessPractical = "practical"
	// StrictnessStrict clears no row that rests on an assumption Assay inferred.
	StrictnessStrict = "strict"
)

// Sources of a run's strictness, in descending precedence.
const (
	// ModeSourceInput is the strictness input or flag.
	ModeSourceInput = "input"
	// ModeSourceConfig is the strictness key of .github/ferralon.yml.
	ModeSourceConfig = "ferralon.yml"
	// ModeSourceDefault is a run that stated none.
	ModeSourceDefault = "default"
)

// Mode records how strictly the run adjudicated and which statement decided it.
type Mode struct {
	// Strictness is StrictnessPractical or StrictnessStrict.
	Strictness string `json:"strictness"`
	// Source is ModeSourceInput, ModeSourceConfig or ModeSourceDefault.
	Source string `json:"source"`
}

// ModeOf is the strictness the report was produced under. A report with no mode field, written
// before the field existed, reads as practical.
func (r Report) ModeOf() string {
	if r.Mode == nil || r.Mode.Strictness == "" {
		return StrictnessPractical
	}
	return r.Mode.Strictness
}

// Application, library and declared stances of an entry-point lane.
const (
	StanceApplication = "application"
	StanceLibrary     = "library"
	StanceDeclared    = "declared"
)

// RunAssumptions gathers what the run took as given about the build it assessed, each part read
// off fields the report already holds. It adds no fact of its own.
type RunAssumptions struct {
	// Entrypoints is the stance each lane that reported an entry-point set took toward the build:
	// application when the lane read the build as an application whose mains are the entry points,
	// declared when the entry points rest on the caller's declaration, library otherwise. The sets
	// themselves are in Report.Entrypoints.
	Entrypoints []EntryStance `json:"entrypoints,omitempty"`
	// Build names what the scan built and read: the commit, the Go main module and workspace modules
	// the build list resolved, the JVM build graph's source, and the JS dependency code source.
	Build RunBuild `json:"build"`
	// SkippedTargets are the modules the scan left out of the build it analysed.
	SkippedTargets []SkippedTarget `json:"skipped_targets,omitempty"`
}

// EntryStance is one lane's stance toward the build.
type EntryStance struct {
	Lane   string `json:"lane"`
	Stance string `json:"stance"`
}

// RunBuild is the build target of a run.
type RunBuild struct {
	ResolvedCommit     string   `json:"resolved_commit"`
	GoMainModule       string   `json:"go_main_module,omitempty"`
	GoWorkspaceModules []string `json:"go_workspace_modules,omitempty"`
	// BuildGraphSource is BuildGraph.Source of a Java or Kotlin scan.
	BuildGraphSource string `json:"build_graph_source,omitempty"`
	// DependencyCodeSource is DependencyCode.Source of a JavaScript scan.
	DependencyCodeSource string `json:"dependency_code_source,omitempty"`
}

// SkippedTarget is a module in the checkout that the scan did not analyse.
type SkippedTarget struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// AssumptionsOf derives the run's assumptions from r. It reads Entrypoints, SBOM, Subject,
// BuildGraph, DependencyCode and Partiality, so it is called once the last of them is set.
func AssumptionsOf(r Report) RunAssumptions {
	a := RunAssumptions{Build: RunBuild{
		ResolvedCommit:     r.Subject.ResolvedCommit,
		GoMainModule:       r.SBOM.GoMainModule,
		GoWorkspaceModules: slices.Clone(r.SBOM.GoWorkspaceModules),
	}}
	for _, e := range r.Entrypoints {
		stance := StanceLibrary
		switch e.Source {
		case plugin.LibraryEntrypointsSourceMains:
			stance = StanceApplication
		case plugin.LibraryEntrypointsSourceDeclared:
			stance = StanceDeclared
		}
		a.Entrypoints = append(a.Entrypoints, EntryStance{Lane: e.Lane, Stance: stance})
	}
	if r.BuildGraph != nil {
		a.Build.BuildGraphSource = r.BuildGraph.Source
	}
	if r.DependencyCode != nil {
		a.Build.DependencyCodeSource = r.DependencyCode.Source
	}
	for _, n := range r.Partiality {
		if n.Reason == plugin.PartialReasonNestedModule && n.Path != "" {
			a.SkippedTargets = append(a.SkippedTargets, SkippedTarget{Path: n.Path, Reason: n.Reason})
		}
	}
	slices.SortFunc(a.SkippedTargets, func(x, y SkippedTarget) int { return strings.Compare(x.Path, y.Path) })
	a.SkippedTargets = slices.Compact(a.SkippedTargets)
	return a
}
