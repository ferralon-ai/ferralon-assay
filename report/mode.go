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

// ToolchainSourceUnresolved is SubjectToolchain.Source when no source produced a version.
const ToolchainSourceUnresolved = "unresolved"

// SubjectToolchain is the Go toolchain version the run analysed the subject under, as the analysis
// resolved it, with the source that decided it.
type SubjectToolchain struct {
	// Version is the normalized go1.21.3 form; empty exactly when Source is unresolved.
	Version string `json:"version,omitempty"`
	// Bound is exact (the toolchain is this version), minimum (it is this version or later) or none.
	Bound string `json:"bound"`
	// Source is subject_declared, ci_observed, build_resolved, toolchain_directive, go_directive or
	// unresolved.
	Source string `json:"source"`
	// Assumption is set when Version is the practical-mode floor taken from the go.mod toolchain line.
	// StrictVersion is then the floor without that assumption, empty when there is none.
	Assumption    string `json:"assumption,omitempty"`
	StrictVersion string `json:"strict_version,omitempty"`
}

// RootsShown bounds how many entry points RunAssumptions lists per kind; Count states the total.
const RootsShown = 5

// RunAssumptions gathers what the run took as given about the build it assessed, each part read
// off fields the report already holds. It adds no fact of its own.
type RunAssumptions struct {
	// Entrypoints is, per lane that reported an entry-point set, the stance it took toward the build
	// and the entry points it used.
	Entrypoints []EntryStance `json:"entrypoints,omitempty"`
	// Build names what the scan built and read: the commit, the Go main module and workspace modules
	// the build list resolved, the toolchain, the JVM build graph's source, and the JS dependency
	// code source.
	Build RunBuild `json:"build"`
	// SkippedTargets are the modules and lanes the scan left out of the build it analysed.
	SkippedTargets []SkippedTarget `json:"skipped_targets,omitempty"`
}

// EntryStance is one lane's stance toward the build and the entry points it analysed.
type EntryStance struct {
	Lane string `json:"lane"`
	// Stance is application when the lane read the build as an application whose mains are the entry
	// points, declared when the entry points rest on the caller's declaration, library otherwise.
	Stance string `json:"stance"`
	// Source is the entry-point record's source: auto, mains or declared.
	Source string `json:"source"`
	// Roots is the entry points the lane analysed, by kind. The full sets are in Report.Entrypoints.
	Roots []EntryRoots `json:"roots,omitempty"`
}

// EntryRoots is one kind of entry point a lane analysed: how many, and the first RootsShown.
type EntryRoots struct {
	Kind  string   `json:"kind"`
	Count int      `json:"count"`
	First []string `json:"first,omitempty"`
}

// RunBuild is the build target of a run.
type RunBuild struct {
	ResolvedCommit     string   `json:"resolved_commit"`
	GoMainModule       string   `json:"go_main_module,omitempty"`
	GoWorkspaceModules []string `json:"go_workspace_modules,omitempty"`
	// Toolchain is the Go toolchain the run analysed under. Another lane's runtime appears nowhere
	// in the report, so a run with no Go assessment states none.
	Toolchain *SubjectToolchain `json:"toolchain,omitempty"`
	// BuildGraphSource is BuildGraph.Source of a Java or Kotlin scan.
	BuildGraphSource string `json:"build_graph_source,omitempty"`
	// DependencyCodeSource is DependencyCode.Source of a JavaScript scan.
	DependencyCodeSource string `json:"dependency_code_source,omitempty"`
}

// Kinds of SkippedTarget.
const (
	// SkippedModule is a module in the checkout that the scan did not analyse; Path is its directory.
	SkippedModule = "module"
	// SkippedLane is a language the checkout holds that no analyzer was installed for; Detail names it.
	SkippedLane = "lane"
)

// SkippedTarget is something in the checkout that the scan did not analyse.
type SkippedTarget struct {
	Kind   string `json:"kind"`
	Path   string `json:"path,omitempty"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// AssumptionsOf derives the run's assumptions from r. It reads Entrypoints, SBOM, Subject,
// SubjectToolchain, BuildGraph, DependencyCode and Partiality, so it is called once the last of them
// is set.
func AssumptionsOf(r Report) RunAssumptions {
	a := RunAssumptions{Build: RunBuild{
		ResolvedCommit:     r.Subject.ResolvedCommit,
		GoMainModule:       r.SBOM.GoMainModule,
		GoWorkspaceModules: slices.Clone(r.SBOM.GoWorkspaceModules),
	}}
	if t := r.SubjectToolchain; t != nil {
		c := *t
		a.Build.Toolchain = &c
	}
	for _, e := range r.Entrypoints {
		stance := StanceLibrary
		switch e.Source {
		case plugin.LibraryEntrypointsSourceMains:
			stance = StanceApplication
		case plugin.LibraryEntrypointsSourceDeclared:
			stance = StanceDeclared
		}
		a.Entrypoints = append(a.Entrypoints, EntryStance{Lane: e.Lane, Stance: stance, Source: e.Source, Roots: rootsOf(e.Effective)})
	}
	if r.BuildGraph != nil {
		a.Build.BuildGraphSource = r.BuildGraph.Source
	}
	if r.DependencyCode != nil {
		a.Build.DependencyCodeSource = r.DependencyCode.Source
	}
	for _, n := range r.Partiality {
		switch {
		case n.Reason == plugin.PartialReasonNestedModule && n.Path != "":
			a.SkippedTargets = append(a.SkippedTargets, SkippedTarget{Kind: SkippedModule, Path: n.Path, Reason: n.Reason})
		case n.Reason == plugin.PartialReasonNoPlugin:
			a.SkippedTargets = append(a.SkippedTargets, SkippedTarget{Kind: SkippedLane, Reason: n.Reason, Detail: n.Detail})
		}
	}
	slices.SortFunc(a.SkippedTargets, func(x, y SkippedTarget) int {
		return strings.Compare(x.Kind+"\x00"+x.Path+"\x00"+x.Detail, y.Kind+"\x00"+y.Path+"\x00"+y.Detail)
	})
	a.SkippedTargets = slices.Compact(a.SkippedTargets)
	return a
}

// rootsOf summarizes a record's effective roots per kind, kinds sorted, each bounded to RootsShown.
func rootsOf(effective map[string][]string) []EntryRoots {
	kinds := make([]string, 0, len(effective))
	for k := range effective {
		kinds = append(kinds, k)
	}
	slices.Sort(kinds)
	var out []EntryRoots
	for _, k := range kinds {
		roots := effective[k]
		out = append(out, EntryRoots{Kind: k, Count: len(roots), First: slices.Clone(roots[:min(len(roots), RootsShown)])})
	}
	return out
}
