package javaanalysis

import (
	"context"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// units.go — a multi-module Maven reactor searched one application unit at a time, and a checkout
// two build tools each resolved searched one tool's graph at a time (toolUnits). A unit is a
// module with code that no other module with code depends on, or one with launch evidence of its
// own (launchSignal) however many depend on it: what the reactor deploys. A library module's code
// runs only inside a unit that loads it, so it is searched there, on that unit's resolved
// versions; a deployable module another loads is searched on its own versions as well. Each unit
// is searched over its own class output plus that of every reactor sibling on its runtime
// classpath, with the dependency JARs its own module resolved. A module has code when it has
// main sources under its src/ or main class output; a test-only module has none. A module
// without code that loads a sibling at runtime is a unit too, unless it is provably inert.
//
// The plan is built from the build graph alone, and any code it cannot place leaves the build
// with the run-wide multiple_projects_unsupported answer: a module with code no unit loads, a
// main source under no module, class output under a module the plan does not search, a reactor
// artifact loaded from somewhere other than a module's own output, a classpath copy, two modules
// at one path or with one root, and a graph from any tool but Maven.

// reactorUnit is one application unit of a reactor plan.
type reactorUnit struct {
	id   string   // the unit module's ID
	path string   // its module path, slash-separated
	dir  string   // its module directory
	dirs []string // dir plus each reactor sibling on its runtime classpath, sorted
	tool string   // for a whole-tool unit, the build tool whose graph it is; "" for a reactor module
	// loads is the directory of every reactor sibling on its runtime classpath, code or none.
	loads []string
}

// whole reports whether u is one build tool's whole graph over the checkout's first-party
// classes, not one reactor module.
func (u reactorUnit) whole() bool { return u.tool != "" }

// reactorPlan is the units a reactor is searched as, and every module directory, by which a
// file is attributed to the module whose directory most closely holds it.
type reactorPlan struct {
	units      []reactorUnit
	moduleDirs []string
}

// byTool reports whether the plan splits a dual-tool checkout into one unit per build tool.
func (p *reactorPlan) byTool() bool { return len(p.units) > 0 && p.units[0].whole() }

// owner returns the directory of the module whose directory most closely holds path, or "".
func (p *reactorPlan) owner(path string) string {
	best := ""
	for _, d := range p.moduleDirs {
		if within(d, path) && len(d) > len(best) {
			best = d
		}
	}
	return best
}

// withUnit scopes the dependency closure to the runtime classpath of the reactor module id.
func withUnit(id string) Option {
	return func(a *analyzer) { a.unit = id }
}

// withTool scopes the dependency closure to the modules the build tool resolved.
func withTool(tool string) Option {
	return func(a *analyzer) { a.tool = tool }
}

// toolModules returns the modules of g the build tool resolved, never a classpath copy.
func toolModules(g *buildgraph.Graph, tool string) []buildgraph.Module {
	var out []buildgraph.Module
	for _, m := range g.Modules {
		if _, isCopy := m.Project(); !isCopy && g.ModuleTool(m) == tool {
			out = append(out, m)
		}
	}
	return out
}

// toolUnits splits a graph two build tools resolved into one unit per tool. Each tool's graph is
// the whole of what that build puts on the classpath, so it is searched over the checkout's
// first-party classes as a single-tool build is; two tools disagreeing on a version is then two
// searches, not one ambiguous classpath. A tool with more than one module with code, or with a
// classpath copy, cannot be placed beside another tool's whole build.
func toolUnits(g *buildgraph.Graph, buildDir string) (plan *reactorPlan, multi bool, why string) {
	plan = &reactorPlan{}
	for _, tool := range g.Tools() {
		mods := toolModules(g, tool)
		if len(mods) != len(toolGraph(g, tool).Modules) {
			return nil, true, "classpath copy in the " + tool + " build graph"
		}
		if m, w := multipleModules(toolGraph(g, tool), buildDir); m {
			return nil, true, tool + ": " + w
		}
		plan.units = append(plan.units, reactorUnit{id: tool, path: ".", dir: buildDir, dirs: []string{buildDir}, tool: tool})
	}
	return plan, false, ""
}

// toolOutputs returns the class outputs the build tool wrote: Maven's target/classes, Gradle's
// build/classes/<lang>/main.
func toolOutputs(tool string, outputs []classOutput) []classOutput {
	var out []classOutput
	for _, o := range outputs {
		wrote := "gradle"
		if filepath.Base(filepath.Dir(o.root)) == "target" {
			wrote = "maven"
		}
		if wrote == tool {
			out = append(out, o)
		}
	}
	return out
}

// toolGraph is g restricted to the modules the build tool resolved.
func toolGraph(g *buildgraph.Graph, tool string) *buildgraph.Graph {
	out := *g
	out.Modules = nil
	for _, m := range g.Modules {
		if g.ModuleTool(m) == tool {
			out.Modules = append(out.Modules, m)
		}
	}
	return &out
}

// unitModules returns the module of g whose ID is id, never a classpath copy.
func unitModules(g *buildgraph.Graph, id string) []buildgraph.Module {
	var out []buildgraph.Module
	for _, m := range g.Modules {
		if _, isCopy := m.Project(); !isCopy && m.ID == id {
			out = append(out, m)
		}
	}
	return out
}

// reactorUnits plans the per-unit search of the build at buildDir. plan is nil when the build
// graph holds at most one module with code; multi is set, with why, when it holds several and the
// plan cannot place every one.
func reactorUnits(buildDir string, opts ...Option) (plan *reactorPlan, multi bool, why string) {
	g := BuildGraph(opts...)
	if g == nil {
		return nil, false, ""
	}
	if len(g.Tools()) > 1 {
		return toolUnits(g, buildDir)
	}
	multi, why = multipleModules(g, buildDir)
	if !multi {
		return nil, false, ""
	}
	sources, err := javaFiles(buildDir)
	if err != nil {
		return nil, true, why + ": " + err.Error()
	}
	roots := classOutputRoots(buildDir)
	launch := func(dir string, code bool) bool {
		var own []string
		for _, r := range roots {
			if classOutputProject(r) == dir {
				own = append(own, r)
			}
		}
		return launchSignal(buildDir, dir, own, code)
	}
	plan, failure := planUnits(g, buildDir, sources, classOutputProjects(roots), launch)
	if plan == nil {
		return nil, true, why + ": " + failure
	}
	return plan, false, ""
}

// planUnits places every module with code of g as a unit or as a reactor sibling a unit loads.
// sources are the build's .java files, outputs the project directories of its class output, and
// launch reports whether a module directory with code carries launch evidence of its own, and
// whether one without code is other than provably inert. On failure the plan is nil and failure says what could not be placed.
func planUnits(g *buildgraph.Graph, buildDir string, sources, outputs []string, launch func(dir string, code bool) bool) (plan *reactorPlan, failure string) {
	if tools := g.Tools(); len(tools) != 1 || tools[0] != "maven" {
		return nil, "not a Maven reactor (" + strings.Join(tools, ", ") + ")"
	}
	var mods []buildgraph.Module
	paths := map[string]bool{}
	byRoot := map[string]int{}
	for _, m := range g.Modules {
		if _, isCopy := m.Project(); isCopy {
			return nil, "classpath copy " + m.ID
		}
		if paths[m.Path] {
			return nil, "two modules at " + m.Path
		}
		paths[m.Path] = true
		if _, dup := byRoot[m.Root]; dup {
			return nil, "two modules with root " + m.Root
		}
		byRoot[m.Root] = len(mods)
		mods = append(mods, m)
	}
	byCoord := map[string]int{}
	for i, m := range mods {
		for _, n := range m.Nodes {
			if n.ID == m.Root {
				byCoord[strings.ToLower(n.Group+":"+n.Artifact)] = i
			}
		}
		for _, a := range m.Aliases {
			byCoord[strings.ToLower(a)] = i
		}
	}

	dirs := make([]string, len(mods))
	byDir := map[string]int{}
	for i, m := range mods {
		dirs[i] = filepath.Join(buildDir, filepath.FromSlash(m.Path))
		byDir[dirs[i]] = i
	}
	plan = &reactorPlan{moduleDirs: dirs}
	code := make([]bool, len(mods))
	for _, s := range sources {
		if !isMainSource(buildDir, s) {
			continue
		}
		if i, ok := byDir[plan.owner(s)]; ok && within(filepath.Join(dirs[i], "src"), s) {
			code[i] = true
		}
	}
	for _, o := range outputs {
		if i, ok := byDir[o]; ok {
			code[i] = true
		}
	}

	// A module without code that loads reactor siblings (a dist, assembly or shading module) may
	// ship their classes as a program, in more ways than launch evidence can list: it is a unit of
	// those classes on its own classpath unless it is provably inert (launch reports false), and
	// a unit with no main it can resolve withholds. One that loads none, an aggregator whose
	// profile its children inherit, ships no first-party code; the children carry that evidence
	// themselves.
	packs := make([]bool, len(mods))
	referenced := make([]bool, len(mods))
	siblings := make([][]int, len(mods))
	for i, m := range mods {
		if !code[i] && !launch(dirs[i], false) {
			continue
		}
		var refs []int
		for _, n := range m.Nodes {
			if n.ID == m.Root {
				continue
			}
			j, isRoot := byRoot[n.ID]
			if !isRoot {
				var isReactor bool
				j, isReactor = byCoord[strings.ToLower(n.Group+":"+n.Artifact)]
				if !isReactor {
					continue
				}
				// A reactor artifact other than a module's own output (a test-jar, a classified
				// or relocated build) is not code the plan can place.
				if runtimeScope(n.Scope) {
					return nil, m.Path + " loads reactor artifact " + n.ID + ", not a module's own output"
				}
			}
			if j == i {
				continue
			}
			refs = append(refs, j)
			if isRoot && runtimeScope(n.Scope) {
				siblings[i] = append(siblings[i], j)
			}
		}
		if !code[i] {
			if packs[i] = len(siblings[i]) > 0; !packs[i] {
				continue
			}
		}
		for _, j := range refs {
			referenced[j] = true
		}
	}

	covered := make([]bool, len(mods))
	for i, m := range mods {
		// A module another loads is a unit too when it also ships on its own: it runs there on
		// its own resolved versions, which mediation in the loading module may not share.
		if !packs[i] && (!code[i] || referenced[i] && !launch(dirs[i], true)) {
			continue
		}
		u := reactorUnit{id: m.ID, path: m.Path, dir: dirs[i], dirs: []string{dirs[i]}}
		covered[i] = true
		for _, j := range siblings[i] {
			covered[j] = true
			u.loads = append(u.loads, dirs[j])
			if code[j] && !slices.Contains(u.dirs, dirs[j]) {
				u.dirs = append(u.dirs, dirs[j])
			}
		}
		sort.Strings(u.dirs)
		plan.units = append(plan.units, u)
	}
	if len(plan.units) == 0 {
		return nil, "no module with code is an application unit"
	}
	searched := map[string]bool{}
	for i, m := range mods {
		if code[i] && !covered[i] {
			return nil, m.Path + " has code no application unit loads"
		}
		if code[i] {
			searched[dirs[i]] = true
		}
	}
	for _, s := range sources {
		if !isMainSource(buildDir, s) {
			continue
		}
		if !searched[plan.owner(s)] {
			return nil, relSlash(buildDir, s) + " is in no module the units load"
		}
	}
	for _, o := range outputs {
		if !searched[o] {
			return nil, "class output in " + relSlash(buildDir, o) + " is in no module the units load"
		}
	}
	sort.Slice(plan.units, func(i, j int) bool { return plan.units[i].path < plan.units[j].path })
	return plan, ""
}

// unitOutput is a unit's own module output, from which its launch entry is read.
type unitOutput struct {
	dir     string
	roots   []string
	classes []classfile.Class
	// siblingRepackages is set when a reactor sibling the unit loads may publish an artifact
	// carrying classes besides its own (mavenRepackages): the unit's runtime classpath then holds
	// classes its loaded closure, read from the sibling's class output, does not.
	siblingRepackages bool
}

// unitBytecode is the first-party view of unit u: the class output of its directories, checked
// against files, the main sources those directories own (unitFiles), with the unit module's own
// output kept apart for the launch entry.
func unitBytecode(buildDir string, u reactorUnit, outputs []classOutput, files []fileParse) *firstPartyBytecode {
	var kept []classOutput
	own := &unitOutput{dir: u.dir}
	for _, o := range outputs {
		d := classOutputProject(o.root)
		if !slices.Contains(u.dirs, d) {
			continue
		}
		kept = append(kept, o)
		if d == u.dir {
			own.roots = append(own.roots, o.root)
			own.classes = append(own.classes, o.classes...)
		}
	}
	for _, d := range u.loads {
		if mavenRepackages(buildDir, d) {
			own.siblingRepackages = true
		}
	}
	fp := assembleFirstParty(buildDir, kept, files)
	fp.unit = own
	return fp
}

// unitFiles returns the parsed files the unit's directories own.
func unitFiles(plan *reactorPlan, u reactorUnit, files []fileParse) []fileParse {
	var out []fileParse
	for _, f := range files {
		if slices.Contains(u.dirs, plan.owner(f.path)) {
			out = append(out, f)
		}
	}
	return out
}

// unitsReachability searches the dependency sinks in every unit of plan and combines the
// answers. A path any unit finds is reported, the first unit's, its trace starting in that
// unit's classes. A sink is Searched only when every unit searched it with no path. Reasons and
// scoped reasons are the union over the units.
func unitsReachability(ctx context.Context, buildDir string, prog *program, plan *reactorPlan, outputs []classOutput, sinks []string, opts ...Option) ([]plugin.ReachPath, []string, map[string]bool, []plugin.ScopedReason, error) {
	reasons := map[string]bool{}
	var paths []plugin.ReachPath
	var scoped []plugin.ScopedReason
	seenScoped := map[string]bool{}
	pathFound := map[string]bool{}
	searchedBy := map[string]int{}
	for _, u := range plan.units {
		files, fp, uopt := prog.files, (*firstPartyBytecode)(nil), withTool(u.tool)
		if u.whole() {
			own := toolOutputs(u.tool, outputs)
			if len(own) == 0 {
				// No class output is that tool's own, and the merged set would run another build's
				// classes on this tool's dependencies: this unit searches nothing.
				reasons[plugin.PartialReasonReachabilityUndetermined] = true
				continue
			}
			fp = assembleFirstParty(buildDir, own, prog.files)
		} else {
			files = unitFiles(plan, u, prog.files)
			fp = unitBytecode(buildDir, u, outputs, files)
			uopt = withUnit(u.id)
		}
		uopts := append(append([]Option{}, opts...), uopt)
		bp, searched, br, sc, err := bytecodeReachability(ctx, buildDir, files, fp, sinks, uopts...)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		for _, p := range bp {
			if !pathFound[p.Sink.SCIP] {
				pathFound[p.Sink.SCIP] = true
				paths = append(paths, p)
			}
		}
		unitSearched := map[string]bool{}
		for _, s := range searched {
			if !unitSearched[s] {
				unitSearched[s] = true
				searchedBy[s]++
			}
		}
		for r := range br {
			reasons[r] = true
		}
		for _, s := range sc {
			key := s.Reason + "\x00" + s.Package + "\x00" + s.Path + "\x00" + strings.Join(s.Targets, "\x00")
			if !seenScoped[key] {
				seenScoped[key] = true
				scoped = append(scoped, s)
			}
		}
	}
	var searched []string
	listed := map[string]bool{}
	for _, id := range sinks {
		if searchedBy[id] == len(plan.units) && !pathFound[id] && !listed[id] {
			listed[id] = true
			searched = append(searched, id)
		}
	}
	return paths, searched, reasons, scoped, nil
}
