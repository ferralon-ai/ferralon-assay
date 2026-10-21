package buildgraph

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

//go:embed assay-buildgraph.init.gradle
var gradleInitScript []byte

// Gradle steps, as they appear in commands[] and in tool_failed:<step>.
const (
	stepGraph      = "graph"
	stepConditions = "conditions"
	stepResolve    = "resolve"
)

// gradleProject is one project's assayBuildGraph output.
type gradleProject struct {
	Gradle       string                     `json:"gradle"`
	Java         string                     `json:"java"`
	JavaVendor   string                     `json:"java_vendor"`
	Path         string                     `json:"path"`
	Dir          string                     `json:"dir"`
	RootDir      string                     `json:"root_dir"`
	Group        string                     `json:"group"`
	Name         string                     `json:"name"`
	Version      string                     `json:"version"`
	JDKToolchain string                     `json:"jdk_toolchain"`
	OtherRuntime []string                   `json:"other_runtime_classpaths"`
	Projects     map[string]gradleCoord     `json:"projects"`
	Classpaths   map[string]gradleClasspath `json:"classpaths"`
}

// gradleClasspath is one configuration as Gradle resolved it.
type gradleClasspath struct {
	Components []gradleComponent                     `json:"components"`
	Edges      []Edge                                `json:"edges"`
	Unresolved []struct{ Requested, Failure string } `json:"unresolved"`
	Files      []gradleFile                          `json:"files"`
}

// The classpaths the producer reads, in precedence order, and the scope each contributes.
// Gradle mediates each configuration on its own, so one coordinate can resolve to different
// versions on each; the runtime classpath's version is the one the application runs, and wins.
// A key on runtimeClasspath and compileClasspath is compile scope; compile-only is provided, as
// a container supplies it at run time; test-only, or only on another runtime classpath, is test. This is the Maven tree's shape: one
// version per key per module, at the strongest scope.
const (
	gradleRuntime = "runtimeClasspath"
	gradleCompile = "compileClasspath"
	gradleTest    = "testRuntimeClasspath"
)

// gradleFile is one resolved artifact: its component, its file, and the name it was published
// under, which the cache's file name may not keep.
type gradleFile struct {
	Component string `json:"component"`
	File      string `json:"file"`
	Name      string `json:"name"`
}

type gradleCoord struct {
	Group   string `json:"group"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type gradleComponent struct {
	Key string `json:"key"`
	ID  struct {
		Group   string `json:"group"`
		Name    string `json:"name"`
		Version string `json:"version"`
		Project string `json:"project"`
		Build   string `json:"build"`
		Other   string `json:"other"`
	} `json:"id"`
}

func resolveGradle(ctx context.Context, r *runner, c Conditions) (*Graph, error) {
	if len(c.Profiles) > 0 {
		return nil, &Failure{Kind: KindToolFailed, Detail: stepConditions, Log: "Gradle has no profiles; stated: " + strings.Join(c.Profiles, ",")}
	}
	script := filepath.Join(r.work, "assay-buildgraph.init.gradle")
	if err := os.WriteFile(script, gradleInitScript, 0o644); err != nil {
		return nil, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: err.Error()}
	}
	out := filepath.Join(r.work, "gradle")
	if err := os.MkdirAll(out, 0o755); err != nil {
		return nil, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: err.Error()}
	}
	// The project cache and problems report would otherwise land in the checkout.
	args := []string{"-q", "--no-configuration-cache", "--project-cache-dir", filepath.Join(r.work, "pcache"),
		"-Dorg.gradle.problems.report=false", "--init-script", script, "-Dassay.out=" + out}
	keys := make([]string, 0, len(c.Properties))
	for k := range c.Properties {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "-P"+k+"="+c.Properties[k])
	}
	args = append(args, "assayBuildGraph")
	if _, err := r.run(ctx, stepGraph, args...); err != nil {
		return nil, err
	}

	projects, err := readGradleProjects(out)
	if err != nil {
		return nil, err
	}
	first := projects[0]
	// Gradle looks upward for a settings file, so a directory inside a larger build runs that build.
	if !sameDir(first.RootDir, r.dir) {
		return nil, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: "Gradle ran the build rooted at " + first.RootDir + ", not " + r.dir}
	}
	g := &Graph{
		Tool: Tool{Name: "gradle", Version: first.Gradle},
		JVM:  JVM{Version: first.Java, Vendor: first.JavaVendor},
	}
	if f := checkJDK(c.JDK, g.JVM.Version); f != nil {
		return nil, f
	}
	for _, p := range projects {
		ms, err := gradleModule(p)
		if err != nil {
			return nil, err
		}
		if p.JDKToolchain != "" {
			for i := range ms {
				ms[i].JDKToolchains = []string{p.JDKToolchain}
			}
		}
		g.Modules = append(g.Modules, ms...)
	}
	if g.Subject.IncludedBuilds, g.Subject.UnbindableIncludedBuilds, err = gradleIncludedBuilds(out, r.dir); err != nil {
		return nil, err
	}
	g.Subject.Inputs, err = gradleBuildInputs(r.dir, g.Subject.IncludedBuilds)
	if err != nil {
		return nil, err
	}
	return g, nil
}

// gradleIncludedBuilds reads the directories the init script recorded for the included builds:
// inside, by slash path from the checkout once symlinks are resolved, and outside, absolute. An
// included build outside the checkout cannot be bound to the graph, so only the run that resolved
// it may use the graph. The root build's own includes must all be among those recorded; one that
// is not means the init script missed a nested build, whose build logic would go unbound.
func gradleIncludedBuilds(out, root string) (inside, outside []string, err error) {
	fail := func(log string) error { return &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: log} }
	read := func(sub string) ([]string, error) {
		entries, err := os.ReadDir(filepath.Join(out, sub))
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, fail(err.Error())
		}
		var paths []string
		for _, e := range entries {
			b, err := os.ReadFile(filepath.Join(out, sub, e.Name()))
			if err != nil {
				return nil, fail(err.Error())
			}
			p := strings.TrimSpace(string(b))
			if p == "" || !filepath.IsAbs(p) {
				return nil, fail("included build recorded without an absolute path: " + p)
			}
			paths = append(paths, p)
		}
		return paths, nil
	}
	recorded, err := read("included")
	if err != nil {
		return nil, nil, err
	}
	direct, err := read("direct")
	if err != nil {
		return nil, nil, err
	}
	seen := map[string]bool{}
	key := func(p string) (string, bool) {
		rel, ok := realRel(root, p)
		if !ok {
			if r, err := evalExisting(p); err == nil {
				return filepath.ToSlash(r), false
			}
			return filepath.ToSlash(filepath.Clean(p)), false
		}
		return rel, true
	}
	for _, p := range recorded {
		k, in := key(p)
		if k == "." {
			return nil, nil, fail("the root build includes itself, so every file in the checkout would be a build input")
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		if in {
			inside = append(inside, k)
		} else {
			outside = append(outside, k)
		}
	}
	for _, p := range direct {
		if k, _ := key(p); !seen[k] {
			return nil, nil, fail("included build " + p + " was not recorded by the init script, so its build logic cannot be bound to the graph")
		}
	}
	sort.Strings(inside)
	sort.Strings(outside)
	return inside, outside, nil
}

// gradleBuildInputs is every file gradleInput accepts under dir, and every file of buildSrc and of
// each included build, each walked from its own directory.
func gradleBuildInputs(dir string, included []string) ([]Input, error) {
	inputs, err := collectInputs(dir, gradleInput)
	if err != nil {
		return nil, err
	}
	trees := included
	if fi, err := os.Stat(filepath.Join(dir, "buildSrc")); err == nil && fi.IsDir() && !slices.Contains(included, "buildSrc") {
		trees = append(slices.Clone(included), "buildSrc")
	}
	byPath := map[string]Input{}
	for _, in := range inputs {
		byPath[in.Path] = in
	}
	for _, d := range trees {
		// Gradle builds a buildSrc no settings file names; an empty one holds nothing to bind.
		tree, err := collectTree(dir, d, d != "buildSrc" || slices.Contains(included, d))
		if err != nil {
			return nil, err
		}
		for _, in := range tree {
			byPath[in.Path] = in
		}
	}
	out := make([]Input, 0, len(byPath))
	for _, in := range byPath {
		out = append(out, in)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// readGradleProjects reads every project's output. All of them must agree on the root, the
// Gradle version and the JVM, and each must cover the whole project set.
func readGradleProjects(dir string) ([]gradleProject, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: err.Error()}
	}
	var out []gradleProject
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasPrefix(e.Name(), "project") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: err.Error()}
		}
		var p gradleProject
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: e.Name() + ": " + err.Error()}
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: "no project output"}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	first := out[0]
	if len(out) != len(first.Projects) {
		return nil, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: fmt.Sprintf("%d project outputs for %d projects", len(out), len(first.Projects))}
	}
	for _, p := range out {
		if _, ok := first.Projects[p.Path]; !ok || p.RootDir != first.RootDir || p.Gradle != first.Gradle || p.Java != first.Java {
			return nil, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: "project outputs disagree at " + p.Path}
		}
	}
	return out, nil
}

// gradleModule folds one project's classpaths into a module: the three, then any other runtime
// classpath beside runtimeClasspath. Each classpath is
// translated on its own (gradleClasspathNodes); then each g:a:type:classifier keeps the node of
// the first classpath in precedence order that has it, at the scope gradleScope gives, and every
// classpath's edges are joined onto the kept nodes. A later classpath's copy at another version
// goes to that classpath's copy module (classpathCopies), returned after the project's own.
func gradleModule(p gradleProject) ([]Module, error) {
	rel, ok := relPath(p.RootDir, p.Dir)
	if !ok {
		return nil, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: "project " + p.Path + " outside the root"}
	}
	if rel == "" {
		rel = "."
	}
	self := gradleCoord{Group: p.Group, Name: p.Name, Version: p.Version}
	root := Node{ID: NodeID(self.Group, self.Name, "jar", "", self.Version), Group: self.Group, Artifact: self.Name, Version: self.Version, Type: "jar"}
	m := Module{ID: p.Path, Path: rel, Root: root.ID, Nodes: []Node{root}}
	var others []string
	for _, c := range p.OtherRuntime {
		if c != gradleRuntime && c != gradleTest {
			others = append(others, c)
		}
	}
	if _, ok := p.Classpaths[gradleRuntime]; !ok && len(others) > 0 {
		return nil, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: "project " + p.Path + " has no runtimeClasspath, only " + strings.Join(others, ", ")}
	}
	// Beside runtimeClasspath, every other runtime classpath folds in at test scope: a copy only
	// one of them resolves is still in the build, so leaving it out would claim it absent.
	for _, c := range others {
		if _, ok := p.Classpaths[c]; !ok {
			return nil, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: "project " + p.Path + ": " + c + " was not resolved"}
		}
	}

	var cps []gradleTranslated
	onCompile := map[string]bool{}
	for _, name := range append([]string{gradleRuntime, gradleCompile, gradleTest}, others...) {
		cp, ok := p.Classpaths[name]
		if !ok {
			continue
		}
		nodes, ids, err := gradleClasspathNodes(p, name, cp, root)
		if err != nil {
			return nil, err
		}
		if name == gradleCompile {
			for _, n := range nodes {
				onCompile[n.Key()] = true
			}
		}
		var edges []Edge
		for _, e := range cp.Edges {
			from, to := ids[e.From], ids[e.To]
			if len(from) == 0 || len(to) == 0 {
				return nil, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: name + ": edge to an unlisted component: " + e.From + " -> " + e.To}
			}
			for _, f := range from {
				for _, t := range to {
					if f != t {
						edges = append(edges, Edge{From: f, To: t})
					}
				}
			}
		}
		cps = append(cps, gradleTranslated{name: name, nodes: nodes, ids: ids, edges: edges})
	}

	kept := map[string]string{root.Key(): root.ID}
	for _, cp := range cps {
		for _, n := range cp.nodes {
			if _, dup := kept[n.Key()]; dup {
				continue
			}
			kept[n.Key()] = n.ID
			n.Scope = gradleScope(cp.name, onCompile[n.Key()])
			m.Nodes = append(m.Nodes, n)
		}
	}
	keyOf := map[string]string{}
	for _, cp := range cps {
		for _, n := range cp.nodes {
			keyOf[n.ID] = n.Key()
		}
	}
	keyOf[root.ID] = root.Key()
	seen := map[Edge]bool{}
	for _, cp := range cps {
		for _, e := range cp.edges {
			k := Edge{From: kept[keyOf[e.From]], To: kept[keyOf[e.To]]}
			if k.From != k.To && !seen[k] {
				seen[k] = true
				m.Edges = append(m.Edges, k)
			}
		}
	}
	return append([]Module{m}, classpathCopies(m, cps, onCompile)...), nil
}

// gradleTranslated is one classpath translated onto node IDs.
type gradleTranslated struct {
	name  string
	nodes []Node
	ids   map[string][]string
	edges []Edge
}

// classpathCopies keeps what the fold into m drops: a component a later classpath resolved at a
// version other than the one m kept. Each such classpath gets a copy module holding m's root and
// those copies at that classpath's scope, so a version question sees every version the classpaths
// resolved for a component other than the project itself. A copy an earlier module already holds
// is not repeated.
func classpathCopies(m Module, cps []gradleTranslated, onCompile map[string]bool) []Module {
	held := map[string]bool{}
	for _, n := range m.Nodes {
		held[n.ID] = true
	}
	var root Node
	for _, n := range m.Nodes {
		if n.ID == m.Root {
			root = n
		}
	}
	var out []Module
	for _, cp := range cps {
		c := Module{ID: ClasspathCopyID(m.ID, cp.name), CopyOf: m.ID, Path: m.Path, Root: m.Root, Nodes: []Node{root}}
		in := map[string]bool{m.Root: true}
		for _, n := range cp.nodes {
			if held[n.ID] || n.Key() == root.Key() {
				continue
			}
			held[n.ID] = true
			in[n.ID] = true
			n.Scope = gradleScope(cp.name, onCompile[n.Key()])
			c.Nodes = append(c.Nodes, n)
		}
		if len(c.Nodes) == 1 {
			continue
		}
		for _, e := range cp.edges {
			if in[e.From] && in[e.To] {
				c.Edges = append(c.Edges, e)
			}
		}
		out = append(out, c)
	}
	return out
}

// gradleScope is the scope of a node kept from classpath cp.
func gradleScope(cp string, onCompile bool) string {
	switch {
	case cp == gradleRuntime && onCompile:
		return "compile"
	case cp == gradleRuntime:
		return "runtime"
	case cp == gradleCompile:
		return "provided"
	}
	return "test"
}

// gradleClasspathNodes translates one classpath. A module component becomes one node per
// artifact file, typed by extension with the classifier read from the file name, or one pom
// node when it has no artifact. A project component is a sibling: one jar node and no file; the
// project itself maps to root. ids maps each component key to its node ids.
func gradleClasspathNodes(p gradleProject, name string, cp gradleClasspath, root Node) ([]Node, map[string][]string, error) {
	if len(cp.Unresolved) > 0 {
		var log strings.Builder
		for _, u := range cp.Unresolved {
			log.WriteString(name + ": " + u.Requested + ": " + u.Failure + "\n")
		}
		return nil, nil, classify(stepResolve, []byte(log.String()))
	}
	files := map[string][]gradleFile{}
	for _, f := range cp.Files {
		files[f.Component] = append(files[f.Component], f)
	}
	var nodes []Node
	ids := map[string][]string{}
	seen := map[string]*File{root.ID: nil}
	add := func(key string, n Node) error {
		ids[key] = append(ids[key], n.ID)
		if prev, dup := seen[n.ID]; dup {
			if prev != nil && n.File != nil && prev.Path != n.File.Path {
				return &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: name + ": " + n.ID + " resolved to " + prev.Path + " and " + n.File.Path}
			}
			return nil
		}
		seen[n.ID] = n.File
		nodes = append(nodes, n)
		return nil
	}
	for _, c := range cp.Components {
		var err error
		switch {
		case c.ID.Project != "":
			if c.ID.Project == p.Path && c.ID.Build == ":" {
				ids[c.Key] = []string{root.ID}
				delete(files, c.Key)
				continue
			}
			sib, ok := p.Projects[c.ID.Project]
			if !ok || c.ID.Build != ":" {
				return nil, nil, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: "project component outside this build: " + c.Key}
			}
			// A sibling's own artifact is built, not resolved; its file is not this graph's.
			delete(files, c.Key)
			err = add(c.Key, Node{ID: NodeID(sib.Group, sib.Name, "jar", "", sib.Version), Group: sib.Group, Artifact: sib.Name, Version: sib.Version, Type: "jar"})
		case c.ID.Name != "":
			fs := files[c.Key]
			delete(files, c.Key)
			if len(fs) == 0 {
				err = add(c.Key, Node{ID: NodeID(c.ID.Group, c.ID.Name, "pom", "", c.ID.Version), Group: c.ID.Group, Artifact: c.ID.Name, Version: c.ID.Version, Type: "pom"})
				break
			}
			sort.Slice(fs, func(i, j int) bool { return fs[i].File < fs[j].File })
			for _, f := range fs {
				fname := f.Name
				if fname == "" {
					fname = filepath.Base(f.File)
				}
				typ, classifier := gradleArtifact(c.ID.Name, c.ID.Version, fname)
				sum, sumErr := sha256File(f.File)
				if sumErr != nil {
					return nil, nil, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: sumErr.Error()}
				}
				if err = add(c.Key, Node{
					ID: NodeID(c.ID.Group, c.ID.Name, typ, classifier, c.ID.Version), Group: c.ID.Group, Artifact: c.ID.Name, Version: c.ID.Version,
					Type: typ, Classifier: classifier, File: &File{Path: f.File, SHA256: sum},
				}); err != nil {
					break
				}
			}
		default:
			return nil, nil, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: "unsupported component " + c.Key}
		}
		if err != nil {
			return nil, nil, err
		}
	}
	// What remains is on the classpath without a component: files() and fileTree() dependencies,
	// which have no coordinate to record.
	if len(files) > 0 {
		var log strings.Builder
		for _, fs := range files {
			for _, f := range fs {
				log.WriteString(f.File + "\n")
			}
		}
		return nil, nil, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: "project " + p.Path + " " + name + " has file dependencies without a coordinate:\n" + log.String()}
	}
	return nodes, ids, nil
}

// gradleArtifact reads the type and classifier from an artifact file named
// <name>-<version>[-<classifier>].<ext>. A file named otherwise has its extension as its type
// and no classifier.
func gradleArtifact(name, version, file string) (typ, classifier string) {
	ext := path.Ext(file)
	typ = strings.TrimPrefix(ext, ".")
	if typ == "" {
		typ = "jar"
	}
	stem := strings.TrimSuffix(file, ext)
	if rest, ok := strings.CutPrefix(stem, name+"-"+version); ok {
		classifier = strings.TrimPrefix(rest, "-")
	}
	return typ, classifier
}

// gradleInput accepts the build scripts, properties, version catalogs, lockfiles and wrapper
// properties Gradle reads.
func gradleInput(rel, name string) bool {
	switch {
	case strings.HasSuffix(name, ".gradle"), strings.HasSuffix(name, ".gradle.kts"),
		name == "gradle.properties", strings.HasSuffix(name, ".versions.toml"),
		strings.HasSuffix(name, ".lockfile"), name == "gradle-wrapper.properties":
		return true
	}
	return false
}
