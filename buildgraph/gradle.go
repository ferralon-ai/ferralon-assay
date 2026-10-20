package buildgraph

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
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
	Gradle              string                                `json:"gradle"`
	Java                string                                `json:"java"`
	JavaVendor          string                                `json:"java_vendor"`
	Path                string                                `json:"path"`
	Dir                 string                                `json:"dir"`
	RootDir             string                                `json:"root_dir"`
	Group               string                                `json:"group"`
	Name                string                                `json:"name"`
	Version             string                                `json:"version"`
	HasRuntimeClasspath bool                                  `json:"has_runtime_classpath"`
	OtherRuntime        []string                              `json:"other_runtime_classpaths"`
	Projects            map[string]gradleCoord                `json:"projects"`
	Components          []gradleComponent                     `json:"components"`
	Edges               []Edge                                `json:"edges"`
	Unresolved          []struct{ Requested, Failure string } `json:"unresolved"`
	Files               []gradleFile                          `json:"files"`
}

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
		m, err := gradleModule(p)
		if err != nil {
			return nil, err
		}
		g.Modules = append(g.Modules, m)
	}
	g.Subject.Inputs, err = collectInputs(r.dir, gradleInput)
	if err != nil {
		return nil, err
	}
	return g, nil
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

// gradleModule translates one project's runtimeClasspath. A module component becomes one node
// per artifact file, typed by extension with the classifier read from the file name, or one pom
// node when it has no artifact; an edge between components joins all their nodes. A project
// component is a sibling: one jar node and no file.
func gradleModule(p gradleProject) (Module, error) {
	rel, ok := relPath(p.RootDir, p.Dir)
	if !ok {
		return Module{}, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: "project " + p.Path + " outside the root"}
	}
	if rel == "" {
		rel = "."
	}
	if len(p.Unresolved) > 0 {
		var log strings.Builder
		for _, u := range p.Unresolved {
			log.WriteString(u.Requested + ": " + u.Failure + "\n")
		}
		f := classify(stepResolve, []byte(log.String()))
		return Module{}, f
	}
	self := gradleCoord{Group: p.Group, Name: p.Name, Version: p.Version}
	root := Node{ID: NodeID(self.Group, self.Name, "jar", "", self.Version), Group: self.Group, Artifact: self.Name, Version: self.Version, Type: "jar"}
	m := Module{ID: p.Path, Path: rel, Root: root.ID, Nodes: []Node{root}}
	if !p.HasRuntimeClasspath {
		var others []string
		for _, c := range p.OtherRuntime {
			if c != "testRuntimeClasspath" {
				others = append(others, c)
			}
		}
		if len(others) > 0 {
			return Module{}, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: "project " + p.Path + " has no runtimeClasspath, only " + strings.Join(others, ", ")}
		}
		return m, nil
	}

	files := map[string][]gradleFile{}
	for _, f := range p.Files {
		files[f.Component] = append(files[f.Component], f)
	}
	byKey := map[string][]string{}
	seen := map[string]*File{root.ID: nil}
	add := func(key string, n Node) error {
		byKey[key] = append(byKey[key], n.ID)
		if prev, dup := seen[n.ID]; dup {
			if prev != nil && n.File != nil && prev.Path != n.File.Path {
				return &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: n.ID + " resolved to " + prev.Path + " and " + n.File.Path}
			}
			return nil
		}
		seen[n.ID] = n.File
		m.Nodes = append(m.Nodes, n)
		return nil
	}
	for _, c := range p.Components {
		var err error
		switch {
		case c.ID.Project != "":
			if c.ID.Project == p.Path && c.ID.Build == ":" {
				byKey[c.Key] = []string{root.ID}
				delete(files, c.Key)
				continue
			}
			sib, ok := p.Projects[c.ID.Project]
			if !ok || c.ID.Build != ":" {
				return Module{}, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: "project component outside this build: " + c.Key}
			}
			// A sibling's own artifact is built, not resolved; its file is not this graph's.
			delete(files, c.Key)
			err = add(c.Key, Node{ID: NodeID(sib.Group, sib.Name, "jar", "", sib.Version), Group: sib.Group, Artifact: sib.Name, Version: sib.Version, Type: "jar", Scope: "runtime"})
		case c.ID.Name != "":
			fs := files[c.Key]
			delete(files, c.Key)
			if len(fs) == 0 {
				err = add(c.Key, Node{ID: NodeID(c.ID.Group, c.ID.Name, "pom", "", c.ID.Version), Group: c.ID.Group, Artifact: c.ID.Name, Version: c.ID.Version, Type: "pom", Scope: "runtime"})
				break
			}
			sort.Slice(fs, func(i, j int) bool { return fs[i].File < fs[j].File })
			for _, f := range fs {
				name := f.Name
				if name == "" {
					name = filepath.Base(f.File)
				}
				typ, classifier := gradleArtifact(c.ID.Name, c.ID.Version, name)
				sum, sumErr := sha256File(f.File)
				if sumErr != nil {
					return Module{}, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: sumErr.Error()}
				}
				if err = add(c.Key, Node{
					ID: NodeID(c.ID.Group, c.ID.Name, typ, classifier, c.ID.Version), Group: c.ID.Group, Artifact: c.ID.Name, Version: c.ID.Version,
					Type: typ, Classifier: classifier, Scope: "runtime", File: &File{Path: f.File, SHA256: sum},
				}); err != nil {
					break
				}
			}
		default:
			return Module{}, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: "unsupported component " + c.Key}
		}
		if err != nil {
			return Module{}, err
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
		return Module{}, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: "project " + p.Path + " has file dependencies without a coordinate:\n" + log.String()}
	}
	edges := map[Edge]bool{}
	for _, e := range p.Edges {
		from, to := byKey[e.From], byKey[e.To]
		if len(from) == 0 || len(to) == 0 {
			return Module{}, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: "edge to an unlisted component: " + e.From + " -> " + e.To}
		}
		for _, f := range from {
			for _, t := range to {
				if f != t && !edges[Edge{From: f, To: t}] {
					edges[Edge{From: f, To: t}] = true
					m.Edges = append(m.Edges, Edge{From: f, To: t})
				}
			}
		}
	}
	return m, nil
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
// properties Gradle reads, and everything under buildSrc.
func gradleInput(rel, name string) bool {
	switch {
	case strings.HasSuffix(name, ".gradle"), strings.HasSuffix(name, ".gradle.kts"),
		name == "gradle.properties", strings.HasSuffix(name, ".versions.toml"),
		strings.HasSuffix(name, ".lockfile"), name == "gradle-wrapper.properties",
		strings.HasPrefix(rel, "buildSrc/"):
		return true
	}
	return false
}
