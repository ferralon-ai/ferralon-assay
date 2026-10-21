// Package buildgraph produces and checks a JVM project's dependency graph as the project's own
// build tool resolves it. The repository's Maven or Gradle runs with the job's environment and
// JDK; the run conditions it is handed are recorded, never inferred. The result is an
// assay.buildgraph/v1 document bound to the checkout by the sha256 of every build input the
// tool read.
package buildgraph

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Schema is the only schema identifier this package writes or accepts.
const Schema = "assay.buildgraph/v1"

// Graph is one assay.buildgraph/v1 document.
type Graph struct {
	Schema     string     `json:"schema"`
	Producer   Producer   `json:"producer"`
	Tool       Tool       `json:"tool"`
	JVM        JVM        `json:"jvm"`
	Conditions Conditions `json:"conditions"`
	Subject    Subject    `json:"subject"`
	Modules    []Module   `json:"modules"`
	Commands   []Command  `json:"commands"`
	Sidecars   []Sidecar  `json:"sidecars,omitempty"`
}

// Producer identifies the build of the code that wrote the graph.
type Producer struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Tool is the build tool that resolved the graph. Wrapper is set when the repository's own
// wrapper script ran it.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Wrapper bool   `json:"wrapper"`
}

// JVM is the Java runtime the build tool reported running on.
type JVM struct {
	Version string `json:"version"`
	Vendor  string `json:"vendor,omitempty"`
}

// Conditions are the run conditions the producer was handed, recorded verbatim.
type Conditions struct {
	Profiles   []string          `json:"profiles,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	JDK        string            `json:"jdk,omitempty"`
}

// Subject binds the graph to the tree it was resolved from.
type Subject struct {
	Commit       string  `json:"commit,omitempty"`
	Tree         string  `json:"tree,omitempty"`
	Inputs       []Input `json:"inputs"`
	InputsDigest string  `json:"inputs_digest"`
}

// Input is one build file the tool read, by its slash-separated path from the repository root.
type Input struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Module is one Maven reactor module or Gradle project, or a classpath copy of a Gradle project:
// ID "<project>#<classpath>", the project's Path and Root, holding the components that classpath
// resolved at a version other than the one the project kept.
type Module struct {
	ID             string   `json:"id"`
	Path           string   `json:"path"`
	Root           string   `json:"root"`
	ActiveProfiles []string `json:"active_profiles,omitempty"`
	Nodes          []Node   `json:"nodes"`
	Edges          []Edge   `json:"edges"`
}

// classpathSep separates a classpath copy's project ID from its classpath name.
const classpathSep = "#"

// ClasspathCopyID is the ID of project's copy for classpath.
func ClasspathCopyID(project, classpath string) string { return project + classpathSep + classpath }

// Project returns the ID of the project m belongs to, and whether m is a classpath copy rather
// than the project itself. A consumer counting projects or their directories skips the copies.
func (m Module) Project() (id string, isCopy bool) {
	if i := strings.Index(m.ID, classpathSep); i >= 0 {
		return m.ID[:i], true
	}
	return m.ID, false
}

// Node is one resolved component. Root is the module itself. File is absent for the module
// root and for a reactor sibling the tool resolved to its own build output.
type Node struct {
	ID         string `json:"id"`
	Group      string `json:"group"`
	Artifact   string `json:"artifact"`
	Version    string `json:"version"`
	Type       string `json:"type,omitempty"`
	Classifier string `json:"classifier,omitempty"`
	Scope      string `json:"scope,omitempty"`
	Optional   bool   `json:"optional,omitempty"`
	File       *File  `json:"file,omitempty"`
}

// File is a resolved artifact on disk and its digest.
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Edge is a dependency of From on To, both node ids in the same module.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Command is one tool invocation the producer ran, with the tool named as invoked.
type Command struct {
	Step string   `json:"step"`
	Argv []string `json:"argv"`
	Exit int      `json:"exit"`
}

// Sidecar is a further tool output written beside the graph, such as the effective POM.
type Sidecar struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// NodeID is a node's identity within its module: group:artifact:type[:classifier]:version.
func NodeID(group, artifact, typ, classifier, version string) string {
	if typ == "" {
		typ = "jar"
	}
	if classifier == "" {
		return group + ":" + artifact + ":" + typ + ":" + version
	}
	return group + ":" + artifact + ":" + typ + ":" + classifier + ":" + version
}

// Key is the node's coordinate without its version, group:artifact:type:classifier: a module
// holds at most one node per key.
func (n Node) Key() string {
	return n.Group + ":" + n.Artifact + ":" + n.Type + ":" + n.Classifier
}

// InputsDigest is the sha256 over the inputs sorted by path, one "path\x00sha256\n" line each.
func InputsDigest(inputs []Input) string {
	sorted := append([]Input(nil), inputs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	h := sha256.New()
	for _, in := range sorted {
		fmt.Fprintf(h, "%s\x00%s\n", in.Path, in.SHA256)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Normalize puts every list in its canonical order, so the same resolution always serializes to
// the same bytes.
func (g *Graph) Normalize() {
	sort.Slice(g.Subject.Inputs, func(i, j int) bool { return g.Subject.Inputs[i].Path < g.Subject.Inputs[j].Path })
	if g.Subject.Inputs == nil {
		g.Subject.Inputs = []Input{}
	}
	sort.Slice(g.Modules, func(i, j int) bool {
		if g.Modules[i].Path != g.Modules[j].Path {
			return g.Modules[i].Path < g.Modules[j].Path
		}
		return g.Modules[i].ID < g.Modules[j].ID
	})
	for i := range g.Modules {
		m := &g.Modules[i]
		if m.Nodes == nil {
			m.Nodes = []Node{}
		}
		if m.Edges == nil {
			m.Edges = []Edge{}
		}
		sort.Slice(m.Nodes, func(a, b int) bool { return m.Nodes[a].ID < m.Nodes[b].ID })
		sort.Slice(m.Edges, func(a, b int) bool {
			if m.Edges[a].From != m.Edges[b].From {
				return m.Edges[a].From < m.Edges[b].From
			}
			return m.Edges[a].To < m.Edges[b].To
		})
	}
	sort.Slice(g.Sidecars, func(i, j int) bool { return g.Sidecars[i].Path < g.Sidecars[j].Path })
}

// Validate checks what the document alone can show: the schema, a tool version and JVM, the
// inputs digest, and that every module's root and edges name nodes it holds exactly once. It
// returns the failed check's name, or "" when the graph passes. Checks against the checkout and
// the scan's conditions belong to ingest.
func (g *Graph) Validate() string {
	switch {
	case g.Schema != Schema:
		return "schema"
	case strings.TrimSpace(g.Tool.Name) == "" || strings.TrimSpace(g.Tool.Version) == "":
		return "tool_version"
	case strings.TrimSpace(g.JVM.Version) == "":
		return "jvm"
	case g.Subject.InputsDigest != InputsDigest(g.Subject.Inputs):
		return "inputs_digest"
	case len(g.Modules) == 0:
		return "modules"
	}
	modules := map[string]bool{}
	for _, m := range g.Modules {
		if m.ID == "" || modules[m.ID] {
			return "module_id"
		}
		modules[m.ID] = true
		nodes := make(map[string]bool, len(m.Nodes))
		for _, n := range m.Nodes {
			if n.ID == "" || n.ID != NodeID(n.Group, n.Artifact, n.Type, n.Classifier, n.Version) {
				return "node_id"
			}
			if nodes[n.ID] {
				return "duplicate_node"
			}
			nodes[n.ID] = true
		}
		if !nodes[m.Root] {
			return "missing_node"
		}
		for _, e := range m.Edges {
			if !nodes[e.From] || !nodes[e.To] {
				return "missing_node"
			}
		}
	}
	byID := make(map[string]Module, len(g.Modules))
	for _, m := range g.Modules {
		byID[m.ID] = m
	}
	for _, m := range g.Modules {
		if id, isCopy := m.Project(); isCopy {
			if p, ok := byID[id]; !ok || p.Path != m.Path || p.Root != m.Root {
				return "classpath_copy"
			}
		}
	}
	return ""
}
