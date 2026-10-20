package javaanalysis

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// graph.go — the one source of a JVM build's dependencies: the assay.buildgraph/v1 graph the
// host resolved with the repository's own Maven or Gradle and checked against the checkout
// (buildgraph.Load) before it handed the plugin the file. The node set, every version, every
// scope and every artifact file come from it. Nothing here reads a build script, a lockfile or
// a cached POM to work them out; without a graph each op declares build_graph_absent.

// PartialReasonBuildGraphAbsent marks an op that ran without a build graph: the scan ran with
// the graph off, or the host could not hand one over. Nothing about the dependencies is known.
const PartialReasonBuildGraphAbsent = plugin.PartialReasonToolFailure + ":build_graph_absent"

// PartialReasonOtherToolBuild marks dependency facts read from a graph beside a build of the other
// tool: the graph covers its own build, and the other can resolve versions it never saw.
const PartialReasonOtherToolBuild = "other_tool_build"

// otherToolBuild reports whether buildDir holds a build of the tool that did not resolve g. A walk
// that fails leaves that unknown, which counts as there being one.
func otherToolBuild(g *buildgraph.Graph, buildDir string) bool {
	in, err := buildgraph.OtherToolInputs(buildDir, g.Tool.Name)
	return err != nil || len(in) > 0
}

// coverage is the Partiality of facts read from g: Complete, unless the checkout also holds a
// build of the other tool.
func coverage(uncovered bool) plugin.Partiality {
	if uncovered {
		return plugin.Partial(PartialReasonOtherToolBuild)
	}
	return plugin.Complete()
}

// WithBuildGraph points the ops at the build graph file the host accepted for this checkout. An
// empty file leaves them without one.
func WithBuildGraph(file string) Option {
	return func(a *analyzer) { a.graphFile = file }
}

// graphMemo keeps the last decoded graph: every op subprocess call reads the same file.
var graphMemo struct {
	sync.Mutex
	file string
	g    *buildgraph.Graph
}

// BuildGraph returns the build graph the options name, or nil when there is none or it no longer
// decodes.
func BuildGraph(opts ...Option) *buildgraph.Graph {
	return resolveOptions(opts).graph()
}

func (a analyzer) graph() *buildgraph.Graph {
	if a.graphFile == "" {
		return nil
	}
	graphMemo.Lock()
	defer graphMemo.Unlock()
	if graphMemo.file == a.graphFile {
		return graphMemo.g
	}
	g, err := buildgraph.Decode(a.graphFile)
	if err != nil {
		return nil
	}
	graphMemo.file, graphMemo.g = a.graphFile, g
	return g
}

// moduleRoots returns the root node id of every module: the reactor's own projects, which a
// module that depends on another names as a node with no file.
func moduleRoots(g *buildgraph.Graph) map[string]bool {
	out := make(map[string]bool, len(g.Modules))
	for _, m := range g.Modules {
		out[m.Root] = true
	}
	return out
}

// moduleCoordinates returns the group:artifact of every module.
func moduleCoordinates(g *buildgraph.Graph) map[string]bool {
	out := make(map[string]bool, len(g.Modules))
	for _, m := range g.Modules {
		for _, n := range m.Nodes {
			if n.ID == m.Root {
				out[n.Group+":"+n.Artifact] = true
			}
		}
	}
	return out
}

// nodePURL renders a node's Package URL, with the classifier and a type other than jar as
// qualifiers so two files of one coordinate stay two packages.
func nodePURL(n buildgraph.Node) string {
	purl := mavenPURL(n.Group, n.Artifact, n.Version)
	var q []string
	if n.Classifier != "" {
		q = append(q, "classifier="+n.Classifier)
	}
	if n.Type != "" && n.Type != "jar" {
		q = append(q, "type="+n.Type)
	}
	if len(q) > 0 {
		purl += "?" + strings.Join(q, "&")
	}
	return purl
}

// graphInventory renders the graph as the dependency inventory: one node per module per
// dependency, the module roots left out (an edge from one marks its child Direct). uncovered marks
// it partial: a build of the other tool sits beside the one g resolved.
func graphInventory(g *buildgraph.Graph, uncovered bool) plugin.DependencyInventory {
	var nodes []plugin.DependencyNode
	var edges []plugin.DependencyEdge
	for _, m := range g.Modules {
		ids := make(map[string]string, len(m.Nodes))
		direct := map[string]bool{}
		for _, e := range m.Edges {
			if e.From == m.Root {
				direct[e.To] = true
			}
		}
		for _, n := range m.Nodes {
			if n.ID == m.Root {
				continue
			}
			purl := nodePURL(n)
			id := m.Path + "|" + n.Scope + "|" + purl
			ids[n.ID] = id
			dn := plugin.DependencyNode{
				ID:         id,
				PURL:       purl,
				Version:    n.Version,
				Direct:     direct[n.ID],
				Membership: plugin.DependencyMembership{Project: m.Path, Target: n.Scope},
				Artifact:   plugin.DependencyArtifact{Identity: n.ID},
				Provenance: plugin.DependencyProvenance{Resolver: g.Tool.Name},
				Partiality: plugin.Complete(),
			}
			if n.File != nil {
				dn.Artifact = plugin.DependencyArtifact{Identity: filepath.Base(n.File.Path), Digest: "sha256:" + n.File.SHA256}
			}
			nodes = append(nodes, dn)
		}
		for _, e := range m.Edges {
			parent, okP := ids[e.From]
			child, okC := ids[e.To]
			if okP && okC {
				edges = append(edges, plugin.DependencyEdge{Parent: parent, Child: child})
			}
		}
	}
	return assembleInventory(nodes, edges, coverage(uncovered))
}

// graphVersions answers a version request from the graph. Every copy of the coordinate is a
// Match candidate, one per module that resolved it, whatever its scope; the Match is resolved
// only when they all agree, since one patched module beside an affected one must not rule the
// build not-affected. The graph holds every version the build resolved, so the copies are
// complete, unless uncovered: a build of the other tool beside it can resolve another.
func graphVersions(g *buildgraph.Graph, coordinate string, uncovered bool) plugin.DependencyVersionResult {
	res := plugin.DependencyVersionResult{Partiality: coverage(uncovered)}
	roots := moduleRoots(g)
	want := strings.ToLower(strings.TrimSpace(coordinate))
	seen := map[string]bool{}
	for _, m := range g.Modules {
		for _, n := range m.Nodes {
			if roots[n.ID] {
				continue
			}
			d := plugin.ResolvedDependency{Coordinate: n.Group + ":" + n.Artifact, Version: n.Version, Resolved: true, Source: g.Tool.Name}
			// One module holds a coordinate once per file; its versions are the same.
			if k := m.Path + "|" + d.Coordinate; !seen[k] {
				seen[k] = true
				res.All = append(res.All, d)
				if want != "" && strings.ToLower(d.Coordinate) == want {
					res.Matches = append(res.Matches, d)
				}
			}
		}
	}
	if len(res.Matches) == 0 {
		return res
	}
	res.Found = true
	res.Match = res.Matches[0]
	presence := res.Matches[0]
	res.Presence = &presence
	for _, d := range res.Matches[1:] {
		if d.Version != res.Match.Version {
			res.Match.Version = ""
			res.Match.Resolved = false
			break
		}
	}
	res.MatchesComplete = !uncovered
	return res
}

// absentVersions is the version answer without a graph: a requested coordinate is Found and
// unresolved, since nothing rules any version in or out.
func absentVersions(coordinate string) plugin.DependencyVersionResult {
	res := plugin.DependencyVersionResult{Partiality: plugin.Partial(PartialReasonBuildGraphAbsent)}
	if c := strings.TrimSpace(coordinate); c != "" {
		res.Found = true
		res.Match = plugin.ResolvedDependency{Coordinate: c}
	}
	return res
}

// RuntimeJar is one dependency JAR on the classpath the application runs with.
type RuntimeJar struct {
	Coordinate, Version, Classifier string
	Path, SHA256                    string
}

// GAV names the JAR as group:artifact:version, with its classifier appended when it has one.
func (j RuntimeJar) GAV() string {
	s := j.Coordinate + ":" + j.Version
	if j.Classifier != "" {
		s += ":" + j.Classifier
	}
	return s
}

// PackageURL is the coordinate's PURL without a version.
func (j RuntimeJar) PackageURL() string { return mavenPURLNoVersion(j.Coordinate) }

// RuntimeMiss is a coordinate on the runtime classpath whose code cannot be loaded: Ambiguous
// when the modules resolved it at more than one version (loading one would trace a body that
// may not run), else its file is not a JAR.
type RuntimeMiss struct {
	Coordinate string
	Ambiguous  bool
	Detail     string
}

// runtimeScope reports whether a scope puts a file on the classpath the application runs with:
// provided because the container supplies it at run time.
func runtimeScope(scope string) bool {
	switch scope {
	case "compile", "runtime", "provided", "system":
		return true
	}
	return false
}

// RuntimeSelection picks the dependency JARs a search loads: the files of every node on a
// module's runtime classpath, the reactor's own projects left out since their code is the
// first-party output. A coordinate the modules resolved at two versions is a miss rather than a
// pick. Output is sorted so the load order, and so which JAR wins a duplicate class, is
// deterministic.
func RuntimeSelection(g *buildgraph.Graph) (load []RuntimeJar, miss []RuntimeMiss) {
	reactor := moduleCoordinates(g)
	roots := moduleRoots(g)
	byCoord := map[string][]buildgraph.Node{}
	for _, m := range g.Modules {
		for _, n := range m.Nodes {
			c := n.Group + ":" + n.Artifact
			if roots[n.ID] || reactor[c] || !runtimeScope(n.Scope) {
				continue
			}
			byCoord[c] = append(byCoord[c], n)
		}
	}
	coords := make([]string, 0, len(byCoord))
	for c := range byCoord {
		coords = append(coords, c)
	}
	sort.Strings(coords)
	for _, c := range coords {
		versions := map[string]bool{}
		for _, n := range byCoord[c] {
			versions[n.Version] = true
		}
		if len(versions) > 1 {
			vs := make([]string, 0, len(versions))
			for v := range versions {
				vs = append(vs, v)
			}
			sort.Strings(vs)
			miss = append(miss, RuntimeMiss{Coordinate: c, Ambiguous: true, Detail: c + ": runtime versions " + strings.Join(vs, ", ")})
			continue
		}
		files := map[string]bool{}
		for _, n := range byCoord[c] {
			switch {
			case n.File == nil:
				// A pom with nothing to load.
			case !strings.HasSuffix(n.File.Path, ".jar"):
				if n.Type != "pom" && !files[n.File.Path] {
					files[n.File.Path] = true
					miss = append(miss, RuntimeMiss{Coordinate: c, Detail: n.ID + ": " + filepath.Base(n.File.Path) + " is not a JAR"})
				}
			case !files[n.File.Path]:
				files[n.File.Path] = true
				load = append(load, RuntimeJar{Coordinate: c, Version: n.Version, Classifier: n.Classifier, Path: n.File.Path, SHA256: n.File.SHA256})
			}
		}
	}
	sort.SliceStable(load, func(i, j int) bool {
		if load[i].Coordinate != load[j].Coordinate {
			return load[i].Coordinate < load[j].Coordinate
		}
		return load[i].Classifier < load[j].Classifier
	})
	return load, miss
}

// CoordinateJars returns every JAR the graph resolved for coordinate, in any scope, at version
// when one is given.
func CoordinateJars(g *buildgraph.Graph, coordinate, version string) []RuntimeJar {
	roots := moduleRoots(g)
	seen := map[string]bool{}
	var out []RuntimeJar
	for _, m := range g.Modules {
		for _, n := range m.Nodes {
			if roots[n.ID] || n.Group+":"+n.Artifact != coordinate || n.File == nil || seen[n.File.Path] {
				continue
			}
			if version != "" && n.Version != version || !strings.HasSuffix(n.File.Path, ".jar") {
				continue
			}
			seen[n.File.Path] = true
			out = append(out, RuntimeJar{Coordinate: coordinate, Version: n.Version, Classifier: n.Classifier, Path: n.File.Path, SHA256: n.File.SHA256})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GAV() < out[j].GAV() })
	return out
}

// graphVersionsOf returns the distinct versions the graph resolved for coordinate, sorted.
func graphVersionsOf(g *buildgraph.Graph, coordinate string) []string {
	roots := moduleRoots(g)
	seen := map[string]bool{}
	var out []string
	for _, m := range g.Modules {
		for _, n := range m.Nodes {
			if !roots[n.ID] && n.Group+":"+n.Artifact == coordinate && !seen[n.Version] {
				seen[n.Version] = true
				out = append(out, n.Version)
			}
		}
	}
	sort.Strings(out)
	return out
}

// BlindSpotTargets bounds a blind spot in coordinate's unread code (contract §4, with the
// callback amendment): the code can call coordinate itself, anything on the classpath it is
// loaded on, and back into first-party code, which reaches that classpath too. So Targets is ""
// plus every package of each module that resolved coordinate, as versionless PURLs. A tighter
// bound would need the JAR's own declarations, which the graph does not carry. nil when no
// module resolved coordinate.
func BlindSpotTargets(g *buildgraph.Graph, coordinate string) []string {
	out := map[string]bool{}
	for _, m := range g.Modules {
		holds := false
		for _, n := range m.Nodes {
			if n.ID != m.Root && n.Group+":"+n.Artifact == coordinate {
				holds = true
				break
			}
		}
		if !holds {
			continue
		}
		for _, n := range m.Nodes {
			if n.ID != m.Root {
				out[mavenPURLNoVersion(n.Group+":"+n.Artifact)] = true
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	targets := make([]string, 0, len(out)+1)
	targets = append(targets, "")
	for t := range out {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	return targets
}

// jarLookup is the outcome of reading a JAR the build graph names.
type jarLookup int

const (
	jarMissing    jarLookup = iota // nothing is at the path
	jarFound                       // the file holds the bytes the graph recorded
	jarUnreadable                  // the file cannot be read, or its bytes changed since the build resolved it
)

// artifactJar is a read dependency JAR: its path and the bytes read from it.
type artifactJar struct {
	path string
	data []byte
}

// readJar reads a graph JAR and checks it still has the digest the graph recorded, so what is
// parsed is the file the build resolved.
func readJar(j RuntimeJar) (artifactJar, jarLookup) {
	data, err := readRegular(j.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return artifactJar{}, jarMissing
		}
		return artifactJar{}, jarUnreadable
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != j.SHA256 {
		return artifactJar{}, jarUnreadable // the file changed since the build resolved it
	}
	return artifactJar{path: j.Path, data: data}, jarFound
}

// multipleModules reports whether the graph holds more than one module with code of its own: a
// module directory with a src directory. why names them, for the partiality path.
func multipleModules(g *buildgraph.Graph, buildDir string) (multi bool, why string) {
	var withCode []string
	for _, m := range g.Modules {
		if info, err := os.Stat(filepath.Join(buildDir, filepath.FromSlash(m.Path), "src")); err == nil && info.IsDir() {
			withCode = append(withCode, m.Path)
		}
	}
	if len(withCode) > 1 {
		return true, "build graph modules " + strings.Join(withCode, ", ")
	}
	return false, ""
}

// graphJars returns every JAR file the graph names, in any scope, once each, the reactor's own
// projects left out.
func graphJars(g *buildgraph.Graph) []RuntimeJar {
	roots := moduleRoots(g)
	seen := map[string]bool{}
	var out []RuntimeJar
	for _, m := range g.Modules {
		for _, n := range m.Nodes {
			if roots[n.ID] || n.File == nil || seen[n.File.Path] || !strings.HasSuffix(n.File.Path, ".jar") {
				continue
			}
			seen[n.File.Path] = true
			out = append(out, RuntimeJar{Coordinate: n.Group + ":" + n.Artifact, Version: n.Version, Classifier: n.Classifier, Path: n.File.Path, SHA256: n.File.SHA256})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GAV() < out[j].GAV() })
	return out
}

// ReadRuntimeJar returns a graph JAR's bytes once they check against the digest the graph
// recorded. ok is false when the file is missing, unreadable or changed since the build resolved
// it.
func ReadRuntimeJar(j RuntimeJar) (data []byte, ok bool) {
	jar, found := readJar(j)
	return jar.data, found == jarFound
}
