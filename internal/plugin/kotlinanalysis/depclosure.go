package kotlinanalysis

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// depclosure.go — load the build's resolved dependency closure so Reachability traces from
// first-party code into the exact dependency bytecode the build resolved. The node set comes
// from the shared JVM inventory (javaanalysis.ResolveInventory: Maven reactor + .m2 POMs, or
// the Gradle lockfile + modules-2 POMs, or Gradle declared-direct without a lockfile); each
// node's JAR is located in the local caches by LocateDependencyJar (Gradle modules-2, then
// .m2) and parsed by the shared classfile reader.
//
// A dependency that is in the inventory but whose JAR cannot be opened is a blind spot bounded
// by what it could reach: a ScopedReason whose Targets are the JAR's package plus its
// transitive dependency closure (contract §4). Targets is nil (unbounded) when that closure is
// not fully known — the node or a descendant carries a relationship_unexpressed reason, so its
// out-edges were never read.
//
// A dependency the inventory does not list at all is never silently trusted: depreach treats
// any call into a class that is neither loaded nor platform as an unloaded_dependency hazard,
// so reaching it makes the search undetermined.

// partialReasonMissingJar is the scoped reason for an inventory node whose JAR is not in any
// local cache (or whose version is unresolved, so no JAR can be located). Same string as
// javaanalysis's maven_uncached_subtree: its subtree's code is unseen.
const partialReasonMissingJar = plugin.PartialReasonRelationshipUnexpressed + ":maven_uncached_subtree"

// partialReasonDuplicateClass is the scoped reason for a dependency class whose binary name a
// previously loaded JAR already defined. The engine keeps one body per name, so the shadowed
// body's edges are unseen.
const partialReasonDuplicateClass = plugin.PartialReasonRelationshipUnexpressed + ":duplicate_class"

// depClosure is the loaded dependency bytecode plus the scoped blind spots loading it incurred.
type depClosure struct {
	classes []classfile.Class
	scoped  []plugin.ScopedReason
	// loaded maps "group:artifact:version" to the JAR path that was opened, for evidence.
	loaded map[string]string
}

// depNode is one distinct (group, artifact, version) from the inventory, with the inventory
// node IDs that carry it.
type depNode struct {
	group, artifact, version string
	ids                      []string
}

func (n depNode) coordinate() string { return n.group + ":" + n.artifact }
func (n depNode) packageURL() string { return "pkg:maven/" + n.group + "/" + n.artifact }
func (n depNode) gav() string        { return n.coordinate() + ":" + n.version }

// loadDependencyClosure resolves the inventory for buildDir and loads every node's JAR it can
// locate. firstParty names classes already loaded from the build output; a dependency class
// with the same binary name is skipped (the build output is what the build packaged).
func loadDependencyClosure(ctx context.Context, buildDir string, firstParty map[string]bool) (*depClosure, error) {
	inv, err := javaanalysis.ResolveInventory(ctx, plugin.ResolveInventoryRequest{BuildDir: buildDir})
	if err != nil {
		return nil, err
	}
	g := newInventoryGraph(inv)
	dc := &depClosure{loaded: map[string]string{}}

	definedBy := map[string]depNode{} // class binary name -> the dependency that defined it
	shadowed := map[string]bool{}     // "<kept gav>|<shadowed gav>" pairs already reported

	for _, n := range g.distinctNodes() {
		jarPath, ok := "", false
		if n.version != "" {
			jarPath, ok = LocateDependencyJar(buildDir, n.coordinate(), n.version)
		}
		if !ok {
			dc.scoped = append(dc.scoped, plugin.ScopedReason{
				Reason:  partialReasonMissingJar,
				Package: n.packageURL(),
				Path:    n.gav(),
				Targets: g.targets(n),
			})
			continue
		}
		jr, err := classfile.LoadJar(jarPath)
		if err != nil {
			dc.scoped = append(dc.scoped, plugin.ScopedReason{
				Reason:  plugin.PartialReasonToolFailure,
				Package: n.packageURL(),
				Path:    n.gav(),
				Targets: g.targets(n),
			})
			continue
		}
		if len(jr.Failed) > 0 {
			// Unparsed classes are absent from the engine, so a call into one is already an
			// unloaded_dependency hazard; the scoped reason discloses the gap and bounds it.
			dc.scoped = append(dc.scoped, plugin.ScopedReason{
				Reason:  plugin.PartialReasonToolFailure,
				Package: n.packageURL(),
				Path:    n.gav() + ": " + jr.Failed[0],
				Targets: g.targets(n),
			})
		}
		dc.loaded[n.gav()] = jarPath
		for _, c := range jr.Classes {
			if firstParty[c.Name] {
				continue
			}
			if prev, dup := definedBy[c.Name]; dup {
				key := prev.gav() + "|" + n.gav()
				if !shadowed[key] {
					shadowed[key] = true
					dc.scoped = append(dc.scoped, plugin.ScopedReason{
						Reason:  partialReasonDuplicateClass,
						Package: n.packageURL(),
						Path:    fmt.Sprintf("%s shadowed by %s: %s", n.gav(), prev.gav(), c.Name),
						Targets: g.targets(n),
					})
				}
				continue
			}
			definedBy[c.Name] = n
			dc.classes = append(dc.classes, c)
		}
	}
	return dc, nil
}

// inventoryGraph indexes a DependencyInventory for closure queries.
type inventoryGraph struct {
	byID     map[string]plugin.DependencyNode
	children map[string][]string
	nodes    []depNode
}

func newInventoryGraph(inv plugin.DependencyInventory) *inventoryGraph {
	g := &inventoryGraph{byID: map[string]plugin.DependencyNode{}, children: map[string][]string{}}
	byGAV := map[string]*depNode{}
	var order []string
	for _, n := range inv.Nodes {
		g.byID[n.ID] = n
		group, artifact, version, ok := splitMavenNodePURL(n.PURL)
		if !ok {
			continue
		}
		if version == "" {
			version = n.Version
		}
		key := group + ":" + artifact + ":" + version
		if d, seen := byGAV[key]; seen {
			d.ids = append(d.ids, n.ID)
			continue
		}
		byGAV[key] = &depNode{group: group, artifact: artifact, version: version, ids: []string{n.ID}}
		order = append(order, key)
	}
	for _, e := range inv.Edges {
		g.children[e.Parent] = append(g.children[e.Parent], e.Child)
	}
	sort.Strings(order)
	for _, k := range order {
		g.nodes = append(g.nodes, *byGAV[k])
	}
	return g
}

// distinctNodes returns one entry per distinct group:artifact:version, sorted, so the load
// order (and therefore which JAR wins a duplicate class) is deterministic.
func (g *inventoryGraph) distinctNodes() []depNode { return g.nodes }

// targets returns the packages (PURL without version) any code in n could reach: n itself and
// its transitive dependency closure. It is nil (unbounded) when some node in that closure has
// out-edges the inventory could not read (a relationship_unexpressed reason on the node) or a
// node is not a Maven package.
func (g *inventoryGraph) targets(n depNode) []string {
	seen := map[string]bool{}
	out := map[string]bool{}
	stack := append([]string(nil), n.ids...)
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[id] {
			continue
		}
		seen[id] = true
		node, ok := g.byID[id]
		if !ok {
			return nil
		}
		for _, r := range node.Partiality.Reasons {
			if strings.HasPrefix(r, plugin.PartialReasonRelationshipUnexpressed) {
				return nil
			}
		}
		group, artifact, _, ok := splitMavenNodePURL(node.PURL)
		if !ok {
			return nil
		}
		out["pkg:maven/"+group+"/"+artifact] = true
		stack = append(stack, g.children[id]...)
	}
	return sortedKeys(out)
}

// splitMavenNodePURL parses an inventory node PURL "pkg:maven/<group>/<artifact>@<version>".
func splitMavenNodePURL(purl string) (group, artifact, version string, ok bool) {
	coordinate, version, ok := parseMavenPURL(purl)
	if !ok {
		return "", "", "", false
	}
	group, artifact, ok = splitCoordinate(coordinate)
	return group, artifact, version, ok
}
