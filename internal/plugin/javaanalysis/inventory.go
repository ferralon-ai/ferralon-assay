package javaanalysis

// inventory.go — the JVM dependency inventory (§4.1): the build graph rendered as one
// DependencyNode per module per resolved package, with parent edges, scope membership, the
// artifact file's digest and the build tool as resolver. Kotlin delegates here.

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ResolveInventory renders the build graph for the checkout at req.BuildDir. A missing or
// unreadable build dir is a hard error (inv.4); with no graph the inventory is empty and
// Partial(build_graph_absent), never Complete.
func ResolveInventory(_ context.Context, req plugin.ResolveInventoryRequest, opts ...Option) (plugin.DependencyInventory, error) {
	info, err := os.Stat(req.BuildDir)
	if err != nil {
		return plugin.DependencyInventory{}, fmt.Errorf("javaanalysis: stat build dir %q: %w", req.BuildDir, err)
	}
	if !info.IsDir() {
		return plugin.DependencyInventory{}, fmt.Errorf("javaanalysis: build dir %q is not a directory", req.BuildDir)
	}
	g := BuildGraph(opts...)
	if g == nil {
		return assembleInventory(nil, nil, plugin.Partial(PartialReasonBuildGraphAbsent)), nil
	}
	return graphInventory(g), nil
}

// --- shared PURL + assembly --------------------------------------------------

// mavenPURL renders the normalized Package URL for a Maven-coordinate artifact. The group is
// the purl namespace with dots preserved (purl-spec maven type), e.g.
// ("org.apache.commons","commons-lang3","3.12.0") -> "pkg:maven/org.apache.commons/commons-lang3@3.12.0".
func mavenPURL(group, artifact, version string) string {
	return "pkg:maven/" + group + "/" + artifact + "@" + version
}

// assembleInventory sorts nodes by ID and edges by (Parent, Child) — the frozen deterministic
// encoding order (§7) — de-duplicates edges, and attaches the graph-level partiality. No map is
// an iteration source on this output path.
func assembleInventory(nodes []plugin.DependencyNode, edges []plugin.DependencyEdge, part plugin.Partiality) plugin.DependencyInventory {
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	seen := make(map[string]bool, len(edges))
	uniq := make([]plugin.DependencyEdge, 0, len(edges))
	for _, e := range edges {
		k := e.Parent + "\x00" + e.Child
		if seen[k] {
			continue
		}
		seen[k] = true
		uniq = append(uniq, e)
	}
	sort.Slice(uniq, func(i, j int) bool {
		if uniq[i].Parent != uniq[j].Parent {
			return uniq[i].Parent < uniq[j].Parent
		}
		return uniq[i].Child < uniq[j].Child
	})

	return plugin.DependencyInventory{Partiality: part, Nodes: nodes, Edges: uniq}
}
