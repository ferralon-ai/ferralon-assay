package cfamilyanalysis

import (
	"context"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ResolveInventory builds the C/C++ codebase's dependency inventory from the Conan and vcpkg
// manifests at the build root, through the same reader ResolveDependencyVersions uses. It reads
// files only; it never runs conan or vcpkg and never fetches.
//
// Each manifest entry is one node, keyed by (manifest, triplet, PURL). A Conan lockfile and
// vcpkg's installed-package database (vcpkg_installed/vcpkg/status) are each manager's lock tier:
// their entries are exact pins, and the status file's Depends fields are the only edges the lane
// emits. A conanfile.txt or vcpkg.json is the declared tier: it marks which locked packages are
// Direct, and it is a node of its own only where no lock pins its name. Direct is set on positive
// evidence only, so a lock read with no declared manifest beside it carries no direct nodes.
//
// The inventory reads Complete only when every manager with a manifest at the root has a lock tier
// that parsed and pins at least one package, and every node is pinned. Otherwise it declares why:
//
//   - no manifest at the root: no_manifest, zero nodes;
//   - a manifest that does not parse: tool_failure;
//   - a manager with no lock tier, or one that is empty or does not parse: source_unpinned, since
//     its transitive packages and their versions are not in any file the lane read;
//   - a node with no exact pin: source_unpinned, on the graph and on the node.
//
// A Complete inventory covers only what the package managers installed. System packages and
// vendored sources never appear in a package manifest; ResolveDependencyVersions declares a
// coordinate it cannot find no_manifest for that reason.
//
// A missing or non-directory build dir is a hard error.
func ResolveInventory(_ context.Context, req plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	if err := checkBuildDir(req.BuildDir); err != nil {
		return plugin.DependencyInventory{}, err
	}
	ms := readManifests(req.BuildDir)

	reasons := newReasonSet()
	if ms.read == 0 {
		reasons.add(plugin.PartialReasonNoManifest)
	}
	if ms.parseFailed {
		reasons.add(plugin.PartialReasonToolFailure)
	}
	for mgr := range ms.present {
		if !ms.locked[mgr] {
			reasons.add(plugin.PartialReasonSourceUnpinned)
		}
	}

	type instance struct{ source, name, triplet string }
	ids := map[instance]string{}
	nodes := make([]plugin.DependencyNode, 0, len(ms.deps))
	for _, d := range ms.deps {
		n := inventoryNode(d, ms.declared[d.purlType][strings.ToLower(d.name)])
		if !d.resolved {
			reasons.add(plugin.PartialReasonSourceUnpinned)
		}
		ids[instance{d.source, strings.ToLower(d.name), d.triplet}] = n.ID
		nodes = append(nodes, n)
	}

	var edges []plugin.DependencyEdge
	for _, d := range ms.deps {
		parent := ids[instance{d.source, strings.ToLower(d.name), d.triplet}]
		for _, dep := range d.depends {
			child, ok := ids[instance{d.source, dep.name, dep.triplet}]
			if !ok || child == parent {
				// A Depends entry vcpkg did not record as installed has no node to point at; the
				// edge is left out rather than given an invented endpoint.
				continue
			}
			edges = append(edges, plugin.DependencyEdge{Parent: parent, Child: child})
		}
	}
	return assembleInventory(nodes, edges, reasons.partiality()), nil
}

func inventoryNode(d cdep, declared bool) plugin.DependencyNode {
	purl := dependencyPURL(d)
	n := plugin.DependencyNode{
		ID:         d.source + "|" + d.triplet + "|" + purl,
		PURL:       purl,
		Direct:     declared,
		Artifact:   plugin.DependencyArtifact{Identity: d.ref},
		Provenance: plugin.DependencyProvenance{Resolver: resolverName(d), Target: d.triplet},
		Partiality: plugin.Complete(),
	}
	if d.resolved {
		n.Version = d.fullVersion()
	} else {
		n.Partiality = plugin.Partial(plugin.PartialReasonSourceUnpinned)
	}
	if d.lockTier {
		n.Provenance.Lockfile = d.source
		if declared {
			n.Provenance.Manifest = declaredManifest(d.purlType)
		}
	} else {
		n.Provenance.Manifest = d.source
	}
	return n
}

// dependencyPURL is d's Package URL. A Conan reference's user and channel and a vcpkg port-version
// ride as qualifiers, so the version stays the upstream one an advisory range is written against.
// An unpinned dependency's PURL carries no version.
func dependencyPURL(d cdep) string {
	var b strings.Builder
	b.WriteString("pkg:" + d.purlType + "/" + url.PathEscape(strings.ToLower(d.name)))
	if !d.resolved {
		return b.String()
	}
	b.WriteString("@" + url.PathEscape(d.version))
	q := url.Values{}
	if d.channel != "" {
		q.Set("channel", d.channel)
	}
	if d.user != "" {
		q.Set("user", d.user)
	}
	if d.portVersion != 0 {
		q.Set("port_version", strconv.Itoa(d.portVersion))
	}
	if len(q) > 0 {
		b.WriteString("?" + q.Encode())
	}
	return b.String()
}

func resolverName(d cdep) string {
	switch {
	case d.purlType == purlTypeConan && d.lockTier:
		return "conan lockfile"
	case d.purlType == purlTypeConan:
		return "conanfile.txt requires"
	case d.lockTier:
		return "vcpkg installed status"
	default:
		return "vcpkg manifest"
	}
}

func declaredManifest(purlType string) string {
	if purlType == purlTypeConan {
		return conanTxtFile
	}
	return vcpkgFile
}

// assembleInventory orders nodes by ID and edges by (Parent, Child), keeping the first of any
// repeated node or edge, so the same tree always yields the same inventory.
func assembleInventory(nodes []plugin.DependencyNode, edges []plugin.DependencyEdge, part plugin.Partiality) plugin.DependencyInventory {
	sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	nodeSeen := make(map[string]bool, len(nodes))
	uniqNodes := nodes[:0]
	for _, n := range nodes {
		if !nodeSeen[n.ID] {
			nodeSeen[n.ID] = true
			uniqNodes = append(uniqNodes, n)
		}
	}
	nodes = uniqNodes
	seen := make(map[plugin.DependencyEdge]bool, len(edges))
	uniq := edges[:0]
	for _, e := range edges {
		if !seen[e] {
			seen[e] = true
			uniq = append(uniq, e)
		}
	}
	sort.Slice(uniq, func(i, j int) bool {
		if uniq[i].Parent != uniq[j].Parent {
			return uniq[i].Parent < uniq[j].Parent
		}
		return uniq[i].Child < uniq[j].Child
	})
	if len(nodes) == 0 {
		nodes = nil
	}
	if len(uniq) == 0 {
		uniq = nil
	}
	return plugin.DependencyInventory{Partiality: part, Nodes: nodes, Edges: uniq}
}
