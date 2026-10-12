package javaanalysis

import (
	"slices"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// depclosure.go — the package bound for a blind spot inside a dependency JAR. When a JAR's
// code cannot be read, any call hidden inside it can reach the JAR itself and everything
// the JAR's code can call: its dependencies, theirs, and so on. A scoped partiality reason
// for that JAR names this closure as its Targets, so the limit counts against an advisory
// on any package in the closure and against nothing else.
//
// The closure must over-approximate. The inventory's edges alone are not enough: Maven
// drops optional and provided dependencies from the transitive graph, yet the JAR's code
// was compiled against them and calls them whenever they are on the classpath. So each
// package in the closure contributes every dependency its POM chain declares — every
// scope but test, optional or not, under every profile whether active or not — as well as
// its inventory children. Anything that prevents reading that declaration (a POM or parent
// POM missing from the cache, a Gradle-resolved node, an unresolved version or coordinate)
// makes the closure unbounded: the caller gets nil, which counts against every advisory.

// mavenPURLNoVersion renders "pkg:maven/<group>/<artifact>" for a "group:artifact"
// coordinate.
func mavenPURLNoVersion(coordinate string) string {
	group, artifact, ok := splitCoordinate(coordinate)
	if !ok {
		return ""
	}
	return "pkg:maven/" + group + "/" + artifact
}

// coordinateOfPURL returns the "group:artifact" coordinate and version of a Maven PURL
// ("pkg:maven/<group>/<artifact>[@version][?qualifiers]"). ok is false for any other PURL.
func coordinateOfPURL(purl string) (coordinate, version string, ok bool) {
	const prefix = "pkg:maven/"
	if !strings.HasPrefix(purl, prefix) {
		return "", "", false
	}
	rest := purl[len(prefix):]
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		version = strings.TrimSpace(rest[i+1:])
		rest = rest[:i]
	}
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return "", "", false
	}
	group, artifact := strings.TrimSpace(rest[:slash]), strings.TrimSpace(rest[slash+1:])
	if group == "" || artifact == "" || strings.Contains(artifact, "/") {
		return "", "", false
	}
	return group + ":" + artifact, version, true
}

// inventoryIndex groups an inventory's nodes by coordinate and its edges by parent.
type inventoryIndex struct {
	byCoordinate map[string][]plugin.DependencyNode
	children     map[string][]string // parent node ID -> child node IDs
	byID         map[string]plugin.DependencyNode
}

func indexInventory(inv plugin.DependencyInventory) inventoryIndex {
	ix := inventoryIndex{
		byCoordinate: map[string][]plugin.DependencyNode{},
		children:     map[string][]string{},
		byID:         map[string]plugin.DependencyNode{},
	}
	for _, n := range inv.Nodes {
		coord, _, ok := coordinateOfPURL(n.PURL)
		if !ok {
			continue
		}
		ix.byCoordinate[coord] = append(ix.byCoordinate[coord], n)
		ix.byID[n.ID] = n
	}
	for _, e := range inv.Edges {
		ix.children[e.Parent] = append(ix.children[e.Parent], e.Child)
	}
	return ix
}

// versionsOf returns the distinct resolved versions the inventory selected for coordinate,
// sorted.
func (ix inventoryIndex) versionsOf(coordinate string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range ix.byCoordinate[coordinate] {
		if n.Version != "" && !seen[n.Version] {
			seen[n.Version] = true
			out = append(out, n.Version)
		}
	}
	sort.Strings(out)
	return out
}

// variantAt reports whether any inventory node for coordinate at version carries the
// maven_artifact_variant reason: the build declares a classifier or non-jar type for it.
func (ix inventoryIndex) variantAt(coordinate, version string) bool {
	for _, n := range ix.byCoordinate[coordinate] {
		if n.Version == version && slices.Contains(n.Partiality.Reasons, reasonMavenArtifactVariant) {
			return true
		}
	}
	return false
}

// dependencyTargets returns the versionless PURLs of coordinate and every package its code
// can call, or nil when that set cannot be bounded (see the file comment).
func dependencyTargets(ix inventoryIndex, cache *mavenCache, coordinate string) []string {
	if _, ok := ix.byCoordinate[coordinate]; !ok {
		return nil
	}
	targets := map[string]bool{}
	visited := map[string]bool{coordinate: true}
	queue := []string{coordinate}
	for len(queue) > 0 {
		coord := queue[0]
		queue = queue[1:]
		targets[coord] = true

		nodes := ix.byCoordinate[coord]
		// A declared dependency absent from the inventory is not on this build's classpath, so
		// nothing can load it: it is a target, but there is no code of it to expand.
		for _, n := range nodes {
			declared, ok := declaredDependencies(n, cache)
			if !ok {
				return nil
			}
			for _, childID := range ix.children[n.ID] {
				if child, ok := ix.byID[childID]; ok {
					if c, _, ok := coordinateOfPURL(child.PURL); ok {
						declared = append(declared, c)
					}
				}
			}
			for _, d := range declared {
				if !visited[d] {
					visited[d] = true
					queue = append(queue, d)
				}
			}
		}
	}
	out := make([]string, 0, len(targets))
	for c := range targets {
		out = append(out, mavenPURLNoVersion(c))
	}
	sort.Strings(out)
	return out
}

// declaredDependencies returns every coordinate the node's POM chain declares outside test
// scope, across all profiles. ok is false when the declaration cannot be read in full.
func declaredDependencies(n plugin.DependencyNode, cache *mavenCache) ([]string, bool) {
	if n.Provenance.Resolver != "maven-effective" || n.Version == "" {
		return nil, false
	}
	coord, _, ok := coordinateOfPURL(n.PURL)
	if !ok {
		return nil, false
	}
	group, artifact, _ := splitCoordinate(coord)
	pom, ok := cache.get(group, artifact, n.Version)
	if !ok {
		return nil, false
	}
	chain := parentChain(pom, nil, cache, 0)
	if chain.parentMissing {
		return nil, false
	}
	props := map[string]string{
		"project.groupId":    pom.GroupID,
		"project.artifactId": pom.ArtifactID,
		"project.version":    pom.Version,
	}
	for _, anc := range chain.poms {
		for k, v := range anc.Properties {
			props[k] = v
		}
		for _, pr := range anc.Profiles {
			for k, v := range pr.Properties {
				if _, set := props[k]; !set {
					props[k] = v
				}
			}
		}
	}
	interpProps(props)

	var out []string
	add := func(deps []mvnDep) bool {
		for _, d := range deps {
			if strings.EqualFold(d.Scope, "test") {
				continue
			}
			g, gok := literalOrInterp(d.GroupID, props)
			a, aok := literalOrInterp(d.ArtifactID, props)
			if !gok || !aok {
				return false
			}
			out = append(out, g+":"+a)
		}
		return true
	}
	for _, anc := range chain.poms {
		if !add(anc.Deps) {
			return nil, false
		}
		for _, pr := range anc.Profiles {
			if !add(pr.Deps) {
				return nil, false
			}
		}
	}
	return out, true
}

// literalOrInterp returns s unchanged when it carries no property reference, else its
// interpolation. ok is false for an empty or unresolvable value.
func literalOrInterp(s string, props map[string]string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if !strings.Contains(s, "${") {
		return s, true
	}
	return interp(s, props)
}
