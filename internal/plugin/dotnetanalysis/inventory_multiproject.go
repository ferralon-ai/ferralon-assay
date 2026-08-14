package dotnetanalysis

// Build 3b — the multi-PROJECT layer on top of 3a's single-project resolver core (inventory.go).
//
// Given ONE BuildDir (WorkspacePlan supplies no project list — A2), the tree-walker discovers the
// member projects — a .sln's project list parsed LEXICALLY (never MSBuild), or the project files
// directly under BuildDir when there is no .sln — plus the ProjectReference graph between them. It
// then runs the UNMODIFIED 3a per-project resolver (the precedence chain in inventory.go) for each
// discovered project and MERGES the results into one plugin.DependencyInventory, stamping
// Membership.Project (owning project, BuildDir-relative) and Membership.Workspace (the .sln, when
// one groups them) onto every node.
//
// Two invariants carry the honesty bar into the multi-project layer:
//   - A ProjectReference is membership / an inter-project EDGE, never a NuGet package node: it has
//     no PURL, so fabricating a node for it would be a phantom dependency. Inter-project edges use
//     a distinct "project::<rel>" endpoint marker that can never collide with a package Node.ID
//     (which is "<project>|<scope>|pkg:nuget/…"). The core parsers already skip assets/lock
//     entries of type "project", so no phantom node leaks in from restore output either.
//   - A project that fails to resolve (malformed, or a .sln member missing on disk) contributes
//     DECLARED partiality — its named reasons merge into the graph-level Partiality and any nodes
//     it did resolve are retained — never a silent drop (§3.6).
//
// This file is ADDITIVE: it introduces no change to 3a's resolution logic; ResolveInventory gains
// one early dispatch branch (inventory.go) that delegates here when a workspace is detected.

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// discoverWorkspace decides whether req.BuildDir is a multi-project workspace and, if so, returns
// the governing .sln (empty when none) and the member project files. Multi-project mode triggers
// when a .sln is present (its lexically-parsed member list is authoritative) OR when two or more
// project files sit under BuildDir with no .sln. A single project with no .sln stays on the 3a
// single-project path (isMulti false) — byte-identical to before this build.
func discoverWorkspace(buildDir string) (sln string, projects []string, isMulti bool) {
	var slns, projs []string
	_ = filepath.WalkDir(buildDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree contributes nothing; keep walking.
		}
		if d.IsDir() {
			if path != buildDir && skipDir(d.Name()) { // skipDir already excludes obj/bin/.git/…
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(d.Name())) {
		case ".sln":
			slns = append(slns, path)
		case ".csproj", ".fsproj", ".vbproj":
			projs = append(projs, path)
		}
		return nil
	})

	sort.Strings(slns)
	if len(slns) > 0 {
		if members := parseSolutionProjects(slns[0]); len(members) > 0 {
			return slns[0], members, true
		}
	}
	if len(projs) >= 2 {
		sort.Strings(projs)
		return "", projs, true
	}
	return "", nil, false
}

// parseSolutionProjects extracts the member project paths from a .sln LEXICALLY (no MSBuild). Each
// `Project("{type}") = "name", "relative\path.ext", "{guid}"` line yields its second quoted field;
// solution folders (whose path has no project extension) are skipped, so only real .csproj/.fsproj/
// .vbproj members survive. Returned paths are cleaned absolute paths; a member missing on disk is
// intentionally retained (resolveOneProject turns it into declared partiality, not a drop).
func parseSolutionProjects(slnPath string) []string {
	data, err := os.ReadFile(slnPath)
	if err != nil {
		return nil
	}
	slnDir := filepath.Dir(slnPath)
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Project(") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		fields := strings.Split(line[eq+1:], ",")
		if len(fields) < 2 {
			continue
		}
		rel := strings.Trim(strings.TrimSpace(fields[1]), `"`)
		rel = strings.ReplaceAll(rel, `\`, string(filepath.Separator))
		switch strings.ToLower(filepath.Ext(rel)) {
		case ".csproj", ".fsproj", ".vbproj":
			out = append(out, filepath.Clean(filepath.Join(slnDir, rel)))
		}
	}
	sort.Strings(out)
	return out
}

// resolveWorkspace runs the 3a per-project resolver for each discovered project and merges the
// results into one inventory. Every node is stamped with Membership.Workspace (the .sln, when
// present); Membership.Project is set by the per-project resolver from the BuildDir-relative
// project path. Inter-project ProjectReference edges are added with project:: markers. Graph
// partiality is Complete only when EVERY project resolved Complete; otherwise the union of the
// failing projects' named reasons — declared partiality, never a silent drop.
func resolveWorkspace(buildDir, slnPath string, projectPaths []string) plugin.DependencyInventory {
	workspaceRel := ""
	if slnPath != "" {
		workspaceRel = relTo(buildDir, slnPath)
	}

	sort.Strings(projectPaths)

	var allNodes []plugin.DependencyNode
	var allEdges []plugin.DependencyEdge
	var reasons []string
	complete := true

	for _, pp := range projectPaths {
		projRel := relTo(buildDir, pp)
		inv := resolveOneProject(buildDir, pp, projRel)
		if !inv.Partiality.Complete {
			complete = false
			reasons = mergeReasons(reasons, inv.Partiality.Reasons...)
		}
		for i := range inv.Nodes {
			inv.Nodes[i].Membership.Workspace = workspaceRel
		}
		allNodes = append(allNodes, inv.Nodes...)
		allEdges = append(allEdges, inv.Edges...)

		// A ProjectReference is an inter-project edge, NOT a NuGet node (it has no PURL).
		for _, ref := range projectReferences(pp) {
			allEdges = append(allEdges, plugin.DependencyEdge{
				Parent: projectMarker(projRel),
				Child:  projectMarker(relTo(buildDir, ref)),
			})
		}
	}

	part := plugin.Complete()
	if !complete {
		part = plugin.Partial(reasons...)
	}
	return assemble(allNodes, allEdges, part)
}

// resolveOneProject runs 3a's precedence chain scoped to a SINGLE project's directory, reusing the
// unmodified core parsers (parseAssets → tierFallback). It differs from ResolveInventory only in
// that the file search is rooted at the project's own directory (so a sibling project's obj/ can
// never bleed in) while projRel remains BuildDir-relative (so per-project membership stays
// distinct across the workspace). buildDir (the workspace root) is passed as the CPM walk bound so
// a solution-ROOT Directory.Packages.props — the standard CPM layout, an ANCESTOR of projDir — is
// discovered for versionless PackageReferences, while the lock/manifest search stays projDir-scoped;
// the walk is bounded to buildDir for hermeticity. A .sln member whose file is absent yields declared
// partiality.
func resolveOneProject(buildDir, projPath, projRel string) plugin.DependencyInventory {
	if _, err := os.Stat(projPath); err != nil {
		// A .sln listed this project but it is missing on disk: declared partiality, not a drop.
		return assemble(nil, nil, plugin.Partial(plugin.PartialReasonNoManifest))
	}
	projDir := filepath.Dir(projPath)

	// Tier 1: project.assets.json under this project's own tree (obj/ included).
	if assetsPath, ok := findFile(projDir, "project.assets.json", true); ok {
		if data, err := os.ReadFile(assetsPath); err == nil {
			if nodes, edges, pok := parseAssets(data, projRel); pok {
				return assemble(nodes, edges, plugin.Complete())
			}
			return tierFallback(projDir, projDir, projRel, buildDir, []string{plugin.PartialReasonToolFailure})
		}
	}
	return tierFallback(projDir, projDir, projRel, buildDir, nil)
}

// projectReferences extracts a project's declared ProjectReference targets LEXICALLY, resolved to
// cleaned absolute paths relative to the referencing project's directory. These become
// inter-project edges; the packages they pull in belong to the referenced project's own node set,
// never re-parented here (that would invent cross-project transitive edges with no restore
// evidence).
func projectReferences(projPath string) []string {
	data, err := os.ReadFile(projPath)
	if err != nil {
		return nil
	}
	var doc struct {
		ItemGroups []struct {
			Refs []struct {
				Include string `xml:"Include,attr"`
			} `xml:"ProjectReference"`
		} `xml:"ItemGroup"`
	}
	if xml.Unmarshal(data, &doc) != nil {
		return nil
	}
	projDir := filepath.Dir(projPath)
	var out []string
	for _, ig := range doc.ItemGroups {
		for _, r := range ig.Refs {
			inc := strings.TrimSpace(r.Include)
			if inc == "" {
				continue
			}
			inc = strings.ReplaceAll(inc, `\`, string(filepath.Separator))
			out = append(out, filepath.Clean(filepath.Join(projDir, inc)))
		}
	}
	sort.Strings(out)
	return out
}

// projectMarker renders an inter-project edge endpoint. The "project::" prefix guarantees it can
// never collide with a package Node.ID ("<project>|<scope>|pkg:nuget/…"), so a ProjectReference is
// unambiguously an edge between projects and never mistaken for a package node.
func projectMarker(projRel string) string {
	return "project::" + projRel
}
