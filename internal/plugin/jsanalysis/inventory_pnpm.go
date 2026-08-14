package jsanalysis

// inventory_pnpm.go — the pnpm inventory adapter (graph-representation.md §3d). Unlike the
// flat parsePnpmLock (versions.go:396), which reads ONLY `packages:`, the inventory adapter
// reads all three blocks: `packages:` (per-instance metadata + digest), `snapshots:` (edges),
// and `importers:` (workspace membership + direct deps). It parses pnpm-lock.yaml lexically
// (no YAML library — matching the dependency-free scanner ethos). No package manager is run.
//
// Instance identity: a snapshot/package key "name@version(peer@v)…" splits into name, version,
// and a parenthesized peer-set suffix; the suffix becomes the ID's ?resolution_scope= token
// verbatim (instance-key-contract.md §2, per-dialect pnpm row). A key with no suffix yields
// ID == PURL.

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

type pnpmAdapter struct{}

// pnpmLockData is the parsed subset of a pnpm-lock.yaml the inventory adapter needs.
type pnpmLockData struct {
	packages  map[string]*pnpmPkg
	snapshots map[string]*pnpmSnap
	importers map[string]*pnpmImporter
	pkgOrder  []string
	snapOrder []string
	impOrder  []string
}

type pnpmPkg struct {
	integrity   string
	hasPlatform bool // os/cpu/libc gate present → unevaluable without targeting a platform
}

type pnpmSnap struct {
	deps    map[string]string // childName → childSpec (already-resolved version, may carry peer suffix)
	depKeys []string
}

type pnpmImporter struct {
	deps []pnpmDirect // dependencies + devDependencies + optionalDependencies, in scope order
}

type pnpmDirect struct {
	name    string
	version string
	target  string // "runtime" | "dev" | "optional"
}

func (pnpmAdapter) Parse(sel selectedLock, manifests []manifestFile) ([]plugin.DependencyNode, []plugin.DependencyEdge, plugin.Partiality) {
	data, err := os.ReadFile(sel.path)
	if err != nil {
		return nil, nil, plugin.Partial(plugin.PartialReasonToolFailure)
	}
	lock := parsePnpmLockData(data)
	part := plugin.Complete()

	nodesByID := make(map[string]*plugin.DependencyNode)
	var order []string
	addNode := func(n plugin.DependencyNode) *plugin.DependencyNode {
		if existing, ok := nodesByID[n.ID]; ok {
			mergeNode(existing, n)
			return existing
		}
		cp := n
		nodesByID[n.ID] = &cp
		order = append(order, n.ID)
		return &cp
	}
	var edges []plugin.DependencyEdge

	// Package nodes: per-instance identity + digest metadata.
	for _, key := range lock.pkgOrder {
		pkg := lock.packages[key]
		name, version, peer := splitPnpmKey(key)
		if name == "" || version == "" {
			part = mergePartiality(part, plugin.Partial(plugin.PartialReasonToolFailure))
			continue
		}
		purl := makePURL(name, version)
		node := plugin.DependencyNode{
			ID:      makeID(purl, peer),
			PURL:    purl,
			Version: version,
			Artifact: plugin.DependencyArtifact{
				Identity: artifactIdentity("", name, version),
				Digest:   mapIntegrity(pkg.integrity),
			},
			Provenance: plugin.DependencyProvenance{Lockfile: sel.path, Resolver: "pnpm"},
			Partiality: plugin.Complete(),
		}
		if pkg.hasPlatform {
			// Optional dep gated on os/cpu/libc: the gate is unevaluable from metadata
			// without targeting a platform, so Target stays empty and the node is declared
			// partial — never guessed active-on-target (§3.1, cell 5).
			node.Partiality = plugin.Partial(plugin.PartialReasonPlatformCondition)
		}
		addNode(node)
	}

	// Edges from snapshots (parent→child, both already node IDs).
	for _, key := range lock.snapOrder {
		snap := lock.snapshots[key]
		pn, pv, pp := splitPnpmKey(key)
		if pn == "" || pv == "" {
			continue
		}
		parentID := makeID(makePURL(pn, pv), pp)
		for _, childName := range snap.depKeys {
			spec := snap.deps[childName]
			cn, cv, cp := splitPnpmKey(childName + "@" + spec)
			if cn == "" || cv == "" {
				continue
			}
			edges = append(edges, plugin.DependencyEdge{Parent: parentID, Child: makeID(makePURL(cn, cv), cp)})
		}
	}

	// Importers: one project/member node per importer, membership + direct edges. The root
	// importer is ".", others are member directories relative to the workspace root.
	manByRel := make(map[string]manifestFile)
	for _, m := range manifests {
		rel, rerr := filepath.Rel(sel.root, m.dir)
		if rerr != nil {
			continue
		}
		manByRel[filepath.ToSlash(rel)] = m
	}
	rootName := ""
	if rm, ok := manByRel["."]; ok {
		rootName = rm.pkg.Name
	}

	for _, member := range lock.impOrder {
		imp := lock.importers[member]
		m, haveMan := manByRel[member]
		var memberID, memberName string
		if haveMan && m.pkg.Name != "" && m.pkg.Version != "" {
			memberName = m.pkg.Name
			memberID = makePURL(memberName, m.pkg.Version)
			mn := plugin.DependencyNode{
				ID:      memberID,
				PURL:    memberID,
				Version: m.pkg.Version,
				Membership: plugin.DependencyMembership{
					Project:   memberName,
					Workspace: workspaceLabel(member, rootName),
				},
				Provenance: plugin.DependencyProvenance{
					Manifest: m.path,
					Lockfile: sel.path,
					Resolver: "pnpm",
					Runtime:  runtimeSpec(m.pkg),
				},
				Partiality: plugin.Complete(),
			}
			addNode(mn)
		} else if len(imp.deps) > 0 {
			// A member with direct deps but no readable manifest: attribution is incomplete.
			part = mergePartiality(part, plugin.Partial(plugin.PartialReasonWorkspaceAttrib))
		}

		for _, d := range imp.deps {
			cn, cv, cp := splitPnpmKey(d.name + "@" + d.version)
			if cn == "" || cv == "" {
				continue
			}
			childID := makeID(makePURL(cn, cv), cp)
			if child, ok := nodesByID[childID]; ok {
				child.Direct = true
				if child.Membership.Project == "" {
					child.Membership.Project = memberName
				}
				if child.Membership.Target == "" {
					child.Membership.Target = d.target
				}
				if child.Membership.Workspace == "" {
					child.Membership.Workspace = workspaceLabel(member, rootName)
				}
			}
			if memberID != "" {
				edges = append(edges, plugin.DependencyEdge{Parent: memberID, Child: childID})
			}
		}
	}

	out := make([]plugin.DependencyNode, 0, len(order))
	for _, id := range order {
		out = append(out, *nodesByID[id])
	}
	return out, edges, part
}

// workspaceLabel returns the enclosing workspace label for a member importer: empty for the
// root importer ("."), the workspace root name for members.
func workspaceLabel(member, rootName string) string {
	if member == "." || member == "" {
		return ""
	}
	return rootName
}

// runtimeSpec derives the Runtime provenance ("node<major>"-ish) from the owning package.json's
// engines.node, when declared. Metadata only; no runtime is executed.
func runtimeSpec(m invManifest) string {
	if v := strings.TrimSpace(m.Engines["node"]); v != "" {
		return "node " + v
	}
	return ""
}

// splitPnpmKey splits a pnpm packages/snapshots key "name@version(peer@v)…" into its name,
// version, and the verbatim parenthesized peer-set suffix (including the parentheses, or ""
// when absent). Scoped names (@scope/name@version) are handled: the version '@' is the last
// '@' of the core (pre-suffix) segment.
func splitPnpmKey(key string) (name, version, peerToken string) {
	key = strings.TrimSpace(key)
	core := key
	if i := strings.IndexByte(key, '('); i >= 0 {
		core = key[:i]
		peerToken = key[i:]
	}
	at := strings.LastIndexByte(core, '@')
	if at <= 0 {
		return core, "", peerToken
	}
	return core[:at], core[at+1:], peerToken
}

// --- lexical pnpm-lock.yaml parser (v9 layout: importers/packages/snapshots) ---

func parsePnpmLockData(data []byte) pnpmLockData {
	d := pnpmLockData{
		packages:  make(map[string]*pnpmPkg),
		snapshots: make(map[string]*pnpmSnap),
		importers: make(map[string]*pnpmImporter),
	}
	lines := strings.Split(string(data), "\n")

	section := ""
	var curMember string
	var curImp *pnpmImporter
	impBlock := "" // "runtime" | "dev" | "optional" | ""
	pendingDep := ""
	var curKey string
	var curPkg *pnpmPkg
	var curSnap *pnpmSnap
	snapBlock := "" // "dependencies" | "optionalDependencies" | ""

	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		ind := indentWidth(line)

		if ind == 0 {
			switch {
			case strings.HasPrefix(trimmed, "importers:"):
				section = "importers"
			case strings.HasPrefix(trimmed, "packages:"):
				section = "packages"
			case strings.HasPrefix(trimmed, "snapshots:"):
				section = "snapshots"
			default:
				section = "other"
			}
			curMember, curImp, impBlock, pendingDep = "", nil, "", ""
			curKey, curPkg, curSnap, snapBlock = "", nil, nil, ""
			continue
		}

		switch section {
		case "importers":
			switch {
			case ind == 2:
				k, _ := splitFirstColon(trimmed)
				curMember = unquoteYAML(strings.TrimSpace(k))
				imp := &pnpmImporter{}
				d.importers[curMember] = imp
				d.impOrder = append(d.impOrder, curMember)
				curImp = imp
				impBlock, pendingDep = "", ""
			case ind == 4:
				k, _ := splitFirstColon(trimmed)
				switch strings.TrimSpace(k) {
				case "dependencies":
					impBlock = "runtime"
				case "devDependencies":
					impBlock = "dev"
				case "optionalDependencies":
					impBlock = "optional"
				default:
					impBlock = ""
				}
				pendingDep = ""
			case ind == 6:
				k, _ := splitFirstColon(trimmed)
				pendingDep = unquoteYAML(strings.TrimSpace(k))
			case ind == 8 && curImp != nil && impBlock != "" && pendingDep != "":
				k, v := splitFirstColon(trimmed)
				if strings.TrimSpace(k) == "version" {
					curImp.deps = append(curImp.deps, pnpmDirect{
						name:    pendingDep,
						version: unquoteYAML(strings.TrimSpace(v)),
						target:  impBlock,
					})
				}
			}

		case "packages":
			switch {
			case ind == 2:
				k, _ := splitFirstColon(trimmed)
				curKey = unquoteYAML(strings.TrimSpace(k))
				p := &pnpmPkg{}
				d.packages[curKey] = p
				d.pkgOrder = append(d.pkgOrder, curKey)
				curPkg = p
			case ind == 4 && curPkg != nil:
				k, _ := splitFirstColon(trimmed)
				switch strings.TrimSpace(k) {
				case "resolution":
					curPkg.integrity = extractIntegrity(trimmed)
				case "os", "cpu", "libc":
					curPkg.hasPlatform = true
				}
			}

		case "snapshots":
			switch {
			case ind == 2:
				k, _ := splitFirstColon(trimmed)
				curKey = unquoteYAML(strings.TrimSpace(k))
				s := &pnpmSnap{deps: make(map[string]string)}
				d.snapshots[curKey] = s
				d.snapOrder = append(d.snapOrder, curKey)
				curSnap = s
				snapBlock = ""
			case ind == 4 && curSnap != nil:
				k, _ := splitFirstColon(trimmed)
				switch strings.TrimSpace(k) {
				case "dependencies", "optionalDependencies":
					snapBlock = "deps"
				default:
					snapBlock = ""
				}
			case ind == 6 && curSnap != nil && snapBlock == "deps":
				k, v := splitFirstColon(trimmed)
				name := unquoteYAML(strings.TrimSpace(k))
				spec := unquoteYAML(strings.TrimSpace(v))
				if name != "" && spec != "" {
					if _, dup := curSnap.deps[name]; !dup {
						curSnap.depKeys = append(curSnap.depKeys, name)
					}
					curSnap.deps[name] = spec
				}
			}
		}
	}
	return d
}

// splitFirstColon splits on the first ':' into key and the remainder (value). When no ':' is
// present the whole string is the key and value is "".
func splitFirstColon(s string) (key, val string) {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// unquoteYAML strips a single layer of matching single/double quotes.
func unquoteYAML(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// extractIntegrity pulls the integrity SRI out of a `resolution: {integrity: sha512-…, …}`
// inline map. Returns "" when absent (e.g. git/tarball resolutions record no integrity here).
func extractIntegrity(trimmed string) string {
	i := strings.Index(trimmed, "integrity:")
	if i < 0 {
		return ""
	}
	rest := trimmed[i+len("integrity:"):]
	rest = strings.TrimSpace(rest)
	// terminate at the first ',' or '}' that closes the value
	end := len(rest)
	for j := 0; j < len(rest); j++ {
		if rest[j] == ',' || rest[j] == '}' {
			end = j
			break
		}
	}
	return strings.TrimSpace(rest[:end])
}
