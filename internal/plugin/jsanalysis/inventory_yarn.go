package jsanalysis

// inventory_yarn.go — the yarn inventory adapter. It carries two edge-resolution MODES behind
// one adapter (graph-representation.md §2): Yarn Classic (v1) descriptor-table resolution
// (§3b) and Yarn Berry (v2+) peer-virtualized resolution (§3c). No package manager is executed.
//
// Berry is VERIFIED against fixture F1 (the yarn-berry-virtual capture, Yarn 4.18.0,
// nodeLinker: node-modules). The F1 specimen corrected two provisional assumptions from
// instance-key-contract.md §2 (which flagged the Berry row UNVERIFIED):
//
//  1. The `virtual:<hash>#npm:<ver>` locator is NOT written to the yarn.lock under the
//     node-modules linker. The lockfile stores the plain base locator (resolution:
//     "react-dom@npm:18.2.0") plus a peerDependencies: block; the virtual hash is a Yarn
//     install-time artifact that surfaces only in `yarn info` output. A lockfile-only analyzer
//     therefore cannot reproduce the hash. Instead the resolution-scope suffix is derived from
//     the RESOLVED PEER SET — the same lockfile-derivable, pnpm-consistent grammar the pnpm
//     adapter uses (token "(react@18.2.0)"). berryVirtualToken remains the extractor for an
//     explicit virtual: locator when one is present (PnP linker records it in the locator).
//  2. The virtual hash is 128 hex chars (SHA-512), not the 64 the provisional note assumed.
//
// No Berry lockfile is fabricated; the F1 capture is consumed as cold bytes.

import (
	"os"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

type yarnAdapter struct{}

func (yarnAdapter) Parse(sel selectedLock, manifests []manifestFile) ([]plugin.DependencyNode, []plugin.DependencyEdge, plugin.Partiality) {
	data, err := os.ReadFile(sel.path)
	if err != nil {
		return nil, nil, plugin.Partial(plugin.PartialReasonToolFailure)
	}
	if isYarnBerry(data) {
		return yarnBerryParse(sel, data, manifests)
	}
	return yarnClassicParse(sel, data, manifests)
}

// isYarnBerry reports whether a yarn.lock is the Berry (v2+) dialect. Berry lockfiles carry a
// `__metadata:` block and `@npm:`/`@workspace:` locators; Classic v1 carries neither.
func isYarnBerry(data []byte) bool {
	s := string(data)
	return strings.Contains(s, "__metadata:") || strings.Contains(s, "@npm:")
}

// --- Yarn Classic v1 (LIVE) --------------------------------------------------

type yarnBlock struct {
	descriptors []string // ["name@range", …] — the header's comma-separated descriptors
	version     string
	resolved    string
	integrity   string
	deps        map[string]string // childName → childRange (dependencies + optionalDependencies)
	depOrder    []string
}

func yarnClassicParse(sel selectedLock, data []byte, manifests []manifestFile) ([]plugin.DependencyNode, []plugin.DependencyEdge, plugin.Partiality) {
	blocks := parseYarnClassic(data)
	part := plugin.Complete()

	// descriptor table: "name@range" → resolved version (closed in-file lookup, no network).
	table := make(map[string]string)
	for _, b := range blocks {
		for _, d := range b.descriptors {
			table[d] = b.version
		}
	}

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

	var rootMan invManifest
	var rootManPath string
	for _, m := range manifests {
		if m.dir == sel.root {
			rootMan = m.pkg
			rootManPath = m.path
			break
		}
	}

	for _, b := range blocks {
		if len(b.descriptors) == 0 || b.version == "" {
			continue
		}
		name := yarnDescriptorName(b.descriptors[0])
		if name == "" {
			continue
		}
		purl := makePURL(name, b.version) // Yarn Classic: flat lockfile, no per-instance suffix
		addNode(plugin.DependencyNode{
			ID:      purl,
			PURL:    purl,
			Version: b.version,
			Artifact: plugin.DependencyArtifact{
				Identity: artifactIdentity(b.resolved, name, b.version),
				Digest:   mapIntegrity(b.integrity),
			},
			Provenance: plugin.DependencyProvenance{Manifest: rootManPath, Lockfile: sel.path, Resolver: "yarn"},
			Partiality: plugin.Complete(),
		})
		for _, childName := range b.depOrder {
			childRange := b.deps[childName]
			childVer, ok := table[childName+"@"+childRange]
			if !ok {
				continue // descriptor not in-file: skip the edge (nothing fabricated)
			}
			edges = append(edges, plugin.DependencyEdge{Parent: purl, Child: makePURL(childName, childVer)})
		}
	}

	// Minted root project node + direct edges + membership.
	rootID := ""
	if rootMan.Name != "" && rootMan.Version != "" {
		rootID = makePURL(rootMan.Name, rootMan.Version)
		addNode(plugin.DependencyNode{
			ID:         rootID,
			PURL:       rootID,
			Version:    rootMan.Version,
			Membership: plugin.DependencyMembership{Project: rootMan.Name},
			Provenance: plugin.DependencyProvenance{Manifest: rootManPath, Lockfile: sel.path, Resolver: "yarn", Runtime: runtimeSpec(rootMan)},
			Partiality: plugin.Complete(),
		})
	}
	for _, dm := range depMapsFor(rootMan) {
		for name, rng := range dm.deps {
			ver, ok := table[name+"@"+rng]
			if !ok {
				continue
			}
			childID := makePURL(name, ver)
			if child, ok := nodesByID[childID]; ok {
				child.Direct = true
				if child.Membership.Project == "" {
					child.Membership.Project = rootMan.Name
				}
				if child.Membership.Target == "" {
					child.Membership.Target = dm.target
				}
				// Yarn Classic v1 records NO peerDependencies: a declared peer's relationship
				// is not derivable from the lockfile, so its classification is declared partial
				// (cell 4 = N). The edge/node is still emitted where the version resolves.
				if dm.target == "peer" {
					child.Partiality = mergePartiality(child.Partiality, plugin.Partial(plugin.PartialReasonPeerMetadataAbsent))
				}
			}
			if rootID != "" {
				edges = append(edges, plugin.DependencyEdge{Parent: rootID, Child: childID})
			}
		}
	}

	out := make([]plugin.DependencyNode, 0, len(order))
	for _, id := range order {
		out = append(out, *nodesByID[id])
	}
	return out, edges, part
}

// parseYarnClassic lexically parses a Yarn Classic v1 yarn.lock into blocks.
func parseYarnClassic(data []byte) []yarnBlock {
	lines := strings.Split(string(data), "\n")
	var blocks []yarnBlock
	var cur *yarnBlock
	subblock := "" // "deps" while inside dependencies:/optionalDependencies:

	flush := func() {
		if cur != nil {
			blocks = append(blocks, *cur)
			cur = nil
		}
	}
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !startsWithSpace(line) && strings.HasSuffix(trimmed, ":") {
			flush()
			header := strings.TrimSuffix(trimmed, ":")
			b := yarnBlock{deps: make(map[string]string)}
			for _, d := range strings.Split(header, ",") {
				d = strings.Trim(strings.TrimSpace(d), "\"'")
				if d != "" {
					b.descriptors = append(b.descriptors, d)
				}
			}
			cur = &b
			subblock = ""
			continue
		}
		if cur == nil {
			continue
		}
		ind := indentWidth(line)
		if ind == 2 {
			switch {
			case strings.HasPrefix(trimmed, "version"):
				if v, ok := yarnVersionField(trimmed); ok {
					cur.version = v
				}
				subblock = ""
			case strings.HasPrefix(trimmed, "resolved"):
				cur.resolved = yarnQuotedValue(trimmed[len("resolved"):])
				subblock = ""
			case strings.HasPrefix(trimmed, "integrity"):
				cur.integrity = strings.TrimSpace(trimmed[len("integrity"):])
				subblock = ""
			case trimmed == "dependencies:" || trimmed == "optionalDependencies:":
				subblock = "deps"
			default:
				subblock = ""
			}
			continue
		}
		if ind >= 4 && subblock == "deps" {
			name, rng := yarnDepEntry(trimmed)
			if name != "" {
				if _, dup := cur.deps[name]; !dup {
					cur.depOrder = append(cur.depOrder, name)
				}
				cur.deps[name] = rng
			}
		}
	}
	flush()
	return blocks
}

// yarnDescriptorName extracts the package name from a "name@range" descriptor, preserving a
// leading '@' scope.
func yarnDescriptorName(desc string) string {
	scoped := strings.HasPrefix(desc, "@")
	body := desc
	if scoped {
		body = desc[1:]
	}
	at := strings.IndexByte(body, '@')
	if at < 0 {
		if scoped {
			return "@" + body
		}
		return body
	}
	if scoped {
		return "@" + body[:at]
	}
	return body[:at]
}

// yarnDepEntry parses a Yarn Classic dependency line `name "range"` (name optionally quoted).
func yarnDepEntry(trimmed string) (name, rng string) {
	// name is up to the first whitespace; the range is the quoted remainder.
	i := strings.IndexAny(trimmed, " \t")
	if i < 0 {
		return strings.Trim(trimmed, "\"'"), ""
	}
	name = strings.Trim(strings.TrimSpace(trimmed[:i]), "\"'")
	rng = yarnQuotedValue(trimmed[i:])
	return name, rng
}

// yarnQuotedValue trims whitespace and a single layer of quotes from a value.
func yarnQuotedValue(s string) string {
	return strings.Trim(strings.TrimSpace(s), "\"'")
}

// --- Yarn Berry v2+ (verified against fixture F1) ----------------------------

// yarnBerryParse resolves a Berry yarn.lock (graph-rep §3c). Node identity: the base
// (name, version); a package that declares peerDependencies is peer-virtualized, so its ID
// carries a ?resolution_scope= suffix built from its RESOLVED PEER SET (instance-key-contract
// §2, corrected against F1 — see file header). The importer/workspace blocks (linkType: soft /
// resolution "…@workspace:…") are the project itself, not registry dependencies, so they seed
// membership/peer resolution but are not emitted as dependency nodes. No package manager is run.
func yarnBerryParse(sel selectedLock, data []byte, manifests []manifestFile) ([]plugin.DependencyNode, []plugin.DependencyEdge, plugin.Partiality) {
	blocks := parseYarnBerry(data)
	part := plugin.Complete()

	// Pass 1: descriptor → resolved version (closed in-file lookup, no network).
	descToVersion := make(map[string]string)
	for _, b := range blocks {
		if b.version == "" {
			continue
		}
		for _, d := range b.descriptors {
			descToVersion[d] = b.version
		}
	}

	// Pass 2: per-block resolved direct deps (childName → resolved version). A dep VALUE already
	// carries its protocol ("npm:^1.1.0"), so the descriptor is childName + "@" + value verbatim.
	resolvedDeps := make([]map[string]string, len(blocks))
	for i, b := range blocks {
		rd := make(map[string]string, len(b.depOrder))
		for _, childName := range b.depOrder {
			if ver, ok := descToVersion[childName+"@"+b.deps[childName]]; ok {
				rd[childName] = ver
			}
		}
		resolvedDeps[i] = rd
	}

	// Pass 3: node ID per block, minting the peer-set resolution-scope suffix for a virtualized
	// package. A package with a non-empty peerDependencies block is virtualized per consumer; its
	// peers are resolved in the scope of a consumer that also provides them. F1 has a single
	// react across the whole lockfile and react-dom is a direct dep of the sole importer, so the
	// peer set resolves unambiguously to (react@18.2.0). (Distinct peer sets across multiple
	// consumers — multiple virtual instances of one package — are not exercised by F1.)
	blockName := make([]string, len(blocks))
	blockID := make([]string, len(blocks))
	descToID := make(map[string]string)
	for i, b := range blocks {
		if b.version == "" {
			continue
		}
		name := berryDescriptorName(b.descriptors[0])
		blockName[i] = name
		purl := makePURL(name, b.version)
		token := berryPeerScopeToken(b, i, blocks, resolvedDeps, descToVersion)
		id := makeID(purl, token)
		blockID[i] = id
		for _, d := range b.descriptors {
			descToID[d] = id
		}
	}

	nodesByID := make(map[string]*plugin.DependencyNode)
	var order []string
	addNode := func(n plugin.DependencyNode) {
		if existing, ok := nodesByID[n.ID]; ok {
			mergeNode(existing, n)
			return
		}
		cp := n
		nodesByID[n.ID] = &cp
		order = append(order, n.ID)
	}
	var edges []plugin.DependencyEdge

	// Pass 4: emit dependency nodes + edges. Importer/workspace blocks are skipped as nodes.
	for i, b := range blocks {
		if b.version == "" || berryIsImporter(b) {
			continue
		}
		name := blockName[i]
		id := blockID[i]
		addNode(plugin.DependencyNode{
			ID:         id,
			PURL:       makePURL(name, b.version),
			Version:    b.version,
			Artifact:   plugin.DependencyArtifact{Identity: artifactIdentity(b.resolution, name, b.version), Digest: mapIntegrity(b.integrity)},
			Provenance: plugin.DependencyProvenance{Lockfile: sel.path, Resolver: "yarn"},
			Partiality: plugin.Complete(),
		})
		for _, childName := range b.depOrder {
			if cid, ok := descToID[childName+"@"+b.deps[childName]]; ok {
				edges = append(edges, plugin.DependencyEdge{Parent: id, Child: cid})
			}
		}
	}

	out := make([]plugin.DependencyNode, 0, len(order))
	for _, id := range order {
		out = append(out, *nodesByID[id])
	}
	return out, edges, part
}

// berryIsImporter reports whether a block is an importer/workspace (the project itself), not a
// registry dependency: Berry marks these linkType: soft with a "…@workspace:…" resolution.
func berryIsImporter(b yarnBerryBlock) bool {
	return b.linkType == "soft" || strings.Contains(b.resolution, "@workspace:")
}

// berryPeerScopeToken derives the resolution-scope token for block i. If the resolution already
// carries an explicit virtual: locator (the PnP linker records it), that token is used verbatim.
// Otherwise, when the block declares peerDependencies (node-modules linker — the F1 case), the
// token is the resolved peer set "(peer@ver,…)", peers resolved in a consuming block's scope.
// A plain package with no peers yields "" (ID == PURL).
func berryPeerScopeToken(b yarnBerryBlock, i int, blocks []yarnBerryBlock, resolvedDeps []map[string]string, descToVersion map[string]string) string {
	if v := berryVirtualToken(b.resolution); v != "" {
		return v
	}
	if len(b.peerOrder) == 0 {
		return ""
	}
	name := berryDescriptorName(b.descriptors[0])
	scope := berryConsumerScope(name, b.version, i, blocks, resolvedDeps)
	var parts []string
	for _, peer := range b.peerOrder {
		if ver, ok := scope[peer]; ok {
			parts = append(parts, peer+"@"+ver)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	return "(" + strings.Join(parts, ",") + ")"
}

// berryConsumerScope returns the resolved-dependency map of a block that consumes (name@version),
// i.e. an ancestor whose scope provides the virtualized package's peers. In the hoisted
// node-modules layout the direct consumer that also declares the peer is the provider. Falls back
// to the block's own resolved deps when no distinct consumer is found.
func berryConsumerScope(name, version string, self int, blocks []yarnBerryBlock, resolvedDeps []map[string]string) map[string]string {
	for i := range blocks {
		if i == self {
			continue
		}
		if resolvedDeps[i][name] == version {
			return resolvedDeps[i]
		}
	}
	return resolvedDeps[self]
}

type yarnBerryBlock struct {
	descriptors []string
	version     string
	resolution  string
	integrity   string
	linkType    string
	deps        map[string]string // childName → dep value ("npm:^1.1.0")
	depOrder    []string
	peers       map[string]string // peerName → peer range
	peerOrder   []string
}

// parseYarnBerry lexically parses a Berry yarn.lock (YAML-ish): comma-separated descriptor
// headers, then version / resolution / checksum / linkType scalars and the dependencies +
// peerDependencies maps. Verified against F1 (Yarn 4.18.0, __metadata version 10).
func parseYarnBerry(data []byte) []yarnBerryBlock {
	lines := strings.Split(string(data), "\n")
	var blocks []yarnBerryBlock
	var cur *yarnBerryBlock
	subblock := "" // "deps" | "peers" | ""
	flush := func() {
		if cur != nil {
			blocks = append(blocks, *cur)
			cur = nil
		}
	}
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !startsWithSpace(line) && strings.HasSuffix(trimmed, ":") {
			flush()
			header := strings.TrimSuffix(trimmed, ":")
			if header == "__metadata" {
				cur = nil
				subblock = ""
				continue
			}
			b := yarnBerryBlock{deps: make(map[string]string), peers: make(map[string]string)}
			for _, d := range strings.Split(header, ",") {
				d = strings.Trim(strings.TrimSpace(d), "\"'")
				if d != "" {
					b.descriptors = append(b.descriptors, d)
				}
			}
			cur = &b
			subblock = ""
			continue
		}
		if cur == nil {
			continue
		}
		ind := indentWidth(line)
		if ind == 2 {
			k, v := splitFirstColon(trimmed)
			switch strings.TrimSpace(k) {
			case "version":
				cur.version = unquoteYAML(strings.TrimSpace(v))
				subblock = ""
			case "resolution":
				cur.resolution = unquoteYAML(strings.TrimSpace(v))
				subblock = ""
			case "checksum":
				cur.integrity = unquoteYAML(strings.TrimSpace(v))
				subblock = ""
			case "linkType":
				cur.linkType = unquoteYAML(strings.TrimSpace(v))
				subblock = ""
			case "dependencies":
				subblock = "deps"
			case "peerDependencies":
				subblock = "peers"
			default:
				subblock = ""
			}
			continue
		}
		if ind >= 4 {
			switch subblock {
			case "deps":
				k, v := splitFirstColon(trimmed)
				name := unquoteYAML(strings.TrimSpace(k))
				if name != "" {
					if _, dup := cur.deps[name]; !dup {
						cur.depOrder = append(cur.depOrder, name)
					}
					cur.deps[name] = unquoteYAML(strings.TrimSpace(v))
				}
			case "peers":
				k, v := splitFirstColon(trimmed)
				name := unquoteYAML(strings.TrimSpace(k))
				if name != "" {
					if _, dup := cur.peers[name]; !dup {
						cur.peerOrder = append(cur.peerOrder, name)
					}
					cur.peers[name] = unquoteYAML(strings.TrimSpace(v))
				}
			}
		}
	}
	flush()
	return blocks
}

// berryDescriptorName recovers the plain package name from a Berry descriptor
// "name@npm:range" / "@scope/name@npm:range" / "name@workspace:…".
func berryDescriptorName(desc string) string {
	if scoped := strings.HasPrefix(desc, "@"); scoped {
		if slash := strings.IndexByte(desc, '/'); slash > 0 {
			if at := strings.IndexByte(desc[slash:], '@'); at > 0 {
				return desc[:slash+at]
			}
		}
	} else if at := strings.IndexByte(desc, '@'); at > 0 {
		return desc[:at]
	}
	return desc
}

// berryVirtualToken extracts the scope token from an explicit Berry virtual locator of the form
// "name@virtual:<hash>#npm:<ver>" → "virtual:<hash>", or "" when the resolution is a plain
// locator. Under the node-modules linker the yarn.lock stores plain npm: locators and this
// returns "" (the peer set supplies the token instead); the extractor is retained for PnP
// lockfiles, which record the virtual locator directly, and to confirm the `yarn info` locator
// spelling in tests. F1 confirmed the hash is 128 hex chars (SHA-512).
func berryVirtualToken(resolution string) string {
	i := strings.Index(resolution, "virtual:")
	if i < 0 {
		return ""
	}
	tok := resolution[i:]
	if h := strings.IndexByte(tok, '#'); h >= 0 {
		tok = tok[:h]
	}
	return tok
}
