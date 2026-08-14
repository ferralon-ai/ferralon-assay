package jsanalysis

// inventory_yarn.go — the yarn inventory adapter. It carries two edge-resolution MODES behind
// one adapter (graph-representation.md §2): Yarn Classic (v1) descriptor-table resolution
// (§3b, LIVE) and Yarn Berry (v2+) virtual-locator resolution (§3c, UNVERIFIED — see below).
// No package manager is executed.
//
// ⚠ BERRY IS DEFERRED AND UNVERIFIED (PLAN-160 stage-4 dependency). Zero Berry lockfiles exist
// in the corpus (stage-1 gap #1); the `virtual:<hash>#npm:<ver>` locator form and its
// ?resolution_scope= token spelling are FORMAT-KNOWLEDGE ONLY, not confirmed against a
// specimen. The Berry path below is written against graph-rep §3c but MUST be re-confirmed
// against fixture F1 before it is trusted; its test is t.Skip'd pending that specimen. A Berry
// lockfile is deliberately NOT fabricated here — a hand-authored virtual hash would be fake
// metadata (fixture-specs.md cold-fixture rule).

import (
	"os"
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

// --- Yarn Berry v2+ (UNVERIFIED — deferred, no specimen) ---------------------

// yarnBerryParse resolves a Berry yarn.lock against graph-rep §3c. UNVERIFIED: the virtual
// locator spelling is format-knowledge, not confirmed against a specimen (fixture F1). Its
// test is t.Skip'd. TODO(PLAN-160 stage-4): re-confirm the `virtual:<hash>` token and the
// resolution/descriptor mapping against a real Berry lockfile before trusting this path.
func yarnBerryParse(sel selectedLock, data []byte, manifests []manifestFile) ([]plugin.DependencyNode, []plugin.DependencyEdge, plugin.Partiality) {
	blocks := parseYarnBerry(data)
	part := plugin.Complete()

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
	descToID := make(map[string]string) // descriptor "name@npm:range" → node ID
	var edges []plugin.DependencyEdge

	for _, b := range blocks {
		if len(b.descriptors) == 0 || b.version == "" {
			continue
		}
		name := berryDescriptorName(b.descriptors[0])
		purl := makePURL(name, b.version)
		scopeToken := berryVirtualToken(b.resolution)
		id := makeID(purl, scopeToken)
		addNode(plugin.DependencyNode{
			ID:         id,
			PURL:       purl,
			Version:    b.version,
			Artifact:   plugin.DependencyArtifact{Identity: artifactIdentity("", name, b.version), Digest: mapIntegrity(b.integrity)},
			Provenance: plugin.DependencyProvenance{Lockfile: sel.path, Resolver: "yarn"},
			Partiality: plugin.Complete(),
		})
		for _, d := range b.descriptors {
			descToID[d] = id
		}
	}
	for _, b := range blocks {
		if len(b.descriptors) == 0 || b.version == "" {
			continue
		}
		parentID := descToID[b.descriptors[0]]
		for _, childName := range b.depOrder {
			childDesc := childName + "@npm:" + b.deps[childName]
			if cid, ok := descToID[childDesc]; ok {
				edges = append(edges, plugin.DependencyEdge{Parent: parentID, Child: cid})
			}
		}
	}

	out := make([]plugin.DependencyNode, 0, len(order))
	for _, id := range order {
		out = append(out, *nodesByID[id])
	}
	return out, edges, part
}

type yarnBerryBlock struct {
	descriptors []string
	version     string
	resolution  string
	integrity   string
	deps        map[string]string
	depOrder    []string
}

// parseYarnBerry lexically parses a Berry yarn.lock (YAML-ish). UNVERIFIED (see file header).
func parseYarnBerry(data []byte) []yarnBerryBlock {
	lines := strings.Split(string(data), "\n")
	var blocks []yarnBerryBlock
	var cur *yarnBerryBlock
	subblock := ""
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
			b := yarnBerryBlock{deps: make(map[string]string)}
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
			case "dependencies":
				subblock = "deps"
			default:
				subblock = ""
			}
			continue
		}
		if ind >= 4 && subblock == "deps" {
			k, v := splitFirstColon(trimmed)
			name := unquoteYAML(strings.TrimSpace(k))
			if name != "" {
				if _, dup := cur.deps[name]; !dup {
					cur.depOrder = append(cur.depOrder, name)
				}
				cur.deps[name] = unquoteYAML(strings.TrimSpace(v))
			}
		}
	}
	flush()
	return blocks
}

// berryDescriptorName recovers the plain package name from a Berry descriptor
// "name@npm:range" / "@scope/name@npm:range".
func berryDescriptorName(desc string) string {
	if i := strings.Index(desc, "@npm:"); i > 0 {
		return desc[:i]
	}
	return yarnDescriptorName(desc)
}

// berryVirtualToken extracts the resolution-scope token from a Berry resolution locator of the
// form "name@virtual:<hash>#npm:<ver>" → "virtual:<hash>". UNVERIFIED spelling (fixture F1).
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
