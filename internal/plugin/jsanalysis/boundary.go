package jsanalysis

import (
	"context"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Package-boundary nodes. A call that enters a dependency (a member of an import binding to
// a bare specifier the resolver attributes to a package, or a method on a value derived from
// one) gets an edge to a synthetic node naming the package member it calls:
//
//	npm:<name>[/<subpath>]#<member>[.<member>...]
//
// e.g. JSON5.parse → npm:json5#parse, new CookieJar().setCookie → npm:tough-cookie#CookieJar.setCookie,
// res.redirect in an Express handler → npm:express#response.redirect. The member chain is
// the path from the module object; callBoundary marks calling a value, so express() is
// npm:express#<call> and app.listen() on app = express() is npm:express#<call>.listen.
// Unlike first-party SCIP ids, a boundary id carries no arity: a package member is named
// once whatever the call site passes, and advisory symbols name it without one. The
// "npm:" scheme keeps every boundary id disjoint from the lane's "scip-typescript " ids.
//
// The package stays uninspectable: a boundary node has no outgoing edges, and the graph
// keeps declaring uninspectable_package for every call that reaches one.
const (
	boundaryScheme = "npm:"
	callBoundary   = "<call>"
)

// algoReceiverModel names an edge whose callee was typed by the receiver table
// (receivers.go) rather than by resolving a specifier: res.redirect in an Express handler.
const algoReceiverModel resolveAlgo = "receiver_model"

// boundaryRef is a value the scanner traced to a package: the bare specifier it was
// imported through and the member chain from that module's export object.
type boundaryRef struct {
	spec    string
	members []string
}

func (b boundaryRef) id() string {
	chain := strings.Join(b.members, ".")
	if chain == "" {
		chain = callBoundary
	}
	return boundaryScheme + b.spec + "#" + chain
}

// isBoundaryID reports whether a call-graph node is a package-boundary node.
func isBoundaryID(scip string) bool {
	return strings.HasPrefix(scip, boundaryScheme)
}

// boundaryPackage returns the package name a boundary id belongs to ("@scope/pkg" for
// npm:@scope/pkg/sub#x).
func boundaryPackage(scip string) string {
	spec := strings.TrimPrefix(scip, boundaryScheme)
	if i := strings.IndexByte(spec, '#'); i >= 0 {
		spec = spec[:i]
	}
	name, _ := splitBareSpecifier(spec)
	return name
}

// boundaryResolver traces call sites to boundary nodes over one parsed program.
type boundaryResolver struct {
	rs       *resolver
	pkgSpec  map[string]bool           // module+"\x00"+specifier → the specifier resolves to a package
	handlers map[string]*receiverModel // handler frame SCIP → the model typing its parameters
}

func newBoundaryResolver(prog *program, rs *resolver) *boundaryResolver {
	br := &boundaryResolver{rs: rs, pkgSpec: map[string]bool{}, handlers: map[string]*receiverModel{}}
	for _, f := range prog.files {
		for _, in := range f.ingresses {
			if len(in.router) == 0 {
				continue
			}
			ref, ok := br.value(f.module, in.router, 0)
			if !ok {
				continue
			}
			m := routerModel(ref)
			if m == nil {
				continue
			}
			if scip := prog.resolveIngressSymbol(f.module, in); scip != "" {
				br.handlers[scip] = m
			}
		}
	}
	return br
}

// callee returns the boundary node a call site enters, with the provenance of the
// resolution, or ok=false when the call does not reach a package member.
func (br *boundaryResolver) callee(module string, cs callSite) (string, provenance, bool) {
	if cs.calleeFrame || cs.receiverThis || len(cs.chain) == 0 {
		return "", provenance{}, false
	}
	if cs.headParam.idx >= 0 {
		// The head is a parameter: only a parameter the receiver table types names a package.
		owner := funcSCIP(module, cs.headParam.enclosing, cs.headParam.name, cs.headParam.arity)
		m := br.handlers[owner]
		if m == nil {
			return "", provenance{}, false
		}
		typ := m.paramType(cs.headParam.arity, cs.headParam.idx)
		if typ == "" {
			return "", provenance{}, false
		}
		ref := boundaryRef{spec: m.pkg, members: append([]string{typ}, cs.chain[1:]...)}
		return ref.id(), provenance{Algo: algoReceiverModel}, true
	}
	ref, algo, ok := br.valueAlgo(module, cs.chain, 0)
	if !ok {
		return "", provenance{}, false
	}
	return ref.id(), provenance{Algo: algo}, true
}

func (br *boundaryResolver) value(module string, chain []string, depth int) (boundaryRef, bool) {
	ref, _, ok := br.valueAlgo(module, chain, depth)
	return ref, ok
}

// valueAlgo traces the value a dotted chain names in module back to a package: an import
// binding to a package specifier, a local bound to a call of such a value
// (`const app = express()`), or a local bound to `new` of one (`new CookieJar()`). The
// algo is the one that resolved the root specifier.
func (br *boundaryResolver) valueAlgo(module string, chain []string, depth int) (boundaryRef, resolveAlgo, bool) {
	mi := br.rs.prog.modules[module]
	if mi == nil || len(chain) == 0 || depth > 4 {
		return boundaryRef{}, "", false
	}
	head := chain[0]
	if mi.bindings.ambiguous[head] {
		return boundaryRef{}, "", false
	}
	if b, ok := mi.bindings.imports[head]; ok {
		algo := algoESM
		if b.Kind == bindRequire {
			algo = algoCJS
		}
		if !br.isPackageSpecifier(module, b, algo) {
			return boundaryRef{}, "", false
		}
		var members []string
		if b.Imported != "*" && b.Imported != "default" && b.Imported != "" {
			members = append(members, b.Imported)
		}
		return boundaryRef{spec: b.Specifier, members: append(members, chain[1:]...)}, algo, true
	}
	if mi.funcs[head] != nil || mi.classes[head] {
		return boundaryRef{}, "", false
	}
	if d, ok := mi.bindings.derived[head]; ok {
		base, algo, ok := br.valueAlgo(module, strings.Split(d, "."), depth+1)
		if !ok {
			return boundaryRef{}, "", false
		}
		members := append(append(append([]string(nil), base.members...), callBoundary), chain[1:]...)
		return boundaryRef{spec: base.spec, members: members}, algo, true
	}
	if c, ok := mi.bindings.instances[head]; ok {
		base, algo, ok := br.valueAlgo(module, strings.Split(c, "."), depth+1)
		if !ok {
			return boundaryRef{}, "", false
		}
		members := append(append([]string(nil), base.members...), chain[1:]...)
		return boundaryRef{spec: base.spec, members: members}, algo, true
	}
	return boundaryRef{}, "", false
}

// isPackageSpecifier reports whether a binding's specifier resolves to a dependency the
// lane does not open (the resolver's resolvePackage outcome), excluding Node built-ins,
// which are not npm packages.
func (br *boundaryResolver) isPackageSpecifier(module string, b binding, algo resolveAlgo) bool {
	spec := b.Specifier
	if spec == "" || strings.HasPrefix(spec, "#") || isRelativeSpecifier(spec) || strings.HasPrefix(spec, "/") || isNodeBuiltin(spec) {
		return false
	}
	key := module + "\x00" + spec
	if v, ok := br.pkgSpec[key]; ok {
		return v
	}
	v := br.rs.resolveBareSpecifier(module, spec, b.Imported, -1, algo).Kind == resolvePackage
	br.pkgSpec[key] = v
	return v
}

// isNodeBuiltin reports whether a specifier names a Node.js core module, which Node loads in
// preference to any installed package of the same name.
func isNodeBuiltin(spec string) bool {
	if strings.HasPrefix(spec, "node:") {
		return true
	}
	name, _ := splitBareSpecifier(spec)
	return nodeBuiltins[name]
}

var nodeBuiltins = map[string]bool{
	"assert": true, "async_hooks": true, "buffer": true, "child_process": true, "cluster": true,
	"console": true, "constants": true, "crypto": true, "dgram": true, "diagnostics_channel": true,
	"dns": true, "domain": true, "events": true, "fs": true, "http": true, "http2": true,
	"https": true, "inspector": true, "module": true, "net": true, "os": true, "path": true,
	"perf_hooks": true, "process": true, "punycode": true, "querystring": true, "readline": true,
	"repl": true, "stream": true, "string_decoder": true, "sys": true, "timers": true, "tls": true,
	"trace_events": true, "tty": true, "url": true, "util": true, "v8": true, "vm": true,
	"wasi": true, "worker_threads": true, "zlib": true,
}

// --- advisory symbol → boundary node -------------------------------------------------

// npmPURLName returns the package name a pkg:npm PURL names ("@scope/name" for
// pkg:npm/%40scope/name@1.0.0), or "" for any other PURL.
func npmPURLName(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:npm/")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.ReplaceAll(rest, "%40", "@")
	rest = strings.ReplaceAll(rest, "%2F", "/")
	if i := strings.LastIndexByte(rest, '@'); i > 0 {
		rest = rest[:i]
	}
	return strings.ToLower(rest)
}

// originPURL is the versionless PURL Origins records for a package name.
func originPURL(name string) string {
	return strings.TrimSuffix(makePURL(name, ""), "@")
}

// buildPackages is what the build's own manifests and lockfiles say about npm package
// names: which are in-tree (a package.json's own name), which are declared as
// dependencies, and which a selected lockfile resolved.
type buildPackages struct {
	inTree   map[string]bool
	declared map[string]bool
	locked   map[string]bool // keyed by originPURL
}

func readBuildPackages(ctx context.Context, buildDir string) buildPackages {
	bp := buildPackages{inTree: map[string]bool{}, declared: map[string]bool{}, locked: map[string]bool{}}
	for _, mf := range manifestsUnder(buildDir) {
		if mf.pkg.Name != "" {
			bp.inTree[strings.ToLower(mf.pkg.Name)] = true
		}
		for _, dm := range depMapsFor(mf.pkg) {
			for name := range dm.deps {
				bp.declared[strings.ToLower(name)] = true
			}
		}
	}
	if inv, err := ResolveInventory(ctx, plugin.ResolveInventoryRequest{BuildDir: buildDir}); err == nil {
		for _, n := range inv.Nodes {
			if i := strings.LastIndexByte(n.PURL, '@'); i > len("pkg:npm/") {
				bp.locked[n.PURL[:i]] = true
			}
		}
	}
	return bp
}

// isDependency reports whether name is a package this build depends on rather than one of
// its own: declared or locked, and not the name of any in-tree package.json.
func (bp buildPackages) isDependency(name string) bool {
	if name == "" || bp.inTree[name] {
		return false
	}
	return bp.declared[name] || bp.locked[originPURL(name)]
}

// internalEntries maps an advisory symbol that names a package-internal function (which no
// first-party code can call) to the public members whose call runs it. Each row is a claim
// about the package's own source, checked against the versions its comment names; a row
// may only widen candidates, never narrow them.
var internalEntries = map[string]map[string][]string{
	"multer": {
		// lib/make-middleware.js exports makeMiddleware, whose returned closure is the request
		// handler that parses multipart fields. index.js calls it from
		// Multer.prototype._makeMiddleware (behind single, array, fields and none) and from
		// any(), and multer(opts) returns a Multer. Checked in 1.4.2 and 2.1.1.
		"makeMiddleware": {"<call>.single", "<call>.array", "<call>.fields", "<call>.none", "<call>.any"},
	},
	"qs": {
		// lib/parse.js: the exported parse calls parseValues for a string input; parseValues
		// calls interpretNumericEntities and (6.14) parseArrayValue, which parseObject also
		// calls on the parseKeys path. lib/index.js exports it as parse. Checked in 6.7.0 and
		// 6.14.1 (parseArrayValue is absent from 6.7.0).
		"parseValues":              {"parse"},
		"parseArrayValue":          {"parse"},
		"interpretNumericEntities": {"parse"},
	},
}

// boundaryCandidates returns the boundary ids an advisory symbol can name for package pkg:
// the symbol with its "<pkg>." qualifier stripped (tough-cookie's symbols carry none), the
// receiver table's spelling of its first segment (express res → response), and the public
// members internalEntries says run it.
func boundaryCandidates(pkg, symbol string) []string {
	path := stripArity(symbol)
	if rest, ok := strings.CutPrefix(path, pkg+"."); ok {
		path = rest
	}
	if path == "" {
		return nil
	}
	segs := strings.Split(path, ".")
	out := []string{boundaryRef{spec: pkg, members: segs}.id()}
	if m := modelFor(pkg); m != nil {
		if canon, ok := m.aliases[segs[0]]; ok {
			out = append(out, boundaryRef{spec: pkg, members: append([]string{canon}, segs[1:]...)}.id())
		}
	}
	for _, member := range internalEntries[pkg][path] {
		out = append(out, boundaryRef{spec: pkg, members: strings.Split(member, ".")}.id())
	}
	return out
}

// resolveBoundarySymbols maps the request's advisory symbols onto boundary nodes present in
// the call graph. A node resolves only when the graph has an edge into it; its Origin is the
// lockfile-resolved package of the specifier it was imported through, and is absent when no
// selected lockfile resolved that package.
func resolveBoundarySymbols(pkg string, symbols []string, edges []plugin.CallEdge, bp buildPackages) (resolved []plugin.Symbol, origins map[string]string, matched map[string][]string) {
	nodes := map[string]bool{}
	for _, e := range edges {
		if isBoundaryID(e.Callee.SCIP) {
			nodes[e.Callee.SCIP] = true
		}
	}
	seen := map[string]bool{}
	for _, s := range symbols {
		for _, id := range boundaryCandidates(pkg, s) {
			if !nodes[id] {
				continue
			}
			if matched == nil {
				matched = map[string][]string{}
			}
			matched[s] = append(matched[s], id)
			if seen[id] {
				continue
			}
			seen[id] = true
			resolved = append(resolved, sym(id))
			if o := originPURL(boundaryPackage(id)); bp.locked[o] {
				if origins == nil {
					origins = map[string]string{}
				}
				origins[id] = o
			}
		}
	}
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].SCIP < resolved[j].SCIP })
	return resolved, origins, matched
}
