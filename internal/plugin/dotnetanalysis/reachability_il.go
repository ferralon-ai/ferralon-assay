package dotnetanalysis

// reachability_il.go — the STRONG (IL whole-program) tier of the Reachability op
// (PLAN-350 barrier-4b). It wires the two-trace PoNE engine (depreach) into the plugin
// contract: locate+read the first-party assembly and its spanning dependency set from the
// build output, run the engine per requested sink, and map the engine Verdict → the frozen
// plugin.ReachabilityResult.
//
// SOUNDNESS-CRITICAL — the verdict→result join. not_exploitable-equivalent (a clean,
// undetermined-free result) is emitted ONLY from a genuine two-trace NotExploitable; any
// unreconciled sink, missing addressability, or engine Undetermined degrades to
// reachability_undetermined, and a missing/unreadable first-party IL degrades to the lexical
// tier + tool_failure (Reachability). The plugin does NO Warrant adjudication — it emits
// paths + partiality; the trigger classifies.

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/depreach"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// tblMethodDefTable is the ECMA-335 MethodDef metadata table id (§II.22.26); an assembly
// EntryPoint token in this table names the program's Main root.
const tblMethodDefTable = 0x06

// tblMemberRefTable is the ECMA-335 MemberRef metadata table id (§II.22.25); a MethodImpl
// Declaration in this table names an out-of-set overridden method (e.g. System.Object::Finalize).
const tblMemberRefTable = 0x0A

// ilReachability runs the whole-program IL engine when the first-party compiled assembly is
// present in req.BuildDir's build output. handled is false to signal DEGRADE (no first-party
// IL, or a reader parse-hazard): the caller falls back to the lexical tier + tool_failure and
// NEVER an empty IL graph, NEVER a false not_exploitable.
func ilReachability(req plugin.ReachabilityRequest) (plugin.ReachabilityResult, bool) {
	build := locateFirstPartyBuild(req.BuildDir)
	if build.fp == nil {
		return plugin.ReachabilityResult{}, false // degrade to lexical + tool_failure
	}
	fp := build.fp
	var (
		deps    []assembly.DepRef
		locator *assembly.AssetsLocator
		graph   *assetsGraph
		rt      runtimeTarget
	)
	if build.assets != nil {
		if loc, parsed := assembly.ParseAssetsLocator(build.assets); parsed {
			locator = loc
		}
		graph = parseAssetsGraph(build.assets)
		rt = resolveRuntimeTarget(graph, build.target, build.runtime, locator)
		for _, d := range depRefsFrom(build.assets, rt.load) {
			if rt.shadowed[d.PkgKey] {
				continue
			}
			d.Runtime = build.runtime
			deps = append(deps, d)
		}
	}

	// A dep that does not locate/read is a DECLARED MISS: absent from the set ⇒ out-of-set ⇒
	// a completeness hazard on any call into it ⇒ undetermined, never a silent leaf. It is
	// disclosed as a scoped limit bounded by what the missing code could reach, and as a
	// run-wide reason too, so a consumer that reads only Reasons still sees it.
	set := assembly.LoadSpanningSet(req.BuildDir, fp, locator, deps)
	set.Misses = append(set.Misses, rt.misses...)
	engine := depreach.NewEngine(set.Assemblies)
	idx := buildReconcileIndex(set.Assemblies)
	// Two root classes. MAIN is the confident, PRECISE two-trace root and the ONLY root that
	// can license a clean not_exploitable: a hazard-free hit or miss from Main is the EARNED
	// confident verdict (reachable path / clean NE). The RUNTIME roots (module initializer +
	// finalizers) are a SOUND OVER-APPROXIMATION that AUGMENTS Main to close the barrier-5
	// false-NE gap (an entry the CLR/GC invokes with no call edge from Main); they can only
	// ADD reachable/undetermined, never license an NE on their own.
	mainKey, mainOK := idx.entryKey(fp)
	runtimeRoots := idx.runtimeRootKeys(set.Assemblies)

	reasons := map[string]bool{}
	for _, r := range build.reasons {
		reasons[r] = true
	}
	for _, m := range set.Misses {
		reasons[missReason(m.Reason)] = true
	}
	var paths []plugin.ReachPath
	var searched []string
	for _, scip := range req.Symbols {
		if scip == "" {
			continue
		}
		sinkKeys := idx.reconcile(scip)
		if len(sinkKeys) == 0 || !mainOK {
			// NO LOADED SINK / NO CONFIDENT ROOT: a sink whose SCIP names no method of the
			// loaded set, or a program with NO Main (a library — whose consumer-invoked public
			// API is NOT a runtime root, so the runtime roots alone cannot bound
			// reachability), is UNDETERMINED — never a false not_exploitable.
			// NE-LICENSING INVARIANT (i): a clean NE requires a confident program entry.
			reasons[plugin.PartialReasonReachabilityUndetermined] = true
			continue
		}
		// A SCIP id names a method at (type, name, arity) granularity, so it can cover several
		// same-arity overloads. The sink is the whole set: reached if any member is reached,
		// not_exploitable only if no member is.
		//
		// (1) MAIN is authoritative and settles the sink whenever it reaches it or hits a
		// frontier hazard (reachable ⇒ path + real frontier reason; undetermined ⇒
		// reachability_undetermined). Only a hazard-free Main NotExploitable falls through:
		// Main alone would clear it, but a runtime entry may still reach it (the barrier-5
		// defect). NE-LICENSING INVARIANT (ii).
		res := engine.ReachAny(mainKey, sinkKeys)
		switch res.Verdict {
		case depreach.ReachableCandidate:
			paths = append(paths, idx.projectPath(res.Path, scip))
			if res.HazardOnFrontier {
				// The reason the explored frontier ACTUALLY carries (a real HazardWhy →
				// its reason) — NOT a blanket dynamic_dispatch (the IL path resolved
				// dispatch; declaring it would understate the result).
				reasons[hazardReason(res.HazardWhy)] = true
			}
			continue
		case depreach.Undetermined:
			reasons[plugin.PartialReasonReachabilityUndetermined] = true
			continue
		case depreach.NotExploitable:
			// fall through to the runtime roots
		}
		// (2) Main did not settle it as reachable/undetermined. Consult the OVER-APPROXIMATED
		// runtime roots (module init, finalizers). A hit here is NOT Main's confident verdict
		// — the finalizer floor over-approximates reachable instantiations — so it degrades
		// to reachability_undetermined WITH a candidate evidence path, never the confident-
		// safe Complete and never a false NE. A hazard on a runtime root's frontier likewise
		// degrades to undetermined. Only when Main NE AND every runtime root is a hazard-free
		// NotExploitable is the sink SEARCHED.
		runtimeHit := false
		for _, root := range runtimeRoots {
			res := engine.ReachAny(root, sinkKeys)
			switch res.Verdict {
			case depreach.ReachableCandidate:
				paths = append(paths, idx.projectPath(res.Path, scip))
				runtimeHit = true
			case depreach.Undetermined:
				runtimeHit = true
			case depreach.NotExploitable:
			}
			if runtimeHit {
				break // a single non-NE runtime root already forces undetermined
			}
		}
		if runtimeHit {
			reasons[plugin.PartialReasonReachabilityUndetermined] = true
			continue
		}
		// EVERY root (Main + runtime) proved NotExploitable over a hazard-free frontier, and
		// every sink key is a method of an assembly this run read (reconcile only indexes the
		// loaded set, never a boundary node). That is a searched sink: listing it in Searched
		// is the lane's positive claim the not_exploitable gate requires.
		searched = append(searched, scip)
	}

	if len(build.reasons) > 0 {
		// Another project or entry assembly went untraced, or the dependency bytes may not
		// be the ones this build runs against: nothing was searched for the whole program.
		searched = nil
	}
	return plugin.ReachabilityResult{
		Partiality: ilPartiality(reasons, missScopes(set.Misses, graph)),
		Paths:      paths,
		Searched:   searched,
	}, true
}

// missScopes discloses each declared dependency miss as a scoped limit: the package's code
// was not read, so any call into it hides edges into it and everything it depends on.
func missScopes(misses []assembly.DepMiss, graph *assetsGraph) []plugin.ScopedReason {
	var out []plugin.ScopedReason
	seen := map[string]bool{}
	for _, m := range misses {
		id, _ := splitPkgKey(m.Dep.PkgKey)
		if id == "" || seen[m.Dep.PkgKey] {
			continue
		}
		seen[m.Dep.PkgKey] = true
		out = append(out, plugin.ScopedReason{
			Reason:  missReason(m.Reason),
			Package: nugetPackageURL(id),
			Path:    m.Dep.PkgKey,
			Targets: graph.closure(m.Dep.Target, m.Dep.PkgKey),
		})
	}
	return out
}

// missReason maps a spanning-set miss to its partiality code: code that was not on disk
// (or only as a stub reference assembly) is an unavailable artifact; bytes that did not
// parse are a reader failure; a per-runtime implementation the build's runtime does not
// pick out is named for why.
func missReason(miss string) string {
	switch miss {
	case assembly.MissUnreadable:
		return plugin.PartialReasonToolFailure
	case assembly.MissRIDUnknown:
		return partialReasonRIDUnknown
	case assembly.MissRIDAmbiguous:
		return partialReasonRIDAmbiguous
	}
	return partialReasonNoDependencyArtifact
}

// depRefsFrom extracts the dependency coordinates to load from a project.assets.json's
// package rows for target, or every target when target is "" (an unbound build, which is
// never searched). Project references are skipped — they are first-party siblings, not
// NuGet deps. A dep that later fails to locate/read is a declared miss inside
// LoadSpanningSet, never fabricated. Sorted for a deterministic loaded-set order.
func depRefsFrom(data []byte, target string) []assembly.DepRef {
	var af struct {
		Targets map[string]map[string]struct {
			Type string `json:"type"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(data, &af); err != nil {
		return nil
	}
	var out []assembly.DepRef
	for tfm, pkgs := range af.Targets {
		if target != "" && tfm != target {
			continue
		}
		for pkgKey, meta := range pkgs {
			if strings.EqualFold(meta.Type, "project") {
				continue
			}
			out = append(out, assembly.DepRef{Target: tfm, PkgKey: pkgKey})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].PkgKey < out[j].PkgKey
	})
	return out
}

// reconcileIndex maps the plugin's SCIP addressing onto the engine's MethodKey addressing,
// built over the loaded assembly set. scipToKeys maps a SCIP to EVERY MethodKey it covers
// (same-arity overloads share a SCIP); the caller searches the whole set. keyToSym projects
// a resolved path node back to a source-level plugin.Symbol.
type reconcileIndex struct {
	scipToKeys map[string]map[depreach.MethodKey]bool
	keyToSym   map[depreach.MethodKey]plugin.Symbol
}

// buildReconcileIndex indexes every method of the loaded set by its reconstructed SCIP id
// (IndexSymbols' scheme) and its engine MethodKey (computed with the SAME formula NewEngine
// uses, so the key resolves in the engine's byKey). The SCIP keys on (namespace, enclosing
// type chain, name, decoded arity), with generic types' backtick arity dropped as C# source
// spells them; anything it cannot reconcile degrades to undetermined.
func buildReconcileIndex(asms []*assembly.Assembly) *reconcileIndex {
	idx := &reconcileIndex{
		scipToKeys: map[string]map[depreach.MethodKey]bool{},
		keyToSym:   map[depreach.MethodKey]plugin.Symbol{},
	}
	for _, a := range asms {
		if a == nil || a.Failed {
			continue
		}
		for i := range a.Types {
			td := &a.Types[i]
			for _, m := range td.Methods {
				if m == nil {
					continue
				}
				key, scip := methodIdentity(a, td, m)
				if idx.scipToKeys[scip] == nil {
					idx.scipToKeys[scip] = map[depreach.MethodKey]bool{}
				}
				idx.scipToKeys[scip][key] = true
				if _, seen := idx.keyToSym[key]; !seen {
					idx.keyToSym[key] = depreach.SymbolFor(a, td, m)
				}
			}
		}
	}
	return idx
}

// methodIdentity computes a method's (engine MethodKey, plugin SCIP id) pair. The MethodKey
// MUST match NewEngine's construction exactly (owner display + name + ECMA-335 signature
// key) so the key resolves in the engine's byKey index. The SCIP is the identity
// ResolveDependencySymbols emits for dependency methods, so a resolved sink reconciles here.
func methodIdentity(a *assembly.Assembly, td *assembly.TypeDef, m *assembly.MethodDef) (depreach.MethodKey, string) {
	sigKey := ""
	arity := 0
	if sig, err := depreach.DecodeMethodSig(m.SigBlob, a); err == nil {
		sigKey = sig.SignatureKey()
		arity = len(sig.Params)
	}
	key := depreach.MethodKey{Owner: ownerDisplay(td.Namespace, td.Name), Name: m.Name, Sig: sigKey}
	ns, chain := sourceTypePath(a, td)
	return key, funcSCIP(ns, chain, m.Name, arity)
}

// sourceTypePath is td's namespace and enclosing chain as C# source names them: nested
// types under their outer types, and a generic type's metadata arity suffix ("List`1")
// dropped.
func sourceTypePath(a *assembly.Assembly, td *assembly.TypeDef) (string, []string) {
	ns, chain := a.TypePath(td)
	for i, t := range chain {
		if j := strings.IndexByte(t, '`'); j > 0 {
			chain[i] = t[:j]
		}
	}
	return ns, chain
}

// ownerDisplay renders a type's "Namespace.Name" display — the same owner spelling
// depreach's typeDisplayTD produces (so a computed MethodKey.Owner matches the engine's).
func ownerDisplay(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return namespace + "." + name
}

// reconcile returns every engine MethodKey the requested sink SCIP covers, sorted for a
// deterministic search order; empty when no loaded method carries that SCIP.
func (idx *reconcileIndex) reconcile(scip string) []depreach.MethodKey {
	keys := make([]depreach.MethodKey, 0, len(idx.scipToKeys[scip]))
	for k := range idx.scipToKeys[scip] {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	return keys
}

// ECMA-335 MethodAttributes bits (§II.23.1.10) used to recognize a finalizer's shape.
const (
	methodAttrStatic  = 0x0010
	methodAttrVirtual = 0x0040
)

// runtimeRootKeys enumerates the CLR/GC-invoked search roots that execute with NO call edge
// from Main, ACROSS THE ENTIRE LOADED SPANNING SET (first-party AND every located dependency):
// each assembly's module initializer (<Module>::.cctor, run UNCONDITIONALLY at that assembly's
// load) and each assembly's finalizers (an Object.Finalize override, invoked by the GC). A
// DEPENDENCY's module init or finalizer can reach a DEPENDENCY sink with no path from
// first-party Main — precisely the dep-CVE-sink class this barrier targets — so restricting the
// enumeration to the first-party assembly would leave a silent false NE. Main is handled
// separately by the caller as the confident/precise root; these are the additional roots whose
// omission is the barrier-5 false-NE defect. Each key is computed with methodIdentity over the
// method's OWN assembly, so it resolves in the engine's byKey (which spans the whole set).
//
// These roots are a SOUND OVER-APPROXIMATION — the caller degrades a hit from them to
// undetermined (never the confident-safe), so an extra root can only move a sink OFF a false
// NE, never the reverse. Over-rooting a never-actually-loaded transitive dep is likewise
// harmless. Unlocated deps are already out-of-set boundary hazards (barrier-3 DepMiss), so this
// located-set enumeration is COMPLETE — there is nothing to root outside the loaded set.
//
// FINALIZER SOUNDNESS/PRECISION TRADE: the precise root set is only the finalizers of types
// newobj'd within the reachable closure (a fix-point). The frozen engine (engine.go) exposes
// no reachable-set / newobj enumeration — Reach returns only a Verdict+Path — so that
// fix-point is not computable here. We take the SOUND FLOOR: ALL Finalize overrides in the set
// are roots. This over-approximates the reachable finalizers (a spurious finalizer root that
// cannot reach the sink yields NotExploitable and is harmless) and is never a false NE.
//
// A finalizer is recognized two ways, unioned: (a) BY NAME — a virtual instance method named
// "Finalize" (the C# compiler's spelling of a destructor); (b) BY EXPLICIT OVERRIDE — the Body
// of a MethodImpl whose Declaration resolves to a method named "Finalize", which the GC invokes
// even though the body carries an arbitrary name. (b) mirrors the engine's own explicit-impl
// dispatch and closes the mangled-name gap (a) alone misses.
func (idx *reconcileIndex) runtimeRootKeys(asms []*assembly.Assembly) []depreach.MethodKey {
	var roots []depreach.MethodKey
	for _, a := range asms {
		if a == nil || a.Failed {
			continue
		}
		for i := range a.Types {
			td := &a.Types[i]
			isModule := td.Namespace == "" && td.Name == "<Module>"
			for _, m := range td.Methods {
				if m == nil {
					continue
				}
				switch {
				case isModule && m.Name == ".cctor":
					// Module initializer: unconditional at that assembly's load.
					k, _ := methodIdentity(a, td, m)
					roots = append(roots, k)
				case m.Name == "Finalize" && m.Flags&methodAttrVirtual != 0 && m.Flags&methodAttrStatic == 0:
					// Sound floor (a): every virtual instance Finalize override.
					k, _ := methodIdentity(a, td, m)
					roots = append(roots, k)
				}
			}
		}
		// (b) MethodImpl-wired finalizers: an explicit .override of Object::Finalize can carry
		// an arbitrary body name, which the name-only match above misses. Root the Body of any
		// MethodImpl whose Declaration names "Finalize".
		for _, mi := range a.MethodImpls {
			if !declarationNamesFinalize(a, mi.Declaration) {
				continue
			}
			if m, td, ok := assemblyMethod(a, mi.Body); ok {
				k, _ := methodIdentity(a, td, m)
				roots = append(roots, k)
			}
		}
	}
	return roots
}

// declarationNamesFinalize reports whether a MethodImpl Declaration token (a MethodDefOrRef,
// resolved in asm's own tables) names a method "Finalize" — the GC-invoked destructor slot.
// Over-approximating on the name alone is sound (an over-broad finalizer root only ever adds a
// reachable/undetermined result, never a false NE); the owner being System.Object is a fine
// extra guard but not required here.
func declarationNamesFinalize(asm *assembly.Assembly, decl assembly.Token) bool {
	switch decl.Table() {
	case tblMethodDefTable:
		if m := asm.MethodByRID(decl.RID()); m != nil {
			return m.Name == "Finalize"
		}
	case tblMemberRefTable:
		rid := int(decl.RID())
		if rid > 0 && rid < len(asm.MemberRefs) {
			return asm.MemberRefs[rid].Name == "Finalize"
		}
	}
	return false
}

// assemblyMethod resolves a MethodDefOrRef token to its MethodDef and declaring TypeDef WITHIN
// asm. A non-MethodDef Body (an out-of-set MemberRef) is not a root defined here and yields
// ok=false — a finalizer is rooted in the assembly that defines its body.
func assemblyMethod(asm *assembly.Assembly, tok assembly.Token) (*assembly.MethodDef, *assembly.TypeDef, bool) {
	if tok.Table() != tblMethodDefTable {
		return nil, nil, false
	}
	m := asm.MethodByRID(tok.RID())
	if m == nil {
		return nil, nil, false
	}
	for i := range asm.Types {
		td := &asm.Types[i]
		for _, mm := range td.Methods {
			if mm == m {
				return m, td, true
			}
		}
	}
	return nil, nil, false
}

// entryKey resolves the first-party assembly's EntryPoint (Main) token to its MethodKey —
// the program root the two-trace search runs from. ok is false when the assembly has no
// managed entry point (a library) or the token does not resolve; the caller then degrades
// every sink to undetermined (never a false NE from an unrooted search).
func (idx *reconcileIndex) entryKey(fp *assembly.Assembly) (depreach.MethodKey, bool) {
	tok := assembly.Token(fp.EntryPoint)
	if tok.IsNull() || tok.Table() != tblMethodDefTable {
		return depreach.MethodKey{}, false
	}
	m := fp.MethodByRID(tok.RID())
	if m == nil {
		return depreach.MethodKey{}, false
	}
	for i := range fp.Types {
		td := &fp.Types[i]
		for _, mm := range td.Methods {
			if mm == m {
				key, _ := methodIdentity(fp, td, mm)
				return key, true
			}
		}
	}
	return depreach.MethodKey{}, false
}

// projectPath renders an engine MethodKey path (ingress..sink) as a plugin.ReachPath, mapping
// each node through the 4a source projection (generated→source), and stamps the requested
// SCIP on the sink so the caller's sink identity round-trips.
func (idx *reconcileIndex) projectPath(path []depreach.MethodKey, sinkSCIP string) plugin.ReachPath {
	trace := make([]plugin.Symbol, len(path))
	for i, k := range path {
		if s, ok := idx.keyToSym[k]; ok {
			trace[i] = s
		} else {
			trace[i] = fallbackSym(k)
		}
	}
	var sink, ingress plugin.Symbol
	if len(trace) > 0 {
		ingress = trace[0]
		sink = trace[len(trace)-1]
	}
	sink.SCIP = sinkSCIP
	return plugin.ReachPath{Sink: sink, Ingress: ingress, Trace: trace}
}

// fallbackSym renders a MethodKey with no projected source symbol (should not happen for an
// in-set node) as a plain method symbol, so a path node is never dropped.
func fallbackSym(k depreach.MethodKey) plugin.Symbol {
	return plugin.Symbol{
		Kind:        plugin.SymbolKindMethod,
		Enclosing:   k.Owner,
		Name:        k.Name,
		DisplayName: ownerDisplay(k.Owner, k.Name),
	}
}

// hazardReason maps an engine frontier-hazard reason to a frozen partiality code. The
// runtime-bound method limits (reflection, DLR-dynamic) map to their quiet method-limit
// codes; every other completeness hazard is this run's specific unresolved-frontier
// signal and maps to reachability_undetermined.
func hazardReason(why string) string {
	w := strings.ToLower(why)
	switch {
	case strings.Contains(w, "reflection"):
		return plugin.PartialReasonReflection
	case strings.Contains(w, "dynamic"):
		return plugin.PartialReasonDynamicDispatch
	default:
		return plugin.PartialReasonReachabilityUndetermined
	}
}

// ilPartiality collapses the accumulated reason set and scoped limits into a Partiality.
// Nothing at all is Complete() — the confident-safe the IL engine EARNS (every requested
// sink was reachable or provably NotExploitable over a hazard-free frontier, and every
// dependency was read).
func ilPartiality(reasons map[string]bool, scoped []plugin.ScopedReason) plugin.Partiality {
	if len(reasons) == 0 && len(scoped) == 0 {
		return plugin.Complete()
	}
	p := plugin.Partiality{Scoped: scoped}
	if len(reasons) > 0 {
		p.Reasons = sortedKeys(reasons)
	}
	return p
}

// withReason returns p with reason added (idempotent), reasons sorted for a stable payload.
// Used to DECLARE the degrade (tool_failure) on the lexical fallback's partiality.
func withReason(p plugin.Partiality, reason string) plugin.Partiality {
	set := map[string]bool{reason: true}
	for _, r := range p.Reasons {
		set[r] = true
	}
	return plugin.Partial(sortedKeys(set)...)
}
