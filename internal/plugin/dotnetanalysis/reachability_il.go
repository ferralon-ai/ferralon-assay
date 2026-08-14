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
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/depreach"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// tblMethodDefTable is the ECMA-335 MethodDef metadata table id (§II.22.26); an assembly
// EntryPoint token in this table names the program's Main root.
const tblMethodDefTable = 0x06

// ilReachability runs the whole-program IL engine when the first-party compiled assembly is
// present in req.BuildDir's build output. handled is false to signal DEGRADE (no first-party
// IL, or a reader parse-hazard): the caller falls back to the lexical tier + tool_failure and
// NEVER an empty IL graph, NEVER a false not_exploitable.
func ilReachability(req plugin.ReachabilityRequest) (plugin.ReachabilityResult, bool) {
	fp, deps, locator, ok := loadFirstPartyIL(req.BuildDir)
	if !ok {
		return plugin.ReachabilityResult{}, false // degrade to lexical + tool_failure
	}

	// A dep that does not locate/read is a DECLARED MISS: absent from the set ⇒ out-of-set ⇒
	// a completeness hazard on any call into it ⇒ undetermined, never a silent leaf.
	set := assembly.LoadSpanningSet(req.BuildDir, fp, locator, deps)
	engine := depreach.NewEngine(set.Assemblies)
	idx := buildReconcileIndex(set.Assemblies)
	entry, entryOK := idx.entryKey(fp)

	reasons := map[string]bool{}
	var paths []plugin.ReachPath
	for _, scip := range req.Symbols {
		if scip == "" {
			continue
		}
		sinkKey, ambiguous, found := idx.reconcile(scip)
		if !found || ambiguous || !entryOK {
			// SYMBOL-NORM (A2) DEFERRAL: a sink whose SCIP does not reconcile to a single
			// MethodKey (or a program with no addressable root) is UNDETERMINED — never a
			// false not_exploitable. This is the conservative, sound direction.
			reasons[plugin.PartialReasonReachabilityUndetermined] = true
			continue
		}
		res := engine.Reach(entry, sinkKey)
		switch res.Verdict {
		case depreach.ReachableCandidate:
			// A concrete candidate path exists: project it to source symbols and emit it.
			paths = append(paths, idx.projectPath(res.Path, scip))
			if res.HazardOnFrontier {
				// Declare the reason the explored frontier ACTUALLY carries (a real
				// HazardWhy → its reason) — NOT a blanket dynamic_dispatch (the IL path
				// resolved dispatch; declaring it would understate the result).
				reasons[hazardReason(res.HazardWhy)] = true
			}
		case depreach.Undetermined:
			// The sink was not reached but a completeness hazard lay on the frontier: the
			// search could not rule a path out. No path; declare it loudly.
			reasons[plugin.PartialReasonReachabilityUndetermined] = true
		case depreach.NotExploitable:
			// Emit NOTHING: no path, and NO partiality reason attributable to this sink.
			// The two-trace PoNE searched a hazard-free, complete frontier and found the
			// sink unreachable, so the ABSENCE of both a path and an undetermined reason IS
			// the sound proven-not-exploitable — the confident-safe the lexical tier is
			// forbidden. Undetermined DOMINATES across sinks (any Undetermined sink poisons
			// the whole result with reachability_undetermined below), so a clean result is
			// only ever produced when EVERY requested sink is reachable-or-provably-NE —
			// undetermined never collapses into a false NE.
		}
	}

	return plugin.ReachabilityResult{
		Partiality: ilPartiality(reasons),
		Paths:      paths,
	}, true
}

// loadFirstPartyIL locates+reads the first-party assembly from the build output and gathers
// the dependency spanning-set inputs. ok is false — the DEGRADE signal — when there is no
// project file, no located first-party dll, or the dll is unreadable / a reader parse-hazard
// (Failed): none of these may fabricate an empty IL graph.
func loadFirstPartyIL(buildDir string) (fp *assembly.Assembly, deps []assembly.DepRef, locator *assembly.AssetsLocator, ok bool) {
	projPath, found := findProjectFile(buildDir)
	if !found {
		return nil, nil, nil, false
	}
	name := strings.TrimSuffix(filepath.Base(projPath), filepath.Ext(projPath))
	dllPath, located := assembly.LocateBuildOutput(buildDir, name)
	if !located {
		return nil, nil, nil, false
	}
	a, read := assembly.ReadAssembly(dllPath)
	if !read || a == nil || a.Failed {
		// A first-party assembly present but unreadable/parse-hazard is a DEGRADE, not a
		// crash and not an empty graph.
		return nil, nil, nil, false
	}
	if assetsPath, has := findFile(buildDir, "project.assets.json", true); has {
		if data, err := os.ReadFile(assetsPath); err == nil {
			if loc, parsed := assembly.ParseAssetsLocator(data); parsed {
				locator = loc
			}
			deps = depRefsFrom(data)
		}
	}
	return a, deps, locator, true
}

// depRefsFrom extracts the dependency coordinates to load from a project.assets.json's
// per-target package rows (project references are skipped — they are first-party siblings,
// not NuGet deps). A dep that later fails to locate/read is a declared miss inside
// LoadSpanningSet, never fabricated. Sorted for a deterministic loaded-set order.
func depRefsFrom(data []byte) []assembly.DepRef {
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
// built over the loaded assembly set. scipToKeys carries the ambiguity guard: a SCIP that
// resolves to more than one distinct MethodKey is unreconcilable (undetermined), never a
// silent pick. keyToSym projects a resolved path node back to a source-level plugin.Symbol.
type reconcileIndex struct {
	scipToKeys map[string]map[depreach.MethodKey]bool
	keyToSym   map[depreach.MethodKey]plugin.Symbol
}

// buildReconcileIndex indexes every method of the loaded set by its reconstructed SCIP id
// (byte-identical to IndexSymbols' scheme) and its engine MethodKey (computed with the SAME
// formula NewEngine uses, so the key resolves in the engine's byKey). A2-LIMITED: the
// reconstruction keys on (namespace, top-level type, name, decoded arity) — flat types,
// arity-disambiguated, no signature-descriptor normalization — which is the deferred
// symbol-norm predecessor. Anything it cannot reconcile degrades to undetermined.
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
// key) so the key resolves in the engine's byKey index.
func methodIdentity(a *assembly.Assembly, td *assembly.TypeDef, m *assembly.MethodDef) (depreach.MethodKey, string) {
	sigKey := ""
	arity := 0
	if sig, err := depreach.DecodeMethodSig(m.SigBlob, a); err == nil {
		sigKey = sig.SignatureKey()
		arity = len(sig.Params)
	}
	key := depreach.MethodKey{Owner: ownerDisplay(td.Namespace, td.Name), Name: m.Name, Sig: sigKey}
	scip := funcSCIP(td.Namespace, []string{td.Name}, m.Name, arity)
	return key, scip
}

// ownerDisplay renders a type's "Namespace.Name" display — the same owner spelling
// depreach's typeDisplayTD produces (so a computed MethodKey.Owner matches the engine's).
func ownerDisplay(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return namespace + "." + name
}

// reconcile resolves a requested sink SCIP to a single engine MethodKey. found is false when
// no method carries that SCIP; ambiguous is true when more than one distinct MethodKey does
// (an overload the arity-only SCIP cannot separate) — both degrade the sink to undetermined,
// never a silent match.
func (idx *reconcileIndex) reconcile(scip string) (key depreach.MethodKey, ambiguous, found bool) {
	keys := idx.scipToKeys[scip]
	switch len(keys) {
	case 0:
		return depreach.MethodKey{}, false, false
	case 1:
		for k := range keys {
			return k, false, true
		}
	}
	return depreach.MethodKey{}, true, true
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

// ilPartiality collapses the accumulated reason set into a Partiality. An EMPTY set is
// Complete() — the confident-safe the IL engine EARNS (every requested sink was reachable
// or provably NotExploitable over a hazard-free frontier); this is the EXCEED-Go result the
// lexical tier is forbidden to produce.
func ilPartiality(reasons map[string]bool) plugin.Partiality {
	if len(reasons) == 0 {
		return plugin.Complete()
	}
	return plugin.Partial(sortedKeys(reasons)...)
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
