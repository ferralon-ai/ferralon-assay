package javaanalysis

import (
	"sort"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/beangraph"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// This file resolves the Java lexical call graph's unresolved interface-dispatch call
// sites through the DI bean model and produces the resolved interface→impl edges the H2
// merge folds in (spring-surface.md §2, edge-seam.md §5). It is the precision lever that
// turns a Partial(dynamic_dispatch) into a confident edge on the Assess path.
//
// The two honesty boundaries (inv.5):
//   - An edge is emitted only when an injection point of the caller's class resolves to a
//     UNIQUE first-party implementation that declares the called method — never guessed.
//   - dynamic_dispatch is RETIRED for a call site only when that impl's method is the
//     UNIQUE CONCRETE method of its name/arity in the program. An abstract interface
//     declaration inflating the candidate count is what made the call "unresolved"; once
//     the sole concrete implementation is identified, resolution is certain. A SECOND
//     concrete method of the same name/arity is a real competitor the receiver-free
//     lexical model cannot rule out, so the site keeps dynamic_dispatch (Undetermined,
//     never a false not_exploitable).

// resolveBeanEdges resolves the program's unresolved call sites through the bean
// registry and returns the resolved edges, the set of keys whose dynamic_dispatch is
// retired, and any partiality reasons the resolution must additionally declare
// (bean_ambiguous). callerOwner maps a caller SCIP id to its owning-class key so a call
// site can be tied to its class's injection points. Output is deterministic.
func resolveBeanEdges(prog *program, reg *beangraph.BeanRegistry, unresolved map[unresolvedCall]bool, callerOwner map[string]string) (edges []plugin.CallEdge, resolvedKeys map[unresolvedCall]bool, reasons []string) {
	resolvedKeys = map[unresolvedCall]bool{}
	edgeSet := map[plugin.CallEdge]bool{}
	beanAmbiguous := false

	// Iterate the unresolved keys in a deterministic order.
	keys := make([]unresolvedCall, 0, len(unresolved))
	for k := range unresolved {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].caller != keys[j].caller {
			return keys[i].caller < keys[j].caller
		}
		if keys[i].calleeName != keys[j].calleeName {
			return keys[i].calleeName < keys[j].calleeName
		}
		return keys[i].calleeArity < keys[j].calleeArity
	})

	for _, k := range keys {
		owner := callerOwner[k.caller]
		if owner == "" {
			continue
		}
		ips := prog.beanData.injByOwner[owner]
		if len(ips) == 0 {
			continue
		}

		// Collect the unique first-party impl-method SCIPs the injection points wire this
		// call to, and note any bean ambiguity that plausibly concerns this call.
		hits := map[string]bool{}
		ambiguousHere := false
		for _, ip := range ips {
			res := reg.Resolve(ip)
			switch {
			case res.Ambiguous:
				if beanTypeHasConcreteMethod(prog, reg, ip.DeclaredType, k.calleeName, k.calleeArity) {
					ambiguousHere = true
				}
			case res.Found:
				if scip, ok := firstPartyImplMethod(prog, res.Impl, k.calleeName, k.calleeArity); ok {
					hits[scip] = true
				}
			}
		}

		if len(hits) == 1 {
			implSCIP := onlyKey(hits)
			// Emit the resolved edge (adds reachability; safe regardless of retirement).
			e := plugin.CallEdge{Caller: sym(k.caller), Callee: sym(implSCIP)}
			if !edgeSet[e] {
				edgeSet[e] = true
				edges = append(edges, e)
			}
			// Retire dynamic_dispatch only when the wired impl's method is the SOLE
			// concrete target of that name/arity — otherwise a real competitor remains.
			if concreteIsSingleton(prog, k.calleeName, k.calleeArity, implSCIP) {
				resolvedKeys[k] = true
			}
			continue
		}
		// No unique wiring. If the block was a genuine bean ambiguity about this call,
		// declare it (a dynamic_dispatch localizer that does NOT retire the base).
		if len(hits) == 0 && ambiguousHere {
			beanAmbiguous = true
		}
	}

	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Caller.SCIP != edges[j].Caller.SCIP {
			return edges[i].Caller.SCIP < edges[j].Caller.SCIP
		}
		return edges[i].Callee.SCIP < edges[j].Callee.SCIP
	})
	if beanAmbiguous {
		reasons = append(reasons, plugin.PartialReasonBeanAmbiguous)
	}
	return edges, resolvedKeys, reasons
}

// firstPartyImplMethod returns the SCIP id of impl's method name/arity when impl is a
// UNIQUELY-located first-party class that concretely declares it. A simple name mapping
// to several first-party classes (a name collision across packages) is not resolvable
// here — the lexical lane cannot pick the right one, so no edge is emitted (sound).
func firstPartyImplMethod(prog *program, impl, name string, arity int) (string, bool) {
	locs := prog.beanData.classLocs[impl]
	if len(locs) != 1 {
		return "", false
	}
	scip := methodSCIP(locs[0].pkg, locs[0].enclosing, name, arity)
	for _, c := range prog.concreteByKey[methodKey(name, arity)] {
		if c == scip {
			return scip, true
		}
	}
	return "", false
}

// beanTypeHasConcreteMethod reports whether some bean satisfying declaredType is a
// first-party class that concretely declares name/arity — i.e. the type is a plausible
// receiver for this call. It gates bean_ambiguous so the localizer is tied to a call the
// ambiguity actually blocks, not raised class-wide.
func beanTypeHasConcreteMethod(prog *program, reg *beangraph.BeanRegistry, declaredType, name string, arity int) bool {
	for _, b := range reg.BeansByType(declaredType) {
		if _, ok := firstPartyImplMethod(prog, b.Impl, name, arity); ok {
			return true
		}
	}
	return false
}

// concreteIsSingleton reports whether implSCIP is the only concrete method of its
// name/arity across the whole program — the condition under which retiring
// dynamic_dispatch for a bean-resolved call is certain (no other concrete competitor).
func concreteIsSingleton(prog *program, name string, arity int, implSCIP string) bool {
	c := prog.concreteByKey[methodKey(name, arity)]
	return len(c) == 1 && c[0] == implSCIP
}

// depBeansSimpleName collapses the classfile-collected dependency beans into the Java
// lane's SIMPLE-name key space, so a first-party injection point of a type a dependency
// also provides is honestly seen as ambiguous (never resolved to a first-party impl it is
// not uniquely wired to). Dependency impls are never first-party graph nodes, so they can
// only ADD ambiguity, never an edge — the sound direction (inv.5).
func depBeansSimpleName(classes []classfile.Class) []beangraph.BeanDef {
	beans := beangraph.BeansFromClasses(classes)
	out := make([]beangraph.BeanDef, 0, len(beans))
	for _, b := range beans {
		sat := make([]string, 0, len(b.Satisfies))
		for _, s := range b.Satisfies {
			sat = append(sat, beangraph.SimpleTypeName(s))
		}
		out = append(out, beangraph.BeanDef{
			Impl:       beangraph.SimpleTypeName(b.Impl),
			Origin:     b.Origin,
			Satisfies:  sat,
			Qualifiers: b.Qualifiers,
			Primary:    b.Primary,
			Profiles:   b.Profiles,
		})
	}
	return out
}

func onlyKey(m map[string]bool) string {
	for k := range m {
		return k
	}
	return ""
}
