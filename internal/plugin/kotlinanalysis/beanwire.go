package kotlinanalysis

import (
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/beangraph"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// beanwire.go — overlay #K: the Kotlin first-party Spring dependency-injection wiring.
//
// Kotlin is analyzed as bytecode, so this is the clean lane (spring-surface.md §0):
// annotation values are visible on the compiled `.class`, and the shared classfile-native
// bean model (internal/plugin/javaanalysis/beangraph) is reused verbatim — NO lexical/SCIP
// dual-track. The registry keys on INTERNAL type names ("com/example/UserService"), which
// is exactly what Kotlin's `classfile.Class` carries, so no key translation is needed
// (contrast the Java first-party lane, which must collapse to simple names).
//
// What it does: for every first-party interface/virtual call site, if the caller's class
// has an @Autowired/@Inject/ctor injection point of the callee's declared (interface) type
// that resolves to a UNIQUE first-party implementation declaring the called method, it adds
// the resolved caller→impl edge. Today Kotlin's call graph emits only the caller→interface
// edge (the DECLARED OWNER, an abstract method with no body), so the impl body is
// unreachable; the wired edge restores that reachability. Emission is purely additive.
//
// The honesty boundary (inv.5): an edge is emitted ONLY for a unique resolution to a
// first-party impl that concretely declares the exact called method (name+descriptor —
// bytecode gives us the precise signature, so no arity approximation). An injection point
// satisfied by more than one bean with no @Primary/unique @Qualifier winner is Ambiguous:
// NO edge, and PartialReasonBeanAmbiguous is declared (a dynamic_dispatch localizer). A
// bean is never guessed.
//
// On dynamic_dispatch retirement (why this is a partial-but-honest landing): in Kotlin's
// edge model, dynamic_dispatch is raised ONLY by `invokedynamic` (the coroutine/lambda/SAM
// frontier, callee owner ""), NOT by interface dispatch — which is emitted as a (coarse)
// edge to the interface, never flagged. Bean wiring resolves interface injection, a set of
// call sites disjoint from the invokedynamic sites that raised dynamic_dispatch, so there
// is no dynamic_dispatch to retire AT the sites we resolve. Retiring the global
// invokedynamic reason on the strength of an unrelated bean resolution would be unsound.
// Making interface dispatch itself raise dynamic_dispatch (the Java lane's unresolved-key
// model) would break the "no beans → byte-identical to today" invariant — every interface
// call would newly go Partial — so it is deliberately out of scope for pass 1. The sound
// pass-1 landing is therefore: ADD the resolved reachability edges, declare bean_ambiguous
// on honest ambiguity, and leave the invokedynamic dynamic_dispatch exactly as it was.

// wireBeanEdges resolves the loaded first-party classes' interface-dispatch call sites
// through the Spring DI bean model and returns the resolved caller→impl edges to fold into
// the call graph, plus any partiality reasons the resolution must additionally declare
// (bean_ambiguous). With no beans it returns (nil, nil) — the graph is byte-identical to
// today. Output is order-independent: the returned edges are deduplicated and the caller
// re-sorts the merged edge set.
func wireBeanEdges(classes []classfile.Class) (edges []plugin.CallEdge, reasons []string) {
	beans := beangraph.BeansFromClasses(classes)
	if len(beans) == 0 {
		return nil, nil
	}
	reg := beangraph.NewRegistry(beans)

	byName := make(map[string]*classfile.Class, len(classes))
	for i := range classes {
		byName[classes[i].Name] = &classes[i]
	}

	// Injection points grouped by the class that owns them, so a call site can be tied to
	// its enclosing class's wiring.
	ipsByOwner := map[string][]beangraph.InjectionPoint{}
	for _, ip := range beangraph.InjectionPointsFromClasses(classes) {
		ipsByOwner[ip.Owner] = append(ipsByOwner[ip.Owner], ip)
	}

	edgeSet := map[plugin.CallEdge]bool{}
	beanAmbiguous := false

	for i := range classes {
		c := &classes[i]
		ips := ipsByOwner[c.Name]
		if len(ips) == 0 {
			continue
		}
		for j := range c.Methods {
			m := &c.Methods[j]
			caller := SymbolFromMethodRef(m.Ref)
			for _, e := range m.Edges {
				if e.Kind != classfile.EdgeInterface && e.Kind != classfile.EdgeVirtual {
					continue // static/special are already exact; dynamic carries no owner to wire
				}
				declaredType := e.To.Owner
				if declaredType == "" {
					continue
				}

				// Collect the unique first-party impl methods this class's injection points
				// of the callee's declared type wire the call to, and note any ambiguity
				// that plausibly concerns this call.
				hits := map[classfile.MethodRef]bool{}
				ambiguousHere := false
				for _, ip := range ips {
					if ip.DeclaredType != declaredType {
						continue
					}
					res := reg.Resolve(ip)
					switch {
					case res.Found:
						if ref, ok := implMethodRef(byName, res.Impl, e.To.Name, e.To.Descriptor); ok {
							hits[ref] = true
						}
					case res.Ambiguous:
						if typeHasImplMethod(reg, byName, declaredType, e.To.Name, e.To.Descriptor) {
							ambiguousHere = true
						}
					}
				}

				if len(hits) == 1 {
					edge := plugin.CallEdge{Caller: caller, Callee: SymbolFromMethodRef(onlyMethodRef(hits))}
					if !edgeSet[edge] {
						edgeSet[edge] = true
						edges = append(edges, edge)
					}
					continue
				}
				// No unique wiring. If a genuine bean ambiguity blocks this call, localize it.
				if len(hits) == 0 && ambiguousHere {
					beanAmbiguous = true
				}
			}
		}
	}

	if beanAmbiguous {
		reasons = append(reasons, plugin.PartialReasonBeanAmbiguous)
	}
	return edges, reasons
}

// implMethodRef returns the MethodRef of impl's concrete declaration of name+descriptor
// when impl is a loaded first-party class that declares it with a body. An abstract
// declaration (no body) is not a wirable target — the edge would reach nothing — so it is
// rejected: the wiring only ever bridges to real first-party code (inv.5, never fabricate).
func implMethodRef(byName map[string]*classfile.Class, impl, name, descriptor string) (classfile.MethodRef, bool) {
	c := byName[impl]
	if c == nil {
		return classfile.MethodRef{}, false
	}
	for k := range c.Methods {
		m := &c.Methods[k]
		if m.Ref.Name == name && m.Ref.Descriptor == descriptor && !m.Abstract {
			return m.Ref, true
		}
	}
	return classfile.MethodRef{}, false
}

// typeHasImplMethod reports whether some bean satisfying declaredType is a first-party
// class that concretely declares name+descriptor — i.e. the type is a plausible receiver
// for this call. It gates bean_ambiguous so the localizer is tied to a call the ambiguity
// actually blocks, not raised class-wide (mirrors the Java lane's beanTypeHasConcreteMethod).
func typeHasImplMethod(reg *beangraph.BeanRegistry, byName map[string]*classfile.Class, declaredType, name, descriptor string) bool {
	for _, b := range reg.BeansByType(declaredType) {
		if _, ok := implMethodRef(byName, b.Impl, name, descriptor); ok {
			return true
		}
	}
	return false
}

func onlyMethodRef(m map[classfile.MethodRef]bool) classfile.MethodRef {
	for k := range m {
		return k
	}
	return classfile.MethodRef{}
}
