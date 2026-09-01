// Package beangraph is the lane-agnostic Spring dependency-injection bean model: a
// registry of the concrete beans a container would register, indexed by the types
// each satisfies, and the resolution rule that maps an @Autowired injection point to
// the unique wired implementation — or declares the wiring honestly undetermined.
//
// It is the pure-Go, zero-egress substitute for what the container decides at runtime
// and what a compiling SCIP indexer gets for free from `implementsOf`: interface→impl
// resolution on the Assess path (spring-surface.md §2, edge-seam.md §2). It never
// executes anything and never guesses — an injection point satisfied by more than one
// bean with no @Primary/@Qualifier winner resolves to Ambiguous, the honest residue
// that keeps dynamic_dispatch partiality (inv.5), never a fabricated edge.
//
// Key neutrality (the source/bytecode asymmetry, spring-surface.md §0): the registry
// keys on opaque type-name strings and never interprets them. The classfile collector
// (collect.go) feeds INTERNAL type names ("com/example/UserService") — the natural
// key for Kotlin first-party and every dependency jar. The Java first-party lane,
// which reads source lexically and has no resolved package for a simple type token,
// feeds SIMPLE names ("UserService"). Each lane builds its own registry in one
// consistent key space; the resolution rule is identical.
package beangraph

import "sort"

// Origin records how a bean entered the registry: a stereotype-annotated class
// (@Component/@Service/@Repository/@Controller/@Configuration) the container would
// instantiate directly, or a value returned from an @Bean factory method on a
// configuration class. The distinction is metadata for the overlay/reviewer; the
// resolution rule treats both identically.
type Origin int

const (
	OriginStereotype Origin = iota // a @Component-family annotated class
	OriginBeanMethod               // an @Bean factory-method return type
)

func (o Origin) String() string {
	if o == OriginBeanMethod {
		return "beanMethod"
	}
	return "stereotype"
}

// BeanDef is one registered bean: the concrete implementation type plus the wiring
// metadata that decides which injection points it satisfies. Satisfies is the set of
// type keys the bean can be injected as — its own type plus every supertype and
// implemented interface the collector could resolve — and is what the registry indexes
// on. Qualifiers hold the bean's explicit @Qualifier values plus its implicit bean
// name (the decapitalized simple class name), the keys a qualified injection point
// matches. Profiles are recorded but their activation is environment-dependent and
// therefore never used to narrow resolution (irreducible residue, spring-surface.md §2).
type BeanDef struct {
	Impl       string   // the concrete implementation type key
	Origin     Origin   // stereotype class vs @Bean method
	Satisfies  []string // every type key this bean can be injected as (incl. Impl); the index keys
	Qualifiers []string // @Qualifier values + the implicit bean name
	Primary    bool     // carries @Primary
	Profiles   []string // @Profile values (recorded, never narrows resolution — activation is runtime)
}

// InjectionPoint is one place the container must supply a bean: a field or constructor
// parameter of declared type DeclaredType, on class Owner, optionally naming a specific
// bean via Qualifier. Site is "field" or "ctorParam" (metadata only). The registry
// resolves DeclaredType (honoring Qualifier) to the wired implementation.
type InjectionPoint struct {
	Owner        string // the class the injection point belongs to (type key)
	Site         string // "field" | "ctorParam"
	DeclaredType string // the injected type key (an interface or concrete class)
	Qualifier    string // @Qualifier value, or "" for by-type injection
}

// Resolution is the outcome of resolving one injection point. Exactly one of the three
// states holds: Found (Impl names the unique wired bean), Ambiguous (>1 satisfying bean
// with no @Primary/@Qualifier winner — the bean_ambiguous residue, keep Partial), or
// neither (no satisfying bean is known — an unknown the caller leaves unresolved). The
// caller emits a resolved edge ONLY for Found; Ambiguous and unknown never fabricate one.
type Resolution struct {
	Impl      string // the wired implementation type key, set iff Found
	Found     bool   // resolved to a unique implementation
	Ambiguous bool   // >1 candidate, no unique winner (raise PartialReasonBeanAmbiguous)
}

// BeanRegistry indexes registered beans by the types they satisfy, by their primary
// election per type, and by qualifier, and answers Resolve. It is immutable after
// NewRegistry; all output-affecting iteration is over sorted slices so a consumer's
// edge set is deterministic (no map iteration on an output path).
type BeanRegistry struct {
	beansByType   map[string][]BeanDef
	primaryByType map[string]BeanDef // present iff exactly one bean satisfying the type is @Primary
	byQualifier   map[string][]BeanDef
}

// NewRegistry builds the registry from the collected bean definitions. beansByType is
// keyed by each entry of a bean's Satisfies set (deduplicated by Impl within a type, so
// a bean listed once per type); primaryByType records a type's @Primary winner only when
// exactly one satisfying bean is primary; byQualifier indexes every qualifier a bean
// carries. Input order does not affect resolution — the winner rules are set-based.
func NewRegistry(beans []BeanDef) *BeanRegistry {
	r := &BeanRegistry{
		beansByType:   map[string][]BeanDef{},
		primaryByType: map[string]BeanDef{},
		byQualifier:   map[string][]BeanDef{},
	}
	// Index by satisfied type, MERGING entries that share an Impl under one type so the
	// same implementation appears once (which keeps the ambiguity count honest) while
	// its wiring facts are unioned: a class registered both as a @Component and as an
	// @Bean(@Primary) is one bean, and its @Primary must survive the merge (else the tie
	// it breaks looks ambiguous). Primary is OR-ed; qualifiers are unioned.
	perType := map[string]map[string]*BeanDef{}
	for i := range beans {
		b := beans[i]
		for _, t := range b.Satisfies {
			if perType[t] == nil {
				perType[t] = map[string]*BeanDef{}
			}
			if existing, ok := perType[t][b.Impl]; ok {
				existing.Primary = existing.Primary || b.Primary
				existing.Qualifiers = dedupeStrings(append(existing.Qualifiers, b.Qualifiers...))
				continue
			}
			merged := b
			merged.Qualifiers = append([]string(nil), b.Qualifiers...)
			perType[t][b.Impl] = &merged
		}
		for _, q := range b.Qualifiers {
			if q != "" {
				r.byQualifier[q] = append(r.byQualifier[q], b)
			}
		}
	}
	// Materialize each type's merged bean set from the per-Impl merge.
	for t, byImpl := range perType {
		defs := make([]BeanDef, 0, len(byImpl))
		for _, d := range byImpl {
			defs = append(defs, *d)
		}
		r.beansByType[t] = defs
	}
	// Elect a per-type primary only when exactly one satisfying bean is @Primary.
	for t, defs := range r.beansByType {
		var primary BeanDef
		count := 0
		for _, d := range defs {
			if d.Primary {
				primary = d
				count++
			}
		}
		if count == 1 {
			r.primaryByType[t] = primary
		}
	}
	// Sort each index for deterministic downstream iteration.
	for t := range r.beansByType {
		defs := r.beansByType[t]
		sort.Slice(defs, func(i, j int) bool { return defs[i].Impl < defs[j].Impl })
	}
	return r
}

// Resolve maps an injection point to its wired implementation under the container's
// resolution rule (spring-surface.md §2):
//
//   - No satisfying bean → unknown (Found=false, Ambiguous=false): an interface with no
//     registered impl (e.g. supplied by a dependency the source lane cannot see). The
//     caller keeps the dispatch unresolved; it is not a bean ambiguity.
//   - A @Qualifier → the beans that both satisfy the type AND carry the qualifier: unique
//     impl ⇒ Found; several distinct impls ⇒ Ambiguous; none ⇒ unknown.
//   - By type: a unique satisfying impl ⇒ Found; else a unique @Primary ⇒ Found; else
//     Ambiguous (the bean_ambiguous residue).
//
// It NEVER returns Found for more than one candidate — ambiguity is honest, never a
// guessed winner (inv.5).
func (r *BeanRegistry) Resolve(ip InjectionPoint) Resolution {
	cands := r.beansByType[ip.DeclaredType]
	if len(cands) == 0 {
		return Resolution{}
	}

	if ip.Qualifier != "" {
		var q []BeanDef
		for _, b := range cands {
			if containsStr(b.Qualifiers, ip.Qualifier) {
				q = append(q, b)
			}
		}
		switch impls := distinctImpls(q); len(impls) {
		case 0:
			return Resolution{} // the qualifier names no satisfying bean — unknown, not ambiguous
		case 1:
			return Resolution{Impl: impls[0], Found: true}
		default:
			return Resolution{Ambiguous: true}
		}
	}

	if impls := distinctImpls(cands); len(impls) == 1 {
		return Resolution{Impl: impls[0], Found: true}
	}
	if p, ok := r.primaryByType[ip.DeclaredType]; ok {
		return Resolution{Impl: p.Impl, Found: true}
	}
	return Resolution{Ambiguous: true}
}

// BeansByType returns the beans registered as satisfying the given type key (a copy is
// not made; callers must not mutate). It is exposed so an overlay can tie a bean
// ambiguity to a specific call (does an ambiguous injection type declare the called
// method) rather than raising bean_ambiguous class-wide.
func (r *BeanRegistry) BeansByType(typeKey string) []BeanDef {
	return r.beansByType[typeKey]
}

// distinctImpls returns the deduplicated, sorted implementation type keys among the
// given beans — the count that decides unique-vs-ambiguous.
func distinctImpls(defs []BeanDef) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range defs {
		if !seen[d.Impl] {
			seen[d.Impl] = true
			out = append(out, d.Impl)
		}
	}
	sort.Strings(out)
	return out
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
