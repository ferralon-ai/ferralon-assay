package depreach

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

// Engine is a class-hierarchy (CHA) call graph over a set of parsed classes: the
// application code plus every dependency JAR whose bytecode was loaded. Classes
// outside this set (the JDK, unloaded dependencies) are out-of-classpath leaves,
// handled soundly by the hazard rules in resolveTargets.
//
// CHA is sound but over-approximate: a virtual call resolves to every concrete
// override in the receiver's subtype closure, even ones the program never
// instantiates. RTA (restricting targets to types reached by a `new`) is the first
// precision lever and is deliberately deferred — it lowers the undetermined rate,
// it does not change soundness.
type Engine struct {
	classes  map[string]*classfile.Class
	declared map[string]*classfile.Method // key: MethodRef.String() -> declaring method
	subtypes map[string][]string          // supertype -> direct subclasses/implementors
}

// NewEngine indexes the classes for hierarchy and method lookup. The input slice is
// retained by pointer, so callers must not mutate it afterwards.
func NewEngine(classes []classfile.Class) *Engine {
	e := &Engine{
		classes:  make(map[string]*classfile.Class, len(classes)),
		declared: map[string]*classfile.Method{},
		subtypes: map[string][]string{},
	}
	for i := range classes {
		c := &classes[i]
		e.classes[c.Name] = c
		for j := range c.Methods {
			e.declared[c.Methods[j].Ref.String()] = &c.Methods[j]
		}
	}
	for _, c := range e.classes {
		for _, parent := range append([]string{c.Super}, c.Interfaces...) {
			if parent != "" {
				e.subtypes[parent] = append(e.subtypes[parent], c.Name)
			}
		}
	}
	return e
}

// subtypeClosure returns owner plus all transitive subclasses/implementors, sorted
// for deterministic target ordering.
func (e *Engine) subtypeClosure(owner string) []string {
	seen := map[string]bool{owner: true}
	stack := []string{owner}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, s := range e.subtypes[cur] {
			if !seen[s] {
				seen[s] = true
				stack = append(stack, s)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// initClosure returns owner plus every in-classpath class whose <clinit> the JVM
// runs when owner is initialized: the transitive superclass chain and implemented
// interfaces (JVMS §5.5 — a class's initialization first initializes its superclass,
// then its default-method superinterfaces). It over-approximates the interface set
// (walking all superinterfaces, not only those declaring a default method): extra
// <clinit>s can only ADD reachability, never hide a path, so this never produces a
// false not_exploitable — at worst a rare over-flag when an interface with a static
// initializer would not actually run. An out-of-classpath ancestor is not in
// e.classes, so its chain cannot be walked (its <clinit> is a sound leaf).
func (e *Engine) initClosure(owner string) []string {
	seen := map[string]bool{}
	var out []string
	stack := []string{owner}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[cur] {
			continue
		}
		seen[cur] = true
		out = append(out, cur)
		c := e.classes[cur]
		if c == nil {
			continue // out-of-classpath: ancestors unknown, <clinit> is a leaf
		}
		if c.Super != "" {
			stack = append(stack, c.Super)
		}
		stack = append(stack, c.Interfaces...)
	}
	return out
}

// hasAppSubtype reports whether some in-classpath class other than typ is a subtype
// of typ — i.e. an application object of the (possibly JDK) type could exist and be
// passed as a callback. Used by the re-entry hazard rule.
func (e *Engine) hasAppSubtype(typ string) bool {
	for _, c := range e.subtypeClosure(typ) {
		if c == typ {
			continue
		}
		if _, inClasspath := e.classes[c]; inClasspath {
			return true
		}
	}
	return false
}

// lookupInherited resolves (owner,name,desc) walking up the superclass chain — for
// static/special edges whose exact target may be declared on an ancestor.
func (e *Engine) lookupInherited(ref classfile.MethodRef) *classfile.Method {
	for cur := ref.Owner; cur != ""; {
		if m, ok := e.declared[(classfile.MethodRef{Owner: cur, Name: ref.Name, Descriptor: ref.Descriptor}).String()]; ok {
			return m
		}
		c := e.classes[cur]
		if c == nil {
			break
		}
		cur = c.Super
	}
	return nil
}

// resolveTargets returns the concrete in-classpath callees of an edge under CHA,
// plus whether the edge is a completeness HAZARD — a call whose real target the
// static graph cannot enumerate — and a human-readable reason when it is.
//
// The hazard rules are the soundness of the whole analysis; each is the seam where a
// missed edge would produce a false not_exploitable:
//   - invokedynamic and reflection: the target is decided at runtime (a lambda's
//     metafactory, Class.forName) and is invisible to a static graph.
//   - a virtual/interface call whose receiver type is out of classpath: real
//     dispatch could land on anything, including the sink.
//   - a static/special call INTO an out-of-classpath method that takes a callback
//     an application class implements: higher-order re-entry (a Comparator handed to
//     Collections.sort, a Runnable to an executor). The callback is invoked inside
//     the out-of-classpath method the graph does not traverse, so it is caught here,
//     caller-side, rather than silently dropped at the leaf.
func (e *Engine) resolveTargets(edge classfile.Edge) (targets []*classfile.Method, hazard bool, why string) {
	if edge.Kind == classfile.EdgeDynamic {
		return nil, true, "invokedynamic (runtime-bound target): " + edge.To.Name + edge.To.Descriptor
	}
	if isReflection(edge.To) {
		return nil, true, "reflection: " + edge.To.String()
	}
	switch edge.Kind {
	case classfile.EdgeStatic, classfile.EdgeSpecial:
		if m := e.lookupInherited(edge.To); m != nil {
			return []*classfile.Method{m}, false, ""
		}
		// Target outside the analyzed classpath (JDK / unloaded dependency). A direct
		// call there is a leaf UNLESS it can re-enter application code through a
		// callback argument — the C8 re-entry seam.
		if cb, ok := e.reentryCallback(edge.To.Descriptor); ok {
			return nil, true, "higher-order re-entry: out-of-classpath call takes app-implemented " + cb
		}
		return nil, false, ""
	case classfile.EdgeVirtual, classfile.EdgeInterface:
		if _, known := e.classes[edge.To.Owner]; !known {
			return nil, true, "virtual/interface call on out-of-classpath receiver " + edge.To.Owner
		}
		for _, c := range e.subtypeClosure(edge.To.Owner) {
			key := (classfile.MethodRef{Owner: c, Name: edge.To.Name, Descriptor: edge.To.Descriptor}).String()
			if m, ok := e.declared[key]; ok && !m.Abstract {
				targets = append(targets, m)
			}
		}
		if len(targets) == 0 {
			// The receiver type is in classpath but the method is declared nowhere in
			// its subtype closure: it is inherited from an out-of-classpath supertype
			// (e.g. MyList extends ArrayList; forEach(...)). The real body is out of
			// classpath, so — exactly as the static/special leaf — a callback argument
			// can re-enter application code. Without this check the virtual branch is a
			// silent leaf where the static branch declares a hazard (C8 re-entry seam).
			if cb, ok := e.reentryCallback(edge.To.Descriptor); ok {
				return nil, true, "higher-order re-entry via inherited out-of-classpath method: takes app-implemented " + cb
			}
		}
		return targets, false, ""
	}
	return nil, false, ""
}

// reentryCallback reports the first descriptor parameter type that an in-classpath
// application class implements — the callback that could re-enter through an
// out-of-classpath higher-order method — and whether any such parameter exists.
func (e *Engine) reentryCallback(desc string) (string, bool) {
	for _, p := range parseParamRefTypes(desc) {
		if e.hasAppSubtype(p) {
			return p, true
		}
	}
	return "", false
}

// isReflection reports whether a call target is a dynamic-resolution entry point
// whose real callee is a string/handle/loaded-class decided at runtime, and which
// can therefore reach code the static graph cannot enumerate. It covers reflection
// proper (Class.forName/newInstance, java/lang/reflect/* including Proxy, MethodHandle)
// and the adjacent dynamic-loading channels (ClassLoader.loadClass, ServiceLoader.load,
// JNDI Context.lookup) that instantiate arbitrary classes by name. Each is a
// completeness hazard: erring toward undetermined over a false not_exploitable.
func isReflection(r classfile.MethodRef) bool {
	switch {
	case r.Owner == "java/lang/Class" && (r.Name == "forName" || r.Name == "newInstance"):
		return true
	case r.Owner == "java/lang/ClassLoader" && r.Name == "loadClass":
		return true
	case r.Owner == "java/util/ServiceLoader" && r.Name == "load":
		return true
	case strings.HasPrefix(r.Owner, "java/lang/reflect/"): // Method.invoke, Constructor.newInstance, Proxy.newProxyInstance
		return true
	case r.Owner == "java/lang/invoke/MethodHandle" || r.Owner == "java/lang/invoke/MethodHandles":
		return true
	case strings.HasPrefix(r.Owner, "javax/naming/") && r.Name == "lookup": // JNDI dynamic resolution
		return true
	}
	return false
}

// Verdict is the three-valued reachability outcome. Its meaning is exactly the Go
// SSA path's: not_exploitable is emitted ONLY from a search that ran and found
// nothing, never from one that found nothing because it could not see.
type Verdict string

const (
	ReachableCandidate Verdict = "reachable_candidate"
	NotExploitable     Verdict = "not_exploitable"
	Undetermined       Verdict = "undetermined"
)

// Result is one two-trace PoNE query outcome.
type Result struct {
	Verdict          Verdict
	Path             []classfile.MethodRef // ingress..sink, present when ReachableCandidate
	SinkPresent      bool                  // trace 1: the sink method exists in the classpath (by descriptor)
	HazardOnFrontier bool                  // a completeness hazard lay on the searched frontier
	HazardWhy        string                // the first such hazard, for the soundness reviewer
	Reached          int                   // methods visited (search size, for diagnostics)
}

// Reach runs the two-trace proof-of-non-exploitability from ingress to sink:
//
//	trace 1 — sink present: the vulnerable method exists in the resolved classpath,
//	          matched by JVM descriptor (not name, not arity).
//	trace 2 — reachability: BFS ingress->sink over CHA-resolved edges, recording
//	          whether any completeness hazard lay on the reachable frontier.
//
// Verdict: a path ⇒ reachable_candidate (ordered path returned); no path and NO
// hazard on the searched frontier ⇒ not_exploitable (a real empty search); no path
// but a hazard could have hidden one ⇒ undetermined (sound abstention).
func (e *Engine) Reach(ingress, sink classfile.MethodRef) Result {
	res := Result{SinkPresent: e.declared[sink.String()] != nil}

	start := e.lookupInherited(ingress)
	if start == nil {
		// The ingress itself is not in the analyzed classpath: the search never
		// began, so absence proves nothing.
		res.Verdict = Undetermined
		res.HazardOnFrontier = true
		res.HazardWhy = "ingress method not found in classpath: " + ingress.String()
		return res
	}

	visited := map[string]bool{start.Ref.String(): true}
	prev := map[string]classfile.MethodRef{}
	queue := []classfile.MethodRef{start.Ref}
	found := false

	// enqueue advances the BFS to t (a nil t — an out-of-classpath or absent method —
	// is a no-op leaf), recording the predecessor for path reconstruction.
	enqueue := func(from classfile.MethodRef, t *classfile.Method) {
		if t == nil {
			return
		}
		if t.Ref == sink {
			prev[sink.String()] = from
			found = true
		}
		if !visited[t.Ref.String()] {
			visited[t.Ref.String()] = true
			prev[t.Ref.String()] = from
			queue = append(queue, t.Ref)
		}
	}

	for len(queue) > 0 && !found {
		cur := queue[0]
		queue = queue[1:]
		m := e.declared[cur.String()]
		if m == nil {
			continue
		}
		if m.Native {
			// A native method body is invisible bytecode: it could reach anything.
			res.HazardOnFrontier = true
			if res.HazardWhy == "" {
				res.HazardWhy = "native method on frontier: " + cur.String()
			}
		}
		for _, edge := range m.Edges {
			targets, hazard, why := e.resolveTargets(edge)
			if hazard {
				res.HazardOnFrontier = true
				if res.HazardWhy == "" {
					res.HazardWhy = why
				}
			}
			for _, t := range targets {
				enqueue(cur, t)
			}
		}
		// Static initialization runs a class's <clinit> on its first active use
		// (new / getstatic / putstatic / invokestatic). <clinit> is never an explicit
		// invoke target, so a sink reachable only through a static initializer would
		// be invisible; walk into the triggered class's <clinit> here. JVMS §5.5
		// initializes the SUPERCLASS (and default-method superinterfaces) before the
		// class itself, so walk the whole init closure — a base class's <clinit>
		// reaching the sink is a real runtime path even when the subclass has none.
		// An out-of-classpath class in the closure has no parsed <clinit> (nil -> leaf).
		for _, owner := range m.InitTriggers {
			for _, cls := range e.initClosure(owner) {
				clinit := classfile.MethodRef{Owner: cls, Name: "<clinit>", Descriptor: "()V"}
				enqueue(cur, e.declared[clinit.String()])
			}
		}
	}
	res.Reached = len(visited)

	switch {
	case found:
		res.Verdict = ReachableCandidate
		res.Path = reconstruct(prev, ingress, sink)
	case res.HazardOnFrontier:
		res.Verdict = Undetermined
	default:
		res.Verdict = NotExploitable
	}
	return res
}

// reconstruct walks the predecessor map from sink back to ingress and returns the
// path in ingress->sink order.
func reconstruct(prev map[string]classfile.MethodRef, ingress, sink classfile.MethodRef) []classfile.MethodRef {
	var rev []classfile.MethodRef
	cur := sink
	for {
		rev = append(rev, cur)
		if cur == ingress {
			break
		}
		p, ok := prev[cur.String()]
		if !ok {
			break
		}
		cur = p
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev
}

// PathString renders a MethodRef path compactly for diagnostics.
func PathString(path []classfile.MethodRef) string {
	parts := make([]string, len(path))
	for i, m := range path {
		owner := m.Owner
		if k := strings.LastIndex(owner, "/"); k >= 0 {
			owner = owner[k+1:]
		}
		parts[i] = fmt.Sprintf("%s.%s%s", owner, m.Name, m.Descriptor)
	}
	return strings.Join(parts, " -> ")
}
