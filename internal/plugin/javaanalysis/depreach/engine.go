package depreach

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

// Engine is a class-hierarchy (CHA) call graph over a set of parsed classes: the
// application code plus every dependency JAR whose bytecode was loaded. Classes
// outside this set split two ways (isPlatformClass): JDK platform classes are
// out-of-classpath leaves guarded by the re-entry rule, and every other unloaded
// class — a dependency whose bytecode was never opened — is a completeness hazard,
// because its body could reach the sink. Both are handled in resolveTargets.
//
// CHA is sound but over-approximate: a virtual call resolves to every concrete
// override in the receiver's subtype closure, even ones the program never
// instantiates. RTA (restricting targets to types reached by a `new`) is the first
// precision lever and is deliberately deferred — it lowers the undetermined rate,
// it does not change soundness.
type Engine struct {
	classes     map[string]*classfile.Class
	declared    map[string]*classfile.Method // key: MethodRef.String() -> declaring method
	subtypes    map[string][]string          // supertype -> direct subclasses/implementors
	overridable map[string]bool              // hasOverridable cache
}

// NewEngine indexes the classes for hierarchy and method lookup. The input slice is
// retained by pointer, so callers must not mutate it afterwards.
func NewEngine(classes []classfile.Class) *Engine {
	e := &Engine{
		classes:     make(map[string]*classfile.Class, len(classes)),
		declared:    map[string]*classfile.Method{},
		subtypes:    map[string][]string{},
		overridable: map[string]bool{},
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
//
// Every name in e.subtypes is a loaded class, so a direct subtype other than typ itself
// is exactly the witness; walking the whole closure (all loaded classes, for
// java/lang/Object) on every call edge made large classpaths quadratic.
func (e *Engine) hasAppSubtype(typ string) bool {
	for _, c := range e.subtypes[typ] {
		if c != typ {
			return true
		}
	}
	return false
}

// lookupInherited resolves (owner,name,desc) walking up the superclass chain — for
// static/special edges whose exact target may be declared on an ancestor.
func (e *Engine) lookupInherited(ref classfile.MethodRef) *classfile.Method {
	m, _ := e.resolveMethod(ref.Owner, ref.Name, ref.Descriptor)
	return m
}

// resolveMethod performs JVM method resolution (JVMS §5.4.3.3) of name+desc starting
// at class owner over the loaded classes: the superclass chain first, then the
// transitive superinterfaces for a default method. When nothing loaded declares it,
// unloaded lists the out-of-classpath ancestors (owner itself, if unloaded) where the
// real body may live, so the caller can decide leaf vs hazard by who owns them. A
// declaration found on the superclass chain wins over any interface, as at runtime.
func (e *Engine) resolveMethod(owner, name, desc string) (m *classfile.Method, unloaded []string) {
	var ifaces []string
	for cur := owner; cur != ""; {
		if m, ok := e.declared[(classfile.MethodRef{Owner: cur, Name: name, Descriptor: desc}).String()]; ok {
			return m, nil
		}
		c := e.classes[cur]
		if c == nil {
			unloaded = append(unloaded, cur)
			break
		}
		ifaces = append(ifaces, c.Interfaces...)
		cur = c.Super
	}
	seen := map[string]bool{}
	for len(ifaces) > 0 {
		cur := ifaces[0]
		ifaces = ifaces[1:]
		if seen[cur] {
			continue
		}
		seen[cur] = true
		if m, ok := e.declared[(classfile.MethodRef{Owner: cur, Name: name, Descriptor: desc}).String()]; ok && !m.Abstract {
			return m, nil
		}
		c := e.classes[cur]
		if c == nil {
			unloaded = append(unloaded, cur)
			continue
		}
		ifaces = append(ifaces, c.Interfaces...)
	}
	return nil, unloaded
}

// unloadedDependency returns the first of names that is neither loaded nor a JDK
// platform class — an opened-never dependency whose bytecode could hide the sink.
func (e *Engine) unloadedDependency(names []string) (string, bool) {
	for _, n := range names {
		if _, loaded := e.classes[n]; !loaded && !isPlatformClass(n) {
			return n, true
		}
	}
	return "", false
}

// isPlatformClass reports whether an internal class name belongs to the Java
// platform (the JDK's own modules), whose bodies the engine treats as leaves under
// the re-entry rule rather than as unseen dependency code. The list is deliberately
// exact: javax/ and com/sun/ also host widely used Maven artifacts (javax/servlet,
// javax/persistence, com/sun/jna, com/sun/mail), so only the subpackages the JDK
// itself ships are named. Misfiling a dependency here would turn its unseen body
// into a silent leaf, so anything not listed is a dependency.
func isPlatformClass(name string) bool {
	if strings.HasPrefix(name, "[") { // array pseudo-class (clone, length)
		return true
	}
	for _, p := range platformPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

var platformPrefixes = []string{
	"java/", "jdk/", "sun/",
	"javax/accessibility/", "javax/annotation/processing/", "javax/crypto/", "javax/imageio/",
	"javax/lang/model/", "javax/management/", "javax/naming/", "javax/net/", "javax/print/",
	"javax/rmi/ssl/", "javax/script/", "javax/security/auth/", "javax/security/cert/",
	"javax/security/sasl/", "javax/smartcardio/", "javax/sound/", "javax/sql/", "javax/swing/",
	"javax/tools/", "javax/transaction/xa/",
	"javax/xml/catalog/", "javax/xml/crypto/", "javax/xml/datatype/", "javax/xml/namespace/",
	"javax/xml/parsers/", "javax/xml/stream/", "javax/xml/transform/", "javax/xml/validation/",
	"javax/xml/xpath/", "javax/xml/XMLConstants",
	"com/sun/crypto/provider/", "com/sun/java/", "com/sun/jdi/", "com/sun/jndi/",
	"com/sun/management/", "com/sun/net/httpserver/", "com/sun/nio/", "com/sun/org/apache/",
	"com/sun/security/", "com/sun/source/", "com/sun/tools/",
	"org/ietf/jgss/", "org/w3c/dom/", "org/xml/sax/",
}

// resolveTargets returns the concrete in-classpath callees of an edge under CHA,
// plus whether the edge is a completeness HAZARD — a call whose real target the
// static graph cannot enumerate — and a human-readable reason when it is. from is
// the class whose method holds the call site: an invokespecial's receiver is an
// instance of it.
//
// The hazard rules are the soundness of the whole analysis; each is the seam where a
// missed edge would produce a false not_exploitable:
//   - invokedynamic, except the two bootstraps whose behaviour is fixed by the JDK
//     (resolveDynamic), and reflection: the target is decided at runtime.
//   - a virtual/interface call whose receiver type is out of classpath: real
//     dispatch could land on anything, including the sink. The exceptions are an
//     array receiver and a final JDK value class (finalValueClasses), whose bodies
//     hold no application object to call back into.
//   - a call whose body lives in an UNLOADED DEPENDENCY (not loaded, not platform):
//     the dependency's bytecode was never opened, so the sink could be anywhere
//     beneath it. Covers a direct static/special call, a method inherited from such
//     an ancestor, and (in Reach) a static initializer that ancestor would run.
//   - a call INTO an out-of-classpath platform method that takes a callback an
//     application class implements: higher-order re-entry (a Comparator handed to
//     Collections.sort, a Runnable to an executor). The callback is invoked inside
//     the out-of-classpath method the graph does not traverse, so it is caught here,
//     caller-side, rather than silently dropped at the leaf.
//   - a platform body that runs with an application object as `this` (an inherited
//     or super-called JDK method): it can call back any method the application class
//     overrides (platformBodyOn).
func (e *Engine) resolveTargets(from string, edge classfile.Edge) (targets []*classfile.Method, hazard bool, why string) {
	if edge.Kind == classfile.EdgeDynamic {
		return e.resolveDynamic(from, edge)
	}
	if isReflection(edge.To) {
		return nil, true, "reflection: " + edge.To.String()
	}
	switch edge.Kind {
	case classfile.EdgeStatic, classfile.EdgeSpecial:
		m, unloaded := e.resolveMethod(edge.To.Owner, edge.To.Name, edge.To.Descriptor)
		if m != nil {
			return []*classfile.Method{m}, false, ""
		}
		if dep, ok := e.unloadedDependency(unloaded); ok {
			return nil, true, "unloaded_dependency: " + edge.To.String() + " resolves into unopened " + dep
		}
		// Target in the JDK platform. A direct call there is a leaf UNLESS it can
		// re-enter application code through a callback argument — the C8 re-entry seam.
		if cb, ok := e.reentryCallback(edge.To.Descriptor); ok {
			return nil, true, "higher-order re-entry: out-of-classpath call takes app-implemented " + cb
		}
		if edge.Kind == classfile.EdgeSpecial {
			if receivers := e.specialReceivers(from, edge.To); receivers != nil {
				return e.platformBodyOn(edge.To, e.isObjectBody(edge.To.Owner, edge.To.Name, edge.To.Descriptor), receivers)
			}
		}
		return nil, false, ""
	case classfile.EdgeVirtual, classfile.EdgeInterface:
		if _, known := e.classes[edge.To.Owner]; !known {
			switch {
			case strings.HasPrefix(edge.To.Owner, "["):
				// An array's methods are Object's plus clone; none calls back.
				return nil, false, ""
			case finalValueClasses[edge.To.Owner]:
				// The receiver is exactly this final class, whose body holds no
				// application object; only a callback argument can re-enter.
				if cb, ok := e.reentryCallback(edge.To.Descriptor); ok {
					return nil, true, "higher-order re-entry: out-of-classpath call takes app-implemented " + cb
				}
				return nil, false, ""
			}
			// Any other platform receiver can be a JDK object holding application
			// objects (an ArrayList whose hashCode calls each element's hashCode),
			// which no rule here can bound without a model of the JDK's bodies.
			return nil, true, "virtual/interface call on out-of-classpath receiver " + edge.To.Owner
		}
		// CHA: every class in the receiver's subtype closure dispatches to the method
		// it RESOLVES to — its own declaration or an inherited one — not only to
		// declarations in the closure. A class that inherits the body from outside the
		// loaded set dispatches into code the graph cannot see.
		seen := map[*classfile.Method]bool{}
		var outside, platformExits []string
		for _, c := range e.subtypeClosure(edge.To.Owner) {
			m, unloaded := e.resolveMethod(c, edge.To.Name, edge.To.Descriptor)
			if m == nil {
				outside = append(outside, unloaded...)
				if e.isConcrete(c) {
					platformExits = append(platformExits, c)
				}
				continue
			}
			if !m.Abstract && !seen[m] {
				seen[m] = true
				targets = append(targets, m)
			}
		}
		if dep, ok := e.unloadedDependency(outside); ok {
			return nil, true, "unloaded_dependency: " + edge.To.String() + " inherits from unopened " + dep
		}
		if len(outside) > 0 {
			// Some receiver inherits the body from an out-of-classpath platform
			// supertype (e.g. MyList extends ArrayList; forEach(...)). Exactly as the
			// static/special leaf, a callback argument can re-enter application code
			// (C8 re-entry seam).
			if cb, ok := e.reentryCallback(edge.To.Descriptor); ok {
				return nil, true, "higher-order re-entry via inherited out-of-classpath method: takes app-implemented " + cb
			}
		}
		// The inherited platform body also runs with the receiver as `this`.
		for _, c := range platformExits {
			ts, h, w := e.platformBodyOn(edge.To, e.isObjectBody(c, edge.To.Name, edge.To.Descriptor), []string{c})
			for _, t := range ts {
				if !seen[t] {
					seen[t] = true
					targets = append(targets, t)
				}
			}
			if h {
				return targets, true, w
			}
		}
		return targets, false, ""
	}
	return nil, false, ""
}

// finalValueClasses are final JDK classes whose instances hold only characters and
// primitives, so a method called on one cannot reach an application object except
// through its own arguments. A hand-listed JDK fact: adding a class that can hold
// application objects (a collection, Optional, Thread) would turn a hazard into a
// silent leaf. java/lang/Class is excluded: newInstance and getMethod reach code.
var finalValueClasses = map[string]bool{
	"java/lang/String":        true,
	"java/lang/StringBuilder": true,
	"java/lang/StringBuffer":  true,
	"java/lang/Integer":       true,
	"java/lang/Long":          true,
	"java/lang/Short":         true,
	"java/lang/Byte":          true,
	"java/lang/Character":     true,
	"java/lang/Boolean":       true,
	"java/lang/Float":         true,
	"java/lang/Double":        true,
}

// objectMethods are java/lang/Object's methods (JDK fact). Their bodies call back
// into the receiver only in toString, which calls this.hashCode().
var objectMethods = map[string]bool{
	"<init>()V":                    true,
	"toString()Ljava/lang/String;": true,
	"hashCode()I":                  true,
	"equals(Ljava/lang/Object;)Z":  true,
	"clone()Ljava/lang/Object;":    true,
	"finalize()V":                  true,
	"getClass()Ljava/lang/Class;":  true,
	"notify()V":                    true,
	"notifyAll()V":                 true,
	"wait()V":                      true,
	"wait(J)V":                     true,
	"wait(JI)V":                    true,
}

const (
	objectToString = "toString()Ljava/lang/String;"
	objectClass    = "java/lang/Object"
)

// isConcrete reports whether c is a loaded class an object can have as its exact
// class.
func (e *Engine) isConcrete(c string) bool {
	cls := e.classes[c]
	return cls != nil && !cls.Abstract
}

// chainExit returns the first class on owner's superclass chain that is not loaded:
// where resolution of a method no loaded class declares leaves the loaded set.
func (e *Engine) chainExit(owner string) string {
	cur := owner
	for {
		c := e.classes[cur]
		if c == nil || c.Super == "" {
			return cur
		}
		cur = c.Super
	}
}

// isObjectBody reports whether resolving name+desc on owner, when nothing loaded
// declares it, lands in java/lang/Object's own body. Resolution searches the whole
// superclass chain before any superinterface (JVMS §5.4.3.3), so a chain leaving
// the loaded set at Object binds Object's methods there whatever interfaces the
// class adds.
func (e *Engine) isObjectBody(owner, name, desc string) bool {
	return objectMethods[name+desc] && e.chainExit(owner) == objectClass
}

// specialReceivers returns the classes whose instances can be `this` when an
// invokespecial from class from runs the platform body ref resolves to, or nil when
// the receiver is a fresh object of a platform class (a leaf). An <init> call binds
// `this` only as from's super(...) call, which names its direct superclass (JVMS
// §4.10.1.9); every other invokespecial needs a receiver of from's type.
func (e *Engine) specialReceivers(from string, ref classfile.MethodRef) []string {
	c := e.classes[from]
	if c == nil {
		return nil
	}
	if ref.Name == "<init>" && c.Super != ref.Owner {
		return nil
	}
	return e.subtypeClosure(from)
}

// platformBodyOn resolves a platform method body that runs with `this` bound to an
// instance of each concrete class in receivers. Object's bodies are known: only
// toString calls back, into this.hashCode(). Any other platform body can call every
// method the receiver overrides, and can hand back objects it then calls into, so a
// receiver with an overridable loaded method is a hazard.
func (e *Engine) platformBodyOn(body classfile.MethodRef, objectBody bool, receivers []string) (targets []*classfile.Method, hazard bool, why string) {
	for _, c := range receivers {
		if !e.isConcrete(c) {
			continue
		}
		if objectBody {
			if body.Name+body.Descriptor != objectToString {
				continue
			}
			ts, h, w := e.dispatchOn(c, "hashCode", "()I")
			targets = append(targets, ts...)
			if h && !hazard {
				hazard, why = true, w
			}
			continue
		}
		if e.hasOverridable(c) {
			return targets, true, "higher-order re-entry: inherited platform body " + body.String() + " runs on " + c + ", which overrides methods it may call"
		}
	}
	return targets, hazard, why
}

// dispatchOn resolves a virtual call on a receiver whose exact class is the loaded
// concrete class c.
func (e *Engine) dispatchOn(c, name, desc string) ([]*classfile.Method, bool, string) {
	m, unloaded := e.resolveMethod(c, name, desc)
	if m != nil {
		if m.Abstract {
			return nil, false, ""
		}
		return []*classfile.Method{m}, false, ""
	}
	ref := classfile.MethodRef{Owner: c, Name: name, Descriptor: desc}
	if dep, ok := e.unloadedDependency(unloaded); ok {
		return nil, true, "unloaded_dependency: " + ref.String() + " inherits from unopened " + dep
	}
	return e.platformBodyOn(ref, e.isObjectBody(c, name, desc), []string{c})
}

// hasOverridable reports whether c, its loaded superclasses, or their loaded
// superinterfaces declare a method a platform body could dispatch to on a c
// receiver: an instance method with a body that is neither private nor a
// constructor or initializer.
func (e *Engine) hasOverridable(c string) bool {
	if v, ok := e.overridable[c]; ok {
		return v
	}
	found := false
	seen := map[string]bool{}
	stack := []string{c}
	for len(stack) > 0 && !found {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		cls := e.classes[cur]
		if seen[cur] || cls == nil {
			continue
		}
		seen[cur] = true
		for _, m := range cls.Methods {
			if !m.Static && !m.Private && !m.Abstract && m.Ref.Name != "<init>" && m.Ref.Name != "<clinit>" {
				found = true
				break
			}
		}
		if cls.Super != "" {
			stack = append(stack, cls.Super)
		}
		stack = append(stack, cls.Interfaces...)
	}
	e.overridable[c] = found
	return found
}

// The bootstrap methods whose call sites the engine resolves (JDK API facts).
var (
	lambdaBootstraps = map[string]bool{
		"java/lang/invoke/LambdaMetafactory.metafactory(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;": true,
		"java/lang/invoke/LambdaMetafactory.altMetafactory(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;":                                                                    true,
	}
	concatBootstraps = map[string]bool{
		"java/lang/invoke/StringConcatFactory.makeConcat(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;":                                                   true,
		"java/lang/invoke/StringConcatFactory.makeConcatWithConstants(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;": true,
	}
)

// resolveDynamic resolves an invokedynamic site by its bootstrap method. Two are
// fixed by the JDK and resolved:
//   - LambdaMetafactory builds an object whose functional method calls the
//     implementation handle (bootstrap argument 1). The implementation counts as
//     reached where the lambda is created, which covers every later call wherever
//     the object travels — the analogue of .NET's ldftn.
//   - StringConcatFactory calls String.valueOf, hence toString(), on each dynamic
//     argument and nothing else; each toString is resolved as a virtual call.
//
// Every other bootstrap, or a site with no bootstrap entry, stays a hazard.
func (e *Engine) resolveDynamic(from string, edge classfile.Edge) ([]*classfile.Method, bool, string) {
	opaque := "invokedynamic (runtime-bound target): " + edge.To.Name + edge.To.Descriptor
	b := edge.Bootstrap
	if b == nil || b.Method.Kind != classfile.RefInvokeStatic {
		return nil, true, opaque
	}
	switch boot := b.Method.Ref.String(); {
	case lambdaBootstraps[boot]:
		if len(b.Args) < 2 || b.Args[1].Handle == nil {
			return nil, true, opaque
		}
		ts, h, w := e.resolveHandle(from, *b.Args[1].Handle)
		switch {
		case h && w == "":
			w = opaque
		case h:
			w += " (lambda implementation)"
		}
		return ts, h, w
	case concatBootstraps[boot]:
		var targets []*classfile.Method
		hazard, why := false, ""
		for _, p := range paramTypes(edge.To.Descriptor) {
			ts, h, w := e.resolveTargets(from, classfile.Edge{To: classfile.MethodRef{Owner: p, Name: "toString", Descriptor: "()Ljava/lang/String;"}, Kind: classfile.EdgeVirtual})
			targets = append(targets, ts...)
			if h && !hazard {
				hazard, why = true, w+" (string concatenation toString)"
			}
		}
		return targets, hazard, why
	}
	return nil, true, opaque
}

// resolveHandle resolves the call a lambda's implementation method handle makes,
// by its reference kind (JVMS §5.4.3.5). Invoking a static or constructor handle
// initializes its class (JVMS §5.5), so those also reach the class's static
// initializers. A field handle or unknown kind returns a hazard with an empty reason
// for the caller to fill.
func (e *Engine) resolveHandle(from string, h classfile.MethodHandle) ([]*classfile.Method, bool, string) {
	var kind classfile.EdgeKind
	switch h.Kind {
	case classfile.RefInvokeVirtual:
		kind = classfile.EdgeVirtual
	case classfile.RefInvokeInterface:
		kind = classfile.EdgeInterface
	case classfile.RefInvokeSpecial:
		kind = classfile.EdgeSpecial
	case classfile.RefInvokeStatic:
		kind = classfile.EdgeStatic
	case classfile.RefNewInvokeSpecial:
		// A constructor reference makes a fresh object, never `this` of from.
		from, kind = "", classfile.EdgeSpecial
	default:
		return nil, true, ""
	}
	targets, hazard, why := e.resolveTargets(from, classfile.Edge{To: h.Ref, Kind: kind})
	if h.Kind == classfile.RefInvokeStatic || h.Kind == classfile.RefNewInvokeSpecial {
		ts, ih, iw := e.initTargets(h.Ref.Owner)
		targets = append(targets, ts...)
		if ih && !hazard {
			hazard, why = true, iw
		}
	}
	return targets, hazard, why
}

// initTargets returns the static initializers initializing owner runs, and a hazard
// when one belongs to an unopened dependency (as Reach does for an InitTrigger).
func (e *Engine) initTargets(owner string) (targets []*classfile.Method, hazard bool, why string) {
	for _, cls := range e.initClosure(owner) {
		if dep, ok := e.unloadedDependency([]string{cls}); ok {
			if !hazard {
				hazard, why = true, "unloaded_dependency: static initializer of unopened "+dep
			}
			continue
		}
		if m := e.declared[(classfile.MethodRef{Owner: cls, Name: "<clinit>", Descriptor: "()V"}).String()]; m != nil {
			targets = append(targets, m)
		}
	}
	return targets, hazard, why
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
	HazardKinds      []string              // every distinct hazard kind met on the frontier (HazardKind*), sorted
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
// but a hazard could have hidden one ⇒ undetermined (sound abstention). A sink that
// trace 1 did not find is undetermined outright: the search cannot reach a method it
// never loaded, so its empty result says nothing about the program.
func (e *Engine) Reach(ingress, sink classfile.MethodRef) Result {
	res := Result{SinkPresent: e.declared[sink.String()] != nil}
	if !res.SinkPresent {
		res.Verdict = Undetermined
		res.hazard("sink_not_loaded: " + sink.String())
		return res
	}

	start := e.lookupInherited(ingress)
	if start == nil {
		// The ingress itself is not in the analyzed classpath: the search never
		// began, so absence proves nothing.
		res.Verdict = Undetermined
		res.hazard("ingress method not found in classpath: " + ingress.String())
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
			res.hazard("native method on frontier: " + cur.String())
		}
		for _, edge := range m.Edges {
			targets, hazard, why := e.resolveTargets(cur.Owner, edge)
			if hazard {
				res.hazard(why)
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
		// A platform class in the closure has no parsed <clinit> (nil -> leaf); an
		// unloaded dependency's <clinit> is unseen code and a hazard.
		for _, owner := range m.InitTriggers {
			for _, cls := range e.initClosure(owner) {
				if dep, ok := e.unloadedDependency([]string{cls}); ok {
					res.hazard("unloaded_dependency: static initializer of unopened " + dep)
					continue
				}
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

// Hazard kinds, one per resolveTargets/Reach hazard rule, so a caller can map what the
// frontier actually met to partiality reasons without parsing HazardWhy.
const (
	HazardKindSinkNotLoaded      = "sink_not_loaded"
	HazardKindIngressNotFound    = "ingress_not_found"
	HazardKindNative             = "native"
	HazardKindInvokedynamic      = "invokedynamic"
	HazardKindReflection         = "reflection"
	HazardKindUnloadedDependency = "unloaded_dependency"
	HazardKindReentry            = "reentry"
	HazardKindUnknownReceiver    = "unknown_receiver"
	HazardKindOther              = "other"
)

// hazardKind classifies a hazard reason string by the prefix its rule writes.
func hazardKind(why string) string {
	switch {
	case strings.HasPrefix(why, "sink_not_loaded"):
		return HazardKindSinkNotLoaded
	case strings.HasPrefix(why, "ingress method not found"):
		return HazardKindIngressNotFound
	case strings.HasPrefix(why, "native method"):
		return HazardKindNative
	case strings.HasPrefix(why, "invokedynamic"):
		return HazardKindInvokedynamic
	case strings.HasPrefix(why, "reflection"):
		return HazardKindReflection
	case strings.HasPrefix(why, "unloaded_dependency"):
		return HazardKindUnloadedDependency
	case strings.HasPrefix(why, "higher-order re-entry"):
		return HazardKindReentry
	case strings.HasPrefix(why, "virtual/interface call on out-of-classpath receiver"):
		return HazardKindUnknownReceiver
	default:
		return HazardKindOther
	}
}

// hazard records a completeness hazard met on the frontier: the first reason verbatim, and
// its kind in the sorted, de-duplicated HazardKinds.
func (r *Result) hazard(why string) {
	r.HazardOnFrontier = true
	if r.HazardWhy == "" {
		r.HazardWhy = why
	}
	k := hazardKind(why)
	i := sort.SearchStrings(r.HazardKinds, k)
	if i < len(r.HazardKinds) && r.HazardKinds[i] == k {
		return
	}
	r.HazardKinds = append(r.HazardKinds, "")
	copy(r.HazardKinds[i+1:], r.HazardKinds[i:])
	r.HazardKinds[i] = k
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
