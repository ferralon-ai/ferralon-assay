package depreach

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

// Engine is a class-hierarchy (CHA) call graph over a set of parsed classes: the
// application code plus every dependency JAR whose bytecode was loaded. Classes
// outside this set split two ways (platform): JDK platform classes are
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
	loadable    map[string]bool              // platformLoadable cache
	lambdas     map[string][]lambdaSite      // interface a lambda object implements -> its sites
	held        map[string]heldTypes         // heldAs cache
	defined     map[string]bool              // packages a classpath entry defines a class in
	unlisted    bool                         // a classpath entry could not be listed
	methodsHold bool                         // platformMethods lists the runtime's methods
	hidden      []string                     // hiddenSubtypes cache, sorted
	hiddenDone  bool                         // hidden is computed
	linked      bool                         // every class the run's classpath defines is loaded (SetLinked)
	unlinked    map[string]bool              // unlinkable cache
	resolving   map[string]bool              // lambda implementations met in the outermost lambdaImpl
}

// lambdaSite is a LambdaMetafactory call site in class from. The object it produces
// implements ifaces and answers a call to name with one of descs by running handle;
// every other method it runs is java/lang/Object's or a default it inherits.
type lambdaSite struct {
	from   string
	name   string
	descs  []string
	ifaces []string
	handle classfile.MethodHandle
}

// Classpath is what the analysed classpath defines beyond the classes handed to the engine.
type Classpath struct {
	// Packages holds every package some classpath entry (a JAR or class directory, opened or
	// not) defines a class in.
	Packages map[string]bool
	// Unlisted is set when some entry could not be listed: it may define any package.
	Unlisted bool
	// JDK is the feature release of the JDK the program runs on, or 0 when not recorded.
	// platformMethods holds only on the release it was generated from (platformMethodsJDK).
	JDK int
}

// NewEngine indexes the classes for hierarchy and method lookup. The input slice is
// retained by pointer, so callers must not mutate it afterwards.
func NewEngine(classes []classfile.Class) *Engine {
	return NewEngineOn(classes, Classpath{})
}

// BootOnly reports whether a classpath copy of the class named name may not be the body that runs
// on feature release jdk (0 when not recorded): a java/ class, which the JVM refuses from any
// loader but the boot and platform loaders, or a class in a package the JDK's own code occupies.
// On 9 and later a package of a system module in the boot layer hides a classpath copy, and on 8
// the boot and extension class paths are searched first. On a runtime image without the module
// the copy does run, so outside java/ the copy is neither walked nor taken for the JDK's leaf: the
// engine finds its package defined by the classpath and a call into it unopened.
//
// jdkPackages is read from Temurin images, so a vendor's additions (a JavaFX or GraalVM build) are
// not in it. jdk is the release of the JVM that ran the build, which the deployed runtime need not
// match: a copy of a package that only the deployed release has is still walked. A release
// jdkPackages does not cover counts a package any covered release has. So does an unrecorded
// one, which is also a release after the newest covered one when a module's toolchain picks it,
// and so does a newer one; both also count a package where the JDK could add one (jdkSubtree).
func BootOnly(name string, jdk int) bool {
	if strings.HasPrefix(name, "java/") {
		return true
	}
	i := strings.LastIndexByte(name, '/')
	if i <= 0 {
		return false
	}
	pkg := name[:i]
	mask, ok := jdkPackages[pkg]
	if jdk == 0 || jdk > jdkReleases[len(jdkReleases)-1] {
		return ok || jdkSubtree(pkg)
	}
	if !ok {
		return false
	}
	for b, r := range jdkReleases {
		if r == jdk {
			return mask&(1<<b) != 0
		}
	}
	return true
}

// jdkPrefixes holds every proper prefix of a package in jdkPackages: javax/sound for
// javax/sound/midi.
var jdkPrefixes = func() map[string]bool {
	m := map[string]bool{}
	for p := range jdkPackages {
		for i := strings.LastIndexByte(p, '/'); i > 0; i = strings.LastIndexByte(p[:i], '/') {
			m[p[:i]] = true
		}
	}
	return m
}()

// jdkSubtree reports whether a release jdkPackages does not hold could add pkg: a package under
// jdk/ or sun/, one that is a prefix of a JDK package, or one whose parent is a JDK package or a
// prefix of one, at least two segments deep (so not javax/servlet) and three under com/ and org/
// (so not com/sun/jna). Every package Temurin added from 16 to 27 is one.
func jdkSubtree(pkg string) bool {
	if strings.HasPrefix(pkg, "jdk/") || strings.HasPrefix(pkg, "sun/") || jdkPrefixes[pkg] {
		return true
	}
	i := strings.LastIndexByte(pkg, '/')
	if i <= 0 {
		return false
	}
	parent := pkg[:i]
	least := 2
	if strings.HasPrefix(parent, "com/") || strings.HasPrefix(parent, "org/") {
		least = 3
	}
	if strings.Count(parent, "/")+1 < least {
		return false
	}
	_, jdkParent := jdkPackages[parent]
	return jdkParent || jdkPrefixes[parent]
}

// NewEngineOn is NewEngine for classes loaded from a classpath that cp describes. The
// packages of the classes themselves always count as defined by the classpath.
func NewEngineOn(classes []classfile.Class, cp Classpath) *Engine {
	e := &Engine{
		classes:     make(map[string]*classfile.Class, len(classes)),
		declared:    map[string]*classfile.Method{},
		subtypes:    map[string][]string{},
		overridable: map[string]bool{},
		loadable:    map[string]bool{},
		unlinked:    map[string]bool{},
		lambdas:     map[string][]lambdaSite{},
		held:        map[string]heldTypes{},
		resolving:   map[string]bool{},
		defined:     map[string]bool{},
		unlisted:    cp.Unlisted,
		methodsHold: cp.JDK == platformMethodsJDK,
	}
	for p := range cp.Packages {
		e.defined[p] = true
	}
	for i := range classes {
		c := &classes[i]
		if j := strings.LastIndexByte(c.Name, '/'); j > 0 {
			e.defined[c.Name[:j]] = true
		}
		if BootOnly(c.Name, cp.JDK) {
			continue
		}
		e.classes[c.Name] = c
		for j := range c.Methods {
			e.declared[c.Methods[j].Ref.String()] = &c.Methods[j]
			for _, edge := range c.Methods[j].Edges {
				site, ifaces := lambdaSiteOf(c.Name, edge)
				for _, t := range ifaces {
					e.lambdas[t] = append(e.lambdas[t], site)
				}
			}
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
// for deterministic target ordering. It also holds every type below an unopened
// dependency type (hiddenSubtypes): that type's own supertypes are unknown, so it may
// extend owner.
func (e *Engine) subtypeClosure(owner string) []string {
	return e.closureFrom(owner, e.hiddenSubtypes())
}

// closureFrom returns owner, the seeds, and every loaded subtype of them.
func (e *Engine) closureFrom(owner string, seeds []string) []string {
	seen := map[string]bool{owner: true}
	stack := []string{owner}
	for _, h := range seeds {
		if !seen[h] {
			seen[h] = true
			stack = append(stack, h)
		}
	}
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

// hiddenSubtypes returns the loaded classes and interfaces directly below an unopened
// dependency type, and the unopened interfaces lambdas implement; subtypeClosure adds
// everything below them. A JDK supertype hides nothing: the JDK cannot extend a class
// or interface from the classpath.
func (e *Engine) hiddenSubtypes() []string {
	if e.hiddenDone {
		return e.hidden
	}
	e.hiddenDone = true
	for _, c := range e.classes {
		for _, s := range append([]string{c.Super}, c.Interfaces...) {
			if s != "" && e.classes[s] == nil && !e.platform(s) {
				e.hidden = append(e.hidden, c.Name)
				break
			}
		}
	}
	for t := range e.lambdas {
		if e.classes[t] == nil && !e.platform(t) {
			e.hidden = append(e.hidden, t)
		}
	}
	sort.Strings(e.hidden)
	return e.hidden
}

// initClosure returns owner plus every in-classpath class whose <clinit> the JVM
// runs when owner is initialized (JVMS §5.5 step 7): the transitive superclass chain,
// and every superinterface, direct or indirect, that declares a non-abstract,
// non-static method. A superinterface declaring no such method is not initialized, so
// its <clinit> is not included. An out-of-classpath ancestor is included as itself but
// its ancestors cannot be walked (its <clinit> is a leaf, or a hazard when it belongs
// to an unopened dependency); an out-of-classpath superinterface is included because
// whether it declares a default method is unknown.
func (e *Engine) initClosure(owner string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	add(owner)
	walked := map[string]bool{}
	var superinterfaces func(ifaces []string)
	superinterfaces = func(ifaces []string) {
		for _, name := range ifaces {
			if walked[name] {
				continue
			}
			walked[name] = true
			c := e.classes[name]
			if c == nil {
				add(name)
				continue
			}
			if declaresInstanceBody(c) {
				add(name)
			}
			superinterfaces(c.Interfaces)
		}
	}
	for cur := e.classes[owner]; cur != nil; {
		superinterfaces(cur.Interfaces)
		if cur.Super == "" {
			break
		}
		add(cur.Super)
		cur = e.classes[cur.Super]
	}
	return out
}

// fieldInitOwners returns the classes whose initialization a getstatic/putstatic of
// f runs: the class or interface that declares the resolved field (JVMS §5.4.3.2,
// §5.5). When resolution meets a class outside the classpath before finding the
// field, the declarer is unknown, so every ancestor of the named owner is returned.
func (e *Engine) fieldInitOwners(f classfile.FieldRef) []string {
	if declarer, ok := e.resolveField(f.Owner, f.Name, f.Descriptor, map[string]bool{}); ok && declarer != "" {
		return []string{declarer}
	}
	return e.ancestors(f.Owner)
}

// resolveField performs field resolution (JVMS §5.4.3.2) over the loaded classes: the
// class's own fields, then its direct superinterfaces recursively, then its
// superclass recursively. ok is false when an out-of-classpath class could declare
// the field; ("", true) means no loaded declaration and nothing unknown. An unloaded
// platform class declares no application field: its supertypes are platform classes
// too, so skipping it skips no application declarer, and a field it does declare
// initializes only platform code.
func (e *Engine) resolveField(owner, name, desc string, seen map[string]bool) (declarer string, ok bool) {
	if seen[owner] {
		return "", true
	}
	seen[owner] = true
	c := e.classes[owner]
	if c == nil {
		return "", e.platform(owner)
	}
	for _, f := range c.Fields {
		if f.Name == name && f.Descriptor == desc {
			return owner, true
		}
	}
	for _, iface := range c.Interfaces {
		if d, ok := e.resolveField(iface, name, desc, seen); !ok || d != "" {
			return d, ok
		}
	}
	if c.Super == "" {
		return "", true
	}
	return e.resolveField(c.Super, name, desc, seen)
}

// ancestors returns owner plus every superclass and superinterface, direct or
// indirect. An out-of-classpath ancestor is included but its own ancestors are
// unknown.
func (e *Engine) ancestors(owner string) []string {
	seen := map[string]bool{owner: true}
	out := []string{owner}
	stack := []string{owner}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		c := e.classes[cur]
		if c == nil {
			continue
		}
		supers := append([]string(nil), c.Interfaces...)
		if c.Super != "" {
			supers = append(supers, c.Super)
		}
		for _, s := range supers {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
				stack = append(stack, s)
			}
		}
	}
	return out
}

// declaresInstanceBody reports whether c declares a non-abstract, non-static method:
// for an interface, a default (or private instance) method, which makes initializing
// an implementing class initialize the interface too.
func declaresInstanceBody(c *classfile.Class) bool {
	for _, m := range c.Methods {
		if !m.Abstract && !m.Static && m.Ref.Name != "<clinit>" {
			return true
		}
	}
	return false
}

// hasAppSubtype reports whether some in-classpath class other than typ is a direct
// subtype of typ, or a loaded lambda implements typ — i.e. an application object of
// the (possibly JDK) type could exist and be passed as a callback. The re-entry rule names it as the witness; it does not
// gate the hazard, since an app class can reach typ through a platform intermediate.
//
// Every name in e.subtypes is a loaded class, so a direct subtype other than typ itself
// is exactly the witness; walking the whole closure (all loaded classes, for
// java/lang/Object) on every call edge made large classpaths quadratic.
func (e *Engine) hasAppSubtype(typ string) bool {
	if len(e.lambdas[typ]) > 0 {
		return true
	}
	for _, c := range e.subtypes[typ] {
		if c != typ {
			return true
		}
	}
	return false
}

// resolveMethod performs JVM method resolution (JVMS §5.4.3.3) of name+desc starting
// at class owner over the loaded classes: the superclass chain first, then the
// transitive superinterfaces for a default method. When nothing loaded declares it,
// unloaded lists the out-of-classpath ancestors (owner itself, if unloaded) where the
// real body may live, so the caller can decide leaf vs hazard by who owns them. A
// declaration found on the superclass chain wins over any interface, as at runtime.
//
// A loaded default is returned with unloaded listing the unopened dependency
// interfaces it does not extend: one may extend the default's interface and override
// it with a more specific default (JVMS §5.4.3.3), so the caller must treat the default
// as possibly not the one that runs. A JDK interface cannot extend a classpath one, so
// it never overrides a loaded default and is not listed.
func (e *Engine) resolveMethod(owner, name, desc string) (m *classfile.Method, unloaded []string) {
	var ifaces []string
	for cur := owner; cur != ""; {
		if m, ok := e.declared[(classfile.MethodRef{Owner: cur, Name: name, Descriptor: desc}).String()]; ok {
			return m, nil
		}
		c := e.classes[cur]
		if c == nil {
			unloaded = append(unloaded, cur)
			// The whole superclass chain is searched before any superinterface, so a
			// body declared on cur or its ancestors wins over every loaded default.
			// Only java/lang/Object's declarations are known (objectMethods); any
			// other unloaded superclass may declare name+desc itself.
			if cur != objectClass || objectMethods[name+desc] {
				return nil, unloaded
			}
			break
		}
		ifaces = append(ifaces, c.Interfaces...)
		cur = c.Super
	}
	seen := map[string]bool{}
	var decls []*classfile.Method
	for len(ifaces) > 0 {
		cur := ifaces[0]
		ifaces = ifaces[1:]
		if seen[cur] {
			continue
		}
		seen[cur] = true
		// A static or private interface method is no candidate (JVMS §5.4.3.3). The
		// walk goes on past a default: an unopened interface above a sibling one may
		// still override it.
		if d, ok := e.declared[(classfile.MethodRef{Owner: cur, Name: name, Descriptor: desc}).String()]; ok && !d.Static && !d.Private {
			decls = append(decls, d)
		}
		c := e.classes[cur]
		if c == nil {
			unloaded = append(unloaded, cur)
			continue
		}
		ifaces = append(ifaces, c.Interfaces...)
	}
	// The default that runs is a maximally specific one: no other declaration's
	// interface extends its own. The first one met need not be it. Where every
	// maximally specific declaration is abstract the call fails at runtime;
	// the first default stands in for it.
	masked := map[string]bool{}
	for _, d := range decls {
		for _, a := range e.ancestors(d.Ref.Owner)[1:] {
			masked[a] = true
		}
	}
	var found, first *classfile.Method
	for _, d := range decls {
		if d.Abstract {
			continue
		}
		if first == nil {
			first = d
		}
		if !masked[d.Ref.Owner] {
			found = d
			break
		}
	}
	if found == nil {
		found = first
	}
	if found == nil {
		return nil, unloaded
	}
	less := map[string]bool{}
	for _, a := range e.ancestors(found.Ref.Owner) {
		less[a] = true
	}
	var over []string
	for _, u := range unloaded {
		if !less[u] && !e.platform(u) {
			over = append(over, u)
		}
	}
	return found, over
}

// unloadedDependency returns the first of names that is neither loaded nor a JDK
// platform class — an opened-never dependency whose bytecode could hide the sink.
func (e *Engine) unloadedDependency(names []string) (string, bool) {
	for _, n := range names {
		if _, loaded := e.classes[n]; !loaded && !e.platform(n) {
			return n, true
		}
	}
	return "", false
}

// platform reports whether class name is the runtime's own. java/ always is, since the JVM
// refuses to define a java/ class from any other loader, and so are array pseudo-classes.
// Any other class is the platform's only when isPlatformClass lists its package and nothing
// on the analysed classpath defines a class in that package. A runtime image without the
// module (a JRE lacks jdk.compiler, and JDK 8 has no modules) loads the package from the
// class path, as errorprone's javac jar shipping com/sun/tools/javac shows, and a classpath
// that could not be listed in full may define any package.
func (e *Engine) platform(name string) bool {
	if strings.HasPrefix(name, "[") || strings.HasPrefix(name, "java/") {
		return true
	}
	if e.unlisted {
		return false
	}
	if i := strings.LastIndexByte(name, '/'); i > 0 && e.defined[name[:i]] {
		return false
	}
	return isPlatformClass(name)
}

// IsPlatformClass is isPlatformClass for callers outside the engine.
func IsPlatformClass(name string) bool { return isPlatformClass(name) }

// isPlatformClass reports whether an internal class name belongs to the Java
// platform (the JDK's own modules), whose bodies the engine treats as leaves under
// the re-entry rule rather than as unseen dependency code. Misfiling a dependency
// here would turn its unseen body into a silent leaf, so the test is exact: java/
// by prefix, since the JVM refuses to define a java/ class from any other loader,
// and otherwise the class's package must be one platformPackages lists. A prefix
// would not do: javax/, com/sun/, org/w3c/dom/, sun/ and jdk/ all also host Maven
// artifacts (javax/servlet, com/sun/mail, com/sun/tools/xjc, org/w3c/dom/svg).
func isPlatformClass(name string) bool {
	if strings.HasPrefix(name, "[") || strings.HasPrefix(name, "java/") { // "[": array pseudo-class (clone, length)
		return true
	}
	if name == "javax/xml/XMLConstants" { // the one class of the JDK's javax/xml package
		return true
	}
	i := strings.LastIndexByte(name, '/')
	return i > 0 && platformPackages[name[:i]]
}

// resolveTargets returns the concrete in-classpath callees of an edge made from a
// method of class from under CHA, plus whether the edge is a completeness HAZARD — a
// call whose real target the static graph cannot enumerate — and a human-readable
// reason when it is.
//
// The hazard rules are the soundness of the whole analysis; each is the seam where a
// missed edge would produce a false not_exploitable:
//   - invokedynamic, except the two bootstraps whose behaviour is fixed by the JDK
//     (resolveDynamic), and reflection (isReflection): the target is decided at
//     runtime (Class.forName, a deserialized object's hooks) and is invisible to a
//     static graph.
//   - a virtual/interface call whose receiver type is out of classpath: real
//     dispatch could land on anything, including the sink. The exceptions are an
//     array receiver and the listed methods of a final JDK value class
//     (valueReceiverMethods), whose bodies reach no application object.
//   - a call whose body lives in an UNLOADED DEPENDENCY (not loaded, not platform):
//     the dependency's bytecode was never opened, so the sink could be anywhere
//     beneath it. Covers a direct static/special call, a method inherited from such
//     an ancestor, and (in Reach) a static initializer that ancestor would run.
//   - a call INTO an out-of-classpath platform method that takes a reference argument
//     other than a value class (reentryCallback): the argument can be, or hold, an
//     application object the platform body calls back (a Comparator handed to
//     Collections.sort, a Runnable to an executor, a List of Comparables to sort).
//   - a platform body that runs with an application object as `this` (an inherited
//     or super-called JDK method): it can call back any method the application class
//     overrides, or objects it holds (platformBodyOn).
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
			if len(unloaded) > 0 {
				return []*classfile.Method{m}, true, "unloaded_dependency: " + edge.To.String() + " may resolve into unopened " + unloaded[0] + ", which can override " + m.Ref.String()
			}
			return []*classfile.Method{m}, false, ""
		}
		if dep, ok := e.unloadedDependency(unloaded); ok {
			return nil, true, "unloaded_dependency: " + edge.To.String() + " resolves into unopened " + dep
		}
		// Target in the JDK platform. A direct call there is a leaf UNLESS it can
		// re-enter application code through an argument — the C8 re-entry seam — or
		// runs on an application `this`. Object's own bodies never call an argument.
		objectBody := e.isObjectBody(edge.To.Owner, edge.To.Name, edge.To.Descriptor)
		if cb, ok := e.reentryCallback(edge.To.Descriptor); ok && !objectBody {
			return nil, true, "higher-order re-entry: out-of-classpath call takes " + cb
		}
		if edge.Kind == classfile.EdgeSpecial {
			if receivers := e.specialReceivers(from, edge.To); receivers != nil {
				return e.platformBodyOn(edge.To, objectBody, receivers)
			}
		}
		return nil, false, ""
	case classfile.EdgeVirtual, classfile.EdgeInterface:
		if _, known := e.classes[edge.To.Owner]; !known {
			switch {
			case strings.HasPrefix(edge.To.Owner, "["):
				// An array's methods are Object's plus clone; none calls back.
				return nil, false, ""
			case valueReceiverMethods[edge.To.Owner+"."+edge.To.Name+edge.To.Descriptor] != valueUnlisted:
				// The receiver is exactly this final class, and this body reads
				// only it, value arguments and JDK-internal state.
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
		var outside, abstractOutside, platformExits []string
		var lambdaWhy string
		// Only a type known to be a subtype witnesses a loaded implementor; one that
		// is merely below an unopened dependency type may not be a receiver at all.
		known := map[string]bool{}
		for _, c := range e.closureFrom(edge.To.Owner, nil) {
			known[c] = true
		}
		implemented := false
		for _, c := range e.subtypeClosure(edge.To.Owner) {
			if known[c] && (e.isConcrete(c) || len(e.lambdas[c]) > 0) {
				implemented = true
			}
			// A lambda object implementing c answers the call with its
			// implementation, or runs what it inherits, wherever the object was
			// created.
			for _, site := range e.lambdas[c] {
				var ts []*classfile.Method
				var h bool
				var w string
				if site.answers(edge.To.Name, edge.To.Descriptor) {
					ts, h, w = e.lambdaImpl(site.from, site.handle, "invokedynamic (runtime-bound target): lambda implementing "+c)
				} else {
					ts, h, w = e.lambdaInherited(site, edge.To)
				}
				if h && lambdaWhy == "" {
					lambdaWhy = w
				}
				for _, t := range ts {
					if !seen[t] {
						seen[t] = true
						targets = append(targets, t)
					}
				}
			}
			m, unloaded := e.resolveMethod(c, edge.To.Name, edge.To.Descriptor)
			if m == nil {
				// Only an object whose exact class is c runs what c resolves to. An
				// abstract class or interface has none: its loaded concrete subtypes
				// are in the closure, and a lambda implementing it was added above.
				// Where neither exists, its supertypes still say where the unseen
				// receiver's code may come from.
				// An Object body (unloaded is exactly [Object]) never calls an
				// argument; it still runs on c.
				if !e.isConcrete(c) {
					abstractOutside = append(abstractOutside, unloaded...)
					continue
				}
				if !e.isObjectBody(c, edge.To.Name, edge.To.Descriptor) {
					outside = append(outside, unloaded...)
				}
				platformExits = append(platformExits, c)
				continue
			}
			outside = append(outside, unloaded...)
			if !m.Abstract && !seen[m] {
				seen[m] = true
				targets = append(targets, m)
			}
		}
		if !implemented {
			// No loaded class or lambda can be the receiver: the object is generated
			// at runtime (a Proxy, a CGLIB or ByteBuddy subclass, a Spring Data
			// repository, a Feign client) or comes from outside the classpath, and
			// runs code the graph cannot see.
			outside = append(outside, abstractOutside...)
			if dep, ok := e.unloadedDependency(outside); ok {
				return targets, true, "unloaded_dependency: " + edge.To.String() + " inherits from unopened " + dep
			}
			return targets, true, "no loaded implementor: " + edge.To.String() + " dispatches to a class generated at runtime or outside the classpath"
		}
		if dep, ok := e.unloadedDependency(outside); ok {
			return targets, true, "unloaded_dependency: " + edge.To.String() + " inherits from unopened " + dep
		}
		if len(outside) > 0 {
			// Some receiver inherits the body from an out-of-classpath platform
			// supertype (e.g. MyList extends ArrayList; forEach(...)). Exactly as the
			// static/special leaf, an argument can re-enter application code (C8
			// re-entry seam).
			if cb, ok := e.reentryCallback(edge.To.Descriptor); ok {
				return nil, true, "higher-order re-entry via inherited out-of-classpath method: takes " + cb
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
		return targets, lambdaWhy != "", lambdaWhy
	}
	return nil, false, ""
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
//     reached where the lambda is created, and CHA dispatch on any interface the
//     object implements reaches it again (lambdaSiteOf), so a call from a root that
//     never reaches the creation site still finds it. A lambda handed to the
//     platform is caught by the re-entry rule at that call.
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
		return e.lambdaImpl(from, *b.Args[1].Handle, opaque)
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

// lambdaImpl resolves a lambda's implementation handle, naming opaque when the
// handle itself cannot be followed.
//
// A handle can call back into a dispatch that reaches the same lambda: a method
// reference t::apply implementing the interface whose apply it calls, or two lambdas
// whose handles call each other's interfaces. Within the outermost resolution, an
// implementation met again adds nothing: every frame folds its targets and hazards into
// that outermost result, which already holds them or is collecting them. Keeping each
// implementation until the outermost one returns, not just while it is on the stack,
// resolves it once per resolution rather than once per path to it. Nothing caches a
// result, so no partial one outlives that outermost resolution.
func (e *Engine) lambdaImpl(from string, h classfile.MethodHandle, opaque string) ([]*classfile.Method, bool, string) {
	key := fmt.Sprintf("%s %d %s", from, h.Kind, h.Ref.String())
	if e.resolving[key] {
		return nil, false, ""
	}
	if len(e.resolving) == 0 {
		defer clear(e.resolving)
	}
	e.resolving[key] = true
	ts, hz, w := e.resolveHandle(from, h)
	switch {
	case hz && w == "":
		w = opaque
	case hz:
		w += " (lambda implementation)"
	}
	return ts, hz, w
}

// lambdaSiteOf indexes a LambdaMetafactory site in class from by every interface
// its object implements: the indy return type, plus altMetafactory's marker
// interfaces. The functional method is the indy name with the erased SAM
// descriptor (bootstrap argument 0) or a bridge descriptor. altMetafactory's flags
// and counts are integer constants the parser leaves empty, so after the three
// fixed arguments every class is a marker and every method type a bridge. Any other
// edge returns no interfaces.
func lambdaSiteOf(from string, edge classfile.Edge) (lambdaSite, []string) {
	b := edge.Bootstrap
	if edge.Kind != classfile.EdgeDynamic || b == nil || b.Method.Kind != classfile.RefInvokeStatic ||
		!lambdaBootstraps[b.Method.Ref.String()] || len(b.Args) < 2 || b.Args[1].Handle == nil {
		return lambdaSite{}, nil
	}
	produced, ok := returnRefType(edge.To.Descriptor)
	if !ok {
		return lambdaSite{}, nil
	}
	site := lambdaSite{from: from, name: edge.To.Name, handle: *b.Args[1].Handle}
	if d := b.Args[0].MethodType; d != "" {
		site.descs = append(site.descs, d)
	}
	ifaces := []string{produced}
	for i := 3; i < len(b.Args); i++ {
		if c := b.Args[i].Class; c != "" {
			ifaces = append(ifaces, c)
		}
		if d := b.Args[i].MethodType; d != "" {
			site.descs = append(site.descs, d)
		}
	}
	site.ifaces = ifaces
	return site, ifaces
}

// answers reports whether the site's object runs its implementation for a call to
// name+desc. A site with no SAM descriptor answers every descriptor of the name.
func (s lambdaSite) answers(name, desc string) bool {
	if name != s.name {
		return false
	}
	if len(s.descs) == 0 {
		return true
	}
	for _, d := range s.descs {
		if d == desc {
			return true
		}
	}
	return false
}

// lambdaInherited resolves a call to ref on site's object that its implementation
// does not answer. The object's class is generated: its superclass is
// java/lang/Object, whose bodies on it call nothing it defines, and it inherits every
// default of its interfaces, which runs with the object as `this`. A loaded default
// is a target. A default that may sit in an unopened dependency is a hazard, and so
// is one that may sit in the JDK, which can call the implementation back. An unopened
// dependency can also override a loaded default beside it.
func (e *Engine) lambdaInherited(site lambdaSite, ref classfile.MethodRef) ([]*classfile.Method, bool, string) {
	if objectMethods[ref.Name+ref.Descriptor] {
		return nil, false, ""
	}
	var targets []*classfile.Method
	var unloaded []string
	for _, t := range site.ifaces {
		m, u := e.resolveMethod(t, ref.Name, ref.Descriptor)
		if m != nil {
			if !m.Abstract {
				targets = append(targets, m)
			}
			unloaded = append(unloaded, u...)
			continue
		}
		for _, n := range u {
			if n != objectClass {
				unloaded = append(unloaded, n)
			}
		}
	}
	if len(unloaded) == 0 {
		return targets, false, ""
	}
	if dep, ok := e.unloadedDependency(unloaded); ok {
		return targets, true, "unloaded_dependency: " + ref.String() + " on a lambda inherits from unopened " + dep
	}
	if len(targets) > 0 {
		// A JDK interface cannot extend an application one, so it cannot override
		// the loaded default.
		return targets, false, ""
	}
	return nil, true, "higher-order re-entry: inherited platform body " + ref.Name + ref.Descriptor + " of " + unloaded[0] + " runs on a lambda implementing " + site.ifaces[0] + ", which it can call back"
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

// A valueReceiverMethods entry says why a value-class method is a leaf.
const (
	valueUnlisted   = iota // not listed: the call stays a hazard
	valueArgs              // every reference parameter is a value class
	valueComparedTo        // its Object parameter is only tested with instanceof
)

// valueReceiverMethods lists, by owner.name+descriptor, the methods of the final
// value classes whose JDK bodies (OpenJDK 17/21) read only the receiver, value
// arguments and JDK-internal state: no service or provider lookup, no class named
// by configuration, and no call on an argument. A hand-listed JDK fact. Leaving a
// method out keeps it a hazard; listing one that reaches a provider turns a hidden
// edge into a silent leaf. String.getBytes(String) is out for that reason:
// Charset.forName finds charsets through CharsetProvider services, which can be
// application classes. So are getBytes(), the case mappings and every method
// taking a CharSequence, Object or functional argument.
var valueReceiverMethods = func() map[string]int {
	m := map[string]int{}
	add := func(owner string, kind int, methods ...string) {
		for _, s := range methods {
			m[owner+"."+s] = kind
		}
	}
	const str = "Ljava/lang/String;"
	add("java/lang/String", valueArgs,
		"length()I", "isEmpty()Z", "isBlank()Z", "charAt(I)C", "codePointAt(I)I",
		"hashCode()I", "toString()"+str, "toCharArray()[C", "intern()"+str,
		"substring(I)"+str, "substring(II)"+str, "subSequence(II)Ljava/lang/CharSequence;",
		"indexOf(I)I", "indexOf(II)I", "indexOf("+str+")I", "indexOf("+str+"I)I",
		"lastIndexOf(I)I", "lastIndexOf(II)I", "lastIndexOf("+str+")I", "lastIndexOf("+str+"I)I",
		"startsWith("+str+")Z", "startsWith("+str+"I)Z", "endsWith("+str+")Z",
		"trim()"+str, "strip()"+str, "stripLeading()"+str, "stripTrailing()"+str,
		"concat("+str+")"+str, "repeat(I)"+str, "replace(CC)"+str,
		"equalsIgnoreCase("+str+")Z", "compareTo("+str+")I", "compareToIgnoreCase("+str+")I",
		"contentEquals(Ljava/lang/StringBuffer;)Z",
		"regionMatches(I"+str+"II)Z", "regionMatches(ZI"+str+"II)Z",
		"matches("+str+")Z", "replaceAll("+str+str+")"+str, "replaceFirst("+str+str+")"+str,
		"split("+str+")[Ljava/lang/String;", "split("+str+"I)[Ljava/lang/String;")
	add("java/lang/String", valueComparedTo, "equals(Ljava/lang/Object;)Z", "compareTo(Ljava/lang/Object;)I")
	for _, sb := range []string{"java/lang/StringBuilder", "java/lang/StringBuffer"} {
		self := "L" + sb + ";"
		add(sb, valueArgs,
			"length()I", "charAt(I)C", "toString()"+str, "setLength(I)V",
			"append("+str+")"+self, "append(Ljava/lang/StringBuffer;)"+self, "append([C)"+self,
			"append([CII)"+self, "append(C)"+self, "append(I)"+self, "append(J)"+self,
			"append(Z)"+self, "append(F)"+self, "append(D)"+self,
			"insert(I"+str+")"+self, "insert(IC)"+self, "insert(II)"+self,
			"reverse()"+self, "delete(II)"+self, "deleteCharAt(I)"+self,
			"replace(II"+str+")"+self, "setCharAt(IC)V",
			"indexOf("+str+")I", "lastIndexOf("+str+")I", "substring(I)"+str, "substring(II)"+str,
			"compareTo("+self+")I")
	}
	boxed := map[string][]string{
		"java/lang/Integer":   {"intValue()I", "longValue()J", "doubleValue()D", "floatValue()F", "shortValue()S", "byteValue()B"},
		"java/lang/Long":      {"intValue()I", "longValue()J", "doubleValue()D", "floatValue()F", "shortValue()S", "byteValue()B"},
		"java/lang/Short":     {"intValue()I", "longValue()J", "doubleValue()D", "floatValue()F", "shortValue()S", "byteValue()B"},
		"java/lang/Byte":      {"intValue()I", "longValue()J", "doubleValue()D", "floatValue()F", "shortValue()S", "byteValue()B"},
		"java/lang/Float":     {"intValue()I", "longValue()J", "doubleValue()D", "floatValue()F", "isNaN()Z", "isInfinite()Z"},
		"java/lang/Double":    {"intValue()I", "longValue()J", "doubleValue()D", "floatValue()F", "isNaN()Z", "isInfinite()Z"},
		"java/lang/Character": {"charValue()C"},
		"java/lang/Boolean":   {"booleanValue()Z"},
	}
	for owner, ms := range boxed {
		add(owner, valueArgs, append(ms, "hashCode()I", "toString()"+str, "compareTo(L"+owner+";)I")...)
		add(owner, valueComparedTo, "equals(Ljava/lang/Object;)Z", "compareTo(Ljava/lang/Object;)I")
	}
	return m
}()

// valueClasses are final JDK classes whose instances hold only characters and
// primitives (JDK fact): handing one to a platform method gives the method no
// application object to call. A hand-listed fact; adding a class that can hold
// application objects (a collection, Optional, Thread) would turn a hazard into a
// silent leaf. java/lang/Class is excluded: newInstance and getMethod reach code.
var valueClasses = map[string]bool{
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

// reentryCallback reports the argument through which an out-of-classpath platform
// method could call back into application code, and whether one exists. Every
// reference parameter (array element types included) except a value class
// qualifies: the argument can be an application object, or a platform object
// holding them (a List of Comparables handed to Collections.sort, a TimerTask
// subclass reaching Runnable through a platform intermediate). When a loaded class
// directly implements the parameter type, the reason names it as the witness.
func (e *Engine) reentryCallback(desc string) (string, bool) {
	refs := parseParamRefTypes(desc)
	for _, p := range refs {
		if e.hasAppSubtype(p) {
			return "app-implemented " + p, true
		}
	}
	for _, p := range refs {
		if !valueClasses[p] {
			return "reference argument " + p + ", which can carry application objects", true
		}
	}
	return "", false
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

// statelessBases are platform superclasses whose bodies neither call a method an
// application subclass can override nor hold application objects (JDK fact):
// java/lang/Enum keeps a name and an ordinal, and its overridable-looking methods
// are final or return those fields. A subclass that adds no overridable method
// runs their bodies as leaves.
var statelessBases = map[string]bool{
	"java/lang/Enum": true,
}

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
// method the receiver overrides and every object its inherited state holds (an
// ArrayList subclass's hashCode calls each element's hashCode), so it is a hazard
// unless the class sits directly on a stateless base and overrides nothing.
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
		if statelessBases[e.chainExit(c)] && !e.hasOverridable(c) {
			continue
		}
		return targets, true, "higher-order re-entry: inherited platform body " + body.String() + " runs on " + c + ", which it can call back or whose held objects it can call"
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

// isOverridable reports whether m is an instance method with a body that virtual
// dispatch can select: neither static, private, abstract, a constructor nor an
// initializer.
func isOverridable(m *classfile.Method) bool {
	return !m.Static && !m.Private && !m.Abstract && m.Ref.Name != "<init>" && m.Ref.Name != "<clinit>"
}

// hasOverridable reports whether c, its loaded superclasses, or their loaded
// superinterfaces declare a method a platform body could dispatch to on a c
// receiver.
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
		for i := range cls.Methods {
			if isOverridable(&cls.Methods[i]) {
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

// isReflection reports whether a call target is a dynamic-resolution entry point:
// its real callee is a string, handle, loaded class or byte stream decided at
// runtime, so it can reach code the static graph cannot enumerate. Each is a
// completeness hazard: erring toward undetermined over a false not_exploitable.
// The channels are JDK API facts:
//   - reflection proper: Class.forName/newInstance, java/lang/reflect/* (Method.invoke,
//     Constructor.newInstance, Proxy), java/lang/invoke/* (method handles, hidden
//     classes), sun/misc/Unsafe, the internal reflection factories.
//   - loading by name: any platform method that defines or loads a class
//     (ClassLoader.loadClass/findClass/defineClass, Lookup.defineHiddenClass), all of
//     ServiceLoader, JNDI, java/beans (Beans.instantiate, XMLDecoder, EventHandler),
//     javax/management (MBean server, MLet), javax/script, java/lang/instrument.
//   - deserialization: ObjectInputStream/ObjectOutputStream run readObject,
//     readResolve, writeReplace and a serializable lambda's $deserializeLambda$ on
//     classes the stream names; SignedObject and SealedObject getObject read one
//     through an ObjectInputStream; java/rmi lookups and calls deserialize results.
//   - process-global inputs: System/Runtime load/loadLibrary (a native library's
//     JNI_OnLoad can call any Java method) and System.setProperty/setProperties
//     (platform factories instantiate classes their properties name).
func isReflection(r classfile.MethodRef) bool {
	switch {
	case r.Owner == "java/lang/Class" && (r.Name == "forName" || r.Name == "newInstance"):
		return true
	case r.Owner == "java/util/ServiceLoader" || strings.HasPrefix(r.Owner, "java/util/ServiceLoader$"):
		return true
	case r.Owner == "java/io/ObjectInputStream" || r.Owner == "java/io/ObjectOutputStream":
		return true
	case (r.Owner == "java/security/SignedObject" || r.Owner == "javax/crypto/SealedObject") && r.Name == "getObject":
		return true
	case (r.Owner == "java/lang/System" || r.Owner == "java/lang/Runtime") && (r.Name == "load" || r.Name == "loadLibrary"):
		return true
	case r.Owner == "java/lang/System" && (r.Name == "setProperty" || r.Name == "setProperties"):
		return true
	case isPlatformClass(r.Owner) && classLoadingMethods[r.Name]:
		return true
	}
	for _, p := range reflectionPrefixes {
		if strings.HasPrefix(r.Owner, p) {
			return true
		}
	}
	return false
}

// classLoadingMethods are platform method names that define or load a class by name
// or from bytes (ClassLoader, SecureClassLoader, URLClassLoader, MethodHandles.Lookup,
// Unsafe).
var classLoadingMethods = map[string]bool{
	"loadClass": true, "findClass": true, "findSystemClass": true, "defineClass": true,
	"defineHiddenClass": true, "defineHiddenClassWithClassData": true, "defineAnonymousClass": true,
}

var reflectionPrefixes = []string{
	"java/lang/reflect/", "java/lang/invoke/", "java/lang/instrument/",
	"sun/misc/Unsafe", "jdk/internal/misc/Unsafe", "sun/reflect/", "jdk/internal/reflect/",
	"javax/naming/", "java/beans/", "javax/management/", "javax/script/", "java/rmi/",
}

// deniedLoadable are platform types the JDK never instantiates by name through a
// provider lookup (they are not service types or factory types, JDK fact), and
// whose own platform supertypes are all likewise denied, so a class that reaches
// the platform only through them cannot be loaded by the JDK from a
// META-INF/services entry. Throwables and java/util/function are denied by name
// (loadableType).
var deniedLoadable = map[string]bool{
	"java/lang/Object": true, "java/lang/Comparable": true, "java/lang/Iterable": true,
	"java/lang/Runnable": true, "java/lang/AutoCloseable": true, "java/lang/Cloneable": true,
	"java/lang/CharSequence": true, "java/lang/Appendable": true, "java/lang/Readable": true,
	"java/lang/Enum": true, "java/lang/Record": true, "java/lang/Number": true, "java/lang/Thread": true,
	"java/lang/ThreadLocal": true, "java/lang/InheritableThreadLocal": true,
	"java/lang/constant/Constable": true, "java/lang/constant/ConstantDesc": true,
	"java/lang/ref/Reference": true, "java/lang/ref/WeakReference": true,
	"java/lang/ref/SoftReference": true, "java/lang/ref/PhantomReference": true,
	"java/io/Serializable": true, "java/io/Externalizable": true, "java/io/Closeable": true,
	"java/io/Flushable": true, "java/io/InputStream": true, "java/io/OutputStream": true,
	"java/io/Reader": true, "java/io/Writer": true, "java/io/FilterInputStream": true,
	"java/io/FilterOutputStream": true, "java/io/FilterReader": true, "java/io/FilterWriter": true,
	"java/util/Collection": true, "java/util/List": true, "java/util/Set": true, "java/util/Map": true,
	"java/util/Map$Entry": true, "java/util/Queue": true, "java/util/Deque": true,
	"java/util/SortedMap": true, "java/util/SortedSet": true, "java/util/NavigableMap": true,
	"java/util/NavigableSet": true, "java/util/SequencedCollection": true, "java/util/SequencedMap": true,
	"java/util/SequencedSet": true, "java/util/Iterator": true, "java/util/ListIterator": true,
	"java/util/Enumeration": true, "java/util/RandomAccess": true, "java/util/Comparator": true,
	"java/util/EventListener": true, "java/util/EventObject": true, "java/util/Spliterator": true,
	"java/util/AbstractCollection": true, "java/util/AbstractList": true,
	"java/util/AbstractSequentialList": true, "java/util/AbstractSet": true, "java/util/AbstractMap": true,
	"java/util/AbstractQueue": true, "java/util/ArrayList": true, "java/util/LinkedList": true,
	"java/util/HashMap": true, "java/util/LinkedHashMap": true, "java/util/HashSet": true,
	"java/util/LinkedHashSet": true, "java/util/TreeMap": true, "java/util/TreeSet": true,
	"java/util/ArrayDeque": true, "java/util/TimerTask": true, "java/util/Observer": true,
	"java/util/Observable": true, "java/util/AbstractMap$SimpleEntry": true,
	"java/util/AbstractMap$SimpleImmutableEntry": true, "java/lang/ClassValue": true,
	"java/util/concurrent/Callable": true, "java/util/concurrent/Future": true,
	"java/util/concurrent/RunnableFuture": true, "java/util/concurrent/Delayed": true,
	"java/util/concurrent/ScheduledFuture": true, "java/util/concurrent/CompletionStage": true,
	"java/util/concurrent/Executor": true, "java/util/concurrent/ExecutorService": true,
	"java/util/concurrent/ThreadFactory": true,
}

// platformLoadable reports whether the JDK could instantiate loaded class c by name
// from a provider lookup, or hold one and call its methods: c reaches a platform
// supertype outside deniedLoadable, or an unopened dependency supertype (whose own
// supertypes are unknown). On a linked classpath a class that cannot link is neither
// (SetLinked).
func (e *Engine) platformLoadable(c string) bool {
	if v, ok := e.loadable[c]; ok {
		return v
	}
	e.loadable[c] = false // cycle guard
	found := false
	if cls := e.classes[c]; cls != nil && !(e.linked && e.unlinkable(c)) {
		for _, s := range append([]string{cls.Super}, cls.Interfaces...) {
			if s != "" && e.loadableType(s) {
				found = true
				break
			}
		}
	}
	e.loadable[c] = found
	return found
}

// SetLinked declares whether the loaded classes are every class the run's classpath
// defines: the build lists every dependency it installs, each one's JAR was read, the
// class output covers the sources, and the program is launched on that classpath. A
// loaded class with a supertype that is neither loaded nor the JDK's then cannot link,
// since loading a class resolves its superclass and each direct superinterface (JVMS
// 5.3.5), so the JDK can neither instantiate it nor hold one (platformLoadable). This
// trusts the launch the way the build graph does: an agent that appends to the system
// classpath at run time, or a JDK vendor's own packages (OpenJ9's com/ibm, GraalVM's,
// JavaFX), could supply the supertype.
// An unlisted classpath (Classpath.Unlisted) is never linked.
func (e *Engine) SetLinked(linked bool) {
	linked = linked && !e.unlisted
	if linked != e.linked {
		e.linked = linked
		e.loadable = map[string]bool{}
	}
}

// unlinkable reports whether loaded class c cannot link on a linked classpath: some
// supertype is neither loaded nor a type the JDK may define, or is a loaded class that
// cannot link. A type the JDK may define is one in a package some JDK release occupies
// (BootOnly at an unrecorded release), even where a classpath entry also defines that
// package; every platform package is one.
func (e *Engine) unlinkable(c string) bool {
	if v, ok := e.unlinked[c]; ok {
		return v
	}
	e.unlinked[c] = false // cycle guard
	out := false
	for _, s := range append([]string{e.classes[c].Super}, e.classes[c].Interfaces...) {
		if s == "" {
			continue
		}
		if e.classes[s] != nil {
			out = e.unlinkable(s)
		} else {
			out = !BootOnly(s, 0)
		}
		if out {
			break
		}
	}
	e.unlinked[c] = out
	return out
}

// loadableType reports whether type t can be the static type under which the JDK
// holds an object it may call: a loaded class that is platformLoadable, an unopened
// dependency type, or a platform type outside deniedLoadable and the Throwables.
// A Throwable needs no roots: every instance ran Throwable's constructor on itself,
// which the search already treats as a platform body running on that receiver.
func (e *Engine) loadableType(t string) bool {
	if e.classes[t] != nil {
		return e.platformLoadable(t)
	}
	if !e.platform(t) {
		return true
	}
	simple := t[strings.LastIndex(t, "/")+1:]
	if simple == "Throwable" || strings.HasSuffix(simple, "Exception") || strings.HasSuffix(simple, "Error") {
		return false
	}
	return !deniedLoadable[t] && !strings.HasPrefix(t, "java/util/function/")
}

// objectOverridable are java/lang/Object's overridable methods, keyed as platformMethods
// keys them.
var objectOverridable = map[string]bool{
	"toString()": true, "equals(Ljava/lang/Object;)": true, "hashCode()": true, "finalize()": true, "clone()": true,
}

// platformSigs indexes platformMethods' methods by type.
var platformSigs = sync.OnceValue(func() map[string]map[string]bool {
	out := make(map[string]map[string]bool, len(platformMethods))
	for t, pt := range platformMethods {
		sigs := map[string]bool{}
		for _, s := range strings.Fields(pt.methods) {
			sigs[s] = true
		}
		out[t] = sigs
	}
	return out
})

// heldTypes is how the JDK can hold an object: the platformMethods types among its
// supertypes, and unseen when some supertype's methods are unknown to the engine.
type heldTypes struct {
	types  []string
	unseen bool
}

// heldAs returns the heldTypes of every loaded class that is owner or a subtype of it,
// merged: a method owner declares runs on an object of each that does not override it.
// A supertype is unseen when it is neither loaded, java/lang/Object, nor a platform type
// platformMethods lists: an unopened dependency type, whose own supertypes are unknown,
// or a platform type outside the list. Every platform type is unseen when the runtime is
// not the list's release: a later JDK can add a method to a listed type, and an earlier one
// can declare a method since removed (JDK 8's SecurityManager.checkMemberAccess).
func (e *Engine) heldAs(owner string) heldTypes {
	if h, ok := e.held[owner]; ok {
		return h
	}
	var h heldTypes
	seen := map[string]bool{}
	stack := e.subtypeClosure(owner)
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[cur] || cur == objectClass {
			continue
		}
		seen[cur] = true
		if cls := e.classes[cur]; cls != nil {
			if cls.Super != "" {
				stack = append(stack, cls.Super)
			}
			stack = append(stack, cls.Interfaces...)
			continue
		}
		pt, listed := platformMethods[cur]
		if !listed || !e.methodsHold || !e.platform(cur) {
			h.unseen = true
			break
		}
		h.types = append(h.types, cur)
		stack = append(stack, strings.Fields(pt.supers)...)
	}
	e.held[owner] = h
	return h
}

// jdkCallable reports whether JDK code can invoke m, an overridable method of loaded
// class owner, without reflection: the JDK names a method only through a type of its
// own, so m must override a method a platform supertype declares (platformMethods,
// objectOverridable) or one of a supertype the engine cannot see. A match is on name
// and parameter types: a covariant override's bridge and the override itself both
// match. Any other JDK call into m is reflective (deserialization hooks, java/beans,
// JMX, method handles), and the search meets its JDK entry point as a hazard instead
// (isReflection). That holds only for reflection the searched code starts: an endpoint
// launch flags enable, such as JMX remote or an RMI registry, deserializes into
// readResolve and writeReplace with no call in the code, and is outside the search.
func (e *Engine) jdkCallable(owner string, m classfile.MethodRef) bool {
	i := strings.IndexByte(m.Descriptor, ')')
	if i < 0 {
		return true
	}
	sig := m.Name + m.Descriptor[:i+1]
	if objectOverridable[sig] {
		return true
	}
	h := e.heldAs(owner)
	if h.unseen {
		return true
	}
	sigs := platformSigs()
	for _, t := range h.types {
		if sigs[t][sig] {
			return true
		}
	}
	return false
}

// providerRoots returns the methods the JDK itself can call on loaded classes it
// finds or holds without the searched code handing them over: the overridable methods
// the JDK can name (jdkCallable) of each class that is platformLoadable or a supertype
// of one, since a platformLoadable subclass inherits them, and for a platformLoadable
// class that is public and concrete, its public constructors, public static
// provider() and the static initializers instantiating it runs (ServiceLoader,
// DriverManager and the factory lookups load providers named in META-INF/services).
// A root method that returns an object the JDK then calls is a hazard when the
// object's type is not itself covered (a denied or unopened type, such as Object or
// Iterator), because the object's class need not be platformLoadable.
func (e *Engine) providerRoots() (roots []*classfile.Method, hazard string) {
	names := make([]string, 0, len(e.classes))
	for n := range e.classes {
		names = append(names, n)
	}
	sort.Strings(names)
	inherited := e.loadableSupertypes()
	for _, n := range names {
		loadable := e.platformLoadable(n)
		if !loadable && !inherited[n] {
			continue
		}
		cls := e.classes[n]
		byName := loadable && cls.Public && !cls.Abstract
		for i := range cls.Methods {
			m := &cls.Methods[i]
			switch {
			case isOverridable(m):
				if !e.jdkCallable(n, m.Ref) {
					continue
				}
				roots = append(roots, m)
				if rt, ok := returnRefType(m.Ref.Descriptor); ok && hazard == "" && !valueClasses[rt] && !e.loadableType(rt) {
					hazard = "higher-order re-entry: platform-callable " + m.Ref.String() + " returns " + rt + ", which can carry application objects"
				}
			case byName && m.Public && (m.Ref.Name == "<init>" || (m.Static && m.Ref.Name == "provider")):
				roots = append(roots, m)
			}
		}
		if byName {
			for _, c := range e.initClosure(n) {
				if m := e.declared[(classfile.MethodRef{Owner: c, Name: "<clinit>", Descriptor: "()V"}).String()]; m != nil {
					roots = append(roots, m)
				}
			}
		}
	}
	// A lambda the JDK can hold (a HostnameVerifier handed to
	// HttpsURLConnection.setDefaultHostnameVerifier) runs its implementation when the
	// JDK calls it.
	ifaces := make([]string, 0, len(e.lambdas))
	for t := range e.lambdas {
		ifaces = append(ifaces, t)
	}
	sort.Strings(ifaces)
	for _, t := range ifaces {
		if !e.loadableType(t) {
			continue
		}
		for _, site := range e.lambdas[t] {
			ts, h, w := e.lambdaImpl(site.from, site.handle, "invokedynamic (runtime-bound target): lambda implementing "+t)
			roots = append(roots, ts...)
			if h && hazard == "" {
				hazard = w
			}
			descs := site.descs
			if len(descs) == 0 {
				descs = []string{site.handle.Ref.Descriptor}
			}
			for _, d := range descs {
				if rt, ok := returnRefType(d); ok && hazard == "" && !valueClasses[rt] && !e.loadableType(rt) {
					hazard = "higher-order re-entry: platform-callable lambda implementing " + t + " returns " + rt + ", which can carry application objects"
				}
			}
		}
	}
	return roots, hazard
}

// loadableSupertypes returns the loaded classes and interfaces a platformLoadable class
// extends or implements, directly or not: the JDK holding that class runs the methods
// it inherits from them.
func (e *Engine) loadableSupertypes() map[string]bool {
	out := map[string]bool{}
	var stack []string
	for n, cls := range e.classes {
		if e.platformLoadable(n) {
			stack = append(stack, cls.Super)
			stack = append(stack, cls.Interfaces...)
		}
	}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		cls := e.classes[cur]
		if cls == nil || out[cur] {
			continue
		}
		out[cur] = true
		stack = append(stack, cls.Super)
		stack = append(stack, cls.Interfaces...)
	}
	return out
}

// handleTouchesPlatform reports whether a lambda implementation handle runs a JDK
// body: its owner is a JDK class, or it inherits the method from one
// (MyCharset::forName, with MyCharset extending Charset).
func (e *Engine) handleTouchesPlatform(h classfile.MethodHandle) bool {
	o := h.Ref.Owner
	if e.classes[o] == nil {
		return e.platformBody(o)
	}
	if m, unloaded := e.resolveMethod(o, h.Ref.Name, h.Ref.Descriptor); m == nil {
		for _, u := range unloaded {
			if e.platformBody(u) {
				return true
			}
		}
	}
	return false
}

// touchesPlatform reports whether edge can run a JDK body other than
// java/lang/Object's own or an array's: the point from which the JDK can load and
// call providers (providerRoots).
func (e *Engine) touchesPlatform(edge classfile.Edge) bool {
	if edge.Kind == classfile.EdgeDynamic {
		return true
	}
	o := edge.To.Owner
	if _, ok := e.classes[o]; !ok {
		return e.platformBody(o)
	}
	owners := []string{o}
	if edge.Kind == classfile.EdgeVirtual || edge.Kind == classfile.EdgeInterface {
		owners = e.subtypeClosure(o)
	}
	for _, c := range owners {
		// A lambda answering the call runs its implementation, which can be a JDK
		// method (Charset::forName).
		for _, site := range e.lambdas[c] {
			if site.answers(edge.To.Name, edge.To.Descriptor) && e.handleTouchesPlatform(site.handle) {
				return true
			}
		}
		if m, unloaded := e.resolveMethod(c, edge.To.Name, edge.To.Descriptor); m == nil {
			for _, u := range unloaded {
				if e.platformBody(u) {
					return true
				}
			}
		}
	}
	return false
}

// platformBody reports whether a body owned by unloaded class o is JDK code other
// than java/lang/Object's or an array pseudo-class's.
func (e *Engine) platformBody(o string) bool {
	return e.platform(o) && o != objectClass && !strings.HasPrefix(o, "[")
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
//
// Two kinds of call have no edge in the bytecode and are added here: the collector's
// finalize() on every constructed concrete class, and the JDK's own calls into
// provider classes (providerRoots) once the search runs any JDK body. A path through
// a provider root is reported from the JDK call site that opened it.
//
// The JVM initializes the ingress's class before it invokes the ingress (JVMS §5.5), so
// the search starts from that class's initialization closure (initClosure: the class, its
// superclasses, and each superinterface that declares a default method) as well as the
// ingress. An instance ingress also runs the class's no-arg constructor first.
func (e *Engine) Reach(ingress, sink classfile.MethodRef) Result {
	res := Result{SinkPresent: e.declared[sink.String()] != nil}
	if !res.SinkPresent {
		res.Verdict = Undetermined
		res.hazard("sink_not_loaded: " + sink.String())
		return res
	}

	start, over := e.resolveMethod(ingress.Owner, ingress.Name, ingress.Descriptor)
	if start == nil {
		// The ingress itself is not in the analyzed classpath: the search never
		// began, so absence proves nothing.
		res.Verdict = Undetermined
		res.hazard("ingress method not found in classpath: " + ingress.String())
		return res
	}
	if len(over) > 0 {
		// The ingress resolves to a loaded default that an unopened dependency
		// interface may override; the search still runs from the default.
		res.hazard("unloaded_dependency: ingress " + ingress.String() + " may resolve into unopened " + over[0] + ", which can override " + start.Ref.String())
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

	// Once the search runs any JDK body, the JDK can load and call application
	// providers on its own (a JDBC driver from DriverManager, a CharsetProvider from
	// Charset.forName): every providerRoots method joins the frontier, reached from
	// the first such site.
	rooted := false
	root := func(from classfile.MethodRef) {
		if rooted {
			return
		}
		rooted = true
		roots, why := e.providerRoots()
		if why != "" {
			res.hazard(why)
		}
		for _, r := range roots {
			enqueue(from, r)
		}
	}

	// initialize runs the static initializers the JVM runs when owner is initialized:
	// every <clinit> in its init closure. A platform class's initializer is a JDK body;
	// an unloaded dependency's is unseen code and a hazard.
	initialize := func(from classfile.MethodRef, owner string) {
		if !rooted && e.platformBody(owner) {
			root(from)
		}
		for _, cls := range e.initClosure(owner) {
			if dep, ok := e.unloadedDependency([]string{cls}); ok {
				res.hazard("unloaded_dependency: static initializer of unopened " + dep)
				continue
			}
			clinit := classfile.MethodRef{Owner: cls, Name: "<clinit>", Descriptor: "()V"}
			enqueue(from, e.declared[clinit.String()])
		}
	}

	// The JVM initializes the ingress's class before it invokes the ingress (JVMS §5.5):
	// a launch class, a framework handler's class. An instance ingress also runs on an
	// object someone constructed; the launcher builds an instance main's receiver with
	// its no-argument constructor.
	initialize(start.Ref, ingress.Owner)
	if !start.Static {
		enqueue(start.Ref, e.declared[classfile.MethodRef{Owner: ingress.Owner, Name: "<init>", Descriptor: "()V"}.String()])
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
		if cur.Name == "<init>" && e.isConcrete(cur.Owner) {
			// A constructed object can be finalized: the collector calls its
			// finalize() with no edge in the program.
			targets, hazard, why := e.dispatchOn(cur.Owner, "finalize", "()V")
			if hazard {
				res.hazard(why)
			}
			for _, t := range targets {
				enqueue(cur, t)
			}
		}
		for _, edge := range m.Edges {
			if !rooted && e.touchesPlatform(edge) {
				root(cur)
			}
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
			initialize(cur, owner)
		}
		// A static field access initializes the field's declarer, which can be a
		// superinterface the named class's own initialization would skip.
		for _, f := range m.StaticFieldRefs {
			for _, owner := range e.fieldInitOwners(f) {
				initialize(cur, owner)
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

// Add records one classpath entry's listing (classfile.ClasspathPackages): its packages, or,
// when it could not be listed, that the classpath may define any package.
func (cp *Classpath) Add(pkgs map[string]bool, listed bool) {
	if !listed {
		cp.Unlisted = true
		return
	}
	if cp.Packages == nil {
		cp.Packages = map[string]bool{}
	}
	for p := range pkgs {
		cp.Packages[p] = true
	}
}

// Merge adds everything other records.
// A JDK only one side records is kept, and two that differ leave it 0.
func (cp *Classpath) Merge(other Classpath) {
	cp.Add(other.Packages, true)
	cp.Unlisted = cp.Unlisted || other.Unlisted
	switch {
	case cp.JDK == 0:
		cp.JDK = other.JDK
	case other.JDK != 0 && other.JDK != cp.JDK:
		cp.JDK = 0
	}
}
