package depreach

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

// The platform model removes hazards, so it widens not_exploitable. Each row below
// that expects reachable_candidate or undetermined is the guard for one part of the
// over-approximation: narrowing that part turns the row into a false
// not_exploitable.

const (
	appClass   = "com/acme/App"
	lmfOwner   = "java/lang/invoke/LambdaMetafactory"
	lmfDesc    = "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;"
	lmfAltDesc = "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;"
	scfOwner   = "java/lang/invoke/StringConcatFactory"
	scfDesc    = "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;"
	scfKDesc   = "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;"
	toStr      = "()Ljava/lang/String;"
	unopened   = "com/fasterxml/jackson/databind/ObjectMapper"
)

// sinkCall is a body that reaches the UrlFetcher sink.
func sinkCall() []classfile.Edge {
	return []classfile.Edge{
		edge(classfile.EdgeSpecial, "com/evil/netkit/UrlFetcher", "<init>", "()V"),
		edge(classfile.EdgeVirtual, "com/evil/netkit/UrlFetcher", "fetch", sinkDesc),
	}
}

func meth(owner, name, desc string, edges ...classfile.Edge) classfile.Method {
	return classfile.Method{Ref: mref(owner, name, desc), Edges: edges}
}

func class(name, super string, ifaces []string, methods ...classfile.Method) classfile.Class {
	return classfile.Class{Name: name, Super: super, Interfaces: ifaces, Methods: methods}
}

func iface(name string, methods ...classfile.Method) classfile.Class {
	c := class(name, "java/lang/Object", nil, methods...)
	c.Abstract = true
	return c
}

func abstractMeth(owner, name, desc string) classfile.Method {
	m := meth(owner, name, desc)
	m.Abstract = true
	return m
}

func staticMeth(owner, name, desc string, edges ...classfile.Edge) classfile.Method {
	m := meth(owner, name, desc, edges...)
	m.Static = true
	return m
}

func privateMeth(owner, name, desc string, edges ...classfile.Edge) classfile.Method {
	m := meth(owner, name, desc, edges...)
	m.Private = true
	return m
}

func handleArg(kind uint8, owner, name, desc string) classfile.BootstrapArg {
	return classfile.BootstrapArg{Handle: &classfile.MethodHandle{Kind: kind, Ref: mref(owner, name, desc)}}
}

func bootstrap(kind uint8, owner, name, desc string, args ...classfile.BootstrapArg) *classfile.Bootstrap {
	return &classfile.Bootstrap{Method: classfile.MethodHandle{Kind: kind, Ref: mref(owner, name, desc)}, Args: args}
}

func indy(name, desc string, b *classfile.Bootstrap) classfile.Edge {
	return classfile.Edge{To: mref("", name, desc), Kind: classfile.EdgeDynamic, Bootstrap: b}
}

// lambda is a javac-shaped LambdaMetafactory.metafactory site whose implementation
// handle is impl.
func lambda(impl classfile.BootstrapArg) classfile.Edge {
	return indy("run", "()Ljava/lang/Runnable;", bootstrap(classfile.RefInvokeStatic, lmfOwner, "metafactory", lmfDesc,
		classfile.BootstrapArg{MethodType: "()V"}, impl, classfile.BootstrapArg{MethodType: "()V"}))
}

// concat is a makeConcatWithConstants site over the argument types in desc.
func concat(desc string) classfile.Edge {
	return indy("makeConcatWithConstants", desc+"Ljava/lang/String;", bootstrap(classfile.RefInvokeStatic, scfOwner, "makeConcatWithConstants", scfKDesc))
}

type reachCase struct {
	name    string
	ingress classfile.MethodRef // defaults to App.trigger()V
	classes []classfile.Class   // besides UrlFetcher
	want    Verdict
	why     string // required HazardWhy prefix when undetermined
}

func runReachCases(t *testing.T, cases []reachCase) {
	t.Helper()
	sink := mref("com/evil/netkit/UrlFetcher", "fetch", sinkDesc)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ingress := tc.ingress
			if ingress == (classfile.MethodRef{}) {
				ingress = mref(appClass, "trigger", "()V")
			}
			r := NewEngine(append(tc.classes, urlFetcherDep())).Reach(ingress, sink)
			if r.Verdict != tc.want {
				t.Fatalf("verdict = %s, want %s (hazard=%q)", r.Verdict, tc.want, r.HazardWhy)
			}
			if tc.why != "" && !strings.HasPrefix(r.HazardWhy, tc.why) {
				t.Errorf("HazardWhy = %q, want prefix %q", r.HazardWhy, tc.why)
			}
		})
	}
}

// app is com/acme/App with trigger()V making the given calls.
func app(edges ...classfile.Edge) classfile.Class {
	return class(appClass, "java/lang/Object", nil, meth(appClass, "<init>", "()V"), meth(appClass, "trigger", "()V", edges...))
}

const indyWhy = "invokedynamic (runtime-bound target)"

func TestReach_LambdaImplementationIsReached(t *testing.T) {
	widget := func(initEdges, clinitEdges []classfile.Edge) classfile.Class {
		return class("com/acme/Widget", "java/lang/Object", nil,
			meth("com/acme/Widget", "<init>", "()V", initEdges...),
			staticMeth("com/acme/Widget", "<clinit>", "()V", clinitEdges...))
	}
	runReachCases(t, []reachCase{
		{name: "static implementation reaching the sink", want: ReachableCandidate, classes: []classfile.Class{
			class(appClass, "java/lang/Object", nil,
				meth(appClass, "trigger", "()V", lambda(handleArg(classfile.RefInvokeStatic, appClass, "lambda$trigger$0", "()V"))),
				staticMeth(appClass, "lambda$trigger$0", "()V", sinkCall()...)),
		}},
		{name: "clean static implementation removes the hazard", want: NotExploitable, classes: []classfile.Class{
			class(appClass, "java/lang/Object", nil,
				meth(appClass, "trigger", "()V", lambda(handleArg(classfile.RefInvokeStatic, appClass, "lambda$trigger$0", "()V"))),
				staticMeth(appClass, "lambda$trigger$0", "()V")),
		}},
		{name: "altMetafactory virtual implementation", want: ReachableCandidate, classes: []classfile.Class{
			app(indy("get", "(Lcom/acme/Worker;)Ljava/util/function/Supplier;", bootstrap(classfile.RefInvokeStatic, lmfOwner, "altMetafactory", lmfAltDesc,
				classfile.BootstrapArg{MethodType: "()Ljava/lang/Object;"},
				handleArg(classfile.RefInvokeVirtual, "com/acme/Worker", "work", "()V"),
				classfile.BootstrapArg{MethodType: "()V"}))),
			class("com/acme/Worker", "java/lang/Object", nil, meth("com/acme/Worker", "work", "()V")),
			class("com/acme/Night", "com/acme/Worker", nil, meth("com/acme/Night", "work", "()V", sinkCall()...)),
		}},
		{name: "interface implementation dispatches to implementors", want: ReachableCandidate, classes: []classfile.Class{
			app(lambda(handleArg(classfile.RefInvokeInterface, "com/acme/Job", "go", "()V"))),
			iface("com/acme/Job", abstractMeth("com/acme/Job", "go", "()V")),
			class("com/acme/JobImpl", "java/lang/Object", []string{"com/acme/Job"}, meth("com/acme/JobImpl", "go", "()V", sinkCall()...)),
		}},
		{name: "special implementation on a private instance body", want: ReachableCandidate, classes: []classfile.Class{
			class(appClass, "java/lang/Object", nil,
				meth(appClass, "trigger", "()V", lambda(handleArg(classfile.RefInvokeSpecial, appClass, "lambda$trigger$1", "()V"))),
				privateMeth(appClass, "lambda$trigger$1", "()V", sinkCall()...)),
		}},
		{name: "constructor reference runs the constructor", want: ReachableCandidate, classes: []classfile.Class{
			app(lambda(handleArg(classfile.RefNewInvokeSpecial, "com/acme/Widget", "<init>", "()V"))),
			widget(sinkCall(), nil),
		}},
		{name: "constructor reference initializes the class", want: ReachableCandidate, classes: []classfile.Class{
			app(lambda(handleArg(classfile.RefNewInvokeSpecial, "com/acme/Widget", "<init>", "()V"))),
			widget(nil, sinkCall()),
		}},
		{name: "static implementation on another class initializes it", want: ReachableCandidate, classes: []classfile.Class{
			app(lambda(handleArg(classfile.RefInvokeStatic, "com/acme/Helper", "util", "()V"))),
			class("com/acme/Helper", "java/lang/Object", nil,
				staticMeth("com/acme/Helper", "util", "()V"),
				staticMeth("com/acme/Helper", "<clinit>", "()V", sinkCall()...)),
		}},
		{name: "static implementation whose superclass is unopened", want: Undetermined, why: "unloaded_dependency: static initializer", classes: []classfile.Class{
			app(lambda(handleArg(classfile.RefInvokeStatic, "com/acme/Mapper", "util", "()V"))),
			class("com/acme/Mapper", unopened, nil, staticMeth("com/acme/Mapper", "util", "()V")),
		}},
		{name: "static implementation in an unopened jar", want: Undetermined, why: "unloaded_dependency:", classes: []classfile.Class{
			app(lambda(handleArg(classfile.RefInvokeStatic, unopened, "configure", "()V"))),
		}},
		{name: "virtual implementation on a JDK collection", want: Undetermined, why: "virtual/interface call on out-of-classpath receiver java/util/ArrayList", classes: []classfile.Class{
			app(lambda(handleArg(classfile.RefInvokeVirtual, "java/util/ArrayList", "clear", "()V"))),
		}},
		{name: "field handle", want: Undetermined, why: indyWhy, classes: []classfile.Class{
			app(lambda(classfile.BootstrapArg{Handle: &classfile.MethodHandle{Kind: classfile.RefGetField}})),
		}},
		{name: "no implementation handle", want: Undetermined, why: indyWhy, classes: []classfile.Class{
			app(lambda(classfile.BootstrapArg{MethodType: "()V"})),
		}},
		{name: "too few bootstrap arguments", want: Undetermined, why: indyWhy, classes: []classfile.Class{
			app(indy("run", "()Ljava/lang/Runnable;", bootstrap(classfile.RefInvokeStatic, lmfOwner, "metafactory", lmfDesc, classfile.BootstrapArg{MethodType: "()V"}))),
		}},
		{name: "no bootstrap entry", want: Undetermined, why: indyWhy, classes: []classfile.Class{
			app(indy("run", "()Ljava/lang/Runnable;", nil)),
		}},
		{name: "bootstrap handle is not invokestatic", want: Undetermined, why: indyWhy, classes: []classfile.Class{
			app(indy("run", "()Ljava/lang/Runnable;", bootstrap(classfile.RefInvokeVirtual, lmfOwner, "metafactory", lmfDesc,
				classfile.BootstrapArg{MethodType: "()V"}, handleArg(classfile.RefInvokeStatic, appClass, "trigger", "()V"), classfile.BootstrapArg{MethodType: "()V"}))),
		}},
		{name: "metafactory with another descriptor", want: Undetermined, why: indyWhy, classes: []classfile.Class{
			app(indy("run", "()Ljava/lang/Runnable;", bootstrap(classfile.RefInvokeStatic, lmfOwner, "metafactory", "()Ljava/lang/invoke/CallSite;",
				classfile.BootstrapArg{MethodType: "()V"}, handleArg(classfile.RefInvokeStatic, appClass, "trigger", "()V"), classfile.BootstrapArg{MethodType: "()V"}))),
		}},
		{name: "any other bootstrap", want: Undetermined, why: indyWhy, classes: []classfile.Class{
			app(indy("toString", "(Lcom/acme/App;)Ljava/lang/String;", bootstrap(classfile.RefInvokeStatic, "java/lang/runtime/ObjectMethods", "bootstrap",
				"(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/TypeDescriptor;Ljava/lang/Class;Ljava/lang/String;[Ljava/lang/invoke/MethodHandle;)Ljava/lang/Object;"))),
		}},
	})
}

func TestReach_StringConcatenation(t *testing.T) {
	evil := class("com/acme/Evil", "java/lang/Object", []string{"com/acme/Shown"}, meth("com/acme/Evil", "toString", toStr, sinkCall()...))
	shown := iface("com/acme/Shown")
	runReachCases(t, []reachCase{
		{name: "values, primitives and arrays are leaves", want: NotExploitable, classes: []classfile.Class{
			app(concat("(Ljava/lang/String;I[Lcom/acme/Evil;Ljava/lang/Integer;J[I)")), evil, shown,
		}},
		{name: "application toString reaching the sink", want: ReachableCandidate, classes: []classfile.Class{
			app(concat("(Ljava/lang/String;Lcom/acme/Evil;)")), evil, shown,
		}},
		{name: "inherited Object.toString calls hashCode", want: ReachableCandidate, classes: []classfile.Class{
			app(concat("(Lcom/acme/Plain;)")),
			class("com/acme/Plain", "java/lang/Object", nil, meth("com/acme/Plain", "hashCode", "()I", sinkCall()...)),
		}},
		{name: "interface-typed argument dispatches to implementors", want: ReachableCandidate, classes: []classfile.Class{
			app(concat("(Lcom/acme/Shown;)")), evil, shown,
		}},
		{name: "makeConcat without constants", want: ReachableCandidate, classes: []classfile.Class{
			app(indy("makeConcat", "(Lcom/acme/Evil;)Ljava/lang/String;", bootstrap(classfile.RefInvokeStatic, scfOwner, "makeConcat", scfDesc))), evil, shown,
		}},
		{name: "Object argument", want: Undetermined, why: "virtual/interface call on out-of-classpath receiver java/lang/Object", classes: []classfile.Class{
			app(concat("(Ljava/lang/Object;)")),
		}},
		{name: "JDK collection argument", want: Undetermined, why: "virtual/interface call on out-of-classpath receiver java/util/List", classes: []classfile.Class{
			app(concat("(ILjava/util/List;)")),
		}},
		{name: "argument from an unopened jar", want: Undetermined, why: "virtual/interface call on out-of-classpath receiver " + unopened, classes: []classfile.Class{
			app(concat("(L" + unopened + ";)")),
		}},
		{name: "argument inheriting a platform toString", want: Undetermined, why: "higher-order re-entry: inherited platform body", classes: []classfile.Class{
			app(concat("(Lcom/acme/EvilList;)")),
			class("com/acme/EvilList", "java/util/AbstractList", nil,
				meth("com/acme/EvilList", "<init>", "()V"),
				meth("com/acme/EvilList", "iterator", "()Ljava/util/Iterator;", sinkCall()...)),
		}},
	})
}

func TestReach_PlatformReceiver(t *testing.T) {
	evil := class("com/acme/Evil", "java/lang/Object", nil, meth("com/acme/Evil", "toString", toStr, sinkCall()...))
	var cases []reachCase
	for owner := range valueClasses {
		cases = append(cases, reachCase{name: "final value receiver " + owner, want: NotExploitable, classes: []classfile.Class{
			app(edge(classfile.EdgeVirtual, owner, "toString", toStr)), evil,
		}})
	}
	// Every other platform receiver can hold application objects; adding any of these
	// to valueClasses must fail here.
	for _, r := range []classfile.MethodRef{
		mref("java/util/ArrayList", "hashCode", "()I"),
		mref("java/lang/Object", "toString", toStr),
		mref("java/lang/CharSequence", "length", "()I"),
		mref("java/util/Optional", "get", "()Ljava/lang/Object;"),
		mref("java/lang/Thread", "start", "()V"),
		mref("java/lang/Class", "getName", toStr),
		mref("java/lang/Number", "intValue", "()I"),
		mref("java/lang/Iterable", "iterator", "()Ljava/util/Iterator;"),
	} {
		cases = append(cases, reachCase{name: "receiver " + r.Owner, want: Undetermined, why: "virtual/interface call on out-of-classpath receiver " + r.Owner, classes: []classfile.Class{
			app(classfile.Edge{To: r, Kind: classfile.EdgeVirtual}), evil,
		}})
	}
	cases = append(cases,
		reachCase{name: "final value receiver method not listed", want: Undetermined, why: "virtual/interface call on out-of-classpath receiver java/lang/StringBuilder", classes: []classfile.Class{
			app(edge(classfile.EdgeVirtual, "java/lang/StringBuilder", "append", "(Ljava/lang/Object;)Ljava/lang/StringBuilder;")), evil,
		}},
		reachCase{name: "final value receiver taking a final argument", want: NotExploitable, classes: []classfile.Class{
			app(edge(classfile.EdgeVirtual, "java/lang/String", "concat", "(Ljava/lang/String;)Ljava/lang/String;")), evil,
		}},
		reachCase{name: "array receiver", want: NotExploitable, classes: []classfile.Class{
			app(edge(classfile.EdgeVirtual, "[Lcom/acme/Evil;", "clone", "()Ljava/lang/Object;"), edge(classfile.EdgeVirtual, "[I", "toString", toStr)), evil,
		}},
	)
	runReachCases(t, cases)
}

// A platform body inherited by, or super-called from, an application class runs
// with the application object as `this` and can call back its overrides.
func TestReach_PlatformBodyRunsOnThis(t *testing.T) {
	evilList := class("com/acme/EvilList", "java/util/AbstractList", nil,
		meth("com/acme/EvilList", "<init>", "()V"),
		meth("com/acme/EvilList", "iterator", "()Ljava/util/Iterator;", sinkCall()...))
	plain := class("com/acme/Plain", "java/lang/Object", []string{"java/lang/Comparable"},
		meth("com/acme/Plain", "<init>", "()V"),
		meth("com/acme/Plain", "hashCode", "()I", sinkCall()...),
		meth("com/acme/Plain", "trigger", "()V", edge(classfile.EdgeSpecial, "java/lang/Object", "toString", toStr)),
		meth("com/acme/Plain", "init", "()V", edge(classfile.EdgeSpecial, "java/lang/Object", "<init>", "()V")),
		meth("com/acme/Plain", "hash", "()I", edge(classfile.EdgeSpecial, "java/lang/Object", "hashCode", "()I")))
	cmp := class("com/acme/Cmp", "java/lang/Object", []string{"java/util/Comparator"},
		meth("com/acme/Cmp", "compare", "(Ljava/lang/Object;Ljava/lang/Object;)I", sinkCall()...),
		meth("com/acme/Cmp", "trigger", "()V", edge(classfile.EdgeSpecial, "java/util/Comparator", "reversed", "()Ljava/util/Comparator;")))
	runReachCases(t, []reachCase{
		{name: "inherited platform body calls an override", want: Undetermined, why: "higher-order re-entry: inherited platform body", classes: []classfile.Class{
			app(edge(classfile.EdgeVirtual, "com/acme/EvilList", "toString", toStr)), evilList,
		}},
		// class Foos extends ArrayList<Foo> {}: overriding nothing does not make the
		// inherited body a leaf, since ArrayList.hashCode calls each element's hashCode.
		{name: "stateful platform base with nothing overridden", want: Undetermined, why: "higher-order re-entry: inherited platform body", classes: []classfile.Class{
			app(edge(classfile.EdgeVirtual, "com/acme/Foos", "hashCode", "()I")),
			class("com/acme/Foos", "java/util/ArrayList", nil,
				meth("com/acme/Foos", "<init>", "()V"),
				staticMeth("com/acme/Foos", "of", "()V", sinkCall()...),
				privateMeth("com/acme/Foos", "help", "()V", sinkCall()...)),
		}},
		{name: "override inherited from a loaded superclass", want: Undetermined, why: "higher-order re-entry: inherited platform body", classes: []classfile.Class{
			app(edge(classfile.EdgeVirtual, "com/acme/SubList", "toString", toStr)),
			evilList,
			class("com/acme/SubList", "com/acme/EvilList", nil, meth("com/acme/SubList", "<init>", "()V")),
		}},
		{name: "override from a loaded interface default", want: Undetermined, why: "higher-order re-entry: inherited platform body", classes: []classfile.Class{
			app(edge(classfile.EdgeVirtual, "com/acme/MixList", "toString", toStr)),
			class("com/acme/MixList", "java/util/AbstractList", []string{"com/acme/Sized"}, meth("com/acme/MixList", "<init>", "()V")),
			iface("com/acme/Sized", meth("com/acme/Sized", "size", "()I", sinkCall()...)),
		}},
		{name: "abstract class has no instances of its own", want: NotExploitable, classes: []classfile.Class{
			app(edge(classfile.EdgeVirtual, "com/acme/AbsList", "toString", toStr)),
			func() classfile.Class {
				c := class("com/acme/AbsList", "java/util/AbstractList", nil, meth("com/acme/AbsList", "iterator", "()Ljava/util/Iterator;", sinkCall()...))
				c.Abstract = true
				return c
			}(),
		}},
		{name: "platform interface default runs on the implementor", want: Undetermined, why: "higher-order re-entry: inherited platform body", classes: []classfile.Class{
			app(edge(classfile.EdgeVirtual, "com/acme/Cmp", "reversed", "()Ljava/util/Comparator;")), cmp,
		}},
		{name: "Object.toString calls hashCode", want: ReachableCandidate, classes: []classfile.Class{
			app(edge(classfile.EdgeVirtual, "com/acme/Plain", "toString", toStr)), plain,
		}},
		{name: "Object.toString calls an inherited loaded hashCode", want: ReachableCandidate, classes: []classfile.Class{
			app(edge(classfile.EdgeVirtual, "com/acme/Kid", "toString", toStr)), plain,
			class("com/acme/Kid", "com/acme/Plain", nil, meth("com/acme/Kid", "<init>", "()V")),
		}},
		{name: "Object.hashCode calls nothing", want: NotExploitable, classes: []classfile.Class{
			app(edge(classfile.EdgeVirtual, "com/acme/Loud", "hashCode", "()I")),
			class("com/acme/Loud", "java/lang/Object", nil, meth("com/acme/Loud", "shout", "()V", sinkCall()...)),
		}},
		{name: "super.toString into AbstractCollection", want: Undetermined, why: "higher-order re-entry: inherited platform body", ingress: mref("com/acme/EvilList", "describe", "()V"), classes: []classfile.Class{
			func() classfile.Class {
				c := evilList
				c.Methods = append(append([]classfile.Method(nil), c.Methods...), meth("com/acme/EvilList", "describe", "()V", edge(classfile.EdgeSpecial, "java/util/AbstractCollection", "toString", toStr)))
				return c
			}(),
		}},
		{name: "special method reference into a platform body", want: Undetermined, why: "higher-order re-entry: inherited platform body", ingress: mref("com/acme/EvilList", "describe", "()V"), classes: []classfile.Class{
			func() classfile.Class {
				c := evilList
				c.Methods = append(append([]classfile.Method(nil), c.Methods...), meth("com/acme/EvilList", "describe", "()V", lambda(handleArg(classfile.RefInvokeSpecial, "java/util/AbstractCollection", "toString", toStr))))
				return c
			}(),
		}},
		// Selection finds Object's hashCode on the superclass chain before any
		// superinterface (JVMS §5.4.6), so the unopened interface cannot supply it.
		// The call comes from another class: a search from Tagged itself first
		// initializes Tagged, and the unopened interface's initializer is a hazard.
		{name: "toString into Object on a class with an unopened interface", want: NotExploitable, classes: []classfile.Class{
			class("com/acme/Tagged", "java/lang/Object", []string{unopened}),
			app(edge(classfile.EdgeVirtual, "com/acme/Tagged", "toString", toStr)),
		}},
		{name: "a search from a class with an unopened interface initializes it", want: Undetermined, why: "unloaded_dependency: static initializer of unopened " + unopened, ingress: mref("com/acme/Tagged", "trigger", "()V"), classes: []classfile.Class{
			class("com/acme/Tagged", "java/lang/Object", []string{unopened},
				meth("com/acme/Tagged", "trigger", "()V", edge(classfile.EdgeSpecial, "java/lang/Object", "toString", toStr))),
		}},
		{name: "super.toString through a loaded intermediate", want: Undetermined, why: "higher-order re-entry: inherited platform body", ingress: mref("com/acme/SubList", "describe", "()V"), classes: []classfile.Class{
			evilList,
			class("com/acme/SubList", "com/acme/EvilList", nil, meth("com/acme/SubList", "describe", "()V", edge(classfile.EdgeSpecial, "com/acme/EvilList", "toString", toStr))),
		}},
		{name: "super call from an abstract class binds its concrete subclasses", want: Undetermined, why: "higher-order re-entry: inherited platform body", ingress: mref("com/acme/Base", "describe", "()V"), classes: []classfile.Class{
			func() classfile.Class {
				c := class("com/acme/Base", "java/util/AbstractList", nil, meth("com/acme/Base", "describe", "()V", edge(classfile.EdgeSpecial, "java/util/AbstractList", "toString", toStr)))
				c.Abstract = true
				return c
			}(),
			class("com/acme/Child", "com/acme/Base", nil, meth("com/acme/Child", "iterator", "()Ljava/util/Iterator;", sinkCall()...)),
		}},
		{name: "super() into a platform constructor", want: Undetermined, why: "higher-order re-entry: inherited platform body", ingress: mref("com/acme/Worker", "<init>", "()V"), classes: []classfile.Class{
			class("com/acme/Worker", "java/lang/Thread", nil,
				meth("com/acme/Worker", "<init>", "()V", edge(classfile.EdgeSpecial, "java/lang/Thread", "<init>", "()V")),
				meth("com/acme/Worker", "run", "()V", sinkCall()...)),
		}},
		{name: "interface super call into a platform default", want: Undetermined, why: "higher-order re-entry: inherited platform body", ingress: mref("com/acme/Cmp", "trigger", "()V"), classes: []classfile.Class{cmp}},
		{name: "super.toString into Object calls hashCode", want: ReachableCandidate, ingress: mref("com/acme/Plain", "trigger", "()V"), classes: []classfile.Class{plain}},
		{name: "super() into Object", want: NotExploitable, ingress: mref("com/acme/Plain", "init", "()V"), classes: []classfile.Class{plain}},
		{name: "super.hashCode into Object", want: NotExploitable, ingress: mref("com/acme/Plain", "hash", "()I"), classes: []classfile.Class{plain}},
		{name: "a fresh platform object is not this", want: NotExploitable, ingress: mref("com/acme/Busy", "make", "()V"), classes: []classfile.Class{
			class("com/acme/Busy", "java/lang/Object", nil,
				meth("com/acme/Busy", "make", "()V", edge(classfile.EdgeSpecial, "java/util/ArrayList", "<init>", "()V")),
				meth("com/acme/Busy", "work", "()V", sinkCall()...)),
		}},
		{name: "a constructor reference is not this", want: NotExploitable, ingress: mref("com/acme/Worker", "make", "()V"), classes: []classfile.Class{
			class("com/acme/Worker", "java/lang/Thread", nil,
				meth("com/acme/Worker", "make", "()V", lambda(handleArg(classfile.RefNewInvokeSpecial, "java/lang/Thread", "<init>", "()V"))),
				meth("com/acme/Worker", "run", "()V", sinkCall()...)),
		}},
	})
}

func TestParamTypes(t *testing.T) {
	cases := []struct {
		desc string
		want []string
	}{
		{"()V", nil},
		{"(IJZ)V", nil},
		{"(Ljava/lang/String;I)Ljava/lang/String;", []string{"java/lang/String"}},
		{"([I[[Ljava/lang/Object;Lcom/acme/A;)V", []string{"[I", "[[Ljava/lang/Object;", "com/acme/A"}},
		{"(Lunterminated", nil},
		{"no parens", nil},
	}
	for _, tc := range cases {
		got := paramTypes(tc.desc)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") || len(got) != len(tc.want) {
			t.Errorf("paramTypes(%q) = %q, want %q", tc.desc, got, tc.want)
		}
	}
}
