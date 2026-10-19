package depreach

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

// launchMain is com/acme/Main with an empty main of the given staticness, the given
// supertypes, and extra methods.
func launchMain(static bool, super string, ifaces []string, extra ...classfile.Method) classfile.Class {
	main := classfile.Method{Ref: holeIngress, Static: static, Public: true}
	return classfile.Class{Name: holeMain, Super: super, Interfaces: ifaces, Public: true,
		Methods: append([]classfile.Method{main}, extra...)}
}

func clinitCallingSink(owner string) classfile.Method {
	m := callsSink(owner, "<clinit>", "()V")
	m.Static = true
	return m
}

func ifaceWith(name string, ifaces []string, methods ...classfile.Method) classfile.Class {
	return classfile.Class{Name: name, Super: objectClass, Interfaces: ifaces, Abstract: true, Public: true, Methods: methods}
}

// TestReach_LaunchClassInitialization: the JVM initializes the launch class before it
// invokes main (JVMS §5.5), and builds an instance main's receiver first.
func TestReach_LaunchClassInitialization(t *testing.T) {
	const (
		base  = "com/acme/Base"
		deflt = "com/acme/WithDefault"
		plain = "com/acme/Plain"
	)
	abstractM := func(owner string) classfile.Method {
		return classfile.Method{Ref: mref(owner, "m", "()V"), Abstract: true, Public: true}
	}
	defaultM := func(owner string) classfile.Method { return pubMethod(owner, "m", "()V") }
	runHoleCases(t, []holeCase{
		{name: "launch class <clinit> runs before an empty main", want: ReachableCandidate, via: "Main.<clinit>",
			classes: []classfile.Class{launchMain(true, objectClass, nil, clinitCallingSink(holeMain))}},
		{name: "launch class's superclass <clinit>", want: ReachableCandidate, via: "Base.<clinit>",
			classes: []classfile.Class{
				launchMain(true, base, nil),
				{Name: base, Super: objectClass, Public: true, Methods: []classfile.Method{clinitCallingSink(base)}},
			}},
		{name: "superinterface declaring a default method is initialized", want: ReachableCandidate, via: "WithDefault.<clinit>",
			classes: []classfile.Class{
				launchMain(true, objectClass, []string{deflt}),
				ifaceWith(deflt, nil, defaultM(deflt), clinitCallingSink(deflt)),
			}},
		{name: "default superinterface reached through a plain one", want: ReachableCandidate, via: "WithDefault.<clinit>",
			classes: []classfile.Class{
				launchMain(true, objectClass, []string{plain}),
				ifaceWith(plain, []string{deflt}, abstractM(plain)),
				ifaceWith(deflt, nil, defaultM(deflt), clinitCallingSink(deflt)),
			}},
		{name: "plain superinterface is not initialized", want: NotExploitable,
			classes: []classfile.Class{
				launchMain(true, objectClass, []string{plain}),
				ifaceWith(plain, nil, abstractM(plain), clinitCallingSink(plain)),
			}},
		{name: "superinterface with only a static method is not initialized", want: NotExploitable,
			classes: []classfile.Class{
				launchMain(true, objectClass, []string{plain}),
				ifaceWith(plain, nil, classfile.Method{Ref: mref(plain, "s", "()V"), Static: true, Public: true}, clinitCallingSink(plain)),
			}},
		{name: "pre-51 interface <clinit> without ACC_STATIC is not a default method", want: NotExploitable,
			classes: []classfile.Class{
				launchMain(true, objectClass, []string{plain}),
				ifaceWith(plain, nil, abstractM(plain), callsSink(plain, "<clinit>", "()V")),
			}},
		{name: "instance main: the launcher runs the no-arg constructor", want: ReachableCandidate, via: "Main.<init>",
			classes: []classfile.Class{launchMain(false, objectClass, nil, callsSink(holeMain, "<init>", "()V"), emptyFinalize(holeMain))}},
		{name: "static main: no receiver is constructed", want: NotExploitable,
			classes: []classfile.Class{launchMain(true, objectClass, nil, callsSink(holeMain, "<init>", "()V"), emptyFinalize(holeMain))}},
		// Whether an out-of-classpath superinterface declares a default method is
		// unknown, so its initializer may run.
		{name: "launch class implementing an unopened interface", want: Undetermined, why: "unloaded_dependency: static initializer of unopened " + unopenedIface,
			classes: []classfile.Class{launchMain(true, objectClass, []string{unopenedIface})}},
		{name: "new of a class implementing an unopened interface", want: Undetermined, why: "unloaded_dependency: static initializer of unopened " + unopenedIface,
			classes: []classfile.Class{
				{Name: holeMain, Super: objectClass, Public: true, Methods: []classfile.Method{
					{Ref: holeIngress, Static: true, Public: true, InitTriggers: []string{"com/acme/C"}}}},
				{Name: "com/acme/C", Super: objectClass, Interfaces: []string{unopenedIface}, Public: true},
			}},
	})
}

const unopenedIface = "org/unopened/Iface"

// TestReach_StaticFieldInitialization: getstatic/putstatic initializes the class or
// interface that declares the resolved field (JVMS §5.4.3.2, §5.5), which can be a
// superinterface that initializing the named class would not initialize.
func TestReach_StaticFieldInitialization(t *testing.T) {
	const (
		consts = "com/acme/Consts"
		sub    = "com/acme/Sub"
		base   = "com/acme/Base"
	)
	x := classfile.Field{Name: "X", Descriptor: "Ljava/lang/Object;"}
	readsX := func(owner string, ifaces []string) classfile.Class {
		return classfile.Class{Name: holeMain, Super: objectClass, Interfaces: ifaces, Public: true, Methods: []classfile.Method{
			{Ref: holeIngress, Static: true, Public: true, StaticFieldRefs: []classfile.FieldRef{{Owner: owner, Name: x.Name, Descriptor: x.Descriptor}}}}}
	}
	constIface := func(fields ...classfile.Field) classfile.Class {
		c := ifaceWith(consts, nil, clinitCallingSink(consts))
		c.Fields = fields
		return c
	}
	plainClass := func(name, super string, ifaces []string, fields []classfile.Field, methods ...classfile.Method) classfile.Class {
		return classfile.Class{Name: name, Super: super, Interfaces: ifaces, Public: true, Fields: fields, Methods: methods}
	}
	runHoleCases(t, []holeCase{
		{name: "field named on its declaring interface", want: ReachableCandidate, via: "Consts.<clinit>",
			classes: []classfile.Class{readsX(consts, nil), constIface(x)}},
		{name: "field of a constant-only interface, named on a direct implementor", want: ReachableCandidate, via: "Consts.<clinit>",
			classes: []classfile.Class{readsX(sub, nil), constIface(x), plainClass(sub, objectClass, []string{consts}, nil)}},
		{name: "field of a constant-only interface, implemented through a superclass", want: ReachableCandidate, via: "Consts.<clinit>",
			classes: []classfile.Class{readsX(sub, nil), constIface(x), plainClass(sub, base, nil, nil), plainClass(base, objectClass, []string{consts}, nil)}},
		{name: "launch class reading an inherited interface field by its own name", want: ReachableCandidate, via: "Consts.<clinit>",
			classes: []classfile.Class{readsX(holeMain, []string{consts}), constIface(x)}},
		{name: "field declared on the named class does not initialize its interface", want: NotExploitable,
			classes: []classfile.Class{readsX(sub, nil), constIface(classfile.Field{Name: "Y", Descriptor: x.Descriptor}), plainClass(sub, objectClass, []string{consts}, []classfile.Field{x})}},
		{name: "superinterfaces are searched before the superclass", want: NotExploitable,
			classes: []classfile.Class{readsX(sub, nil),
				func() classfile.Class { c := ifaceWith(consts, nil); c.Fields = []classfile.Field{x}; return c }(),
				plainClass(sub, base, []string{consts}, nil),
				plainClass(base, objectClass, nil, []classfile.Field{x}, clinitCallingSink(base))}},
		{name: "a field declared on the superclass does not initialize the named class", want: NotExploitable,
			classes: []classfile.Class{readsX(sub, nil), plainClass(sub, base, nil, nil, clinitCallingSink(sub)), plainClass(base, objectClass, nil, []classfile.Field{x})}},
		{name: "an unopened superinterface searched before the declaring superclass", want: Undetermined, why: "unloaded_dependency: static initializer of unopened " + unopenedIface,
			classes: []classfile.Class{readsX(sub, nil), plainClass(sub, base, []string{unopenedIface}, nil), plainClass(base, objectClass, nil, []classfile.Field{x})}},
		{name: "a loaded field-less superinterface ends at the platform: the superclass declares", want: NotExploitable,
			classes: []classfile.Class{readsX(sub, nil), ifaceWith(consts, nil), plainClass(sub, base, []string{consts}, nil, clinitCallingSink(sub)), plainClass(base, objectClass, nil, []classfile.Field{x})}},
		{name: "a platform superinterface: the superclass declares", want: NotExploitable,
			classes: []classfile.Class{readsX(sub, nil), plainClass(sub, base, []string{"java/io/Serializable"}, nil, clinitCallingSink(sub)), plainClass(base, objectClass, nil, []classfile.Field{x})}},
		{name: "declarer behind an unopened superclass: every superinterface is initialized", want: ReachableCandidate, via: "Consts.<clinit>",
			classes: []classfile.Class{readsX(sub, nil), constIface(), plainClass(sub, "org/unopened/Base", []string{consts}, nil)}},
		{name: "invokestatic of a method inherited from a superclass initializes the superclass", want: ReachableCandidate, via: "Base.<clinit>",
			classes: []classfile.Class{
				{Name: holeMain, Super: objectClass, Public: true, Methods: []classfile.Method{
					{Ref: holeIngress, Static: true, Public: true, InitTriggers: []string{sub}, Edges: []classfile.Edge{edge(classfile.EdgeStatic, sub, "s", "()V")}}}},
				plainClass(sub, base, nil, nil),
				plainClass(base, objectClass, nil, nil, classfile.Method{Ref: mref(base, "s", "()V"), Static: true, Public: true}, clinitCallingSink(base)),
			}},
	})
}
