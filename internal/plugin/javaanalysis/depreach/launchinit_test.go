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
	})
}
