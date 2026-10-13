package depreach

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

const (
	svc         = "com/acme/Svc"
	transformer = "com/acme/Transformer"
	applyDesc   = "(Ljava/lang/String;)Ljava/lang/Object;"
	implName    = "lambda$make$0"
)

// lambdaSvc is `class Svc { static Transformer make() { return s -> Danger.parse(s); }
// void handle(String in) { ... } }` with the given call in handle and lambda site in
// make. The site lives only in make, which nothing calls, so a search from handle
// (which also runs Svc's initializers and constructor) never reaches it.
func lambdaSvc(call classfile.Edge, site classfile.Edge, extra ...classfile.Class) []classfile.Class {
	return append([]classfile.Class{
		class(svc, "java/lang/Object", nil,
			meth(svc, "<init>", "()V"),
			staticMeth(svc, "make", "()L"+transformer+";", site),
			meth(svc, "handle", "(Ljava/lang/String;)V", call),
			staticMeth(svc, implName, applyDesc, sinkCall()...)),
		iface(transformer,
			abstractMeth(transformer, "apply", applyDesc),
			abstractMeth(transformer, "other", applyDesc)),
	}, extra...)
}

// transformerSite is a metafactory site producing a Transformer from impl.
func transformerSite(impl classfile.BootstrapArg) classfile.Edge {
	return indy("apply", "()L"+transformer+";", bootstrap(classfile.RefInvokeStatic, lmfOwner, "metafactory", lmfDesc,
		classfile.BootstrapArg{MethodType: applyDesc}, impl, classfile.BootstrapArg{MethodType: applyDesc}))
}

// altSite is an altMetafactory site producing a Transformer with the given extra
// arguments after flags (markers, bridges and their integer counts).
func altSite(extra ...classfile.BootstrapArg) classfile.Edge {
	args := append([]classfile.BootstrapArg{
		{MethodType: applyDesc}, handleArg(classfile.RefInvokeStatic, svc, implName, applyDesc), {MethodType: applyDesc}, {},
	}, extra...)
	return indy("apply", "()L"+transformer+";", bootstrap(classfile.RefInvokeStatic, lmfOwner, "altMetafactory", lmfAltDesc, args...))
}

var staticImpl = handleArg(classfile.RefInvokeStatic, svc, implName, applyDesc)

// A lambda object answers interface calls wherever it travels, so its
// implementation must be reached from a root that never reaches its creation site.
func TestReach_LambdaDispatchFromAnyRoot(t *testing.T) {
	handle := mref(svc, "handle", "(Ljava/lang/String;)V")
	callApply := edge(classfile.EdgeInterface, transformer, "apply", applyDesc)
	runReachCases(t, []reachCase{
		{name: "lambda created elsewhere, applied from a handler", ingress: handle, want: ReachableCandidate,
			classes: lambdaSvc(callApply, transformerSite(staticImpl))},
		{name: "call through a superinterface", ingress: handle, want: ReachableCandidate,
			classes: func() []classfile.Class {
				cs := lambdaSvc(edge(classfile.EdgeInterface, "com/acme/Base", "apply", applyDesc), transformerSite(staticImpl),
					iface("com/acme/Base", abstractMeth("com/acme/Base", "apply", applyDesc)))
				cs[1].Interfaces = []string{"com/acme/Base"}
				return cs
			}()},
		{name: "altMetafactory marker interface", ingress: handle, want: ReachableCandidate,
			classes: lambdaSvc(edge(classfile.EdgeInterface, "com/acme/Named", "apply", applyDesc),
				altSite(classfile.BootstrapArg{}, classfile.BootstrapArg{Class: "com/acme/Named"}),
				iface("com/acme/Named", abstractMeth("com/acme/Named", "apply", applyDesc)))},
		// interface Base<T> { Object apply(T t); } interface Transformer extends
		// Base<String> { Object apply(String s); }: javac bridges apply(Object).
		{name: "altMetafactory bridge descriptor", ingress: handle, want: ReachableCandidate,
			classes: func() []classfile.Class {
				cs := lambdaSvc(edge(classfile.EdgeInterface, "com/acme/Base", "apply", "(Ljava/lang/Object;)Ljava/lang/Object;"),
					altSite(classfile.BootstrapArg{}, classfile.BootstrapArg{MethodType: "(Ljava/lang/Object;)Ljava/lang/Object;"}),
					iface("com/acme/Base", abstractMeth("com/acme/Base", "apply", "(Ljava/lang/Object;)Ljava/lang/Object;")))
				cs[1].Interfaces = []string{"com/acme/Base"}
				return cs
			}()},
		{name: "unfollowable implementation handle", ingress: handle, want: Undetermined, why: indyWhy + ": lambda implementing " + transformer,
			classes: lambdaSvc(callApply, transformerSite(classfile.BootstrapArg{Handle: &classfile.MethodHandle{Kind: classfile.RefGetField}}))},
		{name: "other method of the interface is not the lambda's", ingress: handle, want: NotExploitable,
			classes: lambdaSvc(edge(classfile.EdgeInterface, transformer, "other", applyDesc), transformerSite(staticImpl))},
		{name: "same name, other descriptor is not the lambda's", ingress: handle, want: NotExploitable,
			classes: lambdaSvc(edge(classfile.EdgeInterface, transformer, "apply", "(Ljava/lang/Integer;)Ljava/lang/Object;"), transformerSite(staticImpl))},
	})
}

func TestHasAppSubtype_LambdaIsAWitness(t *testing.T) {
	e := NewEngine(lambdaSvc(edge(classfile.EdgeInterface, transformer, "apply", applyDesc), transformerSite(staticImpl)))
	if !e.hasAppSubtype(transformer) {
		t.Errorf("hasAppSubtype(%s) = false with a lambda implementing it", transformer)
	}
	if cb, _ := e.reentryCallback("(L" + transformer + ";)V"); cb != "app-implemented "+transformer {
		t.Errorf("reentryCallback names %q, want the lambda's interface as witness", cb)
	}
}

// Only listed value-class methods are leaves; every other method of the same
// receiver, and every platform call taking a non-value argument, stays a hazard.
func TestReach_ValueReceiverMethods(t *testing.T) {
	const cs = "java/lang/CharSequence"
	evil := class("com/acme/Evil", "java/lang/Object", nil, meth("com/acme/Evil", "toString", toStr, sinkCall()...))
	seq := class("com/acme/Seq", "java/lang/Object", []string{cs},
		meth("com/acme/Seq", "<init>", "()V"),
		meth("com/acme/Seq", "charAt", "(I)C", sinkCall()...),
		meth("com/acme/Seq", "length", "()I", sinkCall()...))
	upper := class("com/acme/Upper", "java/lang/Object", []string{"java/util/function/UnaryOperator"},
		meth("com/acme/Upper", "<init>", "()V"),
		meth("com/acme/Upper", "apply", "(Ljava/lang/Object;)Ljava/lang/Object;", sinkCall()...))
	bag := class("com/acme/Bag", "java/lang/Object", []string{"java/util/List"},
		meth("com/acme/Bag", "<init>", "()V"),
		meth("com/acme/Bag", "iterator", "()Ljava/util/Iterator;", sinkCall()...))
	provider := class("com/acme/XProvider", "java/nio/charset/spi/CharsetProvider", nil,
		meth("com/acme/XProvider", "<init>", "()V"),
		meth("com/acme/XProvider", "charsetForName", "(Ljava/lang/String;)Ljava/nio/charset/Charset;", sinkCall()...))
	provider.Public = true
	provider.Methods[0].Public = true
	unlisted := "virtual/interface call on out-of-classpath receiver "
	sb := "java/lang/StringBuilder"
	v := func(owner, name, desc string) classfile.Edge { return edge(classfile.EdgeVirtual, owner, name, desc) }
	runReachCases(t, []reachCase{
		{name: "getBytes(String) finds charsets through providers", want: Undetermined, why: unlisted + "java/lang/String", classes: []classfile.Class{
			app(v("java/lang/String", "getBytes", "(Ljava/lang/String;)[B")), evil}},
		{name: "getBytes(String) with an application CharsetProvider", want: ReachableCandidate, classes: []classfile.Class{
			app(v("java/lang/String", "getBytes", "(Ljava/lang/String;)[B")), provider}},
		{name: "append(CharSequence) with an application CharSequence", want: Undetermined, why: unlisted + sb, classes: []classfile.Class{
			app(v(sb, "append", "(L"+cs+";)L"+sb+";")), seq}},
		{name: "insert(int, CharSequence) with an application CharSequence", want: Undetermined, why: unlisted + sb, classes: []classfile.Class{
			app(v(sb, "insert", "(IL"+cs+";)L"+sb+";")), seq}},
		{name: "contentEquals(CharSequence) with an application CharSequence", want: Undetermined, why: unlisted + "java/lang/String", classes: []classfile.Class{
			app(v("java/lang/String", "contentEquals", "(L"+cs+";)Z")), seq}},
		{name: "transform with an application UnaryOperator", want: Undetermined, why: unlisted + "java/lang/String", classes: []classfile.Class{
			app(v("java/lang/String", "transform", "(Ljava/util/function/Function;)Ljava/lang/Object;")), upper}},
		{name: "append(Object)", want: Undetermined, why: unlisted + sb, classes: []classfile.Class{
			app(v(sb, "append", "(Ljava/lang/Object;)L"+sb+";")), evil}},
		{name: "String.join over an application List", want: Undetermined, why: "higher-order re-entry:", classes: []classfile.Class{
			app(edge(classfile.EdgeStatic, "java/lang/String", "join", "(L"+cs+";Ljava/lang/Iterable;)Ljava/lang/String;")), bag}},
		{name: "String.valueOf(Object)", want: Undetermined, why: "higher-order re-entry:", classes: []classfile.Class{
			app(edge(classfile.EdgeStatic, "java/lang/String", "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;")), evil}},
		{name: "String.valueOf(char[]) is a leaf", want: NotExploitable, classes: []classfile.Class{
			app(edge(classfile.EdgeStatic, "java/lang/String", "valueOf", "([C)Ljava/lang/String;")), evil}},
		{name: "listed methods with value arguments are leaves", want: NotExploitable, classes: []classfile.Class{
			app(v("java/lang/String", "length", "()I"), v("java/lang/String", "indexOf", "(Ljava/lang/String;I)I"),
				v(sb, "append", "(Ljava/lang/String;)L"+sb+";"), v("java/lang/Integer", "intValue", "()I")), evil}},
		{name: "equals and the compareTo bridge only compare their argument", want: NotExploitable, classes: []classfile.Class{
			app(v("java/lang/String", "equals", "(Ljava/lang/Object;)Z"), v("java/lang/Long", "compareTo", "(Ljava/lang/Object;)I")), evil}},
	})
}

// A listed method is a leaf without a re-entry check, so each must take only value
// or primitive arguments, except the entries marked as comparing an Object.
func TestValueReceiverMethods_TakeNoApplicationObject(t *testing.T) {
	for key, kind := range valueReceiverMethods {
		i := len(key)
		for i > 0 && key[i-1] != '(' {
			i--
		}
		desc := key[i-1:]
		var other []string
		for _, p := range parseParamRefTypes(desc) {
			if !valueClasses[p] {
				other = append(other, p)
			}
		}
		switch kind {
		case valueArgs:
			if len(other) > 0 {
				t.Errorf("%s takes %v", key, other)
			}
		case valueComparedTo:
			if len(other) != 1 || other[0] != "java/lang/Object" {
				t.Errorf("%s is marked as comparing an Object but takes %v", key, other)
			}
		default:
			t.Errorf("%s has kind %d", key, kind)
		}
	}
}
