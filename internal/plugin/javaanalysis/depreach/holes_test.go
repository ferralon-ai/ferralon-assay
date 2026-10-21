package depreach

import (
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

// holeCase is one engine row: classes alongside the sink's UrlFetcher, searched from
// com/acme/Main.main. Each row fails when the rule it names is reverted.
type holeCase struct {
	name    string
	classes []classfile.Class
	want    Verdict
	kind    string // a hazard kind the frontier must meet (Undetermined rows)
	why     string // a substring of some hazard reason the row pins (optional)
	via     string // a method the found path must pass through (ReachableCandidate rows)
	cp      Classpath
}

const holeMain = "com/acme/Main"

var (
	holeSink    = mref("com/evil/netkit/UrlFetcher", "fetch", sinkDesc)
	holeIngress = mref(holeMain, "main", "([Ljava/lang/String;)V")
)

func mainCalls(edges ...classfile.Edge) classfile.Class {
	return classfile.Class{Name: holeMain, Super: objectClass, Public: true, Methods: []classfile.Method{
		{Ref: holeIngress, Static: true, Public: true, Edges: edges},
	}}
}

func callsSink(owner, name, desc string) classfile.Method {
	return classfile.Method{Ref: mref(owner, name, desc), Public: true, Edges: []classfile.Edge{
		edge(classfile.EdgeVirtual, holeSink.Owner, holeSink.Name, holeSink.Descriptor),
	}}
}

func pubMethod(owner, name, desc string, edges ...classfile.Edge) classfile.Method {
	return classfile.Method{Ref: mref(owner, name, desc), Public: true, Edges: edges}
}

// emptyFinalize keeps a fixture's own finalize from being the hazard a row meets.
func emptyFinalize(owner string) classfile.Method { return pubMethod(owner, "finalize", "()V") }

const getProperty = "(Ljava/lang/String;)Ljava/lang/String;"

func runHoleCases(t *testing.T, cases []holeCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewEngineOn(append(tc.classes, urlFetcherDep()), tc.cp).Reach(holeIngress, holeSink)
			if r.Verdict != tc.want {
				t.Fatalf("verdict = %s, want %s (hazard=%q kinds=%v path=%s)", r.Verdict, tc.want, r.HazardWhy, r.HazardKinds, PathString(r.Path))
			}
			if tc.kind != "" && !slices.Contains(r.HazardKinds, tc.kind) {
				t.Errorf("hazard kinds %v lack %s (first %q)", r.HazardKinds, tc.kind, r.HazardWhy)
			}
			if tc.why != "" && !strings.Contains(r.HazardWhy, tc.why) {
				t.Errorf("hazard %q lacks %q", r.HazardWhy, tc.why)
			}
			if tc.via != "" && !strings.Contains(PathString(r.Path), tc.via) {
				t.Errorf("path %s does not pass %s", PathString(r.Path), tc.via)
			}
		})
	}
}

// TestReach_TrackerHoles: the six probes under which the engine returned an empty,
// hazard-free search although the JDK can run the sink.
func TestReach_TrackerHoles(t *testing.T) {
	const d = "com/acme/D"
	runHoleCases(t, []holeCase{
		{
			name: "1 DriverManager.getConnection runs a provider's connect",
			classes: []classfile.Class{
				mainCalls(edge(classfile.EdgeStatic, "java/sql/DriverManager", "getConnection", "(Ljava/lang/String;)Ljava/sql/Connection;")),
				{Name: d, Super: objectClass, Interfaces: []string{"java/sql/Driver"}, Public: true, Methods: []classfile.Method{
					pubMethod(d, "<init>", "()V"),
					callsSink(d, "connect", "(Ljava/lang/String;Ljava/util/Properties;)Ljava/sql/Connection;"),
				}},
			},
			want: ReachableCandidate, via: "D.connect",
		},
		{
			name: "2 ServiceLoader.loadInstalled",
			classes: []classfile.Class{
				mainCalls(edge(classfile.EdgeStatic, "java/util/ServiceLoader", "loadInstalled", "(Ljava/lang/Class;)Ljava/util/ServiceLoader;")),
			},
			want: Undetermined, kind: HazardKindReflection,
		},
		{
			name: "3 new D() runs D.finalize",
			classes: []classfile.Class{
				mainCalls(edge(classfile.EdgeSpecial, d, "<init>", "()V")),
				{Name: d, Super: objectClass, Methods: []classfile.Method{
					pubMethod(d, "<init>", "()V"),
					callsSink(d, "finalize", "()V"),
				}},
			},
			want: ReachableCandidate, via: "D.finalize",
		},
		{
			name: "4 TimerTask subclass handed to runAsync(Runnable)",
			classes: []classfile.Class{
				mainCalls(
					edge(classfile.EdgeSpecial, d, "<init>", "()V"),
					edge(classfile.EdgeStatic, "java/util/concurrent/CompletableFuture", "runAsync", "(Ljava/lang/Runnable;)Ljava/util/concurrent/CompletableFuture;"),
				),
				{Name: d, Super: "java/util/TimerTask", Public: true, Methods: []classfile.Method{
					pubMethod(d, "<init>", "()V"),
					emptyFinalize(d),
					callsSink(d, "run", "()V"),
				}},
			},
			want: Undetermined, kind: HazardKindReentry, why: "reference argument java/lang/Runnable",
		},
		{
			name: "5 java.beans.Beans.instantiate",
			classes: []classfile.Class{
				mainCalls(edge(classfile.EdgeStatic, "java/beans/Beans", "instantiate", "(Ljava/lang/ClassLoader;Ljava/lang/String;)Ljava/lang/Object;")),
			},
			want: Undetermined, kind: HazardKindReflection,
		},
		{
			name: "6 java.rmi.Naming.lookup deserializes D",
			classes: []classfile.Class{
				mainCalls(edge(classfile.EdgeStatic, "java/rmi/Naming", "lookup", "(Ljava/lang/String;)Ljava/rmi/Remote;")),
				{Name: d, Super: objectClass, Interfaces: []string{"java/io/Serializable"}, Methods: []classfile.Method{
					{Ref: mref(d, "readObject", "(Ljava/io/ObjectInputStream;)V"), Private: true, Edges: []classfile.Edge{
						edge(classfile.EdgeVirtual, holeSink.Owner, holeSink.Name, holeSink.Descriptor),
					}},
				}},
			},
			want: Undetermined, kind: HazardKindReflection,
		},
	})
}

// TestReach_ProviderRoots: the JDK loads and calls a class reaching a non-denied
// platform supertype, once the search runs any JDK body.
func TestReach_ProviderRoots(t *testing.T) {
	const d = "com/acme/D"
	touch := edge(classfile.EdgeStatic, "java/lang/System", "getProperty", getProperty)
	runHoleCases(t, []holeCase{
		{
			name: "no JDK body on the frontier: no roots",
			classes: []classfile.Class{
				func() classfile.Class {
					m := mainCalls(edge(classfile.EdgeStatic, holeMain, "helper", "()V"))
					m.Methods = append(m.Methods, classfile.Method{Ref: mref(holeMain, "helper", "()V"), Static: true})
					return m
				}(),
				{Name: d, Super: objectClass, Interfaces: []string{"java/sql/Driver"}, Public: true, Methods: []classfile.Method{
					callsSink(d, "connect", "(Ljava/lang/String;Ljava/util/Properties;)Ljava/sql/Connection;"),
				}},
			},
			want: NotExploitable,
		},
		{
			name: "a JDK static initializer trigger roots providers",
			classes: []classfile.Class{
				{Name: holeMain, Super: objectClass, Methods: []classfile.Method{{Ref: holeIngress, Static: true, InitTriggers: []string{"java/sql/DriverManager"}}}},
				{Name: d, Super: objectClass, Interfaces: []string{"java/sql/Driver"}, Methods: []classfile.Method{
					callsSink(d, "connect", "(Ljava/lang/String;Ljava/util/Properties;)Ljava/sql/Connection;"),
				}},
			},
			want: ReachableCandidate, via: "D.connect",
		},
		{
			name: "public concrete provider: constructor is a root",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: d, Super: "java/nio/charset/spi/CharsetProvider", Public: true, Methods: []classfile.Method{
					callsSink(d, "<init>", "()V"),
				}},
			},
			want: ReachableCandidate, via: "D.<init>",
		},
		{
			name: "public concrete provider: static provider() is a root",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: d, Super: objectClass, Interfaces: []string{"java/net/spi/InetAddressResolverProvider"}, Public: true, Methods: []classfile.Method{
					{Ref: mref(d, "provider", "()Lcom/acme/D;"), Static: true, Public: true, Edges: []classfile.Edge{
						edge(classfile.EdgeVirtual, holeSink.Owner, holeSink.Name, holeSink.Descriptor),
					}},
				}},
			},
			want: ReachableCandidate, via: "D.provider",
		},
		{
			name: "public concrete provider: its static initializer is a root",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: d, Super: objectClass, Interfaces: []string{"java/sql/Driver"}, Public: true, Methods: []classfile.Method{
					{Ref: mref(d, "<clinit>", "()V"), Static: true, Edges: []classfile.Edge{
						edge(classfile.EdgeVirtual, holeSink.Owner, holeSink.Name, holeSink.Descriptor),
					}},
				}},
			},
			want: ReachableCandidate, via: "D.<clinit>",
		},
		{
			name: "non-public provider: constructor is not a root",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: d, Super: "java/nio/charset/spi/CharsetProvider", Methods: []classfile.Method{
					callsSink(d, "<init>", "()V"),
				}},
			},
			want: NotExploitable,
		},
		{
			name: "supertype through a loaded intermediate",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: "com/acme/Base", Super: objectClass, Interfaces: []string{"java/sql/Driver"}},
				{Name: d, Super: "com/acme/Base", Methods: []classfile.Method{
					callsSink(d, "connect", "(Ljava/lang/String;Ljava/util/Properties;)Ljava/sql/Connection;"),
				}},
			},
			want: ReachableCandidate, via: "D.connect",
		},
		{
			name: "unopened dependency supertype",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: d, Super: objectClass, Interfaces: []string{"org/unopened/Plugin"}, Methods: []classfile.Method{
					callsSink(d, "start", "()V"),
				}},
			},
			want: ReachableCandidate, via: "D.start",
		},
		{
			name: "denied supertypes are never JDK-loaded",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: d, Super: objectClass, Interfaces: []string{"java/lang/Runnable", "java/lang/Comparable", "java/util/function/Supplier"}, Public: true, Methods: []classfile.Method{
					callsSink(d, "run", "()V"),
				}},
				{Name: "com/acme/Boom", Super: "java/lang/IllegalStateException", Public: true, Methods: []classfile.Method{
					callsSink("com/acme/Boom", "getMessage", "()Ljava/lang/String;"),
				}},
			},
			want: NotExploitable,
		},
		{
			name: "a root returning a denied type the JDK calls",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: d, Super: "java/nio/charset/spi/CharsetProvider", Methods: []classfile.Method{
					pubMethod(d, "charsets", "()Ljava/util/Iterator;"),
				}},
			},
			want: Undetermined, kind: HazardKindReentry, why: "returns java/util/Iterator",
		},
		{
			name: "a root returning a value or loadable type",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: d, Super: "java/nio/charset/spi/CharsetProvider", Methods: []classfile.Method{
					pubMethod(d, "name", "()Ljava/lang/String;"),
					pubMethod(d, "charsetForName", "(Ljava/lang/String;)Ljava/nio/charset/Charset;"),
					pubMethod(d, "count", "()[I"),
				}},
			},
			want: NotExploitable,
		},
	})
}

// TestReach_SignatureRoots: of a JDK-loadable class's overridable methods, only those
// the JDK can name through a supertype it holds the object under are roots. Rows run on
// the platformMethods release unless they state another runtime, except the last, which states none.
func TestReach_SignatureRoots(t *testing.T) {
	const (
		d    = "com/acme/D"
		base = "com/acme/Base"
		cowl = "java/util/concurrent/CopyOnWriteArrayList"
		ueh  = "java/lang/Thread$UncaughtExceptionHandler"
		sub  = "java/util/concurrent/Flow$Subscriber"
	)
	touch := edge(classfile.EdgeStatic, "java/lang/System", "getProperty", getProperty)
	uncaught := "(Ljava/lang/Thread;Ljava/lang/Throwable;)V"
	undeclared := []classfile.Class{
		mainCalls(touch),
		{Name: d, Super: cowl, Public: true, Methods: []classfile.Method{
			callsSink(d, "snapshot", "()Ljava/lang/Object;"),
			callsSink(d, "cursor", "()Ljava/util/Iterator;"),
		}},
	}
	cases := []holeCase{
		{
			name:    "a method no platform supertype declares is no root, and no re-entry hazard",
			classes: undeclared,
			want:    NotExploitable,
		},
		{
			name:    "the same method on a later JDK, which can declare it, is a root",
			classes: undeclared,
			cp:      Classpath{JDK: platformMethodsJDK + 4},
			want:    ReachableCandidate, via: "D.snapshot",
		},
		{
			name:    "the same on an earlier JDK, which can declare a method since removed",
			classes: undeclared,
			cp:      Classpath{JDK: 8},
			want:    ReachableCandidate, via: "D.snapshot",
		},
		{
			name: "the same on a platform interface's implementor",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: d, Super: objectClass, Interfaces: []string{ueh}, Public: true, Methods: []classfile.Method{
					pubMethod(d, "uncaughtException", uncaught),
					callsSink(d, "snapshot", "()Ljava/lang/Object;"),
				}},
			},
			want: NotExploitable,
		},
		{
			name: "a platform-declared override returning Object stays a root with its hazard",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: d, Super: "java/util/Hashtable", Public: true, Methods: []classfile.Method{
					pubMethod(d, "get", "(Ljava/lang/Object;)Ljava/lang/Object;"),
				}},
			},
			want: Undetermined, kind: HazardKindReentry, why: "returns java/lang/Object",
		},
		{
			name: "an override of a platform interface the class is handed to the JDK under",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: d, Super: objectClass, Interfaces: []string{ueh}, Public: true, Methods: []classfile.Method{
					callsSink(d, "uncaughtException", uncaught),
				}},
			},
			want: ReachableCandidate, via: "D.uncaughtException",
		},
		{
			name: "an inherited method a subclass's platform interface names",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: base, Super: objectClass, Public: true, Methods: []classfile.Method{
					callsSink(base, "uncaughtException", uncaught),
				}},
				{Name: d, Super: base, Interfaces: []string{ueh}, Public: true},
			},
			want: ReachableCandidate, via: "Base.uncaughtException",
		},
		{
			name: "the same two levels up",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: base, Super: objectClass, Public: true, Methods: []classfile.Method{
					callsSink(base, "uncaughtException", uncaught),
				}},
				{Name: "com/acme/Mid", Super: base, Public: true},
				{Name: d, Super: "com/acme/Mid", Interfaces: []string{ueh}, Public: true},
			},
			want: ReachableCandidate, via: "Base.uncaughtException",
		},
		{
			name: "an inherited default method a subclass's platform interface names",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: "com/acme/Handler", Super: objectClass, Abstract: true, Public: true, Methods: []classfile.Method{
					callsSink("com/acme/Handler", "uncaughtException", uncaught),
				}},
				{Name: d, Super: objectClass, Interfaces: []string{"com/acme/Handler", ueh}, Public: true},
			},
			want: ReachableCandidate, via: "Handler.uncaughtException",
		},
		{
			name: "a default method of a superinterface's superinterface",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: "com/acme/Handler", Super: objectClass, Abstract: true, Public: true, Methods: []classfile.Method{
					callsSink("com/acme/Handler", "uncaughtException", uncaught),
				}},
				{Name: "com/acme/Logging", Super: objectClass, Interfaces: []string{"com/acme/Handler"}, Abstract: true, Public: true},
				{Name: d, Super: objectClass, Interfaces: []string{"com/acme/Logging", ueh}, Public: true},
			},
			want: ReachableCandidate, via: "Handler.uncaughtException",
		},
		{
			name: "an inherited method no loadable subclass names is no root",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: base, Super: objectClass, Public: true, Methods: []classfile.Method{
					callsSink(base, "uncaughtException", uncaught),
				}},
				{Name: d, Super: base, Public: true},
			},
			want: NotExploitable,
		},
		{
			name: "a method an unopened supertype may declare",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: d, Super: cowl, Interfaces: []string{"org/unopened/Plugin"}, Public: true, Methods: []classfile.Method{
					callsSink(d, "start", "()V"),
				}},
			},
			want: ReachableCandidate, via: "D.start",
		},
		{
			name: "a method a subclass's unopened supertype may declare",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: base, Super: objectClass, Public: true, Methods: []classfile.Method{
					callsSink(base, "start", "()V"),
				}},
				{Name: d, Super: base, Interfaces: []string{"org/unopened/Plugin"}, Public: true},
			},
			want: ReachableCandidate, via: "Base.start",
		},
		{
			name: "a JDK-prefixed supertype a classpath JAR defines is unopened",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: d, Super: "javax/net/SocketFactory", Public: true, Methods: []classfile.Method{
					callsSink(d, "start", "()V"),
				}},
			},
			cp:   Classpath{Packages: map[string]bool{"javax/net": true}, },
			want: ReachableCandidate, via: "D.start",
		},
		{
			name: "a JAR's own java/ class does not shadow the JDK's",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: cowl, Super: objectClass, Public: true},
				{Name: d, Super: cowl, Public: true, Methods: []classfile.Method{
					callsSink(d, "add", "(Ljava/lang/Object;)Z"),
				}},
			},
			want: ReachableCandidate, via: "D.add",
		},
		{
			name: "the same when the class is JDK-loadable through another supertype",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: cowl, Super: objectClass, Public: true},
				{Name: d, Super: cowl, Interfaces: []string{ueh}, Public: true, Methods: []classfile.Method{
					pubMethod(d, "uncaughtException", uncaught),
					callsSink(d, "add", "(Ljava/lang/Object;)Z"),
				}},
			},
			want: ReachableCandidate, via: "D.add",
		},
		{
			name: "a covariant override of a platform method",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: d, Super: "java/nio/charset/spi/CharsetProvider", Public: true, Methods: []classfile.Method{
					callsSink(d, "charsetForName", "(Ljava/lang/String;)Lcom/acme/AcmeCharset;"),
				}},
			},
			want: ReachableCandidate, via: "D.charsetForName",
		},
		{
			name: "a generic override reached through its bridge",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: d, Super: objectClass, Interfaces: []string{sub}, Public: true, Methods: []classfile.Method{
					callsSink(d, "onNext", "(Ljava/lang/String;)V"),
					pubMethod(d, "onNext", "(Ljava/lang/Object;)V", edge(classfile.EdgeVirtual, d, "onNext", "(Ljava/lang/String;)V")),
				}},
			},
			want: ReachableCandidate, via: "D.onNext(Ljava/lang/Object;)V -> D.onNext(Ljava/lang/String;)V",
		},
		{
			name: "a generic override without its bridge is no root",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: d, Super: objectClass, Interfaces: []string{sub}, Public: true, Methods: []classfile.Method{
					callsSink(d, "onNext", "(Ljava/lang/String;)V"),
				}},
			},
			want: NotExploitable,
		},
		{
			name: "a method a listed platform supertype lacks",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: d, Super: "javax/net/SocketFactory", Public: true, Methods: []classfile.Method{
					callsSink(d, "start", "()V"),
				}},
			},
			want: NotExploitable,
		},
		{
			name: "the same on a classpath not every entry of which was listed",
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: d, Super: "javax/net/SocketFactory", Public: true, Methods: []classfile.Method{
					callsSink(d, "start", "()V"),
				}},
			},
			cp:   Classpath{Unlisted: true},
			want: ReachableCandidate, via: "D.start",
		},
	}
	for _, m := range []struct{ name, desc string }{
		{"toString", "()Ljava/lang/String;"},
		{"equals", "(Ljava/lang/Object;)Z"},
		{"hashCode", "()I"},
		{"finalize", "()V"},
		{"clone", "()Ljava/lang/Object;"},
	} {
		cases = append(cases, holeCase{
			name: "an override of java/lang/Object's " + m.name,
			classes: []classfile.Class{
				mainCalls(touch),
				{Name: d, Super: "java/nio/charset/spi/CharsetProvider", Public: true, Methods: []classfile.Method{
					callsSink(d, m.name, m.desc),
				}},
			},
			want: ReachableCandidate, via: "D." + m.name,
		})
	}
	for i := range cases {
		if cases[i].cp.JDK == 0 {
			cases[i].cp.JDK = platformMethodsJDK
		}
	}
	cases = append(cases, holeCase{
		name:    "the same undeclared method on an unstated JDK",
		classes: undeclared,
		want:    ReachableCandidate, via: "D.snapshot",
	})
	runHoleCases(t, cases)
}

// TestReach_PlatformBodyOnThis: a JDK body running with an application object as
// `this` can call what the object overrides or holds.
func TestReach_PlatformBodyOnThis(t *testing.T) {
	const l = "com/acme/L"
	const e = "com/acme/E"
	list := func(super string) classfile.Class {
		return classfile.Class{Name: l, Super: super, Methods: []classfile.Method{
			pubMethod(l, "<init>", "()V"),
			emptyFinalize(l),
			callsSink(l, "size", "()I"),
		}}
	}
	runHoleCases(t, []holeCase{
		{
			name:    "inherited isEmpty runs size on this",
			classes: []classfile.Class{mainCalls(edge(classfile.EdgeVirtual, l, "isEmpty", "()Z")), list("java/util/AbstractList")},
			want:    Undetermined, kind: HazardKindReentry, why: "runs on " + l,
		},
		{
			name: "super constructor of a platform class runs on this",
			classes: []classfile.Class{
				mainCalls(edge(classfile.EdgeSpecial, l, "<init>", "()V")),
				{Name: l, Super: "java/util/ArrayList", Methods: []classfile.Method{
					pubMethod(l, "<init>", "()V", edge(classfile.EdgeSpecial, "java/util/ArrayList", "<init>", "()V")),
					emptyFinalize(l),
				}},
			},
			want: Undetermined, kind: HazardKindReentry, why: "runs on " + l,
		},
		{
			name:    "constructing a platform object binds no app this",
			classes: []classfile.Class{mainCalls(edge(classfile.EdgeSpecial, "java/util/ArrayList", "<init>", "()V"))},
			want:    NotExploitable,
		},
		{
			name: "Object bodies other than toString are leaves",
			classes: []classfile.Class{
				mainCalls(edge(classfile.EdgeVirtual, l, "hashCode", "()I"), edge(classfile.EdgeVirtual, l, "equals", "(Ljava/lang/Object;)Z")),
				{Name: l, Super: objectClass, Methods: []classfile.Method{emptyFinalize(l), callsSink(l, "size", "()I")}},
			},
			want: NotExploitable,
		},
		{
			name: "Object.toString calls this.hashCode",
			classes: []classfile.Class{
				mainCalls(edge(classfile.EdgeVirtual, l, "toString", "()Ljava/lang/String;")),
				{Name: l, Super: objectClass, Methods: []classfile.Method{callsSink(l, "hashCode", "()I")}},
			},
			want: ReachableCandidate, via: "L.hashCode",
		},
		{
			name: "enum with no overridable method: Enum bodies are leaves",
			classes: []classfile.Class{
				mainCalls(edge(classfile.EdgeVirtual, e, "hashCode", "()I"), edge(classfile.EdgeVirtual, e, "name", "()Ljava/lang/String;")),
				{Name: e, Super: "java/lang/Enum", Methods: []classfile.Method{
					{Ref: mref(e, "<init>", "(Ljava/lang/String;I)V"), Private: true},
					{Ref: mref(e, "values", "()[Lcom/acme/E;"), Static: true, Public: true},
				}},
			},
			want: NotExploitable,
		},
		{
			name: "enum overriding toString: Enum bodies are hazards",
			classes: []classfile.Class{
				mainCalls(edge(classfile.EdgeVirtual, e, "name", "()Ljava/lang/String;")),
				{Name: e, Super: "java/lang/Enum", Methods: []classfile.Method{callsSink(e, "toString", "()Ljava/lang/String;")}},
			},
			want: Undetermined, kind: HazardKindReentry, why: "runs on " + e,
		},
		{
			name: "enum constant body inherits its enum's override",
			classes: []classfile.Class{
				mainCalls(edge(classfile.EdgeVirtual, e+"$1", "name", "()Ljava/lang/String;")),
				{Name: e, Super: "java/lang/Enum", Abstract: true, Methods: []classfile.Method{callsSink(e, "toString", "()Ljava/lang/String;")}},
				{Name: e + "$1", Super: e},
			},
			want: Undetermined, kind: HazardKindReentry, why: "runs on " + e + "$1",
		},
		{
			name: "enum inherits an interface default",
			classes: []classfile.Class{
				mainCalls(edge(classfile.EdgeVirtual, e, "name", "()Ljava/lang/String;")),
				{Name: "com/acme/Named", Super: objectClass, Abstract: true, Methods: []classfile.Method{callsSink("com/acme/Named", "describe", "()Ljava/lang/String;")}},
				{Name: e, Super: "java/lang/Enum", Interfaces: []string{"com/acme/Named"}},
			},
			want: Undetermined, kind: HazardKindReentry, why: "runs on " + e,
		},
		{
			name: "finalize inherited from an unopened dependency",
			classes: []classfile.Class{
				mainCalls(edge(classfile.EdgeSpecial, l, "<init>", "()V")),
				{Name: l, Super: "org/unopened/Base", Methods: []classfile.Method{pubMethod(l, "<init>", "()V")}},
			},
			want: Undetermined, kind: HazardKindUnloadedDependency, why: "finalize",
		},
		{
			name: "ArrayList subclass without overrides: hashCode calls held elements",
			classes: []classfile.Class{
				mainCalls(edge(classfile.EdgeVirtual, l, "hashCode", "()I")),
				{Name: l, Super: "java/util/ArrayList", Methods: []classfile.Method{emptyFinalize(l)}},
			},
			want: Undetermined, kind: HazardKindReentry, why: "runs on " + l,
		},
		{
			name: "ArrayList subclass declaring nothing: hashCode still calls held elements",
			classes: []classfile.Class{
				mainCalls(edge(classfile.EdgeVirtual, l, "hashCode", "()I")),
				{Name: l, Super: "java/util/ArrayList"},
			},
			want: Undetermined, kind: HazardKindReentry, why: "runs on " + l,
		},
		{
			// F5: the superclass chain is searched before any superinterface, so the
			// platform superclass's body wins over the loaded default.
			name: "platform superclass body beats a loaded interface default",
			classes: []classfile.Class{
				mainCalls(edge(classfile.EdgeVirtual, l, "isEmpty", "()Z")),
				{Name: "com/acme/I", Super: objectClass, Abstract: true, Methods: []classfile.Method{pubMethod("com/acme/I", "isEmpty", "()Z")}},
				{Name: l, Super: "java/util/AbstractList", Interfaces: []string{"com/acme/I"}, Methods: []classfile.Method{emptyFinalize(l), callsSink(l, "size", "()I")}},
			},
			want: Undetermined, kind: HazardKindReentry, why: "runs on " + l,
		},
		{
			name: "construction finalizes through an inherited platform body",
			classes: []classfile.Class{
				mainCalls(edge(classfile.EdgeSpecial, l, "<init>", "()V")),
				{Name: l, Super: "java/util/AbstractList", Methods: []classfile.Method{pubMethod(l, "<init>", "()V"), callsSink(l, "size", "()I")}},
			},
			want: Undetermined, kind: HazardKindReentry, why: "finalize",
		},
	})
}

// TestReach_ReentryAnyReferenceArgument: a platform call taking a reference other than
// a value class can call back application objects the argument is or holds.
func TestReach_ReentryAnyReferenceArgument(t *testing.T) {
	runHoleCases(t, []holeCase{
		{
			name:    "Collections.sort(List) with no app List type",
			classes: []classfile.Class{mainCalls(edge(classfile.EdgeStatic, "java/util/Collections", "sort", "(Ljava/util/List;)V"))},
			want:    Undetermined, kind: HazardKindReentry, why: "reference argument java/util/List",
		},
		{
			name:    "array of references",
			classes: []classfile.Class{mainCalls(edge(classfile.EdgeStatic, "java/util/Arrays", "sort", "([Ljava/lang/Object;)V"))},
			want:    Undetermined, kind: HazardKindReentry, why: "java/lang/Object",
		},
		{
			// The JVM defines java/ classes only from the boot loader, so the JDK's put runs and
			// calls K.hashCode, not the stub's empty body.
			name: "a JAR's own java/util/Hashtable does not stand in for the JDK's",
			classes: []classfile.Class{
				mainCalls(
					edge(classfile.EdgeSpecial, "java/util/Hashtable", "<init>", "()V"),
					edge(classfile.EdgeSpecial, "com/acme/K", "<init>", "()V"),
					edge(classfile.EdgeVirtual, "java/util/Hashtable", "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"),
				),
				{Name: "java/util/Hashtable", Super: "java/util/Dictionary", Public: true, Methods: []classfile.Method{
					pubMethod("java/util/Hashtable", "<init>", "()V"),
					emptyFinalize("java/util/Hashtable"),
					pubMethod("java/util/Hashtable", "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"),
				}},
				{Name: "com/acme/K", Super: objectClass, Public: true, Methods: []classfile.Method{
					pubMethod("com/acme/K", "<init>", "()V"),
					emptyFinalize("com/acme/K"),
					callsSink("com/acme/K", "hashCode", "()I"),
				}},
			},
			want: Undetermined,
		},
		{
			name: "value-class and primitive arguments are leaves",
			classes: []classfile.Class{mainCalls(
				edge(classfile.EdgeStatic, "java/lang/Integer", "parseInt", "(Ljava/lang/String;)I"),
				edge(classfile.EdgeStatic, "java/util/Arrays", "sort", "([I)V"),
				edge(classfile.EdgeStatic, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;"),
			)},
			want: NotExploitable,
		},
	})
}

// TestHasAppSubtype_IndirectHierarchy pins A <- B <- C: only a type with a loaded
// subtype other than itself has a witness.
func TestHasAppSubtype_IndirectHierarchy(t *testing.T) {
	eng := NewEngine([]classfile.Class{
		{Name: "com/acme/A", Super: objectClass, Abstract: true},
		{Name: "com/acme/B", Super: objectClass, Interfaces: []string{"com/acme/A"}},
		{Name: "com/acme/C", Super: "com/acme/B"},
	})
	for typ, want := range map[string]bool{"com/acme/A": true, "com/acme/B": true, "com/acme/C": false, "java/lang/Runnable": false} {
		if got := eng.hasAppSubtype(typ); got != want {
			t.Errorf("hasAppSubtype(%s) = %v, want %v", typ, got, want)
		}
	}
	if why, ok := eng.reentryCallback("(Lcom/acme/A;)V"); !ok || !strings.Contains(why, "app-implemented com/acme/A") {
		t.Errorf("reentryCallback names witness: got %q, %v", why, ok)
	}
}

// TestIsReflection_DynamicResolutionChannels: every channel that runs code named by a
// string, a handle or a byte stream.
func TestIsReflection_DynamicResolutionChannels(t *testing.T) {
	yes := []classfile.MethodRef{
		mref("java/util/ServiceLoader", "loadInstalled", "(Ljava/lang/Class;)Ljava/util/ServiceLoader;"),
		mref("java/util/ServiceLoader", "iterator", "()Ljava/util/Iterator;"),
		mref("java/util/ServiceLoader$Provider", "get", "()Ljava/lang/Object;"),
		mref("java/beans/Beans", "instantiate", "(Ljava/lang/ClassLoader;Ljava/lang/String;)Ljava/lang/Object;"),
		mref("java/beans/XMLDecoder", "readObject", "()Ljava/lang/Object;"),
		mref("javax/management/MBeanServer", "invoke", "()V"),
		mref("javax/script/ScriptEngine", "eval", "(Ljava/lang/String;)Ljava/lang/Object;"),
		mref("java/lang/instrument/Instrumentation", "redefineClasses", "()V"),
		mref("java/lang/invoke/MethodHandle", "invokeExact", "()V"),
		mref("java/lang/invoke/MethodHandles$Lookup", "findVirtual", "()V"),
		mref("sun/misc/Unsafe", "allocateInstance", "(Ljava/lang/Class;)Ljava/lang/Object;"),
		mref("jdk/internal/misc/Unsafe", "allocateInstance", "(Ljava/lang/Class;)Ljava/lang/Object;"),
		mref("sun/reflect/ReflectionFactory", "newConstructorForSerialization", "()V"),
		mref("jdk/internal/reflect/Reflection", "getCallerClass", "()Ljava/lang/Class;"),
		mref("java/security/SecureClassLoader", "defineClass", "()V"),
		mref("java/net/URLClassLoader", "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;"),
		mref("java/lang/ClassLoader", "findClass", "(Ljava/lang/String;)Ljava/lang/Class;"),
		mref("java/lang/ClassLoader", "findSystemClass", "(Ljava/lang/String;)Ljava/lang/Class;"),
		mref("java/io/ObjectInputStream", "readObject", "()Ljava/lang/Object;"),
		mref("java/io/ObjectOutputStream", "writeObject", "(Ljava/lang/Object;)V"),
		mref("java/security/SignedObject", "getObject", "()Ljava/lang/Object;"),
		mref("javax/crypto/SealedObject", "getObject", "(Ljava/security/Key;)Ljava/lang/Object;"),
		mref("java/rmi/Naming", "lookup", "(Ljava/lang/String;)Ljava/rmi/Remote;"),
		mref("javax/naming/InitialContext", "<init>", "()V"),
		mref("java/lang/System", "loadLibrary", "(Ljava/lang/String;)V"),
		mref("java/lang/Runtime", "load", "(Ljava/lang/String;)V"),
		mref("java/lang/System", "setProperty", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"),
		mref("java/lang/System", "setProperties", "(Ljava/util/Properties;)V"),
	}
	for _, r := range yes {
		if !isReflection(r) {
			t.Errorf("isReflection(%s) = false, want true", r)
		}
	}
	no := []classfile.MethodRef{
		mref("java/lang/System", "getProperty", getProperty),
		mref("com/acme/Loader", "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;"),
		mref("java/lang/String", "valueOf", "(I)Ljava/lang/String;"),
		mref("java/security/SignedObject", "getSignature", "()[B"),
	}
	for _, r := range no {
		if isReflection(r) {
			t.Errorf("isReflection(%s) = true, want false", r)
		}
	}
}
