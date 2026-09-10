package depreach

import (
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

func mref(owner, name, desc string) classfile.MethodRef {
	return classfile.MethodRef{Owner: owner, Name: name, Descriptor: desc}
}

func edge(kind classfile.EdgeKind, owner, name, desc string) classfile.Edge {
	return classfile.Edge{To: mref(owner, name, desc), Kind: kind}
}

// The C7 scenario shape, as in-memory classes the engine consumes exactly as it
// consumes parsed JAR bytecode (no JRE to compile a fixture). Interface dispatch
// (the hop a lexical pass cannot make), a same-arity overload decoy for descriptor
// resolution, and a reflection ingress — enough to exercise all three verdicts.
const (
	sinkDesc  = "(Ljava/lang/String;)Ljava/lang/String;"
	decoyDesc = "(I)I"
)

func c7Classes() []classfile.Class {
	app := classfile.Class{Name: "com/acme/app/App", Super: "java/lang/Object", Methods: []classfile.Method{
		{Ref: mref("com/acme/app/App", "reachable", "()V"), Edges: []classfile.Edge{
			edge(classfile.EdgeSpecial, "com/evil/netkit/ServiceImpl", "<init>", "()V"),
			edge(classfile.EdgeInterface, "com/evil/netkit/Service", "run", "()V"),
		}},
		{Ref: mref("com/acme/app/App", "unreachable", "()V"), Edges: []classfile.Edge{
			edge(classfile.EdgeSpecial, "com/evil/netkit/UrlFetcher", "<init>", "()V"),
			edge(classfile.EdgeVirtual, "com/evil/netkit/UrlFetcher", "fetch", decoyDesc), // int overload, NOT the sink
		}},
		{Ref: mref("com/acme/app/App", "dynamic", "()V"), Edges: []classfile.Edge{
			edge(classfile.EdgeStatic, "java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;"),
		}},
	}}
	svc := classfile.Class{Name: "com/evil/netkit/Service", Super: "java/lang/Object", Methods: []classfile.Method{
		{Ref: mref("com/evil/netkit/Service", "run", "()V"), Abstract: true},
	}}
	impl := classfile.Class{Name: "com/evil/netkit/ServiceImpl", Super: "java/lang/Object", Interfaces: []string{"com/evil/netkit/Service"}, Methods: []classfile.Method{
		{Ref: mref("com/evil/netkit/ServiceImpl", "<init>", "()V")},
		{Ref: mref("com/evil/netkit/ServiceImpl", "run", "()V"), Edges: []classfile.Edge{
			edge(classfile.EdgeSpecial, "com/evil/netkit/UrlFetcher", "<init>", "()V"),
			edge(classfile.EdgeVirtual, "com/evil/netkit/UrlFetcher", "fetch", sinkDesc),
		}},
	}}
	dep := classfile.Class{Name: "com/evil/netkit/UrlFetcher", Super: "java/lang/Object", Methods: []classfile.Method{
		{Ref: mref("com/evil/netkit/UrlFetcher", "<init>", "()V")},
		{Ref: mref("com/evil/netkit/UrlFetcher", "fetch", sinkDesc)},  // String SSRF sink
		{Ref: mref("com/evil/netkit/UrlFetcher", "fetch", decoyDesc)}, // same-arity int overload
	}}
	return []classfile.Class{app, svc, impl, dep}
}

func TestReach_C7ThreeVerdicts(t *testing.T) {
	eng := NewEngine(c7Classes())
	sink := mref("com/evil/netkit/UrlFetcher", "fetch", sinkDesc)

	cases := []struct {
		name    string
		ingress classfile.MethodRef
		want    Verdict
	}{
		{"reachable via interface hop -> impl -> sink", mref("com/acme/app/App", "reachable", "()V"), ReachableCandidate},
		{"unreachable: fetch(int) decoy, sink never called", mref("com/acme/app/App", "unreachable", "()V"), NotExploitable},
		{"dynamic: Class.forName reflection on frontier", mref("com/acme/app/App", "dynamic", "()V"), Undetermined},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := eng.Reach(tc.ingress, sink)
			if r.Verdict != tc.want {
				t.Fatalf("verdict = %s, want %s (hazard=%q, path=%s)", r.Verdict, tc.want, r.HazardWhy, PathString(r.Path))
			}
			if !r.SinkPresent {
				t.Errorf("trace 1 should find the sink present by descriptor")
			}
			if tc.want == ReachableCandidate {
				last := r.Path[len(r.Path)-1]
				if last != sink {
					t.Errorf("path does not end at sink: %s", PathString(r.Path))
				}
			}
		})
	}
}

// The three verdicts must be pairwise distinguishable (C7's core requirement): a
// positives-only suite cannot tell not_exploitable from undetermined.
func TestReach_C7VerdictsPairwiseDistinct(t *testing.T) {
	eng := NewEngine(c7Classes())
	sink := mref("com/evil/netkit/UrlFetcher", "fetch", sinkDesc)
	got := map[Verdict]bool{
		eng.Reach(mref("com/acme/app/App", "reachable", "()V"), sink).Verdict:   true,
		eng.Reach(mref("com/acme/app/App", "unreachable", "()V"), sink).Verdict: true,
		eng.Reach(mref("com/acme/app/App", "dynamic", "()V"), sink).Verdict:     true,
	}
	if len(got) != 3 {
		t.Fatalf("verdicts not pairwise distinct: %v", got)
	}
}

// Mutation control (C7.2): the dynamic case's undetermined must come from the
// hazard, not luck. Replace the reflection edge with a benign out-of-classpath leaf
// (no callback param) and the verdict must flip to not_exploitable — proving the
// fixture is sensitive to exactly the honesty property it guards.
func TestReach_MutationControl_HazardRemovalFlipsToNotExploitable(t *testing.T) {
	classes := c7Classes()
	for i := range classes {
		if classes[i].Name != "com/acme/app/App" {
			continue
		}
		for j := range classes[i].Methods {
			if classes[i].Methods[j].Ref.Name == "dynamic" {
				// java/io/PrintStream.println(String): out-of-classpath leaf, no app callback.
				classes[i].Methods[j].Edges = []classfile.Edge{
					edge(classfile.EdgeVirtual, "com/acme/app/App", "noop", "()V"),
				}
			}
		}
		classes[i].Methods = append(classes[i].Methods, classfile.Method{Ref: mref("com/acme/app/App", "noop", "()V")})
	}
	eng := NewEngine(classes)
	sink := mref("com/evil/netkit/UrlFetcher", "fetch", sinkDesc)
	if v := eng.Reach(mref("com/acme/app/App", "dynamic", "()V"), sink).Verdict; v != NotExploitable {
		t.Fatalf("with the hazard removed, want not_exploitable, got %s", v)
	}
}

// TestReach_ReentryCallbackForcesUndetermined closes the C8 named-class re-entry
// hole: a concrete app class implements Comparator and its compare() reaches the
// sink, but the only route is Collections.sort(List,Comparator) — an
// out-of-classpath higher-order call the graph cannot traverse. There is no
// traversable edge to compare(), so a naive leaf model would answer not_exploitable.
// The re-entry hazard rule must instead force undetermined.
func TestReach_ReentryCallbackForcesUndetermined(t *testing.T) {
	sink := mref("com/evil/netkit/UrlFetcher", "fetch", sinkDesc)
	cmp := classfile.Class{Name: "com/acme/app/EvilCmp", Super: "java/lang/Object", Interfaces: []string{"java/util/Comparator"}, Methods: []classfile.Method{
		{Ref: mref("com/acme/app/EvilCmp", "compare", "(Ljava/lang/Object;Ljava/lang/Object;)I"), Edges: []classfile.Edge{
			edge(classfile.EdgeSpecial, "com/evil/netkit/UrlFetcher", "<init>", "()V"),
			edge(classfile.EdgeVirtual, "com/evil/netkit/UrlFetcher", "fetch", sinkDesc),
		}},
	}}
	dep := classfile.Class{Name: "com/evil/netkit/UrlFetcher", Super: "java/lang/Object", Methods: []classfile.Method{
		{Ref: mref("com/evil/netkit/UrlFetcher", "<init>", "()V")},
		{Ref: mref("com/evil/netkit/UrlFetcher", "fetch", sinkDesc)},
	}}
	app := classfile.Class{Name: "com/acme/app/App", Super: "java/lang/Object", Methods: []classfile.Method{
		{Ref: mref("com/acme/app/App", "viaSort", "()V"), Edges: []classfile.Edge{
			edge(classfile.EdgeSpecial, "com/acme/app/EvilCmp", "<init>", "()V"),
			// Out-of-classpath higher-order call taking the app Comparator.
			edge(classfile.EdgeStatic, "java/util/Collections", "sort", "(Ljava/util/List;Ljava/util/Comparator;)V"),
		}},
		// Control: an out-of-classpath call whose only ref param is a final JDK type
		// no app class implements — must NOT be flagged, so absence stays provable.
		{Ref: mref("com/acme/app/App", "viaBenign", "()V"), Edges: []classfile.Edge{
			edge(classfile.EdgeStatic, "java/lang/System", "getProperty", "(Ljava/lang/String;)Ljava/lang/String;"),
		}},
	}}
	eng := NewEngine([]classfile.Class{app, cmp, dep})

	if v := eng.Reach(mref("com/acme/app/App", "viaSort", "()V"), sink).Verdict; v != Undetermined {
		t.Errorf("named-class re-entry via Collections.sort must be undetermined, got %s", v)
	}
	if v := eng.Reach(mref("com/acme/app/App", "viaBenign", "()V"), sink).Verdict; v != NotExploitable {
		t.Errorf("benign String-param JDK call must not be over-flagged; want not_exploitable, got %s", v)
	}
}

// urlFetcherDep returns the dependency class holding the String SSRF sink, shared by
// the regression fixtures below.
func urlFetcherDep() classfile.Class {
	return classfile.Class{Name: "com/evil/netkit/UrlFetcher", Super: "java/lang/Object", Methods: []classfile.Method{
		{Ref: mref("com/evil/netkit/UrlFetcher", "<init>", "()V")},
		{Ref: mref("com/evil/netkit/UrlFetcher", "fetch", sinkDesc)},
	}}
}

// C8 HOLE-A regression (independent review, 2026-08-10): a sink reachable ONLY
// through a class's static initializer must not read as not_exploitable. <clinit> is
// never an explicit invoke target; the engine reaches it via the triggering method's
// InitTriggers (here App.trigger's `new Holder`).
func TestReach_StaticInitializerReachesSink_HoleA(t *testing.T) {
	sink := mref("com/evil/netkit/UrlFetcher", "fetch", sinkDesc)
	app := classfile.Class{Name: "com/acme/App", Super: "java/lang/Object", Methods: []classfile.Method{
		{Ref: mref("com/acme/App", "trigger", "()V"),
			InitTriggers: []string{"com/acme/Holder"}, // `new Holder` / static use
			Edges:        []classfile.Edge{edge(classfile.EdgeSpecial, "com/acme/Holder", "<init>", "()V")}},
	}}
	holder := classfile.Class{Name: "com/acme/Holder", Super: "java/lang/Object", Methods: []classfile.Method{
		{Ref: mref("com/acme/Holder", "<init>", "()V")}, // empty: the sink is NOT here
		{Ref: mref("com/acme/Holder", "<clinit>", "()V"), Edges: []classfile.Edge{
			edge(classfile.EdgeVirtual, "com/evil/netkit/UrlFetcher", "fetch", sinkDesc),
		}},
	}}
	eng := NewEngine([]classfile.Class{app, holder, urlFetcherDep()})
	if v := eng.Reach(mref("com/acme/App", "trigger", "()V"), sink).Verdict; v != ReachableCandidate {
		t.Errorf("sink reachable only via <clinit> must be reachable_candidate, got %s", v)
	}
}

// C8 HOLE-A2 regression (re-review, 2026-08-10): JVMS §5.5 initializes the
// SUPERCLASS before the class itself, so a base class's <clinit> reaching the sink
// is a real runtime path even when the instantiated subclass has no <clinit>. The
// engine must walk the triggered class's full init closure (super chain), not just
// the directly-triggered class.
func TestReach_SuperclassStaticInitializerReachesSink_HoleA2(t *testing.T) {
	sink := mref("com/evil/netkit/UrlFetcher", "fetch", sinkDesc)
	app := classfile.Class{Name: "com/acme/App", Super: "java/lang/Object", Methods: []classfile.Method{
		{Ref: mref("com/acme/App", "trigger", "()V"),
			InitTriggers: []string{"com/acme/Sub"}, // `new Sub`
			Edges:        []classfile.Edge{edge(classfile.EdgeSpecial, "com/acme/Sub", "<init>", "()V")}},
	}}
	// Sub has NO <clinit>; its superclass Base does, and Base.<clinit> reaches the sink.
	sub := classfile.Class{Name: "com/acme/Sub", Super: "com/acme/Base", Methods: []classfile.Method{
		{Ref: mref("com/acme/Sub", "<init>", "()V")},
	}}
	base := classfile.Class{Name: "com/acme/Base", Super: "java/lang/Object", Methods: []classfile.Method{
		{Ref: mref("com/acme/Base", "<clinit>", "()V"), Edges: []classfile.Edge{
			edge(classfile.EdgeVirtual, "com/evil/netkit/UrlFetcher", "fetch", sinkDesc),
		}},
	}}
	eng := NewEngine([]classfile.Class{app, sub, base, urlFetcherDep()})
	if v := eng.Reach(mref("com/acme/App", "trigger", "()V"), sink).Verdict; v != ReachableCandidate {
		t.Errorf("sink reachable via a SUPERCLASS <clinit> must be reachable_candidate, got %s", v)
	}
}

// An init trigger whose closure has no sink-reaching <clinit> must stay
// not_exploitable — the init-closure walk must not over-connect.
func TestReach_InitTriggerWithoutSinkStaysNotExploitable(t *testing.T) {
	sink := mref("com/evil/netkit/UrlFetcher", "fetch", sinkDesc)
	app := classfile.Class{Name: "com/acme/App", Super: "java/lang/Object", Methods: []classfile.Method{
		{Ref: mref("com/acme/App", "trigger", "()V"),
			InitTriggers: []string{"com/acme/Plain"},
			Edges:        []classfile.Edge{edge(classfile.EdgeSpecial, "com/acme/Plain", "<init>", "()V")}},
	}}
	plain := classfile.Class{Name: "com/acme/Plain", Super: "java/lang/Object", Methods: []classfile.Method{
		{Ref: mref("com/acme/Plain", "<init>", "()V")},
		{Ref: mref("com/acme/Plain", "<clinit>", "()V")}, // empty: reaches nothing
	}}
	eng := NewEngine([]classfile.Class{app, plain, urlFetcherDep()})
	if v := eng.Reach(mref("com/acme/App", "trigger", "()V"), sink).Verdict; v != NotExploitable {
		t.Errorf("an init trigger with no sink-reaching <clinit> must stay not_exploitable, got %s", v)
	}
}

// C8 HOLE-B regression: a higher-order method inherited from an out-of-classpath
// super (MyList extends ArrayList; forEach(Consumer)) resolves to zero in-classpath
// targets — the real body is out of classpath and re-enters the app Consumer. The
// virtual/interface branch must apply the same re-entry check as static/special and
// force undetermined, never a false not_exploitable.
func TestReach_InheritedHigherOrderReentry_HoleB(t *testing.T) {
	sink := mref("com/evil/netkit/UrlFetcher", "fetch", sinkDesc)
	myList := classfile.Class{Name: "com/acme/MyList", Super: "java/util/ArrayList"} // super out of classpath; forEach inherited
	evil := classfile.Class{Name: "com/acme/EvilConsumer", Super: "java/lang/Object", Interfaces: []string{"java/util/function/Consumer"}, Methods: []classfile.Method{
		{Ref: mref("com/acme/EvilConsumer", "accept", "(Ljava/lang/Object;)V"), Edges: []classfile.Edge{
			edge(classfile.EdgeVirtual, "com/evil/netkit/UrlFetcher", "fetch", sinkDesc),
		}},
	}}
	app := classfile.Class{Name: "com/acme/App", Super: "java/lang/Object", Methods: []classfile.Method{
		{Ref: mref("com/acme/App", "trigger", "()V"), Edges: []classfile.Edge{
			edge(classfile.EdgeSpecial, "com/acme/EvilConsumer", "<init>", "()V"),
			edge(classfile.EdgeSpecial, "com/acme/MyList", "<init>", "()V"),
			edge(classfile.EdgeVirtual, "com/acme/MyList", "forEach", "(Ljava/util/function/Consumer;)V"),
		}},
	}}
	eng := NewEngine([]classfile.Class{app, myList, evil, urlFetcherDep()})
	r := eng.Reach(mref("com/acme/App", "trigger", "()V"), sink)
	if r.Verdict != Undetermined {
		t.Errorf("inherited HOF taking an app callback must be undetermined, got %s (hazard=%q)", r.Verdict, r.HazardWhy)
	}
}

// The expanded dynamic-resolution channels (C8 residual 2) each force undetermined:
// ClassLoader.loadClass, ServiceLoader.load, Proxy.newProxyInstance, JNDI lookup.
func TestReach_ExpandedDynamicResolutionChannels(t *testing.T) {
	sink := mref("com/evil/netkit/UrlFetcher", "fetch", sinkDesc)
	channels := []struct {
		name string
		e    classfile.Edge
	}{
		{"ClassLoader.loadClass", edge(classfile.EdgeVirtual, "java/lang/ClassLoader", "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;")},
		{"ServiceLoader.load", edge(classfile.EdgeStatic, "java/util/ServiceLoader", "load", "(Ljava/lang/Class;)Ljava/util/ServiceLoader;")},
		{"Proxy.newProxyInstance", edge(classfile.EdgeStatic, "java/lang/reflect/Proxy", "newProxyInstance", "(Ljava/lang/ClassLoader;[Ljava/lang/Class;Ljava/lang/reflect/InvocationHandler;)Ljava/lang/Object;")},
		{"JNDI Context.lookup", edge(classfile.EdgeInterface, "javax/naming/Context", "lookup", "(Ljava/lang/String;)Ljava/lang/Object;")},
	}
	for _, ch := range channels {
		app := classfile.Class{Name: "com/acme/App", Super: "java/lang/Object", Methods: []classfile.Method{
			{Ref: mref("com/acme/App", "trigger", "()V"), Edges: []classfile.Edge{ch.e}},
		}}
		eng := NewEngine([]classfile.Class{app, urlFetcherDep()})
		if v := eng.Reach(mref("com/acme/App", "trigger", "()V"), sink).Verdict; v != Undetermined {
			t.Errorf("%s on the frontier must be undetermined, got %s", ch.name, v)
		}
	}
}

func TestReach_UnknownIngressIsUndetermined(t *testing.T) {
	eng := NewEngine(c7Classes())
	sink := mref("com/evil/netkit/UrlFetcher", "fetch", sinkDesc)
	if v := eng.Reach(mref("com/acme/app/Ghost", "nope", "()V"), sink).Verdict; v != Undetermined {
		t.Errorf("an ingress not in classpath must be undetermined (search never ran), got %s", v)
	}
}

func TestParseParamRefTypes(t *testing.T) {
	cases := []struct {
		desc string
		want []string
	}{
		{"(Ljava/lang/String;I)V", []string{"java/lang/String"}},
		{"(Ljava/util/List;Ljava/util/Comparator;)V", []string{"java/util/List", "java/util/Comparator"}},
		{"([Ljava/util/Comparator;I)V", []string{"java/util/Comparator"}},
		{"(IJDZ)Ljava/lang/Object;", nil},
		{"()V", nil},
		{"(Lfoo/Bar;", []string{"foo/Bar"}}, // ';' completes the type even with no ')'
		{"(Lfoo/Bar", nil},                  // malformed: unterminated -> no complete ref
	}
	for _, tc := range cases {
		if got := parseParamRefTypes(tc.desc); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("parseParamRefTypes(%q) = %v, want %v", tc.desc, got, tc.want)
		}
	}
}
