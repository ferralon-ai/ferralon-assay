package depreach

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

// jdkClasses holds one real JDK 21 class under each package family the engine treats
// as platform; jarClasses are named under the same families but ship in Maven
// artifacts or in JDK modules a class-path launch does not resolve.
var (
	jdkClasses = []string{
		"java/lang/Character", "jdk/jfr/Event", "jdk/internal/misc/VM", "sun/misc/Signal", "sun/net/www/protocol/http/Handler",
		"javax/accessibility/Accessible", "javax/annotation/processing/Filer", "javax/crypto/Cipher",
		"javax/imageio/ImageIO", "javax/lang/model/SourceVersion", "javax/management/JMX", "javax/naming/Context",
		"javax/net/ssl/SSLEngine", "javax/print/Doc", "javax/rmi/ssl/SslRMIClientSocketFactory",
		"javax/script/Bindings", "javax/security/auth/Subject", "javax/security/cert/Certificate",
		"javax/security/sasl/Sasl", "javax/smartcardio/Card", "javax/sound/midi/Track", "javax/sql/DataSource",
		"javax/swing/JList", "javax/tools/Tool", "javax/transaction/xa/XAResource", "javax/xml/catalog/Catalog",
		"javax/xml/crypto/KeySelector", "javax/xml/datatype/Duration", "javax/xml/namespace/QName",
		"javax/xml/parsers/SAXParser", "javax/xml/stream/Location", "javax/xml/transform/Source",
		"javax/xml/validation/Schema", "javax/xml/xpath/XPath", "javax/xml/XMLConstants",
		"com/sun/crypto/provider/GCM", "com/sun/java/swing/SwingUtilities3", "com/sun/jdi/Value",
		"com/sun/jndi/ldap/Obj", "com/sun/management/GcInfo", "com/sun/net/httpserver/HttpServer",
		"com/sun/nio/sctp/SctpChannel", "com/sun/org/apache/xpath/internal/XPath", "com/sun/security/auth/NTSid",
		"com/sun/source/tree/Tree", "com/sun/tools/javac/Main", "com/sun/tools/attach/VirtualMachine",
		"com/sun/tools/jconsole/JConsoleContext", "org/ietf/jgss/Oid", "org/w3c/dom/Node",
		"org/w3c/dom/events/EventTarget", "org/w3c/dom/css/CSSRule", "org/xml/sax/Locator",
	}
	jarClasses = []string{
		"javax/security/auth/message/config/AuthConfigFactory", "javax/security/auth/message/AuthStatus",
		"com/sun/tools/xjc/Driver", "com/sun/tools/xjc/outline/Outline", "com/sun/tools/ws/WsImport", "com/sun/tools/jxc/SchemaGenerator",
		"org/w3c/dom/svg/SVGDocument", "org/w3c/dom/smil/ElementTimeControl",
		"sun/net/www/protocol/s3/Handler", "sun/jvm/hotspot/HotSpotAgent", "jdk/vm/ci/meta/JavaKind",
		"javax/xml/Other", "javax/swing2/JList",
		"jdk/jfr/snippet-files/X", "javax/tools/snippet-files/X", "jdk/internal/classfile/snippet-files/X",
	}
)

// TestPlatformPackages_AreModulePackageNames: every key is a package name a module can
// define. A javadoc snippet-files directory in src.zip is not one, and '-' is legal in
// a class file's internal name, so a jar class there must not be filed as the JDK's.
func TestPlatformPackages_AreModulePackageNames(t *testing.T) {
	ident := regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
	for p := range platformPackages {
		for _, seg := range strings.Split(p, "/") {
			if !ident.MatchString(seg) {
				t.Errorf("%q: segment %q is not a Java identifier", p, seg)
			}
		}
	}
}

// TestPlatformPackages_Pinned pins the generated list: the sha256 of its sorted keys (one
// per line), its size, packages each boot-layer family must keep, and names that are not packages of a JDK 21 boot-layer module (javadoc
// snippet-files and doclets parent directories in src.zip, and packages removed from the
// JDK) which must stay out.
func TestPlatformPackages_Pinned(t *testing.T) {
	if n := len(platformPackages); n != 647 {
		t.Errorf("len(platformPackages) = %d, want 647", n)
	}
	const want = "f03a7cf0f1181482d9218bfc8686457fcc484c6886a50c91d9c8aa3457d96546"
	sum := sha256.Sum256([]byte(strings.Join(slices.Sorted(maps.Keys(platformPackages)), "\n") + "\n"))
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Errorf("sha256 of the sorted keys = %s, want %s: regenerate from the jmods as the header describes", got, want)
	}
	for _, p := range []string{
		"com/sun/crypto/provider", "javax/net/ssl", "jdk/internal/misc", "sun/misc", "sun/nio/cs",
		"javax/xml/parsers", "org/w3c/dom", "org/xml/sax", "javax/swing", "javax/annotation/processing",
		"javax/transaction/xa", "com/sun/net/httpserver", "com/sun/tools/javac/main", "com/sun/source/tree",
		"com/sun/jdi", "jdk/jfr", "jdk/internal/vm/annotation", "sun/net/www/protocol/http/spnego",
	} {
		if !platformPackages[p] {
			t.Errorf("%s missing", p)
		}
	}
	for _, p := range []string{
		"jdk/internal/classfile/components/snippet-files", "jdk/internal/classfile/snippet-files",
		"javax/tools/snippet-files", "jdk/jfr/consumer/snippet-files", "jdk/jfr/snippet-files",
		"jdk/javadoc/internal/doclets", "jdk/javadoc/internal/doclets/formats",
		"javax/activation", "javax/annotation", "org/omg/CORBA", "jdk/nashorn/api/scripting",
		"javax/xml/bind", "javax/xml/ws", "javax/jws", "javax/transaction", "javax/rmi/CORBA",
	} {
		if platformPackages[p] {
			t.Errorf("%s listed: no JDK 21 boot-layer module defines it", p)
		}
	}
}

// TestReach_PlatformIsExactPackages: a class the predicate files as the JDK's ends a
// call or a static-field lookup at the platform; one in a jar under the same prefix
// is an unopened dependency, whether it is called, inherited, or searched for a
// field. A JDK row may still meet another hazard (javax/naming is a reflection
// channel; an app subclass of a platform class re-enters), never this one.
func TestReach_PlatformIsExactPackages(t *testing.T) {
	const (
		sub  = "com/acme/Sub"
		base = "com/acme/Base"
	)
	x := classfile.Field{Name: "X", Descriptor: "Ljava/lang/Object;"}
	shapes := []struct {
		name    string
		classes func(dep string) []classfile.Class
	}{
		{"static call", func(dep string) []classfile.Class {
			return []classfile.Class{mainCalls(edge(classfile.EdgeStatic, dep, "m", "()V"))}
		}},
		{"virtual call inherited from it", func(dep string) []classfile.Class {
			return []classfile.Class{
				mainCalls(edge(classfile.EdgeSpecial, sub, "<init>", "()V"), edge(classfile.EdgeVirtual, sub, "m", "()V")),
				{Name: sub, Super: dep, Public: true, Methods: []classfile.Method{pubMethod(sub, "<init>", "()V")}},
			}
		}},
		{"superinterface searched for a field before the declaring superclass", func(dep string) []classfile.Class {
			return []classfile.Class{
				{Name: holeMain, Super: objectClass, Public: true, Methods: []classfile.Method{
					{Ref: holeIngress, Static: true, Public: true, StaticFieldRefs: []classfile.FieldRef{{Owner: sub, Name: x.Name, Descriptor: x.Descriptor}}}}},
				{Name: sub, Super: base, Interfaces: []string{dep}, Public: true},
				{Name: base, Super: objectClass, Public: true, Fields: []classfile.Field{x}},
			}
		}},
	}
	for _, s := range shapes {
		for _, dep := range append(append([]string(nil), jdkClasses...), jarClasses...) {
			jdk := slices.Contains(jdkClasses, dep)
			t.Run(s.name+": "+dep, func(t *testing.T) {
				r := NewEngine(append(s.classes(dep), urlFetcherDep())).Reach(holeIngress, holeSink)
				unopened := slices.Contains(r.HazardKinds, HazardKindUnloadedDependency) && strings.Contains(r.HazardWhy, "unopened "+dep)
				switch {
				case r.Verdict == ReachableCandidate:
					t.Fatalf("reachable_candidate via %s", PathString(r.Path))
				case jdk && slices.Contains(r.HazardKinds, HazardKindUnloadedDependency):
					t.Errorf("JDK class filed as a dependency: %q", r.HazardWhy)
				case !jdk && (r.Verdict != Undetermined || !unopened):
					t.Errorf("verdict %s (hazard=%q kinds=%v), want undetermined on unopened %s", r.Verdict, r.HazardWhy, r.HazardKinds, dep)
				}
			})
		}
	}
}

// TestReach_JarClassesUnderJDKPrefixes: Tomcat's jaspic API (javax/security/auth/message)
// and jaxb-xjc (com/sun/tools/xjc) ship classes with static initializers under package
// families the JDK also uses. Initializing one unopened is unseen code, and a provider
// D the JDK could load must not be rooted from it as if it were a JDK body. A loaded
// class extending a jar's exception is a type the JDK can hold, unlike the JDK's own
// exceptions.
func TestReach_JarClassesUnderJDKPrefixes(t *testing.T) {
	const d = "com/acme/D"
	provider := classfile.Class{Name: d, Super: objectClass, Interfaces: []string{"java/sql/Driver"}, Public: true, Methods: []classfile.Method{
		clinitCallingSink(d),
	}}
	initializes := func(owner string, refs []classfile.FieldRef, edges ...classfile.Edge) classfile.Class {
		return classfile.Class{Name: holeMain, Super: objectClass, Public: true, Methods: []classfile.Method{
			{Ref: holeIngress, Static: true, Public: true, InitTriggers: []string{owner}, StaticFieldRefs: refs, Edges: edges}}}
	}
	const jaspic = "javax/security/auth/message/config/AuthConfigFactory"
	const xjc = "com/sun/tools/xjc/Driver"
	const snippet = "jdk/jfr/snippet-files/X"
	extendsException := func(super string) []classfile.Class {
		return []classfile.Class{
			mainCalls(edge(classfile.EdgeStatic, "java/lang/System", "getProperty", "(Ljava/lang/String;)Ljava/lang/String;")),
			{Name: d, Super: super, Public: true, Methods: []classfile.Method{callsSink(d, "start", "()V")}},
		}
	}
	runHoleCases(t, []holeCase{
		{name: "jaspic AuthConfigFactory static field: its <clinit> is unopened", want: Undetermined, kind: HazardKindUnloadedDependency,
			why:     "static initializer of unopened " + jaspic,
			classes: []classfile.Class{initializes(jaspic, []classfile.FieldRef{{Owner: jaspic, Name: "DEFAULT_FACTORY_SECURITY_PROPERTY", Descriptor: "Ljava/lang/String;"}}), provider}},
		{name: "jaxb-xjc Driver static call: its <clinit> and body are unopened", want: Undetermined, kind: HazardKindUnloadedDependency,
			why:     "unopened " + xjc,
			classes: []classfile.Class{initializes(xjc, nil, edge(classfile.EdgeStatic, xjc, "run", "([Ljava/lang/String;)I")), provider}},
		{name: "a class in a javadoc snippet-files directory is a jar's: its <clinit> and body are unopened", want: Undetermined, kind: HazardKindUnloadedDependency,
			why:     "unopened " + snippet,
			classes: []classfile.Class{initializes(snippet, nil, edge(classfile.EdgeStatic, snippet, "run", "()V")), provider}},
		{name: "JDK control: java/lang static initializer roots the JDK-loadable provider", want: ReachableCandidate, via: "D.<clinit>",
			classes: []classfile.Class{initializes("java/lang/Character", []classfile.FieldRef{{Owner: "java/lang/Character", Name: "MAX_RADIX", Descriptor: "I"}}), provider}},
		{name: "JDK control: javax/xml/parsers static call roots the JDK-loadable provider", want: ReachableCandidate, via: "D.<clinit>",
			classes: []classfile.Class{initializes("javax/xml/parsers/SAXParserFactory", nil, edge(classfile.EdgeStatic, "javax/xml/parsers/SAXParserFactory", "newDefaultInstance", "()Ljavax/xml/parsers/SAXParserFactory;")), provider}},
		{name: "a class extending jaxb-xjc's exception is JDK-holdable: its overridable methods are roots", want: ReachableCandidate, via: "D.start",
			classes: extendsException("com/sun/tools/xjc/BadCommandLineException")},
		{name: "JDK control: a class extending a JDK exception is not", want: NotExploitable,
			classes: extendsException("javax/xml/parsers/ParserConfigurationException")},
	})
}

// TestReach_SplitPackages: a package is the JDK's only while no classpath JAR or class
// directory defines a class in it, since the class path then supplies classes the JDK
// image never had (errorprone's javac on JDK 8, a JRE without jdk.compiler, a jlink image).
// A classpath entry that cannot be listed may define anything, so only java/ and arrays
// stay platform; the class loader refuses java/ from the class path.
func TestReach_SplitPackages(t *testing.T) {
	const (
		d       = "com/acme/D"
		option  = "com/sun/tools/javac/main/Option"
		javac   = "com/sun/tools/javac/main"
		parsers = "javax/xml/parsers/SAXParserFactory"
	)
	provider := classfile.Class{Name: d, Super: objectClass, Interfaces: []string{"java/sql/Driver"}, Public: true, Methods: []classfile.Method{
		clinitCallingSink(d),
	}}
	initializes := func(owner, name, desc string) classfile.Class {
		return classfile.Class{Name: holeMain, Super: objectClass, Public: true, Methods: []classfile.Method{
			{Ref: holeIngress, Static: true, Public: true, InitTriggers: []string{owner}, Edges: []classfile.Edge{edge(classfile.EdgeStatic, owner, name, desc)}}}}
	}
	callOption := initializes(option, "lookup", "(Ljava/lang/String;)Lcom/sun/tools/javac/main/Option;")
	callParsers := initializes(parsers, "newDefaultInstance", "()Ljavax/xml/parsers/SAXParserFactory;")
	callCharacter := initializes("java/lang/Character", "isDigit", "(C)Z")
	sibling := classfile.Class{Name: javac + "/Main", Super: objectClass, Public: true}
	unlisted := Classpath{Unlisted: true}
	runHoleCases(t, []holeCase{
		{name: "errorprone javac: a dependency JAR defines com/sun/tools/javac/main, so Option is unopened", want: Undetermined, kind: HazardKindUnloadedDependency,
			why: "unopened " + option, cp: Classpath{Packages: map[string]bool{javac: true}},
			classes: []classfile.Class{callOption, provider}},
		{name: "errorprone javac: a loaded class in com/sun/tools/javac/main defines it, so Option is unopened", want: Undetermined, kind: HazardKindUnloadedDependency,
			why:     "unopened " + option,
			classes: []classfile.Class{callOption, sibling, provider}},
		{name: "control: nothing on the classpath defines com/sun/tools/javac/main, so Option is the JDK's", want: ReachableCandidate, via: "D.<clinit>",
			cp:      Classpath{Packages: map[string]bool{"com/acme/other": true}},
			classes: []classfile.Class{callOption, provider}},
		{name: "an unlisted classpath entry may define javax/xml/parsers: unopened", want: Undetermined, kind: HazardKindUnloadedDependency,
			why: "unopened " + parsers, cp: unlisted,
			classes: []classfile.Class{callParsers, provider}},
		{name: "control: javax/xml/parsers is the JDK's while every entry is listed", want: ReachableCandidate, via: "D.<clinit>",
			cp:      Classpath{Packages: map[string]bool{"com/acme/other": true}},
			classes: []classfile.Class{callParsers, provider}},
		{name: "an unlisted classpath entry leaves java/ the JDK's", want: ReachableCandidate, via: "D.<clinit>",
			cp:      unlisted,
			classes: []classfile.Class{callCharacter, provider}},
		{name: "a classpath entry defining java/lang leaves java/ the JDK's", want: ReachableCandidate, via: "D.<clinit>",
			cp:      Classpath{Packages: map[string]bool{"java/lang": true}},
			classes: []classfile.Class{callCharacter, provider}},
	})
}

// TestEngine_Platform: the predicate each call site asks, under each classpath shape.
func TestEngine_Platform(t *testing.T) {
	loaded := []classfile.Class{{Name: "com/sun/tools/javac/main/Main", Super: objectClass}}
	for _, tc := range []struct {
		cp    Classpath
		class string
		want  bool
	}{
		{Classpath{}, "javax/xml/parsers/SAXParserFactory", true},
		{Classpath{}, "com/sun/tools/javac/main/Option", false},
		{Classpath{}, "com/sun/tools/javac/api/JavacTool", true},
		{Classpath{Packages: map[string]bool{"javax/xml/parsers": true}}, "javax/xml/parsers/SAXParserFactory", false},
		{Classpath{Packages: map[string]bool{"java/lang": true}}, "java/lang/Character", true},
		{Classpath{Unlisted: true}, "javax/xml/parsers/SAXParserFactory", false},
		{Classpath{Unlisted: true}, "java/lang/Character", true},
		{Classpath{Unlisted: true}, "[Lcom/acme/Thing;", true},
		{Classpath{Unlisted: true}, "[I", true},
	} {
		if got := NewEngineOn(loaded, tc.cp).platform(tc.class); got != tc.want {
			t.Errorf("platform(%s) under %+v = %v, want %v", tc.class, tc.cp, got, tc.want)
		}
	}
}

// TestClasspath_AddAndMerge: an entry that could not be listed marks the classpath
// unlisted, and merging keeps both sides' packages and that mark, and a JDK both sides
// agree on or only one records.
func TestClasspath_AddAndMerge(t *testing.T) {
	var a, b Classpath
	a.Add(map[string]bool{"com/a": true}, true)
	b.Add(map[string]bool{"com/b": true}, true)
	b.Add(map[string]bool{"com/c": true}, false)
	if a.Unlisted || !b.Unlisted || b.Packages["com/c"] {
		t.Fatalf("Add: a=%+v b=%+v", a, b)
	}
	a.Merge(b)
	if !a.Unlisted || !a.Packages["com/a"] || !a.Packages["com/b"] {
		t.Fatalf("Merge: %+v", a)
	}

	for _, tc := range []struct{ a, b, want int }{
		{a: 0, b: 21, want: 21},
		{a: 21, b: 0, want: 21},
		{a: 21, b: 21, want: 21},
		{a: 17, b: 21, want: 0},
	} {
		c := Classpath{JDK: tc.a}
		c.Merge(Classpath{JDK: tc.b})
		if c.JDK != tc.want {
			t.Errorf("Merge JDK %d with %d = %d, want %d", tc.a, tc.b, c.JDK, tc.want)
		}
	}
}
