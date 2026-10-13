package depreach

import (
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
