package depreach

import (
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
		"jdk/jfr/Event", "jdk/internal/misc/VM", "sun/misc/Signal", "sun/net/www/protocol/http/Handler",
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
		"com/sun/tools/xjc/outline/Outline", "com/sun/tools/ws/WsImport", "com/sun/tools/jxc/SchemaGenerator",
		"org/w3c/dom/svg/SVGDocument", "org/w3c/dom/smil/ElementTimeControl",
		"sun/net/www/protocol/s3/Handler", "sun/jvm/hotspot/HotSpotAgent", "jdk/vm/ci/meta/JavaKind",
		"javax/xml/Other", "javax/swing2/JList",
	}
)

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
