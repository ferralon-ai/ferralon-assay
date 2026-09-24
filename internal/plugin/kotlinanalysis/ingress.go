package kotlinanalysis

import (
	"context"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/jvmingress"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// FindIngresses reports the discoverable program entry points of the compiled build
// output. At Assess tier over bytecode the Kotlin lane discovers two classes of root:
// the program entry `main` (kind "main"), a Kotlin-only family recognized outside the
// shared registry; and the framework ingresses declared by the shared JVM ingress
// registry (internal/plugin/jvmingress) — Spring/JAX-RS HTTP routes ("http_route"),
// container-invoked entrypoints (@Scheduled, @EventListener, @PostConstruct/@PreDestroy,
// Kafka/JMS/Rabbit listeners), and servlets ("servlet"). Every family's vocabulary comes
// from Families(), so this lane and GRANITE's Java lanes cannot diverge on what an ingress
// is; each only keeps its own bytecode match form.
//
// Honest-absent (inv.5): a class/method with no recognized annotation and no servlet
// supertype yields no ingress, and a malformed annotation table fails the class parse
// upstream (declared partiality via loadProgram) — never a silently fabricated or dropped
// root.
func FindIngresses(_ context.Context, req plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	prog, err := loadProgram(req.BuildDir)
	if err != nil {
		return plugin.IngressResult{}, err
	}

	var ingresses []plugin.Ingress
	for _, ref := range mainMethodRefs(prog.classes) {
		ingresses = append(ingresses, plugin.Ingress{
			Kind:   "main",
			Symbol: SymbolFromMethodRef(ref),
		})
	}
	ingresses = append(ingresses, registerFrameworkIngresses(prog)...)

	return plugin.IngressResult{
		Partiality: prog.partiality(),
		Ingresses:  ingresses,
	}, nil
}

// registerFrameworkIngresses detects every registry-declared framework ingress from the
// parsed bytecode and emits them, each carrying the Kind the registry assigns its family.
// It mirrors GRANITE's Java lanes over the same shared vocabulary: a method carrying a
// recognized annotation is an ingress, and a servlet method on an HttpServlet subclass is
// an ingress — matching Java, no class-level stereotype is required. The emitted list is
// sorted by canonical symbol (then Kind) for determinism.
func registerFrameworkIngresses(prog *program) []plugin.Ingress {
	var ingresses []plugin.Ingress
	for _, fi := range frameworkIngresses(prog.classes) {
		ingresses = append(ingresses, plugin.Ingress{
			Kind:     fi.kind,
			Symbol:   SymbolFromMethodRef(fi.ref),
			Selector: fi.selector,
		})
	}
	return ingresses
}

// routeVerb, entrypointKind, servletSuperSuffix and servletMethods are the Kotlin bytecode
// adapter's derived views of the shared JVM ingress registry. The registry declares each
// family's vocabulary once; the init below projects it into the simple-name lookup forms
// the bytecode pass needs. There is NO hand-maintained annotation list in this file — the
// vocabulary is read from jvmingress.Families() alone, so this lane cannot drift from the
// Java lanes.
var (
	// routeVerb maps an http_route annotation's simple name to its HTTP verb ("" for
	// @RequestMapping / all-verbs). Membership (comma-ok) is the is-a-route test — an
	// entry may legitimately hold "".
	routeVerb = map[string]string{}
	// entrypointKind maps a non-route annotation's simple name to its ingress Kind
	// (scheduled, event_listener, lifecycle, message_listener).
	entrypointKind = map[string]string{}
	// servletSuperSuffix is the servlet family's direct-superclass name suffix.
	servletSuperSuffix string
	// servletMethods is the servlet family's entry-method-name set.
	servletMethods = map[string]bool{}
)

func init() {
	for _, f := range jvmingress.Families() {
		switch {
		case f.Match.Annotation != "" && f.Kind == jvmingress.KindHTTPRoute:
			routeVerb[f.Match.Annotation] = f.Verb
		case f.Match.Annotation != "":
			entrypointKind[f.Match.Annotation] = f.Kind
		case f.Match.SuperSuffix != "":
			servletSuperSuffix = f.Match.SuperSuffix
			for _, m := range f.Match.Methods {
				servletMethods[m] = true
			}
		}
	}
}

// frameworkIngress is one detected framework handler: the method to seed reachability
// from, the ingress Kind, and a best-effort "VERB /path" selector (empty for non-route
// kinds).
type frameworkIngress struct {
	ref      classfile.MethodRef
	kind     string
	selector string
}

// frameworkIngresses returns every registry-declared framework ingress across the loaded
// classes, sorted by canonical method reference then Kind for deterministic emission.
// Recognition matches GRANITE's Java lanes: a mapping/entrypoint annotation on a method is
// sufficient on its own — no class-level stereotype gate — and a servlet method on a class
// whose direct superclass name ends in the servlet suffix is an ingress. Over-approximating
// roots this way can only raise reachability, never false-safe (inv.5).
func frameworkIngresses(classes []classfile.Class) []frameworkIngress {
	var out []frameworkIngress
	for _, c := range classes {
		base := classRequestMappingPath(c.Annotations)
		isServlet := servletSuperSuffix != "" && superClassMatchesSuffix(c.Super, servletSuperSuffix)
		for _, m := range c.Methods {
			if verb, path, ok := methodMapping(m.Annotations); ok {
				out = append(out, frameworkIngress{ref: m.Ref, kind: jvmingress.KindHTTPRoute, selector: springSelector(verb, base, path)})
				continue
			}
			if kind, ok := methodEntrypointKind(m.Annotations); ok {
				out = append(out, frameworkIngress{ref: m.Ref, kind: kind})
				continue
			}
			if isServlet && servletMethods[m.Ref.Name] {
				out = append(out, frameworkIngress{ref: m.Ref, kind: jvmingress.KindServlet})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := out[i].ref.String(), out[j].ref.String(); a != b {
			return a < b
		}
		return out[i].kind < out[j].kind
	})
	return out
}

// frameworkIngressRefs is the reachability seam: the method references of every framework
// ingress (routes, container entrypoints, and servlets), so Reachability can root a search
// at any framework ingress just as it does at `main`. Order matches frameworkIngresses
// (sorted) for determinism.
func frameworkIngressRefs(classes []classfile.Class) []classfile.MethodRef {
	fis := frameworkIngresses(classes)
	refs := make([]classfile.MethodRef, len(fis))
	for i, fi := range fis {
		refs[i] = fi.ref
	}
	return refs
}

// superClassMatchesSuffix reports whether a class's direct superclass internal name matches
// the servlet family's suffix, name-only. It mirrors Java's isServletBase: reduce the
// internal name to its last segment, then accept an exact match or any name ending in the
// suffix (a conservative *HttpServlet catch). Direct superclass only — no transitive
// supertype resolution.
func superClassMatchesSuffix(super, suffix string) bool {
	if i := strings.LastIndexByte(super, '/'); i >= 0 {
		super = super[i+1:]
	}
	return super == suffix || strings.HasSuffix(super, suffix)
}

// classRequestMappingPath returns the base route path a class-level @RequestMapping
// declares, or "" if absent — the prefix Spring joins to each method's own path.
func classRequestMappingPath(annos []classfile.Annotation) string {
	for _, a := range annos {
		if annotationSimpleName(a.Type) == "RequestMapping" {
			return annotationPath(a)
		}
	}
	return ""
}

// methodMapping reports whether a method carries an http_route mapping annotation,
// returning the HTTP verb ("" for @RequestMapping, which maps all verbs) and its route
// path. The route vocabulary is the registry's http_route families (routeVerb).
func methodMapping(annos []classfile.Annotation) (verb, path string, ok bool) {
	for _, a := range annos {
		name := annotationSimpleName(a.Type)
		if v, isRoute := routeVerb[name]; isRoute {
			return v, annotationPath(a), true
		}
	}
	return "", "", false
}

// methodEntrypointKind reports the ingress Kind of the first container-invoked entrypoint
// annotation (@Scheduled, @EventListener, @PostConstruct/@PreDestroy, Kafka/JMS/Rabbit) a
// method carries, from the registry's non-route annotation families (entrypointKind).
func methodEntrypointKind(annos []classfile.Annotation) (string, bool) {
	for _, a := range annos {
		if kind, ok := entrypointKind[annotationSimpleName(a.Type)]; ok {
			return kind, true
		}
	}
	return "", false
}

// annotationPath extracts the route path ("value" or "path" element) from a mapping
// annotation, "" if neither is present. Both are the conventional Spring route keys.
func annotationPath(a classfile.Annotation) string {
	for _, e := range a.Elements {
		if e.Name == "value" || e.Name == "path" {
			return e.Value
		}
	}
	return ""
}

// annotationSimpleName reduces a JVM field descriptor
// ("Lorg/springframework/web/bind/annotation/GetMapping;") to its simple annotation name
// ("GetMapping"). This is the identity GRANITE's lexical lane keys on, so matching it keeps
// the lanes in agreement regardless of the annotation's package.
func annotationSimpleName(desc string) string {
	s := strings.TrimSuffix(strings.TrimPrefix(desc, "L"), ";")
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndexByte(s, '$'); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// springSelector renders a best-effort "VERB /base/path" ingress selector, omitting a part
// that is empty. It is advisory display only — reachability keys on the method ref.
func springSelector(verb, base, path string) string {
	route := joinRoute(base, path)
	switch {
	case verb != "" && route != "":
		return verb + " " + route
	case verb != "":
		return verb
	default:
		return route
	}
}

// joinRoute concatenates a class-level base path and a method-level path with a single
// separating slash, tolerating either being empty or carrying its own slash.
func joinRoute(base, path string) string {
	switch {
	case base == "":
		return path
	case path == "":
		return base
	default:
		return strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(path, "/")
	}
}
