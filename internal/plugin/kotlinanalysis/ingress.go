package kotlinanalysis

import (
	"context"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// FindIngresses reports the discoverable program entry points of the compiled build
// output. At Assess tier over bytecode, two ingress families are soundly discoverable:
// the program entry `main` (kind "main"), and Spring web handlers detected from the
// class/method RuntimeVisibleAnnotations the shared classfile parser now decodes
// (kind "http_route").
//
// Spring detection reads the SAME annotation names GRANITE's source-lexical Java lane
// (calls.go) recognizes, so the bytecode and source lanes agree on what a Spring ingress
// is. Honest-absent: a class with no recognized Spring stereotype yields no ingress, and a
// malformed annotation table fails the class parse upstream (declared partiality via
// loadProgram), never a silently fabricated or dropped root.
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

// registerFrameworkIngresses detects Spring web handlers from the parsed annotations and
// emits them as http_route ingresses. It mirrors GRANITE's Java lane: a method carrying a
// Spring mapping annotation, on a class carrying a Spring controller stereotype, is a
// framework ingress. The emitted list is sorted by canonical symbol for determinism.
func registerFrameworkIngresses(prog *program) []plugin.Ingress {
	var ingresses []plugin.Ingress
	for _, si := range springIngresses(prog.classes) {
		ingresses = append(ingresses, plugin.Ingress{
			Kind:     "http_route",
			Symbol:   SymbolFromMethodRef(si.ref),
			Selector: si.selector,
		})
	}
	return ingresses
}

// springControllerAnnotations are the class-level stereotypes that mark a type as a
// Spring web controller. A mapping annotation only produces an HTTP handler when its
// enclosing class carries one of these — matching Spring's own component model and
// suppressing false positives from an unrelated @GetMapping.
var springControllerAnnotations = map[string]bool{
	"RestController": true,
	"Controller":     true,
}

// springMappingAnnotations are the method-level route annotations GRANITE's calls.go
// recognizes (the Spring MVC subset). A method carrying one, inside a controller, is an
// ingress root. Recognized by simple NAME, exactly as the source-lexical lane does, so the
// two lanes cannot diverge on the annotation vocabulary.
var springMappingAnnotations = map[string]bool{
	"RequestMapping": true,
	"GetMapping":     true,
	"PostMapping":    true,
	"PutMapping":     true,
	"DeleteMapping":  true,
	"PatchMapping":   true,
}

// springMappingVerb maps a mapping annotation to its HTTP verb. @RequestMapping carries no
// single verb (it maps all methods), so it is absent — the selector then omits the verb.
var springMappingVerb = map[string]string{
	"GetMapping":    "GET",
	"PostMapping":   "POST",
	"PutMapping":    "PUT",
	"DeleteMapping": "DELETE",
	"PatchMapping":  "PATCH",
}

// springIngress is one detected Spring handler: the method to seed reachability from, and
// a best-effort "VERB /path" selector for the emitted Ingress.
type springIngress struct {
	ref      classfile.MethodRef
	selector string
}

// springIngresses returns every Spring HTTP handler across the loaded classes, sorted by
// canonical method reference for deterministic emission. A class with no controller
// stereotype contributes nothing (honest-absent).
func springIngresses(classes []classfile.Class) []springIngress {
	var out []springIngress
	for _, c := range classes {
		if !hasSpringAnnotation(c.Annotations, springControllerAnnotations) {
			continue
		}
		base := classRequestMappingPath(c.Annotations)
		for _, m := range c.Methods {
			verb, path, ok := methodMapping(m.Annotations)
			if !ok {
				continue
			}
			out = append(out, springIngress{ref: m.Ref, selector: springSelector(verb, base, path)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ref.String() < out[j].ref.String() })
	return out
}

// springIngressRefs is the reachability seam: the method references of every Spring
// handler, so Reachability can root a search at a framework ingress just as it does at
// `main`. Order matches springIngresses (sorted) for determinism.
func springIngressRefs(classes []classfile.Class) []classfile.MethodRef {
	sis := springIngresses(classes)
	refs := make([]classfile.MethodRef, len(sis))
	for i, si := range sis {
		refs[i] = si.ref
	}
	return refs
}

// hasSpringAnnotation reports whether any annotation's simple name is in set.
func hasSpringAnnotation(annos []classfile.Annotation, set map[string]bool) bool {
	for _, a := range annos {
		if set[annotationSimpleName(a.Type)] {
			return true
		}
	}
	return false
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

// methodMapping reports whether a method carries a Spring mapping annotation, returning
// the HTTP verb ("" for @RequestMapping, which maps all verbs) and its route path.
func methodMapping(annos []classfile.Annotation) (verb, path string, ok bool) {
	for _, a := range annos {
		name := annotationSimpleName(a.Type)
		if !springMappingAnnotations[name] {
			continue
		}
		return springMappingVerb[name], annotationPath(a), true
	}
	return "", "", false
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
