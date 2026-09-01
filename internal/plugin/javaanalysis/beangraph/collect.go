package beangraph

import (
	"sort"
	"strings"
	"unicode"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

// stereotypeAnnotations are the class-level annotations whose presence registers a
// class as a bean the container instantiates directly. Matched by SIMPLE name (the
// last segment of the annotation's type descriptor), namespace-agnostic like the rest
// of the JVM lane — a @Service is a bean whether it is Spring's or a meta-annotation
// of the same simple name. @Configuration classes are beans too (and additionally the
// source of @Bean factory methods, handled in beansFromClasses).
var stereotypeAnnotations = map[string]bool{
	"Component":      true,
	"Service":        true,
	"Repository":     true,
	"Controller":     true,
	"RestController": true,
	"Configuration":  true,
	"Named":          true, // javax/jakarta.inject.Named — the JSR-330 stereotype
	"ManagedBean":    true,
}

// injectAnnotations mark a field or constructor as a bean injection point. @Value is
// deliberately excluded: it injects a property/expression, not a bean, so it never
// participates in interface→impl resolution.
var injectAnnotations = map[string]bool{
	"Autowired": true,
	"Inject":    true,
	"Resource":  true,
}

// beansFromClasses collects the bean definitions from a set of parsed classes — every
// stereotype-annotated class and every @Bean factory method — keyed on INTERNAL type
// names. It is the lane-agnostic collector reused by the Kotlin first-party lane (#K
// overlay) and by every dependency jar. Satisfies for each bean is the supertype
// closure computed over the given class set (self + transitive supers/interfaces),
// so an injection point of an interface type resolves to the classes implementing it.
// The result is sorted by Impl for determinism.
func BeansFromClasses(classes []classfile.Class) []BeanDef {
	byName := make(map[string]*classfile.Class, len(classes))
	for i := range classes {
		byName[classes[i].Name] = &classes[i]
	}

	var beans []BeanDef
	for i := range classes {
		c := &classes[i]
		if classHasStereotype(c) {
			beans = append(beans, BeanDef{
				Impl:       c.Name,
				Origin:     OriginStereotype,
				Satisfies:  supertypeClosure(c.Name, byName),
				Qualifiers: stereotypeQualifiers(c),
				Primary:    hasAnnotation(c.Annotations, "Primary"),
				Profiles:   annotationStrings(c.Annotations, "Profile"),
			})
		}
		// @Bean factory methods (typically on @Configuration classes; we do not require
		// it — a @Bean method anywhere registers its return type).
		for j := range c.Methods {
			m := &c.Methods[j]
			if !hasAnnotation(m.Annotations, "Bean") {
				continue
			}
			ret := returnRefType(m.Ref.Descriptor)
			if ret == "" {
				continue // a primitive/void @Bean return is not an injectable bean type
			}
			quals := beanMethodQualifiers(m)
			beans = append(beans, BeanDef{
				Impl:       ret,
				Origin:     OriginBeanMethod,
				Satisfies:  supertypeClosure(ret, byName),
				Qualifiers: quals,
				Primary:    hasAnnotation(m.Annotations, "Primary"),
				Profiles:   annotationStrings(m.Annotations, "Profile"),
			})
		}
	}
	sort.Slice(beans, func(i, j int) bool {
		if beans[i].Impl != beans[j].Impl {
			return beans[i].Impl < beans[j].Impl
		}
		return beans[i].Origin < beans[j].Origin
	})
	return beans
}

// injectionPointsFromClasses collects the field and constructor injection points from
// a set of parsed classes, keyed on INTERNAL type names. Field injection: any field
// carrying @Autowired/@Inject/@Resource, with its declared type from the field
// descriptor. Constructor injection: the parameters of a constructor that is either
// explicitly @Autowired or the class's sole constructor (Spring 4.3+ implicit single-
// constructor autowiring), each parameter's type read from the descriptor and its
// @Qualifier from the per-parameter annotations. The result is sorted for determinism.
func InjectionPointsFromClasses(classes []classfile.Class) []InjectionPoint {
	var ips []InjectionPoint
	for i := range classes {
		c := &classes[i]
		for _, f := range c.Fields {
			if !annotationsAny(f.Annotations, injectAnnotations) {
				continue
			}
			t := classfileRefType(f.Descriptor)
			if t == "" {
				continue
			}
			ips = append(ips, InjectionPoint{
				Owner:        c.Name,
				Site:         "field",
				DeclaredType: t,
				Qualifier:    firstAnnotationString(f.Annotations, "Qualifier"),
			})
		}
		ips = append(ips, ctorInjectionPoints(c)...)
	}
	sortInjectionPoints(ips)
	return ips
}

// ctorInjectionPoints returns the constructor-parameter injection points of a class:
// the parameters of an @Autowired constructor, or of the sole constructor when the
// class has exactly one (implicit single-constructor autowiring). A no-arg constructor
// contributes nothing.
func ctorInjectionPoints(c *classfile.Class) []InjectionPoint {
	var ctors []*classfile.Method
	for j := range c.Methods {
		if c.Methods[j].Ref.Name == "<init>" {
			ctors = append(ctors, &c.Methods[j])
		}
	}
	var chosen []*classfile.Method
	for _, ct := range ctors {
		if hasAnnotation(ct.Annotations, "Autowired") || hasAnnotation(ct.Annotations, "Inject") {
			chosen = append(chosen, ct)
		}
	}
	if len(chosen) == 0 && len(ctors) == 1 {
		chosen = ctors // implicit single-constructor autowiring
	}

	var ips []InjectionPoint
	for _, ct := range chosen {
		params := descriptorParamTypes(ct.Ref.Descriptor)
		for slot, t := range params {
			if t == "" {
				continue // a primitive parameter is not a bean injection point
			}
			ips = append(ips, InjectionPoint{
				Owner:        c.Name,
				Site:         "ctorParam",
				DeclaredType: t,
				Qualifier:    paramQualifier(ct.ParameterAnnotations, slot),
			})
		}
	}
	return ips
}

// --- annotation helpers (simple-name, namespace-agnostic) ---

// simpleAnnoName reduces an annotation type descriptor ("Lorg/springframework/
// stereotype/Service;") to its simple name ("Service"). A bare/already-simple value is
// returned as-is.
func simpleAnnoName(desc string) string {
	s := desc
	if strings.HasPrefix(s, "L") && strings.HasSuffix(s, ";") {
		s = s[1 : len(s)-1]
	}
	if k := strings.LastIndexByte(s, '/'); k >= 0 {
		s = s[k+1:]
	}
	if k := strings.LastIndexByte(s, '.'); k >= 0 {
		s = s[k+1:]
	}
	return s
}

func classHasStereotype(c *classfile.Class) bool {
	for _, a := range c.Annotations {
		if stereotypeAnnotations[simpleAnnoName(a.Type)] {
			return true
		}
	}
	return false
}

func hasAnnotation(annos []classfile.Annotation, simpleName string) bool {
	for _, a := range annos {
		if simpleAnnoName(a.Type) == simpleName {
			return true
		}
	}
	return false
}

func annotationsAny(annos []classfile.Annotation, set map[string]bool) bool {
	for _, a := range annos {
		if set[simpleAnnoName(a.Type)] {
			return true
		}
	}
	return false
}

// firstAnnotationString returns the first string element value of the named annotation
// (e.g. @Qualifier("foo") → "foo"), or "" if the annotation or a string value is absent.
func firstAnnotationString(annos []classfile.Annotation, simpleName string) string {
	for _, a := range annos {
		if simpleAnnoName(a.Type) != simpleName {
			continue
		}
		if len(a.Elements) > 0 {
			return a.Elements[0].Value
		}
	}
	return ""
}

// annotationStrings returns every string element value of the named annotation across
// all its occurrences (e.g. @Profile("dev") → ["dev"]).
func annotationStrings(annos []classfile.Annotation, simpleName string) []string {
	var out []string
	for _, a := range annos {
		if simpleAnnoName(a.Type) != simpleName {
			continue
		}
		for _, e := range a.Elements {
			if e.Value != "" {
				out = append(out, e.Value)
			}
		}
	}
	return out
}

// stereotypeQualifiers are the qualifier keys a stereotype bean answers to: its
// explicit @Qualifier value plus its implicit bean name (the decapitalized simple class
// name, Spring's default). Both let a @Qualifier("userService") injection point match.
func stereotypeQualifiers(c *classfile.Class) []string {
	var qs []string
	if q := firstAnnotationString(c.Annotations, "Qualifier"); q != "" {
		qs = append(qs, q)
	}
	// An explicit stereotype value (@Service("foo")) also names the bean.
	for _, a := range c.Annotations {
		if stereotypeAnnotations[simpleAnnoName(a.Type)] && len(a.Elements) > 0 && a.Elements[0].Value != "" {
			qs = append(qs, a.Elements[0].Value)
		}
	}
	qs = append(qs, defaultBeanName(c.Name))
	return dedupeStrings(qs)
}

// beanMethodQualifiers are the qualifier keys an @Bean method's bean answers to: the
// method's own name (the default bean name), any @Bean("name")/@Qualifier value, and
// the decapitalized return-type simple name.
func beanMethodQualifiers(m *classfile.Method) []string {
	qs := []string{m.Ref.Name}
	if q := firstAnnotationString(m.Annotations, "Qualifier"); q != "" {
		qs = append(qs, q)
	}
	if q := firstAnnotationString(m.Annotations, "Bean"); q != "" {
		qs = append(qs, q)
	}
	return dedupeStrings(qs)
}

// defaultBeanName decapitalizes a type's simple name the way Spring derives a default
// bean name: "UserServiceImpl" → "userServiceImpl". An all-caps prefix is left intact
// (Spring's Introspector.decapitalize rule), a refinement we approximate by only
// lowercasing the first rune.
func defaultBeanName(typeKey string) string {
	s := SimpleTypeName(typeKey)
	if s == "" {
		return ""
	}
	r := []rune(s)
	r[0] = unicode.ToLower(r[0])
	return string(r)
}

// simpleTypeName reduces an internal type name ("com/example/UserServiceImpl") or a
// nested one ("com/example/Outer$Inner") to its simple leaf ("UserServiceImpl" /
// "Inner"). A value already simple is returned unchanged.
func SimpleTypeName(typeKey string) string {
	s := typeKey
	if k := strings.LastIndexByte(s, '/'); k >= 0 {
		s = s[k+1:]
	}
	if k := strings.LastIndexByte(s, '$'); k >= 0 {
		s = s[k+1:]
	}
	return s
}

func paramQualifier(paramAnnos [][]classfile.Annotation, slot int) string {
	if slot < 0 || slot >= len(paramAnnos) {
		return ""
	}
	return firstAnnotationString(paramAnnos[slot], "Qualifier")
}

// --- type/descriptor helpers ---

// classfileRefType reduces a field's JVM type descriptor to the internal name of its
// reference type ("Lcom/example/Foo;" → "com/example/Foo"), or "" for a primitive or
// array-of-primitive (not an injectable bean type). An array of a reference type yields
// the element type — the array-ness does not change which bean satisfies it for our
// purpose (a bean injected as a collection is a coarser case we do not model).
func classfileRefType(desc string) string {
	i := 0
	for i < len(desc) && desc[i] == '[' {
		i++
	}
	if i < len(desc) && desc[i] == 'L' && strings.HasSuffix(desc, ";") {
		return desc[i+1 : len(desc)-1]
	}
	return ""
}

// returnRefType returns the internal name of a method descriptor's reference return
// type ("(...)Lcom/example/Foo;" → "com/example/Foo"), or "" for a primitive/void/array
// return.
func returnRefType(desc string) string {
	i := strings.LastIndexByte(desc, ')')
	if i < 0 || i+1 >= len(desc) {
		return ""
	}
	return classfileRefType(desc[i+1:])
}

// descriptorParamTypes returns one entry per formal parameter of a method descriptor,
// in order, aligned to RuntimeVisibleParameterAnnotations slots: the internal name for
// a reference parameter, or "" for a primitive (which still occupies a slot). Array
// parameters yield their reference element type (or "" for an array of primitive).
func descriptorParamTypes(desc string) []string {
	i := strings.IndexByte(desc, '(')
	if i < 0 {
		return nil
	}
	i++
	var out []string
	for i < len(desc) && desc[i] != ')' {
		isArray := false
		for i < len(desc) && desc[i] == '[' {
			isArray = true
			i++
		}
		if i >= len(desc) {
			break
		}
		switch desc[i] {
		case 'L':
			j := i + 1
			for j < len(desc) && desc[j] != ';' {
				j++
			}
			if j >= len(desc) {
				return out // malformed: unterminated object type
			}
			out = append(out, desc[i+1:j])
			i = j + 1
		case 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z':
			out = append(out, "") // primitive: a slot, but not a bean type
			i++
			_ = isArray
		default:
			return out // malformed
		}
	}
	return out
}

// supertypeClosure returns typeName plus every transitive superclass and implemented
// interface reachable within the given class set, deduplicated and sorted. Names whose
// class is not in the set are still included as leaf supertypes (an interface declared
// in a dependency the collector did not open) — indexing a bean under a supertype it
// certainly satisfies never fabricates an edge, and omitting the ancestors of an
// unopened type only under-resolves (sound).
func supertypeClosure(typeName string, byName map[string]*classfile.Class) []string {
	seen := map[string]bool{}
	var out []string
	stack := []string{typeName}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if cur == "" || seen[cur] {
			continue
		}
		seen[cur] = true
		out = append(out, cur)
		c := byName[cur]
		if c == nil {
			continue // out-of-set ancestor: a sound leaf, its own ancestors unknown
		}
		if c.Super != "" && c.Super != "java/lang/Object" {
			stack = append(stack, c.Super)
		}
		stack = append(stack, c.Interfaces...)
	}
	sort.Strings(out)
	return out
}

func dedupeStrings(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

func sortInjectionPoints(ips []InjectionPoint) {
	sort.Slice(ips, func(i, j int) bool {
		if ips[i].Owner != ips[j].Owner {
			return ips[i].Owner < ips[j].Owner
		}
		if ips[i].DeclaredType != ips[j].DeclaredType {
			return ips[i].DeclaredType < ips[j].DeclaredType
		}
		if ips[i].Site != ips[j].Site {
			return ips[i].Site < ips[j].Site
		}
		return ips[i].Qualifier < ips[j].Qualifier
	})
}
