package jvmingress

import (
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/depreach"
)

// compiled.go reads the registry's annotation families off compiled classes, including the
// annotations a method inherits from the methods it overrides. Spring and JAX-RS both look
// a route up on the overridden interface or superclass method, so a handler that carries
// only @Override is still an entry point when the interface declares the mapping, as an
// openapi-generator interface does.

// Entry is one compiled method that a framework calls with no call the search can see.
type Entry struct {
	Ref      classfile.MethodRef
	Kind     string
	Selector string // "VERB /base/path" for a route, advisory display only
}

// annoKind and annoVerb are the annotation-name views of Families(): simple name to Kind,
// and for an http_route the verb ("" for all verbs).
var (
	annoKind = map[string]string{}
	annoVerb = map[string]string{}
)

func init() {
	for _, f := range Families() {
		if f.Match.Annotation == "" {
			continue
		}
		annoKind[f.Match.Annotation] = f.Kind
		if f.Kind == KindHTTPRoute {
			annoVerb[f.Match.Annotation] = f.Verb
		}
	}
}

// Compiled returns the entry points among classes' methods: every concrete method carrying a
// registry annotation, and every concrete instance method that overrides, by name and
// parameter count, a method on a transitive supertype that carries one. Name and parameter
// count, not the descriptor, so a generic interface method (erased to Object) roots the
// override whether or not the compiler emitted a bridge; an overload of the same arity is
// rooted too, which can only raise reachability. A concrete method that a dependency
// supertype (one outside classes) declares as an entry, or inherits as one, is rooted on that
// supertype when the class does not override it by name and descriptor. lookup resolves a binary name to a loaded
// class; a supertype it cannot resolve contributes nothing here (see UnresolvedSupertype).
// Servlet methods are not read: that family is supertype-based, not annotation-based.
func Compiled(classes []classfile.Class, lookup func(string) (*classfile.Class, bool)) []Entry {
	var out []Entry
	seen := map[string]bool{}
	firstParty := make(map[string]bool, len(classes))
	for i := range classes {
		firstParty[classes[i].Name] = true
	}
	add := func(m classfile.Method, supers []*classfile.Class, base string) {
		if m.Abstract {
			return
		}
		kind, anno, ok := classify(m.Annotations)
		if !ok && overridable(m) {
			for _, s := range supers {
				for _, sm := range s.Methods {
					if sm.Ref.Name != m.Ref.Name || sm.Ref.ParamCount() != m.Ref.ParamCount() {
						continue
					}
					if kind, anno, ok = classify(sm.Annotations); ok {
						break
					}
				}
				if ok {
					break
				}
			}
		}
		if !ok || seen[m.Ref.String()] {
			return
		}
		seen[m.Ref.String()] = true
		e := Entry{Ref: m.Ref, Kind: kind}
		if kind == KindHTTPRoute {
			e.Selector = selector(annoVerb[simpleName(anno.Type)], base, path(anno))
		}
		out = append(out, e)
	}
	for i := range classes {
		c := &classes[i]
		supers := ancestors(c, lookup)
		base := basePath(c, supers)
		for _, m := range c.Methods {
			add(m, supers, base)
		}
		// A method a dependency supertype declares and c does not override is c's handler too,
		// and no class file in classes names it. First-party supertypes are visited as classes
		// of their own.
		for _, s := range supers {
			if firstParty[s.Name] {
				continue
			}
			ssupers := ancestors(s, lookup)
			for _, m := range s.Methods {
				if overridden(c, m) {
					continue
				}
				add(m, ssupers, base)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref.String() < out[j].Ref.String() })
	return out
}

// overridden reports whether c declares an instance method with m's name and descriptor. A
// generic or covariant override carries a bridge with the supertype's erased descriptor, so
// the exact match holds for those; a same-name overload is not an override.
func overridden(c *classfile.Class, m classfile.Method) bool {
	if !overridable(m) {
		return true
	}
	for _, cm := range c.Methods {
		if overridable(cm) && cm.Ref.Name == m.Ref.Name && cm.Ref.Descriptor == m.Ref.Descriptor {
			return true
		}
	}
	return false
}

// UnresolvedSupertype reports whether c has a concrete instance method and a transitive
// supertype that is neither loaded nor a platform class. Such a supertype may declare a
// route the class inherits, which Compiled cannot see.
func UnresolvedSupertype(c *classfile.Class, lookup func(string) (*classfile.Class, bool)) bool {
	has := false
	for _, m := range c.Methods {
		if !m.Abstract && overridable(m) {
			has = true
			break
		}
	}
	if !has {
		return false
	}
	seen := map[string]bool{}
	stack := append([]string{c.Super}, c.Interfaces...)
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		s, ok := lookup(n)
		if !ok {
			if depreach.IsPlatformClass(n) {
				continue
			}
			return true
		}
		stack = append(stack, s.Super)
		stack = append(stack, s.Interfaces...)
	}
	return false
}

// overridable reports whether m can override a supertype method: an instance method that is
// not a constructor or initializer.
func overridable(m classfile.Method) bool {
	return !m.Static && !m.Private && !strings.HasPrefix(m.Ref.Name, "<")
}

// ancestors returns c's transitive loaded supertypes, nearest first, each once.
func ancestors(c *classfile.Class, lookup func(string) (*classfile.Class, bool)) []*classfile.Class {
	var out []*classfile.Class
	seen := map[string]bool{c.Name: true}
	queue := append([]string{c.Super}, c.Interfaces...)
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		if s, ok := lookup(n); ok {
			out = append(out, s)
			queue = append(queue, s.Super)
			queue = append(queue, s.Interfaces...)
		}
	}
	return out
}

// classify returns the Kind and annotation of the first registry annotation in annos, a
// route in preference to any other kind.
func classify(annos []classfile.Annotation) (string, classfile.Annotation, bool) {
	var other classfile.Annotation
	otherKind := ""
	for _, a := range annos {
		k, ok := annoKind[simpleName(a.Type)]
		switch {
		case !ok:
		case k == KindHTTPRoute:
			return k, a, true
		case otherKind == "":
			other, otherKind = a, k
		}
	}
	return otherKind, other, otherKind != ""
}

// basePath is the path of the first class-level @RequestMapping on c or its supertypes.
func basePath(c *classfile.Class, supers []*classfile.Class) string {
	for _, k := range append([]*classfile.Class{c}, supers...) {
		for _, a := range k.Annotations {
			if simpleName(a.Type) == "RequestMapping" {
				return path(a)
			}
		}
	}
	return ""
}

func path(a classfile.Annotation) string {
	for _, e := range a.Elements {
		if e.Name == "value" || e.Name == "path" {
			return e.Value
		}
	}
	return ""
}

func selector(verb, base, p string) string {
	route := p
	switch {
	case base == "":
	case p == "":
		route = base
	default:
		route = strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(p, "/")
	}
	switch {
	case verb != "" && route != "":
		return verb + " " + route
	case verb != "":
		return verb
	}
	return route
}

// simpleName reduces a field descriptor ("Lorg/x/GetMapping;") to the annotation's simple name.
func simpleName(desc string) string {
	s := strings.TrimSuffix(strings.TrimPrefix(desc, "L"), ";")
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndexByte(s, '$'); i >= 0 {
		s = s[i+1:]
	}
	return s
}
