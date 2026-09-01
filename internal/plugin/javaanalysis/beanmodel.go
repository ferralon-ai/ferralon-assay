package javaanalysis

import (
	"sort"
	"strings"
	"unicode"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/beangraph"
)

// This file is the Java FIRST-PARTY bean collector: the source-lexical half of the
// Spring DI bean model whose classfile half lives in the shared beangraph package.
// The asymmetry it exists for (spring-surface.md §0): Java first-party code is SOURCE
// at analysis time, not bytecode, so its beans cannot come from the classfile collector
// — they are read here from the same cleaned+raw source the call/ingress pass scans,
// with annotation VALUES now recoverable (Eric decision 2 / commit 7fe66cf). Everything
// operates in SIMPLE-name space (the lexical lane has no resolved package for a bare
// type token), which the key-neutral registry accepts; the classfile lane keys on
// internal names. No output of this file changes the call graph on its own — the
// resolver in beanresolve.go consumes it (H2).
//
// Soundness note: a lexical mis-parse can only produce a wrong TYPE on a bean or
// injection point, never a wrong stereotype/@Autowired/@Bean marker (those come from the
// reliably-parsed annotation set). A wrong type merely fails to resolve — it never
// fabricates an edge (inv.5), because an edge is emitted only for a unique resolution to
// a first-party impl that actually declares the called method.

// stereotypeNames is the simple-name set of class-level annotations that register a
// bean, mirroring beangraph.stereotypeAnnotations for the source path.
var stereotypeNames = map[string]bool{
	"Component": true, "Service": true, "Repository": true, "Controller": true,
	"RestController": true, "Configuration": true, "Named": true, "ManagedBean": true,
}

// injectAnnoNames marks a field/constructor as a bean injection point (source path).
// @Value is excluded — it injects a property, not a bean.
var injectAnnoNames = map[string]bool{"Autowired": true, "Inject": true, "Resource": true}

// parsedAnno is one annotation seen preceding a declaration: its simple name and the
// first recovered string element value (via parseAnnotation with the raw source).
type parsedAnno struct {
	name  string
	value string
}

// ipCandidate is a constructor parameter's injection shape before the single-ctor /
// @Autowired rule decides whether it is a live injection point.
type ipCandidate struct {
	typ       string
	qualifier string
}

type ctorInfo struct {
	params    []ipCandidate
	autowired bool
}

type srcBeanMethod struct {
	returnType string
	name       string
	primary    bool
	qualifier  string
	profiles   []string
}

// sourceClass is one first-party type as the bean scanner sees it: its identity
// (pkg + enclosing chain including self), its direct supertypes (extends/implements
// simple names), and the bean-relevant declarations found in its body.
type sourceClass struct {
	pkg          string
	enclosing    []string // outer→inner, including self
	name         string
	supers       []string // direct extends + implements, simple names
	isStereotype bool
	primary      bool
	qualifiers   []string
	profiles     []string
	injections   []beangraph.InjectionPoint // field injections (Owner = ownerKey)
	ctors        []ctorInfo
	beanMethods  []srcBeanMethod
}

// classLoc locates a first-party class for building an impl method's SCIP id.
type classLoc struct {
	pkg       string
	enclosing []string // including self
}

// sourceBeanData is the assembled first-party bean input for the Java lane: the beans
// (simple-name space), injection points indexed by owner-class key, and the first-party
// class locations used to mint an impl method's SCIP id.
type sourceBeanData struct {
	beans      []beangraph.BeanDef
	injByOwner map[string][]beangraph.InjectionPoint
	classLocs  map[string][]classLoc
}

// ownerKey identifies a class across the call loop and the bean scan by package + its
// full enclosing type chain, so a caller SCIP's owner (f.pkg + cs.callerEnclosing)
// matches an injection point's owner. The NUL separator cannot occur in a Java name.
func ownerKey(pkg string, enclosing []string) string {
	return pkg + "\x00" + strings.Join(enclosing, ".")
}

// scanSourceClasses walks one file's cleaned source (clean) with the raw source (raw)
// alongside for annotation-value recovery, and returns the bean-relevant types it
// finds. It tracks a block stack: a type frame captures a class/interface/enum/record
// body; a bare frame captures any other block (method body, initializer) so members
// inside a method are not mistaken for declarations. pkg is the file's package.
func scanSourceClasses(clean, raw []rune, pkg string) []sourceClass {
	n := len(clean)
	var out []sourceClass
	type frame struct{ cls *sourceClass } // cls != nil for a type frame
	var stack []frame
	var pending []parsedAnno

	typeChain := func() []string {
		var c []string
		for _, f := range stack {
			if f.cls != nil {
				c = append(c, f.cls.name)
			}
		}
		return c
	}

	i := 0
	for i < n {
		c := clean[i]
		switch {
		case c == '@':
			name, val, next := parseAnnotation(clean, raw, i)
			pending = append(pending, parsedAnno{name: name, value: val})
			i = next
		case c == '{':
			stack = append(stack, frame{})
			i++
		case c == '}':
			if len(stack) > 0 {
				if top := stack[len(stack)-1]; top.cls != nil {
					out = append(out, *top.cls)
				}
				stack = stack[:len(stack)-1]
			}
			i++
		case isIdentStart(c):
			word, next := readWord(clean, i)
			switch {
			case typeKeywords[word]:
				nm, supers, openIdx, ok := parseTypeHeaderFull(clean, next)
				if !ok {
					pending = nil
					i = next
					continue
				}
				self := append(append([]string(nil), typeChain()...), nm)
				sc := &sourceClass{pkg: pkg, name: nm, enclosing: self, supers: supers}
				applyClassAnnos(sc, pending)
				pending = nil
				stack = append(stack, frame{cls: sc})
				i = openIdx + 1
			case word == "package" || word == "import":
				pending = nil
				i = skipTo(clean, next, ';')
			default:
				// A member declaration only at type-body depth (top frame is a type).
				if len(stack) > 0 && stack[len(stack)-1].cls != nil {
					if adv, ok := parseMemberBean(clean, raw, i, stack[len(stack)-1].cls, pending); ok {
						pending = nil
						i = adv
						continue
					}
				}
				i = next
			}
		default:
			i++
		}
	}
	return out
}

// parseTypeHeaderFull reads a type name and its full extends/implements supertype list
// (simple names), scanning to the body-opening '{'. It returns ok=false if a ';' or EOF
// is reached first (a forward declaration / annotation type handled elsewhere).
func parseTypeHeaderFull(r []rune, pos int) (name string, supers []string, openIdx int, ok bool) {
	n := len(r)
	pos = skipSpace(r, pos)
	if pos >= n || !isIdentStart(r[pos]) {
		return "", nil, 0, false
	}
	name, pos = readWord(r, pos)
	mode := 0 // 1 extends, 2 implements, 3 permits
	for pos < n {
		switch {
		case r[pos] == '{':
			return name, supers, pos, true
		case r[pos] == ';':
			return name, nil, 0, false
		case r[pos] == '(' || r[pos] == '<' || r[pos] == '[':
			pos = skipGroup(r, pos)
		case isIdentStart(r[pos]):
			w, nx := readQualifiedSimple(r, pos)
			switch w {
			case "extends":
				mode = 1
			case "implements":
				mode = 2
			case "permits":
				mode = 3
			default:
				if mode == 1 || mode == 2 {
					supers = append(supers, w)
				}
			}
			pos = nx
		default:
			pos++
		}
	}
	return "", nil, 0, false
}

// parseMemberBean parses one member at type-body depth on class owner, recording a bean
// method, a constructor's parameters, or an injected field as a side effect. It returns
// the index to resume at and ok: for a method/ctor with a body it returns the index AT
// the '{' (so the main loop pushes a block frame and stays brace-balanced), for an
// abstract method or a field the index past the terminating ';'. ok=false means the run
// is not a member declaration (the caller advances one word).
func parseMemberBean(clean, raw []rune, start int, owner *sourceClass, pending []parsedAnno) (adv int, ok bool) {
	n := len(clean)
	pos := start
	var toks []string // qualified-simple identifiers in declaration order
	for pos < n {
		c := clean[pos]
		switch {
		case c == '(':
			if len(toks) == 0 {
				return start, false
			}
			name := toks[len(toks)-1]
			retType := ""
			if len(toks) >= 2 {
				retType = toks[len(toks)-2]
			}
			params, afterParen := parseParamsBean(clean, raw, pos)
			q := skipSpace(clean, afterParen)
			if q < n && isIdentStart(clean[q]) {
				if w, nx := readWord(clean, q); w == "throws" {
					q = nx
					for q < n && clean[q] != '{' && clean[q] != ';' {
						q++
					}
				}
			}
			if q >= n || (clean[q] != '{' && clean[q] != ';') {
				return start, false
			}
			switch {
			case name == owner.name:
				owner.ctors = append(owner.ctors, ctorInfo{
					params:    params,
					autowired: pendingHas(pending, "Autowired") || pendingHas(pending, "Inject"),
				})
			case pendingHas(pending, "Bean"):
				owner.beanMethods = append(owner.beanMethods, srcBeanMethod{
					returnType: retType,
					name:       name,
					primary:    pendingHas(pending, "Primary"),
					qualifier:  pendingVal(pending, "Qualifier"),
					profiles:   pendingVals(pending, "Profile"),
				})
			}
			if clean[q] == '{' {
				return q, true
			}
			return q + 1, true
		case c == '=':
			recordField(owner, toks, pending)
			return skipTo(clean, pos, ';'), true
		case c == ';':
			recordField(owner, toks, pending)
			return pos + 1, true
		case c == '{' || c == '}':
			return start, false
		case c == '<' || c == '[':
			pos = skipGroup(clean, pos)
		case isIdentStart(c):
			var w string
			w, pos = readQualifiedSimple(clean, pos)
			toks = append(toks, w)
		default:
			pos++
		}
	}
	return start, false
}

// recordField records a field injection point when the field carries an inject
// annotation. toks are the field's declaration tokens (…, Type, name); the type is the
// token before the name.
func recordField(owner *sourceClass, toks []string, pending []parsedAnno) {
	if len(toks) < 2 || !pendingHasAny(pending, injectAnnoNames) {
		return
	}
	typ := toks[len(toks)-2]
	if javaPrimitives[typ] {
		return
	}
	owner.injections = append(owner.injections, beangraph.InjectionPoint{
		Owner:        ownerKey(owner.pkg, owner.enclosing),
		Site:         "field",
		DeclaredType: typ,
		Qualifier:    pendingVal(pending, "Qualifier"),
	})
}

// javaPrimitives are the type keywords that are never a bean injection type.
var javaPrimitives = map[string]bool{
	"byte": true, "short": true, "int": true, "long": true, "float": true,
	"double": true, "boolean": true, "char": true, "void": true,
}

// parseParamsBean parses a parameter group starting at its '(' and returns one
// ipCandidate per parameter plus the index past ')'. It splits on depth-1 commas so a
// generic or annotation-internal comma is not a separator.
func parseParamsBean(clean, raw []rune, open int) ([]ipCandidate, int) {
	end := skipGroup(clean, open) // index past ')'
	var params []ipCandidate
	depth := 0
	segStart := open + 1
	flush := func(a, b int) {
		if strings.TrimSpace(string(clean[a:b])) == "" {
			return
		}
		params = append(params, parseOneParam(clean, raw, a, b))
	}
	for i := open; i < end; i++ {
		switch clean[i] {
		case '(', '[', '<':
			depth++
		case ')', ']', '>':
			depth--
			if depth == 0 {
				flush(segStart, i)
			}
		case ',':
			if depth == 1 {
				flush(segStart, i)
				segStart = i + 1
			}
		}
	}
	return params, end
}

// parseOneParam extracts the declared type and @Qualifier of a single parameter region
// clean[a:b]. The type is the token before the parameter name (the last two qualified
// idents after modifiers/annotations are stripped).
func parseOneParam(clean, raw []rune, a, b int) ipCandidate {
	var toks []string
	qualifier := ""
	i := a
	for i < b {
		c := clean[i]
		switch {
		case c == '@':
			name, val, next := parseAnnotation(clean, raw, i)
			if name == "Qualifier" && val != "" {
				qualifier = val
			}
			i = next
		case c == '<' || c == '[':
			i = skipGroup(clean, i)
		case isIdentStart(c):
			var w string
			w, i = readQualifiedSimple(clean, i)
			toks = append(toks, w)
		default:
			i++
		}
	}
	typ := ""
	if len(toks) >= 2 {
		typ = toks[len(toks)-2]
	} else if len(toks) == 1 {
		typ = toks[0]
	}
	return ipCandidate{typ: typ, qualifier: qualifier}
}

// applyClassAnnos folds a type's preceding annotations into its bean metadata.
func applyClassAnnos(sc *sourceClass, pending []parsedAnno) {
	for _, a := range pending {
		switch {
		case stereotypeNames[a.name]:
			sc.isStereotype = true
			if a.value != "" {
				sc.qualifiers = append(sc.qualifiers, a.value)
			}
		case a.name == "Primary":
			sc.primary = true
		case a.name == "Profile":
			if a.value != "" {
				sc.profiles = append(sc.profiles, a.value)
			}
		case a.name == "Qualifier":
			if a.value != "" {
				sc.qualifiers = append(sc.qualifiers, a.value)
			}
		}
	}
}

// buildSourceBeanData assembles the first-party bean input from every scanned class:
// beans (stereotypes + @Bean methods) with their supertype-closure Satisfies sets,
// injection points indexed by owner key (field injections + constructor injections under
// the @Autowired / sole-constructor rule), and first-party class locations. All outputs
// are deterministically ordered.
func buildSourceBeanData(all []sourceClass) sourceBeanData {
	// Direct supertype edges across all first-party classes, for the closure.
	supersByName := map[string][]string{}
	for _, sc := range all {
		supersByName[sc.name] = append(supersByName[sc.name], sc.supers...)
	}

	data := sourceBeanData{
		injByOwner: map[string][]beangraph.InjectionPoint{},
		classLocs:  map[string][]classLoc{},
	}

	for _, sc := range all {
		data.classLocs[sc.name] = append(data.classLocs[sc.name], classLoc{pkg: sc.pkg, enclosing: sc.enclosing})

		if sc.isStereotype {
			quals := append(append([]string(nil), sc.qualifiers...), decapitalize(sc.name))
			data.beans = append(data.beans, beangraph.BeanDef{
				Impl:       sc.name,
				Origin:     beangraph.OriginStereotype,
				Satisfies:  supertypeClosureNames(sc.name, supersByName),
				Qualifiers: dedupe(quals),
				Primary:    sc.primary,
				Profiles:   sc.profiles,
			})
		}
		for _, bm := range sc.beanMethods {
			if bm.returnType == "" || javaPrimitives[bm.returnType] {
				continue
			}
			quals := []string{bm.name}
			if bm.qualifier != "" {
				quals = append(quals, bm.qualifier)
			}
			data.beans = append(data.beans, beangraph.BeanDef{
				Impl:       bm.returnType,
				Origin:     beangraph.OriginBeanMethod,
				Satisfies:  supertypeClosureNames(bm.returnType, supersByName),
				Qualifiers: dedupe(quals),
				Primary:    bm.primary,
				Profiles:   bm.profiles,
			})
		}

		key := ownerKey(sc.pkg, sc.enclosing)
		ips := append(append([]beangraph.InjectionPoint(nil), sc.injections...), ctorInjectionPointsSource(sc, key)...)
		if len(ips) > 0 {
			data.injByOwner[key] = append(data.injByOwner[key], ips...)
		}
	}

	sort.Slice(data.beans, func(i, j int) bool {
		if data.beans[i].Impl != data.beans[j].Impl {
			return data.beans[i].Impl < data.beans[j].Impl
		}
		return data.beans[i].Origin < data.beans[j].Origin
	})
	for k := range data.injByOwner {
		ips := data.injByOwner[k]
		sort.Slice(ips, func(i, j int) bool {
			if ips[i].DeclaredType != ips[j].DeclaredType {
				return ips[i].DeclaredType < ips[j].DeclaredType
			}
			if ips[i].Site != ips[j].Site {
				return ips[i].Site < ips[j].Site
			}
			return ips[i].Qualifier < ips[j].Qualifier
		})
	}
	return data
}

// ctorInjectionPointsSource applies the constructor-injection rule to a source class:
// the parameters of every @Autowired constructor, or of the sole constructor when there
// is exactly one. A primitive parameter (typ "") is not a bean injection point.
func ctorInjectionPointsSource(sc sourceClass, key string) []beangraph.InjectionPoint {
	var chosen [][]ipCandidate
	for _, ct := range sc.ctors {
		if ct.autowired {
			chosen = append(chosen, ct.params)
		}
	}
	if len(chosen) == 0 && len(sc.ctors) == 1 {
		chosen = [][]ipCandidate{sc.ctors[0].params}
	}
	var ips []beangraph.InjectionPoint
	for _, params := range chosen {
		for _, p := range params {
			if p.typ == "" || javaPrimitives[p.typ] {
				continue
			}
			ips = append(ips, beangraph.InjectionPoint{
				Owner:        key,
				Site:         "ctorParam",
				DeclaredType: p.typ,
				Qualifier:    p.qualifier,
			})
		}
	}
	return ips
}

// sourceRepositoryTypes returns the simple names of the first-party types that are
// Spring Data repositories — a type transitively extending a *Repository base (edge-seam.md
// §4). It is the SOURCE-lane half of the repository type-model the #3 overlay consumes
// (the classfile half is beangraph.RepositoryTypesFromClasses); the base set is shared via
// beangraph.IsRepositoryBaseName. A repository interface is rarely stereotype-annotated, so
// this reads the raw scanned types, not just the beans.
func sourceRepositoryTypes(all []sourceClass) map[string]bool {
	supers := map[string][]string{}
	for _, sc := range all {
		supers[sc.name] = append(supers[sc.name], sc.supers...)
	}
	out := map[string]bool{}
	for _, sc := range all {
		for _, t := range supertypeClosureNames(sc.name, supers) {
			if t != sc.name && beangraph.IsRepositoryBaseName(t) {
				out[sc.name] = true
				break
			}
		}
	}
	return out
}

// supertypeClosureNames returns name plus every transitive supertype reachable through
// the first-party direct-supertype map, deduplicated and sorted. A supertype whose class
// is not first-party is included as a leaf (its own ancestors are unknown but it is a
// valid injection type).
func supertypeClosureNames(name string, supers map[string][]string) []string {
	seen := map[string]bool{}
	var out []string
	stack := []string{name}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if cur == "" || seen[cur] {
			continue
		}
		seen[cur] = true
		out = append(out, cur)
		stack = append(stack, supers[cur]...)
	}
	sort.Strings(out)
	return out
}

// --- small helpers ---

// readQualifiedSimple reads a possibly-dotted name (ident ('.' ident)*) and returns its
// LAST segment plus the index past it — so "com.example.Foo" yields "Foo".
func readQualifiedSimple(r []rune, i int) (last string, next int) {
	last, i = readWord(r, i)
	for {
		j := skipSpace(r, i)
		if j < len(r) && r[j] == '.' {
			k := skipSpace(r, j+1)
			if k < len(r) && isIdentStart(r[k]) {
				last, i = readWord(r, k)
				continue
			}
		}
		break
	}
	return last, i
}

func decapitalize(s string) string {
	if s == "" {
		return ""
	}
	r := []rune(s)
	r[0] = unicode.ToLower(r[0])
	return string(r)
}

func pendingHas(pending []parsedAnno, name string) bool {
	for _, a := range pending {
		if a.name == name {
			return true
		}
	}
	return false
}

func pendingHasAny(pending []parsedAnno, set map[string]bool) bool {
	for _, a := range pending {
		if set[a.name] {
			return true
		}
	}
	return false
}

func pendingVal(pending []parsedAnno, name string) string {
	for _, a := range pending {
		if a.name == name && a.value != "" {
			return a.value
		}
	}
	return ""
}

func pendingVals(pending []parsedAnno, name string) []string {
	var out []string
	for _, a := range pending {
		if a.name == name && a.value != "" {
			out = append(out, a.value)
		}
	}
	return out
}

func dedupe(xs []string) []string {
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
