package javaanalysis

import "strings"

// routeAnnotations are the lexically-detectable HTTP route annotations that mark
// a method as a framework ingress. The set covers Spring MVC
// (@RequestMapping/@GetMapping/@PostMapping) and JAX-RS (@Path/@GET/@POST). They
// are recognized by NAME only — no type resolution — so a same-named annotation
// from an unrelated package is a (rare, declared-partial-free) false positive the
// reachability layer tolerates: an ingress that resolves to no reachable sink
// simply yields no candidate pair.
var routeAnnotations = map[string]bool{
	"RequestMapping": true,
	"GetMapping":     true,
	"PostMapping":    true,
	"PutMapping":     true,
	"DeleteMapping":  true,
	"PatchMapping":   true,
	"Path":           true,
	"GET":            true,
	"POST":           true,
	"PUT":            true,
	"DELETE":         true,
}

// servletEntryMethods are the HttpServlet override names that are servlet
// ingresses when the enclosing class extends HttpServlet.
var servletEntryMethods = map[string]bool{
	"doGet":    true,
	"doPost":   true,
	"doPut":    true,
	"doDelete": true,
	"service":  true,
}

// bodyFrame is one entry on the body-aware block stack used by the call/ingress
// scanner. A named type frame records whether the type extends HttpServlet; a
// method frame records the method being scanned so call sites inside it can name
// their caller. A bare block (if/for/lambda) carries neither.
type bodyFrame struct {
	typeName     string   // non-empty for a class/interface/enum/record body
	isServlet    bool     // typeName extends HttpServlet (or *Servlet by suffix)
	enclosing    []string // enclosing type chain AT this frame (for a method frame, the owning types)
	methodName   string   // non-empty when this frame is a method body
	methodArity  int      // arity of the method whose body this is
	pendingAnnos []pendingAnno
}

// pendingAnno is a route annotation seen at type-body depth that has not yet been
// bound to the method declaration it precedes.
type pendingAnno struct {
	name     string
	selector string
}

// parseCallsAndIngresses scans cleaned Java source (already comment/string-
// stripped) and returns the method-call sites and the annotation/servlet ingress
// markers. It is a second, body-aware pass: it tracks the enclosing type chain,
// whether each type extends HttpServlet, and the method whose body is currently
// open, so a call expression can be attributed to its caller and a servlet/route
// method can be recorded as an ingress.
func parseCallsAndIngresses(r []rune) ([]callSite, []ingressMarker) {
	n := len(r)
	var stack []bodyFrame
	var calls []callSite
	var ingresses []ingressMarker

	// pendingAnnos accumulates route annotations seen at the current type-body
	// depth until the next method declaration consumes them.
	var pendingAnnos []pendingAnno

	enclosingChain := func() []string {
		var out []string
		for _, f := range stack {
			if f.typeName != "" {
				out = append(out, f.typeName)
			}
		}
		return out
	}
	innermostMethod := func() *bodyFrame {
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i].methodName != "" {
				return &stack[i]
			}
		}
		return nil
	}

	i := 0
	for i < n {
		c := r[i]
		switch {
		case c == '@':
			// Annotation. Read the annotation name and an optional ("...") or
			// (path="...") selector. Record it as pending; it binds to the next
			// method declaration at this type-body depth.
			name, sel, next := parseAnnotation(r, i)
			if routeAnnotations[name] {
				pendingAnnos = append(pendingAnnos, pendingAnno{name: name, selector: sel})
			}
			i = next

		case c == '{':
			stack = append(stack, bodyFrame{})
			i++

		case c == '}':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			i++

		case isIdentStart(c):
			word, next := readWord(r, i)
			switch {
			case typeKeywords[word]:
				name, isServlet, openIdx, ok := parseTypeHeaderServlet(r, next)
				if !ok {
					i = next
					continue
				}
				enc := enclosingChain()
				stack = append(stack, bodyFrame{typeName: name, isServlet: isServlet, enclosing: enc})
				pendingAnnos = nil
				i = openIdx + 1
				continue

			case word == "package" || word == "import":
				i = skipTo(r, next, ';')
				continue

			default:
				// Decide between a method DECLARATION at type-body depth, and a CALL
				// expression inside a method body.
				if inTypeBodyFrame(stack) {
					if mname, marity, openIdx, isMethod := methodDeclAt(r, i); isMethod {
						owner := topType(stack)
						enc := enclosingChain()
						// Record annotation + servlet ingresses for this method.
						recordIngresses(&ingresses, enc, mname, marity, owner, pendingAnnos)
						pendingAnnos = nil
						// Push the method body frame; calls inside attribute to it.
						stack = append(stack, bodyFrame{
							enclosing:   enc,
							methodName:  mname,
							methodArity: marity,
						})
						i = openIdx + 1
						continue
					}
				}
				// Inside a method body: a "name(" run is a call expression.
				if m := innermostMethod(); m != nil {
					if cname, carity, after, isCall := callExprAt(r, i); isCall {
						calls = append(calls, callSite{
							callerEnclosing: append([]string(nil), m.enclosing...),
							callerName:      m.methodName,
							callerArity:     m.methodArity,
							calleeName:      cname,
							calleeArity:     carity,
						})
						i = after
						continue
					}
				}
				i = next
			}

		default:
			i++
		}
	}
	return calls, ingresses
}

// recordIngresses appends the ingress markers for a freshly-declared method: one
// per bound route annotation, and a servlet marker when the owning type extends
// HttpServlet and the method is a servlet entry point.
func recordIngresses(out *[]ingressMarker, enc []string, mname string, marity int, owner *bodyFrame, annos []pendingAnno) {
	for _, a := range annos {
		*out = append(*out, ingressMarker{
			enclosing: append([]string(nil), enc...),
			name:      mname,
			arity:     marity,
			kind:      "http_route",
			selector:  a.selector,
		})
	}
	if owner != nil && owner.isServlet && servletEntryMethods[mname] {
		*out = append(*out, ingressMarker{
			enclosing: append([]string(nil), enc...),
			name:      mname,
			arity:     marity,
			kind:      "servlet",
		})
	}
}

// inTypeBodyFrame reports whether the innermost open block is a named type body
// (so the next member is a declaration, not a statement).
func inTypeBodyFrame(stack []bodyFrame) bool {
	if len(stack) == 0 {
		return false
	}
	top := stack[len(stack)-1]
	return top.typeName != ""
}

// topType returns the innermost named-type frame, or nil if none is open.
func topType(stack []bodyFrame) *bodyFrame {
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i].typeName != "" {
			return &stack[i]
		}
	}
	return nil
}

// parseAnnotation reads an annotation starting at the '@' at i. It returns the
// annotation simple name (last dotted segment), the route selector if the
// argument list carries a string literal (which stripJava has blanked, so the
// selector is recovered as "" — we keep the field for forward-compat), and the
// index just past the annotation (including any "(...)" argument group).
//
// Note: string literals are blanked by stripJava before this runs, so the
// selector value is not recoverable here; the field stays "" and the ingress is
// still detected by name. Selector recovery would require running this pass on
// the raw source — deferred (the route path is not needed for reachability).
func parseAnnotation(r []rune, i int) (name, selector string, next int) {
	n := len(r)
	j := skipSpace(r, i+1) // past '@'
	if j >= n || !isIdentStart(r[j]) {
		return "", "", i + 1
	}
	// Read a possibly-dotted annotation name (e.g. "javax.ws.rs.GET").
	start := j
	for j < n && (isIdentPart(r[j]) || r[j] == '.') {
		j++
	}
	full := string(r[start:j])
	name = full
	if dot := strings.LastIndexByte(full, '.'); dot >= 0 {
		name = full[dot+1:]
	}
	j = skipSpace(r, j)
	if j < n && r[j] == '(' {
		j = skipGroup(r, j)
	}
	return name, "", j
}

// methodDeclAt reports whether the run starting at i is a method (or constructor)
// declaration at type-body depth, returning the method name, arity, the index of
// the body-opening '{', and ok. It mirrors parseMember's method branch but does
// not classify fields (the caller only needs methods here). A method with no body
// (abstract/interface, terminated by ';') is NOT reported, since it has no body
// to scan and is not a call-graph caller; ok=false leaves it to the normal
// advance.
func methodDeclAt(r []rune, i int) (name string, arity, openIdx int, ok bool) {
	n := len(r)
	pos := i
	lastIdent := ""
	for pos < n {
		c := r[pos]
		switch {
		case c == '(':
			if lastIdent == "" {
				return "", 0, 0, false
			}
			ar, after := parseParamArity(r, pos)
			q := skipSpace(r, after)
			if q < n && isIdentStart(r[q]) {
				if w, nx := readWord(r, q); w == "throws" {
					q = nx
					for q < n && r[q] != '{' && r[q] != ';' {
						q++
					}
				}
			}
			if q < n && r[q] == '{' {
				return lastIdent, ar, q, true
			}
			return "", 0, 0, false
		case c == '=' || c == ';':
			return "", 0, 0, false // a field, not a method
		case c == '{' || c == '}':
			return "", 0, 0, false
		case c == '<' || c == '[':
			pos = skipGroup(r, pos)
		case isIdentStart(c):
			lastIdent, pos = readWord(r, pos)
		default:
			pos++
		}
	}
	return "", 0, 0, false
}

// callExprAt reports whether the identifier run starting at i is a method-call
// expression ("name(args)"), returning the callee simple name, its argument
// arity, the index just past the closing ')', and ok. It recognizes both a bare
// call "foo(...)" and a qualified call "a.b.foo(...)" — in both cases the callee
// simple name is the identifier immediately before '('. A run that is not
// followed (after optional generic <...> and whitespace) by '(' is not a call.
// Java keywords that take a parenthesized clause (if/for/while/switch/catch/
// synchronized/return/new) are excluded so control flow is not mistaken for a
// call.
func callExprAt(r []rune, i int) (name string, arity, after int, ok bool) {
	n := len(r)
	// Read the (possibly qualified) reference: ident ('.' ident)*.
	pos := i
	last := ""
	for pos < n {
		if isIdentStart(r[pos]) {
			last, pos = readWord(r, pos)
		} else if r[pos] == '.' {
			pos++
		} else {
			break
		}
	}
	if last == "" || callKeywords[last] {
		return "", 0, 0, false
	}
	// Optional generic type witness "<...>" between the name and '(' (e.g.
	// Collections.<String>emptyList()).
	p := skipSpace(r, pos)
	if p < n && r[p] == '<' {
		p = skipGroup(r, p)
		p = skipSpace(r, p)
	}
	if p >= n || r[p] != '(' {
		return "", 0, 0, false
	}
	ar, end := parseParamArity(r, p)
	return last, ar, end, true
}

// callKeywords are Java keywords that are followed by a parenthesized clause but
// are NOT method calls; excluding them prevents control flow from being recorded
// as a call edge.
var callKeywords = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true,
	"catch": true, "synchronized": true, "return": true, "new": true,
	"assert": true, "throw": true, "do": true, "else": true, "yield": true,
	"super": true, "this": true,
}
