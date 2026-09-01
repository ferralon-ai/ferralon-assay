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

// containerEntrypoints are annotations marking a method the Spring container (or
// the JVM lifecycle it honors) invokes with NO syntactic caller: scheduled tasks,
// application-event handlers, bean lifecycle callbacks, and message-listener
// consumers. Such a method is a reachability ROOT — a sink reachable only through
// it is genuinely reachable at runtime, so failing to seed it produces a false
// "unreachable". Each annotation maps to the ingress Kind recorded for it. Like
// routeAnnotations these are matched by NAME only (no type resolution): a
// same-named annotation from an unrelated package is a rare false positive the
// reachability layer tolerates — an entrypoint that reaches no sink yields no
// candidate pair. Adding a root only ever ADDS reachable candidates (it modulates
// strength, never admission — inv.5), so name-only over-recognition is sound.
var containerEntrypoints = map[string]string{
	"Scheduled":      "scheduled",
	"EventListener":  "event_listener",
	"PostConstruct":  "lifecycle",
	"PreDestroy":     "lifecycle",
	"KafkaListener":  "message_listener",
	"JmsListener":    "message_listener",
	"RabbitListener": "message_listener",
}

// registerRouteAnnotation and registerContainerEntrypoint are the lexical half of the
// H1 annotation-classifier registry (edge-seam.md §5): an overlay teaches a new route
// or container-entrypoint annotation from its OWN file's init(), rather than editing
// these maps in place (which would collide every overlay on calls.go). Membership is
// name-only, so registration order is irrelevant. The SCIP-space twins are
// registerMappingSelector / registerContainerEntrypointNeedle in scipindex.go — a new
// annotation taught here must be taught there too (the C3 dual-track rule).
func registerRouteAnnotation(name string) { routeAnnotations[name] = true }

func registerContainerEntrypoint(name, kind string) { containerEntrypoints[name] = kind }

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

// pendingAnno is an ingress-marking annotation (route or container-entrypoint)
// seen at type-body depth that has not yet been bound to the method declaration it
// precedes. kind is the ingress Kind the bound method takes.
type pendingAnno struct {
	name     string
	selector string
	kind     string
}

// parseCallsAndIngresses scans cleaned Java source (already comment/string-
// stripped) and returns the method-call sites and the annotation/servlet ingress
// markers. It is a second, body-aware pass: it tracks the enclosing type chain,
// whether each type extends HttpServlet, and the method whose body is currently
// open, so a call expression can be attributed to its caller and a servlet/route
// method can be recorded as an ingress.
// raw is the un-stripped source runes (same length as the cleaned r), passed
// through to parseAnnotation so a route/@Qualifier string element value can be
// recovered from annotation context; nil disables recovery.
func parseCallsAndIngresses(r, raw []rune) ([]callSite, []ingressMarker) {
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
			name, sel, next := parseAnnotation(r, raw, i)
			if routeAnnotations[name] {
				pendingAnnos = append(pendingAnnos, pendingAnno{name: name, selector: sel, kind: "http_route"})
			} else if k, ok := containerEntrypoints[name]; ok {
				pendingAnnos = append(pendingAnnos, pendingAnno{name: name, kind: k})
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
// per bound annotation (route or container-entrypoint, each carrying its own
// Kind), and a servlet marker when the owning type extends HttpServlet and the
// method is a servlet entry point.
func recordIngresses(out *[]ingressMarker, enc []string, mname string, marity int, owner *bodyFrame, annos []pendingAnno) {
	for _, a := range annos {
		*out = append(*out, ingressMarker{
			enclosing: append([]string(nil), enc...),
			name:      mname,
			arity:     marity,
			kind:      a.kind,
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

// parseAnnotation reads an annotation starting at the '@' at i in the cleaned runes
// r. It returns the annotation simple name (last dotted segment), the recovered
// string element value (the route selector / @Qualifier value), and the index just
// past the annotation (including any "(...)" argument group).
//
// Selector recovery: stripJava blanks string literals in r before this runs, so the
// value is not in r. When raw (the un-stripped source, same rune length as r) is
// supplied, the value is read from raw at the SAME offsets — stripJava preserves rune
// offsets exactly, so the group bounds computed on r index raw identically. Recovery
// happens ONLY here, inside the annotation's own argument group; the general
// string-blanking that protects the lexer everywhere else is untouched. raw==nil
// (the declaration-scan caller, which only needs to step over the annotation) keeps
// the old behavior: selector "".
func parseAnnotation(r, raw []rune, i int) (name, selector string, next int) {
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
		open := j
		j = skipGroup(r, j)
		if raw != nil && len(raw) == len(r) {
			selector = annotationStringValue(raw, open, j)
		}
	}
	return name, selector, j
}

// annotationStringValue recovers the FIRST string-literal element value inside the
// annotation argument group whose '(' is at open and whose extent (index just past
// ')') is end, reading from the raw (un-stripped) source. It skips char literals and
// comments so a '"' inside one is never mistaken for a string, and decodes standard
// escapes. Returns "" when the group holds no string literal. The first string wins,
// which is the value in @Ann("x") and the value=/path= route selector in the common
// mapping forms (@RequestMapping("/x"), @RequestMapping(value="/x", method=...)).
func annotationStringValue(raw []rune, open, end int) string {
	limit := end - 1 // index of ')'
	if limit > len(raw) {
		limit = len(raw)
	}
	for i := open + 1; i < limit; {
		c := raw[i]
		switch {
		case c == '/' && i+1 < limit && raw[i+1] == '/':
			for i < limit && raw[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < limit && raw[i+1] == '*':
			i += 2
			for i < limit && !(raw[i] == '*' && i+1 < limit && raw[i+1] == '/') {
				i++
			}
			i += 2
		case c == '\'':
			i++
			for i < limit && raw[i] != '\'' {
				if raw[i] == '\\' {
					i += 2
				} else {
					i++
				}
			}
			i++
		case c == '"' && i+2 < limit && raw[i+1] == '"' && raw[i+2] == '"':
			return decodeAnnotationString(raw, i+3, limit, true)
		case c == '"':
			return decodeAnnotationString(raw, i+1, limit, false)
		default:
			i++
		}
	}
	return ""
}

// decodeAnnotationString reads a string-literal body from raw starting at start, up
// to its terminator ('"' for a normal literal, '"""' for a text block) or limit,
// decoding the common escapes. Text-block incidental-whitespace normalization is not
// applied (annotation values are effectively always single-line literals); the
// content is captured verbatim.
func decodeAnnotationString(raw []rune, start, limit int, textBlock bool) string {
	var b strings.Builder
	for i := start; i < limit; {
		c := raw[i]
		if textBlock {
			if c == '"' && i+2 < limit && raw[i+1] == '"' && raw[i+2] == '"' {
				break
			}
		} else if c == '"' {
			break
		}
		if c == '\\' && i+1 < limit {
			switch nx := raw[i+1]; nx {
			case 'n':
				b.WriteRune('\n')
			case 't':
				b.WriteRune('\t')
			case 'r':
				b.WriteRune('\r')
			default:
				b.WriteRune(nx)
			}
			i += 2
			continue
		}
		b.WriteRune(c)
		i++
	}
	return b.String()
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
