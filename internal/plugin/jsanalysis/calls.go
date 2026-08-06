package jsanalysis

// routeMethods are the Express/Koa HTTP route-registration method names: a call
// "app.get(...)", "router.post(...)", "app.use(...)" etc. registers a request
// handler — the call's handler argument (when a NAMED function reference) is the
// ingress. Recognized by NAME only (no type resolution): a same-named method on an
// unrelated object is a (rare) false positive the reachability layer tolerates (an
// ingress that reaches no sink yields no candidate pair).
var routeMethods = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true,
	"patch": true, "options": true, "head": true, "all": true,
	"use": true,
}

// serverFactories are the Node HTTP server factory call names whose handler
// argument (a NAMED function reference) is a request ingress: http.createServer,
// https.createServer.
var serverFactories = map[string]bool{
	"createServer": true,
}

// bodyFrame is one entry on the body-aware block stack used by the call/ingress
// scanner. A class frame records the class name (so a method call attributes its
// caller correctly); a function frame records the function being scanned so call
// sites inside it can name their caller; a bare block carries neither.
type bodyFrame struct {
	className string   // non-empty for a class body
	enclosing []string // enclosing class chain AT this frame (for a function frame, the owning classes)
	funcName  string   // non-empty when this frame is a function body
	funcArity int      // arity of the function whose body this is
}

// parseCallsAndIngresses scans cleaned JS/TS source (already comment/string-
// stripped) and returns the call sites and the framework ingress markers. It is a
// body-aware pass: it tracks the enclosing class chain and the function whose body
// is currently open, so a call expression attributes to its caller, and a
// route-registration / server-factory / default-export handler is recorded as an
// ingress NAMING the handler function (so the ingress symbol coincides with a
// call-graph node).
func parseCallsAndIngresses(r []rune) ([]callSite, []ingressMarker) {
	n := len(r)
	var stack []bodyFrame
	var calls []callSite
	var ingresses []ingressMarker

	enclosingChain := func() []string {
		var out []string
		for _, f := range stack {
			if f.className != "" {
				out = append(out, f.className)
			}
		}
		return out
	}
	innermostFunc := func() *bodyFrame {
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i].funcName != "" {
				return &stack[i]
			}
		}
		return nil
	}
	inClassBody := func() bool {
		return len(stack) > 0 && stack[len(stack)-1].className != ""
	}

	// pendingExportDefault marks that the previous tokens were "export default", so a
	// "function handler(req,res)" that follows is a Next.js-style default-export
	// handler ingress.
	pendingExportDefault := false

	i := 0
	for i < n {
		c := r[i]
		switch {
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
			case classKeywords[word]:
				name, openIdx, ok := parseClassHeader(r, next)
				if !ok {
					i = next
					continue
				}
				stack = append(stack, bodyFrame{className: name, enclosing: enclosingChain()})
				pendingExportDefault = false
				i = openIdx + 1
				continue

			case word == "function":
				if mname, marity, openIdx, ok := funcDeclAt(r, next); ok {
					enc := enclosingChain()
					if pendingExportDefault && isHandlerArity(marity) {
						ingresses = append(ingresses, ingressMarker{
							enclosing: append([]string(nil), enc...),
							name:      mname, arity: marity, kind: "handler",
						})
					}
					pendingExportDefault = false
					stack = append(stack, bodyFrame{enclosing: enc, funcName: mname, funcArity: marity})
					i = openIdx + 1
					continue
				}
				i = next
				continue

			case word == "const" || word == "let" || word == "var":
				if mname, marity, openIdx, ok := bindingFuncAt(r, next); ok {
					enc := enclosingChain()
					if pendingExportDefault && isHandlerArity(marity) {
						ingresses = append(ingresses, ingressMarker{
							enclosing: append([]string(nil), enc...),
							name:      mname, arity: marity, kind: "handler",
						})
					}
					pendingExportDefault = false
					stack = append(stack, bodyFrame{enclosing: enc, funcName: mname, funcArity: marity})
					i = openIdx + 1
					continue
				}
				i = next
				continue

			case word == "export":
				// Track "export default" so a following function/binding is recorded as a
				// default-export ingress. Other exports just continue.
				p := skipSpace(r, next)
				if w, nx := peekWord(r, p); w == "default" {
					pendingExportDefault = true
					i = nx
					continue
				}
				i = next
				continue

			case word == "import":
				i = skipTo(r, next, ';')
				continue

			default:
				// At class-body depth: a "name (params) {" run is a method declaration.
				if inClassBody() && !methodModifierSkip(word) {
					if mname, marity, openIdx, ok := methodDeclAt(r, i); ok {
						enc := enclosingChain()
						stack = append(stack, bodyFrame{enclosing: enc, funcName: mname, funcArity: marity})
						i = openIdx + 1
						continue
					}
				}
				pendingExportDefault = false
				// A "ref.method(args)" or "name(args)" run: classify as a route
				// registration / server factory (ingress) or a plain call.
				if cname, leaf, carity, handler, after, isCall := callExprAt(r, i); isCall {
					if in, ok := routeIngress(leaf, handler); ok {
						ingresses = append(ingresses, in)
					}
					if m := innermostFunc(); m != nil {
						calls = append(calls, callSite{
							callerEnclosing: append([]string(nil), m.enclosing...),
							callerName:      m.funcName,
							callerArity:     m.funcArity,
							calleeName:      cname,
							calleeArity:     carity,
						})
					}
					i = after
					continue
				}
				i = next
			}

		default:
			i++
		}
	}
	return calls, ingresses
}

// isHandlerArity reports whether a function's arity matches a request-handler shape
// — Express/Node (req,res) or (req,res,next), or Next.js (req,res). A 1-arity
// handler ((ctx) for Koa-style default exports) is also accepted. This keeps a
// default-export utility that is plainly not a handler (arity 0) from being an
// ingress.
func isHandlerArity(arity int) bool {
	return arity >= 1 && arity <= 3
}

// routeArg captures a route-registration call's recognized handler argument: the
// LAST argument when it is a bare named function reference (the call-graph node we
// can connect an ingress to). For an inline-arrow handler the name is "" (the
// handler is anonymous; no call-graph node by name), so no ingress is recorded —
// the honest "no known ingress" outcome, never a fabricated node.
type routeArg struct {
	leaf       string // the method leaf ("get", "post", "use", "createServer", ...)
	handlerRef string // the named handler function ("" when anonymous/inline)
}

// routeIngress builds an http_route / http_server ingress marker for a recognized
// route-registration or server-factory call whose handler argument is a NAMED
// function reference. The handler ref names a module-level function (enclosing
// empty), so the ingress symbol coincides with that function's call-graph node.
// An anonymous handler (no named ref) records no ingress (sound: absence, never a
// fabricated entry).
func routeIngress(leaf string, h routeArg) (ingressMarker, bool) {
	if h.handlerRef == "" {
		return ingressMarker{}, false
	}
	switch {
	case routeMethods[leaf]:
		return ingressMarker{name: h.handlerRef, arity: handlerRefArity, kind: "http_route"}, true
	case serverFactories[leaf]:
		return ingressMarker{name: h.handlerRef, arity: handlerRefArity, kind: "http_server"}, true
	}
	return ingressMarker{}, false
}

// handlerRefArity is the arity an ingress marker records for a named handler
// reference. A request handler is matched against the declared handler function by
// its declared arity, which we cannot read from the bare reference; the call-graph
// resolver keys ingress symbols by the handler function's OWN declared arity, so
// the ingress marker carries a sentinel that FindIngresses re-resolves against the
// program's declared functions by name. See ingress.go resolveHandlerArity.
const handlerRefArity = -1

// callExprAt reports whether the identifier run starting at i is a call expression
// ("name(args)" or "a.b.name(args)"). It returns: the callee simple name (last
// segment), the qualifier leaf for ingress classification (also the last segment),
// the argument arity, the route-handler argument (named last arg, if any), the
// index just past the closing ')', and ok. JS keywords that take a parenthesized
// clause (if/for/while/switch/catch/return/...) are excluded so control flow is not
// a call.
func callExprAt(r []rune, i int) (name, leaf string, arity int, handler routeArg, after int, ok bool) {
	n := len(r)
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
		return "", "", 0, routeArg{}, 0, false
	}
	p := skipSpace(r, pos)
	// Optional TS generic call witness "foo<T>(...)".
	if p < n && r[p] == '<' {
		p = skipGroup(r, p)
		p = skipSpace(r, p)
	}
	if p >= n || r[p] != '(' {
		return "", "", 0, routeArg{}, 0, false
	}
	ar, end := parseParamArity(r, p)
	h := routeArg{leaf: last, handlerRef: lastArgNamedRef(r, p)}
	return last, last, ar, h, end, true
}

// lastArgNamedRef returns the name of a call's LAST argument when that argument is a
// bare identifier reference (a named function handler), else "". It is used to bind
// an Express/Node route handler reference to its declared function. An inline arrow,
// a member expression, or a literal yields "" (no named ref). Given the position of
// the call's opening '(', it scans the top-level argument list.
func lastArgNamedRef(r []rune, open int) string {
	n := len(r)
	depth := 0
	lastStart := -1 // start of the current top-level argument
	for pos := open; pos < n; pos++ {
		switch r[pos] {
		case '(', '[', '{':
			depth++
			if depth == 1 {
				lastStart = pos + 1
			}
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return soleIdent(r, lastStart, pos)
			}
		case ',':
			if depth == 1 {
				lastStart = pos + 1
			}
		}
	}
	return ""
}

// soleIdent returns the identifier spanning [start,end) iff that range is exactly
// one identifier token (optionally space-padded); otherwise "". A member expression
// ("obj.fn"), an arrow ("(x)=>"), or a literal ("_") is not a sole identifier.
func soleIdent(r []rune, start, end int) string {
	if start < 0 || start >= end {
		return ""
	}
	a := skipSpace(r, start)
	// trim trailing space
	b := end
	for b > a && (r[b-1] == ' ' || r[b-1] == '\t' || r[b-1] == '\n' || r[b-1] == '\r') {
		b--
	}
	if a >= b || !isIdentStart(r[a]) {
		return ""
	}
	word, np := readWord(r, a)
	if np != b {
		return "" // trailing non-identifier chars (".", "(", etc.)
	}
	if callKeywords[word] || word == "_" {
		return ""
	}
	return word
}

// callKeywords are JS/TS keywords that are followed by a parenthesized clause but
// are NOT method calls; excluding them prevents control flow from being recorded as
// a call edge.
var callKeywords = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true,
	"catch": true, "return": true, "new": true, "function": true,
	"throw": true, "do": true, "else": true, "yield": true,
	"await": true, "typeof": true, "delete": true, "void": true,
	"in": true, "of": true, "with": true, "super": true,
}
