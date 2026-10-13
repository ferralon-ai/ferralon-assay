package jsanalysis

import (
	"fmt"
	"sort"
)

// moduleInitFunc names the synthetic frame that owns a module's top-level code. Module
// code runs when the module is loaded, so a call written at the top level (or inside an
// anonymous function at the top level) is attributed to this frame rather than dropped,
// and every module's frame is a call-graph root. The backticks are SCIP's escaped-
// identifier form; the angle brackets keep it disjoint from any declarable JS name.
const moduleInitFunc = "`<module-init>`"

// moduleInitSCIP is the SCIP id of module's top-level frame.
func moduleInitSCIP(module string) string {
	return funcSCIP(module, nil, moduleInitFunc, 0)
}

// anonHandlerFunc names the synthetic frame for a function expression passed to a route
// method or server factory. A named function expression's name binds only inside its own
// body, so the frame is keyed by position even then: the name would share an id with a
// same-named module-level function and merge the two bodies. Its line:column (1-based, in
// runes of the stripped source, which is length-preserving) keeps the id stable and unique
// per file.
func anonHandlerFunc(line, col int) string {
	return fmt.Sprintf("`<handler@%d:%d>`", line, col)
}

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
// argument is a request ingress: http.createServer,
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
	end       int      // > 0 for an expression-bodied arrow: the frame closes when the scan reaches end
}

// handlerExpr is an inline function expression found as a top-level argument of a
// route-method / server-factory call, waiting for the scan to reach it.
type handlerExpr struct {
	kind  string // ingress kind: "http_route" | "http_server"
	arity int
	open  int // index of the body-opening '{'; -1 for an expression body
	body  int // first index of an expression body
	end   int // index of the ',' or ')' that ends the argument
}

// parseCallsAndIngresses scans cleaned JS/TS source (already comment/string-
// stripped) and returns the call sites and the framework ingress markers. It is a
// body-aware pass: it tracks the enclosing class chain and the function whose body
// is currently open, so a call expression attributes to its caller, and a
// route-registration / server-factory / default-export handler is recorded as an
// ingress NAMING the handler function (so the ingress symbol coincides with a
// call-graph node). A call outside every named function attributes to the module's
// top-level frame (moduleInitFunc). Call arguments are scanned too, so calls nested
// in an argument — including the body of an inline callback — are not lost; an inline
// function passed to a route method or server factory gets its own frame, an ingress,
// and an edge from the frame that registered it.
func parseCallsAndIngresses(r []rune) ([]callSite, []ingressMarker) {
	n := len(r)
	var stack []bodyFrame
	var calls []callSite
	var ingresses []ingressMarker
	moduleInit := bodyFrame{funcName: moduleInitFunc}
	pending := map[int]handlerExpr{}
	var lineStarts []int

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
		return &moduleInit
	}
	lineCol := func(pos int) (int, int) {
		if lineStarts == nil {
			lineStarts = []int{0}
			for k, c := range r {
				if c == '\n' {
					lineStarts = append(lineStarts, k+1)
				}
			}
		}
		line := sort.SearchInts(lineStarts, pos+1) // index of the first line starting after pos == 1-based line of pos
		return line, pos - lineStarts[line-1] + 1
	}
	// enterHandler opens the frame of a pending inline handler at its first rune and
	// records its ingress plus the edge from the frame that registered it.
	enterHandler := func(at int, h handlerExpr) int {
		enc := enclosingChain()
		name := anonHandlerFunc(lineCol(at))
		ingresses = append(ingresses, ingressMarker{
			enclosing: append([]string(nil), enc...),
			name:      name, kind: h.kind, arity: h.arity, frame: true,
		})
		m := innermostFunc()
		calls = append(calls, callSite{
			callerEnclosing: append([]string(nil), m.enclosing...),
			callerName:      m.funcName,
			callerArity:     m.funcArity,
			calleeName:      name,
			calleeArity:     h.arity,
			calleeEnclosing: append([]string(nil), enc...),
			calleeFrame:     true,
		})
		f := bodyFrame{enclosing: enc, funcName: name, funcArity: h.arity}
		if h.open >= 0 {
			stack = append(stack, f)
			return h.open + 1
		}
		f.end = h.end
		stack = append(stack, f)
		return h.body
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
		for len(stack) > 0 && stack[len(stack)-1].end > 0 && i >= stack[len(stack)-1].end {
			stack = stack[:len(stack)-1]
		}
		if h, ok := pending[i]; ok {
			delete(pending, i)
			pendingExportDefault = false
			i = enterHandler(i, h)
			continue
		}
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
							name:      mname, kind: "handler",
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
							name:      mname, kind: "handler",
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
				i = skipImportStatement(r, next)
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
				if ce, isCall := callExprAt(r, i); isCall {
					if in, ok := routeIngress(ce.leaf, ce.handler); ok {
						ingresses = append(ingresses, in)
					}
					m := innermostFunc()
					recv := ce.receiver
					recvThis := false
					if recv == "this" {
						recv = ""
						recvThis = true
					}
					// A module-level require(...) is the loader, not a callee to resolve: its
					// specifier is recorded by extractModuleBindings, and callGraphInternal
					// declares an out-of-tree one uninspectable.
					moduleRequire := m == &moduleInit && ce.name == "require" && ce.head == ""
					if !moduleRequire {
						calls = append(calls, callSite{
							callerEnclosing: append([]string(nil), m.enclosing...),
							callerName:      m.funcName,
							callerArity:     m.funcArity,
							calleeName:      ce.name,
							calleeArity:     ce.arity,
							receiver:        recv,
							receiverThis:    recvThis,
							head:            ce.head,
						})
					}
					if kind := handlerKind(ce.leaf); kind != "" {
						for _, h := range inlineHandlerArgs(r, ce.open, kind) {
							pending[skipSpace(r, h.start)] = h.expr
						}
					}
					// Continue inside the argument list so nested calls and inline
					// callback bodies are scanned in the current frame.
					i = ce.open + 1
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

// skipImportStatement advances past an `import` statement's remainder, starting just
// after the `import` keyword. It skips a balanced `{...}` named-import group (which may
// span lines) and terminates at the first `;` OR newline — ESM import statements are
// newline-terminated under ASI, so a semicolon is optional. The former skip-to-`;`
// consumed the whole file when an import had no trailing semicolon (the Prettier/Vue
// `<script setup>` idiom), swallowing every call site after the imports.
func skipImportStatement(r []rune, pos int) int {
	n := len(r)
	for pos < n {
		switch r[pos] {
		case '{':
			pos = skipGroup(r, pos)
		case ';', '\n':
			return pos + 1
		default:
			pos++
		}
	}
	return n
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
// can connect an ingress to). An inline function expression has no reference name
// here; inlineHandlerArgs gives it its own frame instead.
type routeArg struct {
	leaf       string // the method leaf ("get", "post", "use", "createServer", ...)
	handlerRef string // the named handler function ("" when anonymous/inline)
}

// routeIngress builds an http_route / http_server ingress marker for a recognized
// route-registration or server-factory call whose handler argument is a NAMED
// function reference. The handler ref names a module-level function (enclosing
// empty), so the ingress symbol coincides with that function's call-graph node.
// An inline handler is recorded by inlineHandlerArgs, not here.
func routeIngress(leaf string, h routeArg) (ingressMarker, bool) {
	if h.handlerRef == "" {
		return ingressMarker{}, false
	}
	if kind := handlerKind(leaf); kind != "" {
		return ingressMarker{name: h.handlerRef, kind: kind}, true
	}
	return ingressMarker{}, false
}

// handlerKind is the ingress kind for a call whose method leaf registers a request
// handler, or "" when the leaf is neither a route method nor a server factory.
func handlerKind(leaf string) string {
	switch {
	case routeMethods[leaf]:
		return "http_route"
	case serverFactories[leaf]:
		return "http_server"
	}
	return ""
}

// inlineHandler is one inline function-expression argument and where it starts.
type inlineHandler struct {
	start int
	expr  handlerExpr
}

// inlineHandlerArgs returns every top-level argument of the call opening at open that
// is an inline function expression (arrow or function), each tagged with kind. Express
// accepts middleware before the final handler, so every such argument is a handler.
func inlineHandlerArgs(r []rune, open int, kind string) []inlineHandler {
	var out []inlineHandler
	depth := 0
	start := open + 1
	for pos := open; pos < len(r); pos++ {
		switch r[pos] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				if h, ok := funcExprAt(r, start, pos); ok {
					h.kind = kind
					out = append(out, inlineHandler{start: start, expr: h})
				}
				return out
			}
		case ',':
			if depth == 1 {
				if h, ok := funcExprAt(r, start, pos); ok {
					h.kind = kind
					out = append(out, inlineHandler{start: start, expr: h})
				}
				start = pos + 1
			}
		}
	}
	return out
}

// funcExprAt reports whether the argument spanning [start,end) is a function
// expression: "function [name](params) {", "(params) => body", or "x => body", each
// optionally async. A block body reports its '{'; an expression body runs to end.
func funcExprAt(r []rune, start, end int) (handlerExpr, bool) {
	pos := skipSpace(r, start)
	if w, nx := peekWord(r, pos); w == "async" {
		pos = skipSpace(r, nx)
	}
	if w, nx := peekWord(r, pos); w == "function" {
		pos = skipSpace(r, nx)
		if pos < end && r[pos] == '*' {
			pos = skipSpace(r, pos+1)
		}
		if pos < end && isIdentStart(r[pos]) {
			_, pos = readWord(r, pos)
			pos = skipSpace(r, pos)
		}
		if pos >= end || r[pos] != '(' {
			return handlerExpr{}, false
		}
		arity, after := parseParamArity(r, pos)
		open := scanToBrace(r, after)
		if open < 0 || open >= end {
			return handlerExpr{}, false
		}
		return handlerExpr{arity: arity, open: open}, true
	}
	var arity, after int
	parens := false
	switch {
	case pos < end && r[pos] == '(':
		arity, after = parseParamArity(r, pos)
		parens = true
	case pos < end && isIdentStart(r[pos]):
		_, after = readWord(r, pos)
		arity = 1
	default:
		return handlerExpr{}, false
	}
	after = skipSpace(r, after)
	if parens && after < end && r[after] == ':' { // TS return type before "=>"
		for after < end && !(r[after] == '=' && after+1 < end && r[after+1] == '>') {
			after++
		}
	}
	if after+1 >= end || r[after] != '=' || r[after+1] != '>' {
		return handlerExpr{}, false
	}
	body := skipSpace(r, after+2)
	if body < end && r[body] == '{' {
		return handlerExpr{arity: arity, open: body}, true
	}
	return handlerExpr{arity: arity, open: -1, body: body, end: end}, true
}

// callExpr is a recognized call expression ("name(args)" or "a.b.name(args)").
type callExpr struct {
	name     string   // callee simple name (last segment)
	leaf     string   // qualifier leaf for ingress classification (also the last segment)
	arity    int      // argument count
	handler  routeArg // the route-handler argument (named last arg, if any)
	receiver string   // the single-identifier receiver of "recv.name(...)"; "" otherwise
	head     string   // first segment of a dotted chain ("JSON5" in JSON5.parse); "" for a bare call
	open     int      // index of the argument list's '('
}

// callExprAt reports whether the identifier run starting at i is a call expression
// ("name(args)" or "a.b.name(args)"). JS keywords that take a parenthesized clause
// (if/for/while/switch/catch/return/...) are excluded so control flow is not a call.
func callExprAt(r []rune, i int) (callExpr, bool) {
	n := len(r)
	pos := i
	last := ""
	first := ""
	prev := "" // the member-access segment immediately before the leaf ("jar" in jar.setCookie)
	segs := 0  // number of dotted segments consumed
	for pos < n {
		if isIdentStart(r[pos]) {
			prev = last
			last, pos = readWord(r, pos)
			if segs == 0 {
				first = last
			}
			segs++
		} else if r[pos] == '.' {
			pos++
		} else {
			break
		}
	}
	if last == "" || callKeywords[last] {
		return callExpr{}, false
	}
	p := skipSpace(r, pos)
	// Optional TS generic call witness "foo<T>(...)".
	if p < n && r[p] == '<' {
		p = skipGroup(r, p)
		p = skipSpace(r, p)
	}
	if p >= n || r[p] != '(' {
		return callExpr{}, false
	}
	ar, _ := parseParamArity(r, p)
	// A receiver is genuine only when the whole prefix before the leaf is a single
	// identifier ("recv.method", segs==2). For a longer chain ("a.b.c") the prefix is
	// a member expression, not a local instance; reporting the intermediate segment
	// ("b") as the receiver would route the call to receiver-method resolution, which
	// fail-closes on the non-instance and drops the edge. Leave the receiver empty so
	// the leaf resolves through the bare-name path (whose own ambiguity guard keeps it
	// fail-closed against fabrication).
	ce := callExpr{name: last, leaf: last, arity: ar, handler: routeArg{leaf: last, handlerRef: lastArgNamedRef(r, p)}, open: p}
	if segs == 2 {
		ce.receiver = prev
	}
	if segs >= 2 {
		ce.head = first
	}
	return ce, true
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
