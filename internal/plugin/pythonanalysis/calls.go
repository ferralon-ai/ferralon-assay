package pythonanalysis

import (
	"strings"
	"unicode"
)

// routeDecoratorLeafs are the Flask/FastAPI route-registration decorator method names.
// A decorator "@app.route(...)" (Flask) or "@app.get(...)" / "@router.post(...)" /
// "@app.websocket(...)" (FastAPI/Starlette) marks the FOLLOWING def as a request-handler
// ingress. Recognized by the decorator's call LEAF only (no object-type resolution): a
// same-named decorator on an unrelated object is a (rare) false positive the reachability
// layer tolerates — an ingress that reaches no sink yields no candidate pair (inv.5 stays
// on the safe side: an extra candidate, never a false not-affected).
//
// M1 scope is the Flask/FastAPI decorator family. Django URLconf (urlpatterns/path()),
// Celery @task, and raw WSGI/ASGI application callables are recognized frameworks in the
// Python skill's ingress list but are FOLLOW-ON: they are registration-table / callable
// shapes, not def decorators, so they need a distinct scanner and are not wired here.
var routeDecoratorLeafs = map[string]bool{
	"route": true, "get": true, "post": true, "put": true, "delete": true,
	"patch": true, "options": true, "head": true, "trace": true,
	"websocket": true, "api_route": true,
}

// pyCallKeywords are Python keywords that can be immediately followed by a '(' but are
// NOT call expressions; excluding them keeps control flow ("if (x):", "while (y):",
// "return (z)", "for i in (…)") from being recorded as call edges.
var pyCallKeywords = map[string]bool{
	"if": true, "elif": true, "else": true, "while": true, "for": true,
	"return": true, "yield": true, "assert": true, "del": true, "raise": true,
	"with": true, "except": true, "and": true, "or": true, "not": true,
	"in": true, "is": true, "lambda": true, "class": true, "def": true,
	"import": true, "from": true, "as": true, "pass": true, "break": true,
	"continue": true, "global": true, "nonlocal": true, "try": true,
	"finally": true, "await": true, "async": true, "print": false,
	"None": true, "True": true, "False": true,
}

// callExpr is one recognized call site: the callee's simple (leaf) name, its argument
// arity, and the full receiver chain. The leaf is the last segment of a dotted call
// ("a.b.fn(x)" → "fn"); the call graph resolves it against declared functions by (name,
// arity). chain is every dotted segment ending in the leaf ("a.b.fn(x)" → [a b fn]); when
// the receiver is itself a call result ("Environment().from_string(x)") the receiver
// call's chain is prefixed ([Environment from_string]), so an import binding on the first
// segment can name the dependency attribute the call reaches.
type callExpr struct {
	name  string
	arity int
	chain []string
}

// callSite is one call site: the caller (located by its enclosing class chain + name +
// arity, so its SCIP id coincides with the caller's declaration) and the callee's simple
// name + arity (resolved to a concrete declaration by the call graph). A call outside any
// def (module or class body, which run at import time) has callerName "" and is
// attributed to the module-init node. scopes lists the function scopes enclosing the call,
// outer→inner, so an import binding made inside a function applies to calls in it.
type callSite struct {
	callerEnclosing []string
	callerName      string
	callerArity     int
	calleeName      string
	calleeArity     int
	calleeChain     []string
	scopes          []string
}

// scopedBinding is a name bound by an import (or by instantiating an imported class) in
// one scope: scope "" is the module, otherwise the scopeKey of the def that holds it.
// Exactly one of target (a dotted import path) and inst (the chain of the call whose
// result the name holds, resolved through the import bindings later) is set.
type scopedBinding struct {
	scope  string
	local  string
	target string
	inst   []string
}

// scopeKey identifies a def's body as a binding scope within one file.
func scopeKey(enclosing []string, name string, arity int) string {
	return strings.Join(enclosing, "#") + "#" + functionDescriptor(name, arity)
}

// fileScan is everything the call/ingress scanner reads from one file.
type fileScan struct {
	calls     []callSite
	ingresses []ingressMarker
	bindings  []scopedBinding
}

// ingressMarker is one framework entry point discovered lexically: a Flask/FastAPI route
// handler def, located by its enclosing class chain + name + arity so its SCIP id
// coincides with the handler function's declaration (and thus its call-graph node). kind
// is the plugin Ingress kind ("http_route"); selector is the decorator method leaf
// ("route", "get", …) — the path string is not recoverable after literal-stripping.
type ingressMarker struct {
	enclosing []string
	name      string
	arity     int
	kind      string
	selector  string
}

// pyFrame is one entry on the indentation scope stack used by the call/ingress scanner. A
// class frame records the class name (so a method call attributes its caller under the
// class); a function frame records the def whose body is open (so call sites inside it
// name their caller) plus the class chain enclosing that def (for the caller's SCIP id).
type pyFrame struct {
	indent        int
	className     string
	funcName      string
	funcArity     int
	funcEnclosing []string
}

// parseCallsAndIngresses scans the logical lines of one cleaned Python source file
// (already comment/string-stripped, continuations joined) and returns its call sites,
// framework ingress markers, and import bindings. It is an indentation-scoped, body-aware
// pass mirroring parseDecls: it tracks the enclosing class chain and the def whose body is
// currently open, so each call expression attributes to its caller def (or to module init
// when no def is open), and a Flask/FastAPI route decorator immediately above a def records
// that def as an ingress NAMING the handler (so the ingress symbol coincides with the
// handler's call-graph node).
func parseCallsAndIngresses(lines []logicalLine) fileScan {
	var stack []pyFrame
	var calls []callSite
	var ingresses []ingressMarker
	var bindings []scopedBinding

	classChain := func() []string {
		var out []string
		for _, s := range stack {
			if s.className != "" {
				out = append(out, s.className)
			}
		}
		return out
	}
	innermostFunc := func() *pyFrame {
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i].funcName != "" {
				return &stack[i]
			}
		}
		return nil
	}
	funcScopes := func() []string {
		var out []string
		for _, s := range stack {
			if s.funcName != "" {
				out = append(out, scopeKey(s.funcEnclosing, s.funcName, s.funcArity))
			}
		}
		return out
	}

	// pendingRoute marks that a route decorator ("@app.route(...)"/"@app.get(...)") has
	// been seen and the NEXT def is its handler ingress. It persists across stacked
	// non-route decorators until the def consumes it.
	pendingRoute := false
	pendingSelector := ""

	for _, ll := range lines {
		for len(stack) > 0 && ll.indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}

		text := ll.text
		if strings.HasPrefix(text, "@") {
			if leaf, ok := routeDecorator(text); ok {
				pendingRoute = true
				pendingSelector = leaf
			}
			continue
		}

		kw, rest := firstWord(text)
		if kw == "async" {
			kw, rest = firstWord(strings.TrimSpace(rest))
		}
		switch kw {
		case "class":
			name, ok := parseClassName(rest)
			if !ok {
				continue
			}
			stack = append(stack, pyFrame{indent: ll.indent, className: name})
			pendingRoute = false
		case "def":
			name, arity, ok := parseDefSignature(rest)
			if !ok {
				continue
			}
			enc := classChain()
			if pendingRoute {
				ingresses = append(ingresses, ingressMarker{
					enclosing: append([]string(nil), enc...),
					name:      name,
					arity:     arity,
					kind:      "http_route",
					selector:  pendingSelector,
				})
			}
			pendingRoute = false
			stack = append(stack, pyFrame{
				indent:        ll.indent,
				funcName:      name,
				funcArity:     arity,
				funcEnclosing: enc,
			})
		default:
			pendingRoute = false
			scopes := funcScopes()
			bindScope := ""
			if len(scopes) > 0 {
				bindScope = scopes[len(scopes)-1]
			}
			if kw == "import" || kw == "from" {
				for _, ib := range parseImportStatement(text) {
					bindings = append(bindings, scopedBinding{scope: bindScope, local: ib.local, target: ib.target})
				}
				continue
			}
			if local, chain, ok := instanceAssignment(text); ok {
				bindings = append(bindings, scopedBinding{scope: bindScope, local: local, inst: chain})
			}
			// A call outside any def runs when the module (or class body) executes at
			// import time; it is attributed to the module-init caller (callerName "").
			var site callSite
			if m := innermostFunc(); m != nil {
				site = callSite{
					callerEnclosing: append([]string(nil), m.funcEnclosing...),
					callerName:      m.funcName,
					callerArity:     m.funcArity,
				}
			}
			for _, ce := range scanCalls(text) {
				cs := site
				cs.calleeName = ce.name
				cs.calleeArity = ce.arity
				cs.calleeChain = ce.chain
				cs.scopes = scopes
				calls = append(calls, cs)
			}
		}
	}
	return fileScan{calls: calls, ingresses: ingresses, bindings: bindings}
}

// routeDecorator reports whether a decorator line is a Flask/FastAPI route registration
// and returns the decorator's call leaf ("route", "get", …). A decorator must be a CALL
// ("@app.route(...)") whose leaf is a recognized route method; a bare decorator
// ("@login_required", "@pytest.fixture") is not a route.
func routeDecorator(text string) (leaf string, ok bool) {
	body := strings.TrimSpace(strings.TrimPrefix(text, "@"))
	calls := scanCalls(body)
	if len(calls) == 0 {
		return "", false
	}
	if routeDecoratorLeafs[calls[0].name] {
		return calls[0].name, true
	}
	return "", false
}

// scanCalls extracts every call expression in a cleaned logical-line's text: for each
// identifier run (possibly dotted, "a.b.fn") immediately followed by '(', it records the
// LEAF name and the top-level argument arity. Scanning continues INSIDE the argument list
// so nested calls ("foo(bar(x))" → foo and bar) are all found. Python keywords that take a
// parenthesized clause are excluded so control flow is never a call.
func scanCalls(text string) []callExpr {
	r := []rune(text)
	n := len(r)
	var out []callExpr
	// closeChain maps the index of a recorded call's closing ')' to that call's chain, so
	// a call on its result (").attr(") inherits it as the receiver prefix.
	closeChain := map[int][]string{}
	for i := 0; i < n; {
		if !isIdentStartRune(r[i]) {
			i++
			continue
		}
		var segs []string
		if recv, ok := closeChain[receiverClose(r, i)]; ok {
			segs = append(segs, recv...)
		}
		last := ""
		pos := i
		for pos < n {
			if isIdentStartRune(r[pos]) {
				var w string
				w, pos = readWordRunes(r, pos)
				last = w
				segs = append(segs, w)
			} else if r[pos] == '.' {
				pos++
			} else {
				break
			}
		}
		p := skipSpaceRunes(r, pos)
		if last != "" && !pyCallKeywords[last] && p < n && r[p] == '(' {
			out = append(out, callExpr{name: last, arity: paramArity(string(r[p:])), chain: segs})
			if c := matchingClose(r, p); c >= 0 {
				closeChain[c] = segs
			}
		}
		if pos > i {
			i = pos
		} else {
			i++
		}
	}
	return out
}

// receiverClose returns the index of the ')' that closes a call whose result the
// identifier at r[i] is an attribute of (").name"), or -1 when r[i] is not such an
// attribute.
func receiverClose(r []rune, i int) int {
	j := i - 1
	for j >= 0 && unicode.IsSpace(r[j]) {
		j--
	}
	if j < 0 || r[j] != '.' {
		return -1
	}
	j--
	for j >= 0 && unicode.IsSpace(r[j]) {
		j--
	}
	if j < 0 || r[j] != ')' {
		return -1
	}
	return j
}

// matchingClose returns the index of the bracket closing the '(' at r[open], or -1 when
// the line ends first.
func matchingClose(r []rune, open int) int {
	depth := 0
	for i := open; i < len(r); i++ {
		switch r[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// isIdentStartRune reports whether c may start a Python identifier (letter or underscore;
// never a digit).
func isIdentStartRune(c rune) bool {
	return c == '_' || unicode.IsLetter(c)
}

// readWordRunes reads the identifier at r[i:] and returns it with the index just past it.
func readWordRunes(r []rune, i int) (string, int) {
	start := i
	for i < len(r) && isIdentPart(r[i]) {
		i++
	}
	return string(r[start:i]), i
}

// skipSpaceRunes returns the index of the first non-space rune at or after i.
func skipSpaceRunes(r []rune, i int) int {
	for i < len(r) && unicode.IsSpace(r[i]) {
		i++
	}
	return i
}
