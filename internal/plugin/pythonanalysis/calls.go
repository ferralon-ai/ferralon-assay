package pythonanalysis

import (
	"slices"
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
//
// written is the callee as the source writes it, whitespace collapsed and cut at 80 runes. A
// call through a value the scanner cannot name ("HANDLERS[k](x)", "make()(x)") has an empty
// name and chain and only written.
type callExpr struct {
	name    string
	arity   int
	chain   []string
	written string
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
	calleeWritten   string
	scopes          []string
	// inner marks a call whose name (or chain head) a lambda parameter or comprehension
	// variable in the same statement may bind, so no scope's import binding decides it.
	inner bool
	// shadowed marks a call in a class body whose name (or chain head) that body bound
	// earlier: the class attribute, not any def scope's binding, decides it.
	shadowed bool
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
	// guarded marks a binding inside an if/elif/else or try/except/else/finally block of
	// its scope (or on such a header line): an alternative, not a rebinding every path runs.
	guarded bool
}

// scopeKey identifies a def's body as a binding scope within one file.
func scopeKey(enclosing []string, name string, arity int) string {
	return strings.Join(enclosing, "#") + "#" + functionDescriptor(name, arity)
}

// fileScan is everything the call/ingress scanner reads from one file.
// decorated lists the defs under a decorator other than a route registration: the
// decorator receives the function as a value. relBindings are the relative imports'
// bindings (targets keep their leading dots), kept apart from bindings so they never name a
// dependency boundary.
type fileScan struct {
	calls       []callSite
	ingresses   []ingressMarker
	bindings    []scopedBinding
	relBindings []scopedBinding
	decorated   []funcDecl
	// wrapped lists the decorated defs whose decorators are not all known to hand back the
	// def itself or a cache that calls it (wrapsDef).
	wrapped []funcDecl
	refs    valueRefs
	// locals maps a scope to the names its parameters and assignments bind there: in a def
	// they shadow an import binding of the same name in an enclosing scope; at module and
	// class level ("") they are attributes another module may read.
	locals map[string]map[string]bool
	// plain is the subset of locals a scope binds outside any if or try block: parameters
	// and straight-line assignments, which every path through the scope runs.
	plain map[string]map[string]bool
	// binders counts, per scope and name, the bindings other than an import, def or class
	// that may hold the name's value at a call: each parameter, assignment, for or with or
	// except target, walrus and instance (a literal None excepted), and in the module scope
	// each binding a def makes after declaring the name global. defs marks the names a def
	// or class statement binds in a scope.
	binders map[string]map[string]int
	defs    map[string]map[string]bool
}

// countBinders adds one binding of each name to scope, except a literal None assignment.
func (fs *fileScan) countBinders(scope, st string, names []string) {
	if fs.binders == nil {
		fs.binders = map[string]map[string]int{}
	}
	m := fs.binders[scope]
	if m == nil {
		m = map[string]int{}
		fs.binders[scope] = m
	}
	for _, n := range names {
		if !assignsNone(st, n) {
			m[n]++
		}
	}
}

// assignsNone reports whether st is "name = None" (or "name: T = None").
func assignsNone(st, name string) bool {
	lhs, rhs, ok := strings.Cut(st, "=")
	if !ok || strings.TrimSpace(rhs) != "None" {
		return false
	}
	lhs, _, _ = strings.Cut(lhs, ":")
	return strings.TrimSpace(lhs) == name
}

// bindLocals records names a scope binds other than by import ("" is the module). guarded
// is true inside an if or try block of the scope.
func (fs *fileScan) bindLocals(scope string, names []string, guarded bool) {
	if len(names) == 0 {
		return
	}
	addNames(&fs.locals, scope, names)
	if !guarded {
		addNames(&fs.plain, scope, names)
	}
}

func addNames(into *map[string]map[string]bool, scope string, names []string) {
	if *into == nil {
		*into = map[string]map[string]bool{}
	}
	m := (*into)[scope]
	if m == nil {
		m = map[string]bool{}
		(*into)[scope] = m
	}
	for _, n := range names {
		m[n] = true
	}
}

// guardKeywords open a block whose bindings are alternatives to the rest of the scope's.
var guardKeywords = map[string]bool{"if": true, "elif": true, "else": true, "try": true, "except": true, "finally": true, "case": true}

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
	indent    int
	className string
	// classNames are the names a class frame's body has bound so far.
	classNames    map[string]bool
	funcName      string
	funcArity     int
	funcEnclosing []string
	// guard marks an if/elif/else or try/except/else/finally block.
	guard bool
}

// parseCallsAndIngresses scans the logical lines of one cleaned Python source file
// (already comment/string-stripped, continuations joined) and returns its call sites,
// framework ingress markers, import bindings, decorated defs, and the names it uses as
// values. It is an indentation-scoped, body-aware pass mirroring parseDecls: it tracks the
// enclosing class chain and the def whose body is currently open, so each call expression
// attributes to its caller def (or to module init when no def is open), and a Flask/FastAPI
// route decorator immediately above a def records that def as an ingress NAMING the handler
// (so the ingress symbol coincides with the handler's call-graph node).
//
// A decorator expression runs where the def statement runs, so its calls attribute to the
// enclosing frame, and a bare decorator ("@register") is itself a call with the def as its
// one argument. A def's or class's header runs there too (parameter defaults, bases); a
// body written on the header line ("def f(x): return g(x)") runs in the new frame.
func parseCallsAndIngresses(lines []logicalLine) fileScan {
	var stack []pyFrame
	fs := fileScan{refs: newValueRefs()}

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
	// frameSite is a call site attributed to the open frame: the innermost def, or module
	// init (callerName "") when no def is open, since module and class bodies run at import.
	frameSite := func() callSite {
		site := callSite{scopes: funcScopes()}
		if m := innermostFunc(); m != nil {
			site.callerEnclosing = append([]string(nil), m.funcEnclosing...)
			site.callerName = m.funcName
			site.callerArity = m.funcArity
		}
		return site
	}
	// owner is the innermost def or class frame.
	owner := func() *pyFrame {
		for i := len(stack) - 1; i >= 0; i-- {
			if !stack[i].guard {
				return &stack[i]
			}
		}
		return nil
	}
	addCalls := func(text string) {
		site := frameSite()
		inner := innerNames(text)
		for _, ce := range scanCalls(text) {
			cs := site
			cs.calleeName = ce.name
			cs.calleeArity = ce.arity
			cs.calleeChain = ce.chain
			cs.calleeWritten = ce.written
			head := ce.name
			if len(ce.chain) > 1 {
				head = ce.chain[0]
			}
			cs.inner = slices.Contains(inner, head)
			if o := owner(); o != nil && o.className != "" {
				cs.shadowed = o.classNames[head]
			}
			fs.calls = append(fs.calls, cs)
		}
	}
	// inGuard reports a guard block open inside the innermost def (or anywhere, at module
	// level).
	enclosingScope := func() string {
		if scopes := funcScopes(); len(scopes) > 0 {
			return scopes[len(scopes)-1]
		}
		return ""
	}
	inGuard := func() bool {
		for i := len(stack) - 1; i >= 0 && stack[i].funcName == ""; i-- {
			if stack[i].guard {
				return true
			}
		}
		return false
	}
	// globals and nonlocals hold, per def scope, the names it declares global or nonlocal.
	var globals, nonlocals map[string]map[string]bool
	// carry counts names bound in bindScope that a global or nonlocal declaration there
	// sends elsewhere: to the module, or to every enclosing def (the nearest one that binds
	// the name is the one Python picks; counting the others only withholds).
	carry := func(bindScope, st string, names []string) {
		if bindScope == "" {
			return
		}
		var global, nonlocal []string
		for _, n := range names {
			if globals[bindScope][n] {
				global = append(global, n)
			}
			if nonlocals[bindScope][n] {
				nonlocal = append(nonlocal, n)
			}
		}
		fs.countBinders("", st, global)
		if scopes := funcScopes(); len(nonlocal) > 0 && len(scopes) > 1 {
			for _, outer := range scopes[:len(scopes)-1] {
				fs.countBinders(outer, st, nonlocal)
			}
		}
	}
	// bind records the bindings one simple statement makes in bindScope. A compound header
	// with its body on the same line ("except ImportError: g = None") binds the body's
	// names too, as alternatives.
	var bind func(st, bindScope string, guarded bool)
	bind = func(st, bindScope string, guarded bool) {
		kw, rest := firstWord(st)
		if kw == "async" {
			st = strings.TrimSpace(rest)
			kw, rest = firstWord(st)
		}
		var names []string
		switch kw {
		case "import", "from":
			var imported []string
			for _, ib := range parseImportStatement(st) {
				fs.bindings = append(fs.bindings, scopedBinding{scope: bindScope, local: ib.local, target: ib.target, guarded: guarded})
				imported = append(imported, ib.local)
			}
			for _, ib := range parseRelativeImport(st) {
				fs.relBindings = append(fs.relBindings, scopedBinding{scope: bindScope, local: ib.local, target: ib.target, guarded: guarded})
				imported = append(imported, ib.local)
			}
			carry(bindScope, "", imported)
			return
		case "global", "nonlocal":
			return
		case "case":
			header, body := splitHeader(rest)
			if strings.TrimSpace(header) == "" || header == rest {
				break
			}
			for _, sub := range splitStatements(body) {
				bind(sub, bindScope, true)
			}
			names = captureNames(header)
			st = kw + " " + header + ":"
		case "if", "elif", "else", "try", "except", "finally", "while", "for", "with":
			header, body := splitHeader(rest)
			for _, sub := range splitStatements(body) {
				bind(sub, bindScope, true)
			}
			st = kw + " " + header + ":"
		}
		names = append(names, localNames(st)...)
		// A class body's names are class attributes, not names any function resolves; they
		// shadow only for the class body's own later calls.
		if o := owner(); o != nil && o.className != "" {
			if o.classNames == nil {
				o.classNames = map[string]bool{}
			}
			for _, n := range names {
				o.classNames[n] = true
			}
			return
		}
		fs.bindLocals(bindScope, names, guarded)
		fs.countBinders(bindScope, st, names)
		carry(bindScope, st, names)
		if local, chain, ok := instanceAssignment(st); ok {
			fs.bindings = append(fs.bindings, scopedBinding{scope: bindScope, local: local, inst: chain, guarded: guarded})
		}
	}
	statement := func(text string, guarded bool) {
		for _, st := range splitStatements(text) {
			kw, rest := firstWord(st)
			if kw == "async" {
				kw, _ = firstWord(strings.TrimSpace(rest))
			}
			scopes := funcScopes()
			bindScope := ""
			if len(scopes) > 0 {
				bindScope = scopes[len(scopes)-1]
			}
			guarded := guarded || guardKeywords[kw] || inGuard()
			if kw == "global" || kw == "nonlocal" {
				decl := &globals
				if kw == "nonlocal" {
					decl = &nonlocals
				}
				for _, n := range strings.Split(strings.TrimSpace(strings.TrimPrefix(st, kw)), ",") {
					addNames(decl, bindScope, []string{strings.TrimSpace(n)})
				}
				continue
			}
			bind(st, bindScope, guarded)
			if kw == "import" || kw == "from" || kw == "nonlocal" {
				continue
			}
			fs.refs.scan(st, false)
			addCalls(st)
		}
	}

	// pendingRoute marks that a route decorator ("@app.route(...)"/"@app.get(...)") has
	// been seen and the NEXT def is its handler ingress. It persists across stacked
	// non-route decorators until the def consumes it. pendingDecorated marks that some other
	// decorator receives the next def.
	pendingRoute := false
	pendingSelector := ""
	pendingDecorated := false
	pendingWrapped := false

	for _, ll := range lines {
		for len(stack) > 0 && ll.indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}

		text := ll.text
		if strings.HasPrefix(text, "@") {
			body := strings.TrimSpace(strings.TrimPrefix(text, "@"))
			if leaf, ok := routeDecorator(text); ok {
				pendingRoute = true
				pendingSelector = leaf
			} else {
				pendingDecorated = true
				pendingWrapped = pendingWrapped || !fs.wrapsDef(body)
			}
			site := frameSite()
			site.calleeArity = 1
			if isDottedName(body) {
				// "@a.deco" calls a.deco with the def: the leaf is in call position.
				site.calleeChain = strings.Split(body, ".")
				site.calleeName = site.calleeChain[len(site.calleeChain)-1]
				site.calleeWritten = body
				fs.refs.scan(body+"()", false)
			} else {
				// "@deco(args)": the calls in the expression run, then its value is called
				// with the def through a value the scanner cannot name.
				fs.refs.scan(body, false)
				addCalls(body)
				site.calleeWritten = collapseWritten("@" + body)
			}
			fs.calls = append(fs.calls, site)
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
			header, body := splitHeader(rest)
			_, bases := readIdent(header)
			fs.refs.scan(bases, false)
			addCalls(bases)
			if o := owner(); o == nil || o.className == "" {
				addNames(&fs.defs, enclosingScope(), []string{name})
			}
			stack = append(stack, pyFrame{indent: ll.indent, className: name})
			pendingRoute = false
			pendingDecorated = false
			pendingWrapped = false
			if body != "" {
				statement(body, false)
			}
		case "def":
			name, arity, ok := parseDefSignature(rest)
			if !ok {
				continue
			}
			header, body := splitHeader(rest)
			_, params := readIdent(header)
			fs.refs.scan(params, true)
			addCalls(params)
			enc := classChain()
			if pendingRoute {
				fs.ingresses = append(fs.ingresses, ingressMarker{
					enclosing: append([]string(nil), enc...),
					name:      name,
					arity:     arity,
					kind:      "http_route",
					selector:  pendingSelector,
				})
			}
			if pendingDecorated {
				fs.decorated = append(fs.decorated, funcDecl{enclosing: append([]string(nil), enc...), name: name, arity: arity})
			}
			if pendingWrapped {
				fs.wrapped = append(fs.wrapped, funcDecl{enclosing: append([]string(nil), enc...), name: name, arity: arity})
			}
			if o := owner(); o == nil || o.className == "" {
				addNames(&fs.defs, enclosingScope(), []string{name})
			}
			pendingRoute = false
			pendingDecorated = false
			pendingWrapped = false
			stack = append(stack, pyFrame{
				indent:        ll.indent,
				funcName:      name,
				funcArity:     arity,
				funcEnclosing: enc,
			})
			fs.bindLocals(scopeKey(enc, name, arity), paramNames(params), false)
			fs.countBinders(scopeKey(enc, name, arity), "", paramNames(params))
			if body != "" {
				statement(body, false)
			}
		default:
			pendingRoute = false
			pendingDecorated = false
			pendingWrapped = false
			statement(text, false)
			if guardKeywords[kw] {
				stack = append(stack, pyFrame{indent: ll.indent, guard: true})
			}
		}
	}
	return fs
}

// splitHeader splits a def or class statement (the text after its keyword) at the colon
// that ends its header, returning the header and any body written on the same line.
func splitHeader(rest string) (header, body string) {
	depth := 0
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ':':
			if depth == 0 {
				return rest[:i], strings.TrimSpace(rest[i+1:])
			}
		}
	}
	return rest, ""
}

// splitStatements splits a logical line at its top-level semicolons into the simple
// statements it holds.
func splitStatements(text string) []string {
	var out []string
	depth, from := 0, 0
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ';':
			if depth == 0 {
				if st := strings.TrimSpace(text[from:i]); st != "" {
					out = append(out, st)
				}
				from = i + 1
			}
		}
	}
	if st := strings.TrimSpace(text[from:]); st != "" {
		out = append(out, st)
	}
	return out
}

// paramNames lists the names a parameter list binds ("(self, a: int = 1, *args, **kw)" →
// self a args kw).
func paramNames(params string) []string {
	params = strings.TrimSpace(params)
	params = strings.TrimPrefix(params, "(")
	if c := matchingParamClose(params); c >= 0 {
		params = params[:c]
	}
	var out []string
	for _, p := range splitTopLevel(params, ',') {
		p = strings.TrimLeft(strings.TrimSpace(p), "*")
		if name, _ := readIdent(p); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// matchingParamClose returns the index of the ')' closing a parameter list whose '(' has
// been trimmed, or -1.
func matchingParamClose(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return i
			}
			depth--
		}
	}
	return -1
}

// splitTopLevel splits s at each sep outside brackets.
func splitTopLevel(s string, sep byte) []string {
	var out []string
	depth, from := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case sep:
			if depth == 0 {
				out = append(out, s[from:i])
				from = i + 1
			}
		}
	}
	return append(out, s[from:])
}

// localNames lists the names a simple statement binds in its scope: assignment and
// augmented-assignment targets, a for loop's targets, "as" names and walrus targets. A
// lambda's parameters and a comprehension's variables are not: they bind only inside the
// expression (innerNames). Over-reading only withholds an alias edge; the escape scan never
// narrows on it.
func localNames(st string) []string {
	var out []string
	var idents func(s string)
	idents = func(s string) {
		for _, part := range splitTopLevel(s, ',') {
			part = strings.TrimLeft(strings.TrimSpace(part), "*")
			if n := len(part); n >= 2 && (part[0] == '(' || part[0] == '[') && matchingParamClose(part[1:]) == n-2 {
				idents(part[1 : n-1])
				continue
			}
			if before, _, ok := strings.Cut(part, ":"); ok {
				part = before
			}
			if name, rest := readIdent(part); name != "" && strings.TrimSpace(rest) == "" {
				out = append(out, name)
			}
		}
	}
	if kw, rest := firstWord(st); kw == "for" {
		if target, _, ok := strings.Cut(rest, " in "); ok {
			idents(target)
		}
	}
	words := strings.Fields(st)
	for i := 0; i+1 < len(words); i++ {
		if words[i] == "as" {
			if name, _ := readIdent(words[i+1]); name != "" {
				out = append(out, name)
			}
		}
	}
	depth, from := 0, 0
	for i := 0; i < len(st); i++ {
		switch c := st[i]; c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ':':
			if i+1 < len(st) && st[i+1] == '=' {
				j := i
				for j > 0 && st[j-1] == ' ' {
					j--
				}
				k := j
				for k > 0 && isIdentPart(rune(st[k-1])) {
					k--
				}
				if k < j {
					out = append(out, st[k:j])
				}
			}
		case '=':
			if depth != 0 || (i+1 < len(st) && st[i+1] == '=') {
				continue
			}
			lhs := st[from:i]
			if i > 0 {
				switch st[i-1] {
				case '=', '!', ':':
					continue
				case '<', '>':
					if i < 2 || st[i-2] != st[i-1] {
						continue
					}
				}
			}
			idents(strings.TrimRight(lhs, "+-*/%&|^@<> "))
			from = i + 1
		}
	}
	return out
}

// defKeepingDecorators are the standard decorators that hand back the def itself, a
// descriptor over it, or a cache that calls it, keyed by module ("" for builtins).
var defKeepingDecorators = map[string]map[string]bool{
	"":                  {"staticmethod": true, "classmethod": true, "property": true},
	"functools":         {"wraps": true, "lru_cache": true, "cache": true, "cached_property": true},
	"abc":               {"abstractmethod": true},
	"typing":            {"overload": true, "override": true, "final": true},
	"typing_extensions": {"overload": true, "override": true, "final": true},
}

// wrapsDef reports whether a decorator expression (the text after "@") is one that keeps the
// def: a builtin by its bare name, a property's setter, getter or deleter, or a standard
// decorator named through its module or through a name the file imports from it.
func (fs *fileScan) wrapsDef(expr string) bool {
	if i := strings.IndexByte(expr, '('); i >= 0 {
		expr = expr[:i]
	}
	expr = strings.TrimSpace(expr)
	if !isDottedName(expr) {
		return false
	}
	segs := strings.Split(expr, ".")
	leaf := segs[len(segs)-1]
	switch {
	case len(segs) == 1 && defKeepingDecorators[""][leaf]:
		return true
	case len(segs) == 2 && (leaf == "setter" || leaf == "getter" || leaf == "deleter"):
		return true
	case len(segs) == 2:
		return defKeepingDecorators[segs[0]][leaf]
	case len(segs) == 1:
		found := false
		for _, b := range append(slices.Clone(fs.bindings), fs.relBindings...) {
			if b.local != leaf {
				continue
			}
			if mod, name, _ := strings.Cut(b.target, "."); !defKeepingDecorators[mod][name] || name != leaf || mod == "" {
				return false
			}
			found = true
		}
		return found
	}
	return false
}

// captureNames lists the names a match statement's case pattern may bind: every name in
// the pattern before any guard that is not an attribute, a dotted value's head, a class
// pattern's class or a keyword pattern's attribute. Over-reading only withholds.
func captureNames(pattern string) []string {
	r := []rune(pattern)
	depth := 0
	var out []string
	for i := 0; i < len(r); {
		switch r[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		}
		if !isIdentStartRune(r[i]) || (i > 0 && isIdentPart(r[i-1])) {
			i++
			continue
		}
		w, end := readWordRunes(r, i)
		if w == "if" && depth == 0 {
			break
		}
		p := skipSpaceRunes(r, end)
		next := p < len(r) && (r[p] == '(' || r[p] == '.' || (r[p] == '=' && !(p+1 < len(r) && r[p+1] == '=')))
		prev := prevSignificantRune(r, i)
		if !next && !(prev >= 0 && r[prev] == '.') && w != "_" && w != "as" && w != "None" && w != "True" && w != "False" {
			out = append(out, w)
		}
		i = end
	}
	return out
}

// innerNames lists the names a statement binds only inside one of its expressions: lambda
// parameters and comprehension (or for-header) variables. A call through one of them in the
// same statement may stand for whatever the expression is handed.
func innerNames(st string) []string {
	var out []string
	for rest := st; ; {
		i := strings.Index(rest, "lambda")
		if i < 0 {
			break
		}
		after := rest[i+len("lambda"):]
		if (i > 0 && isIdentPart(rune(rest[i-1]))) || (after != "" && isIdentPart(rune(after[0]))) {
			rest = after
			continue
		}
		if head, _, ok := strings.Cut(after, ":"); ok {
			for _, p := range splitTopLevel(head, ',') {
				p = strings.TrimLeft(strings.TrimSpace(p), "*")
				if name, _ := readIdent(p); name != "" {
					out = append(out, name)
				}
			}
		}
		rest = after
	}
	for rest := st; ; {
		i := strings.Index(rest, "for")
		if i < 0 {
			break
		}
		after := rest[i+len("for"):]
		if (i > 0 && isIdentPart(rune(rest[i-1]))) || (after != "" && isIdentPart(rune(after[0]))) {
			rest = after
			continue
		}
		if target, _, ok := strings.Cut(after, " in "); ok {
			for _, p := range splitTopLevel(target, ',') {
				p = strings.Trim(strings.TrimSpace(p), "()[]*")
				if name, _ := readIdent(p); name != "" {
					out = append(out, name)
				}
			}
		}
		rest = after
	}
	return out
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
// parenthesized clause are excluded so control flow is never a call. A '(' that follows a
// closing bracket calls a value the scanner cannot name ("t[k](x)", "f()(x)"): it is
// recorded with only its written form.
func scanCalls(text string) []callExpr {
	r := []rune(text)
	n := len(r)
	var out []callExpr
	// closeChain maps the index of a recorded call's closing ')' to that call's chain, so
	// a call on its result (").attr(") inherits it as the receiver prefix; closeStart maps
	// it to where that call's written form starts.
	closeChain := map[int][]string{}
	closeStart := map[int]int{}
	for i := 0; i < n; {
		if r[i] == '(' {
			if start, ok := calledValueStart(r, i); ok {
				out = append(out, callExpr{arity: paramArityAt(r, i), written: collapseWritten(string(r[start:i]))})
			}
			i++
			continue
		}
		if !isIdentStartRune(r[i]) {
			i++
			continue
		}
		var segs []string
		start := i
		if rc := receiverClose(r, i); rc >= 0 {
			if recv, ok := closeChain[rc]; ok {
				segs = append(segs, recv...)
				start = closeStart[rc]
			}
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
			out = append(out, callExpr{name: last, arity: paramArityAt(r, p), chain: segs, written: collapseWritten(string(r[start:pos]))})
			if c := matchingClose(r, p); c >= 0 {
				closeChain[c] = segs
				closeStart[c] = start
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

// calledValueStart reports whether the '(' at r[open] calls the value of a bracketed
// expression ("t[k](", "f()(", "(g)("), and returns where that callee expression starts.
func calledValueStart(r []rune, open int) (int, bool) {
	j := prevSignificantRune(r, open)
	if j < 0 || (r[j] != ')' && r[j] != ']') {
		return 0, false
	}
	start := j
	for {
		if r[j] == ')' || r[j] == ']' {
			o := matchingOpen(r, j)
			if o < 0 {
				return 0, false
			}
			start = o
			p := prevSignificantRune(r, o)
			if p >= 0 && (isIdentPart(r[p]) || r[p] == ')' || r[p] == ']') {
				j = p
				continue
			}
			return start, true
		}
		s := j
		for s > 0 && isIdentPart(r[s-1]) {
			s--
		}
		if pyCallKeywords[string(r[s:j+1])] {
			return start, true
		}
		start = s
		p := prevSignificantRune(r, s)
		if p < 0 || r[p] != '.' {
			return start, true
		}
		q := prevSignificantRune(r, p)
		if q < 0 || !(isIdentPart(r[q]) || r[q] == ')' || r[q] == ']') {
			return start, true
		}
		j = q
	}
}

// prevSignificantRune returns the index of the last non-space rune before pos, or -1.
func prevSignificantRune(r []rune, pos int) int {
	for p := pos - 1; p >= 0; p-- {
		if !unicode.IsSpace(r[p]) {
			return p
		}
	}
	return -1
}

// matchingOpen returns the index of the bracket opening the one closing at r[close], or -1
// when the text starts first.
func matchingOpen(r []rune, close int) int {
	depth := 0
	for i := close; i >= 0; i-- {
		switch r[i] {
		case ')', ']', '}':
			depth++
		case '(', '[', '{':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// collapseWritten is a callee's written form: whitespace collapsed, cut at 80 runes.
func collapseWritten(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 80 {
		s = string(r[:80])
	}
	return s
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
