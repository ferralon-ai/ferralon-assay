package dotnetanalysis

import "unicode"

// httpMethodAttributes are the ASP.NET Core MVC / Web API action attributes that mark a
// controller method as an HTTP endpoint. A method carrying any of these attributes is a
// request ingress whose handler IS the method itself (like a Java Spring @GetMapping or a
// Python route decorator — the annotation sits on the handler, so its SCIP id is known at
// the declaration site). Recognized by attribute NAME leaf only (arguments are stripped to
// a literal '_'); a same-named attribute in an unrelated position is a rare false positive
// the reachability layer tolerates (an ingress that reaches no sink yields no candidate).
//
// MVP scope is the ASP.NET Core controller attribute family + the minimal-API map methods
// below. Blazor component routes (@page), gRPC service methods, and SignalR hub methods are
// distinct registration shapes (follow-on, named in the .NET skill's ingress list).
var httpMethodAttributes = map[string]bool{
	"HttpGet": true, "HttpPost": true, "HttpPut": true, "HttpDelete": true,
	"HttpPatch": true, "HttpHead": true, "HttpOptions": true, "Route": true,
}

// minimalAPIMapMethods are the ASP.NET Core minimal-API endpoint registration methods on
// WebApplication / IEndpointRouteBuilder: app.MapGet("/x", Handler) registers Handler as an
// HTTP endpoint. The handler argument, when a bare NAMED method-group reference (the last
// argument), is the ingress — resolved to its declared method by name (the same reference
// re-resolution the Express/Node route path uses). An inline lambda handler has no named
// reference, so it records no ingress (honest absence, never a fabricated node).
var minimalAPIMapMethods = map[string]bool{
	"MapGet": true, "MapPost": true, "MapPut": true, "MapDelete": true,
	"MapPatch": true, "MapMethods": true,
}

// csharpCallKeywords are C# keywords that can be immediately followed by a '(' but are NOT
// method calls; excluding them keeps control flow ("if (x)", "while (y)", "return (z)",
// "new T(...)") and operator-like keywords ("typeof", "nameof", "sizeof") from being
// recorded as call edges. "new T(...)" is handled by excluding the "new" leaf: the scanner
// re-reaches the following type name and records the constructor call under the type name
// (which resolves to the constructor declaration, indexed as a method).
var csharpCallKeywords = map[string]bool{
	"if": true, "for": true, "foreach": true, "while": true, "switch": true,
	"catch": true, "using": true, "lock": true, "fixed": true, "return": true,
	"new": true, "throw": true, "yield": true, "await": true, "do": true,
	"else": true, "in": true, "is": true, "as": true, "out": true, "ref": true,
	"typeof": true, "nameof": true, "sizeof": true, "default": true,
	"checked": true, "unchecked": true, "stackalloc": true, "when": true,
	"case": true, "where": true, "select": true, "from": true,
}

// handlerRefArity is the sentinel arity an ingress marker records for a minimal-API handler
// named by REFERENCE (a method group). The reference carries no arity, so the call graph /
// FindIngresses re-resolves it against the program's declared methods by name (resolving
// iff EXACTLY ONE method declares that name). See program.resolveIngressSymbol.
const handlerRefArity = -1

// callSite is one call inside a method body: the caller (located by its namespace +
// enclosing-type chain + name + arity, so its SCIP id coincides with the caller's
// declaration) and the callee's simple name + arity (resolved to a concrete declaration by
// the call graph). Only calls inside a BLOCK-bodied method are attributed (an expression-
// bodied member's body is not scanned for calls — a declared-partial lexical limitation
// that never fabricates an edge).
type callSite struct {
	callerNamespace string
	callerEnclosing []string
	callerName      string
	callerArity     int
	calleeName      string
	calleeArity     int
}

// ingressMarker is one framework entry point discovered lexically. For a controller action
// (HTTP attribute on the method) the namespace + enclosing chain + name + arity are known,
// so the handler's SCIP id is built directly. For a minimal-API registration the handler is
// named by REFERENCE (arity == handlerRefArity, namespace/enclosing empty), re-resolved by
// name. kind is the plugin Ingress kind ("http_route"); selector is the attribute or map
// method leaf ("HttpGet", "MapGet", "Route", …) — the route path string is not recoverable
// after literal-stripping.
type ingressMarker struct {
	namespace string
	enclosing []string
	name      string
	arity     int
	kind      string
	selector  string
}

// scanFrame is one entry on the brace-block stack used by the call/ingress scanner. A frame
// is a namespace frame (nsName set), a type frame (typeName set), a method-body frame
// (funcName set, carrying the namespace and type chain captured at the method's declaration
// so its call sites name their caller's SCIP id), or a plain block (all empty).
type scanFrame struct {
	nsName        string
	typeName      string
	funcName      string
	funcArity     int
	funcNamespace string
	funcEnclosing []string
}

// parseCallsAndIngresses scans cleaned C# source (already comment/string/char-literal and
// preprocessor stripped) and returns the call sites and framework ingress markers. It is a
// body-aware, brace-scoped pass mirroring parseDecls: it tracks the enclosing namespace and
// type chain and the method whose block body is currently open, so each call expression
// attributes to its caller method. A method carrying an ASP.NET HTTP attribute is recorded
// as a controller ingress (handler = the method); an app.MapGet-style minimal-API
// registration whose handler argument is a named method group is recorded as a reference
// ingress. It never fabricates: an anonymous handler or an unresolved reference records no
// ingress, and a call whose callee cannot be resolved records no edge (handled downstream).
func parseCallsAndIngresses(r []rune) ([]callSite, []ingressMarker) {
	n := len(r)
	var stack []scanFrame
	var calls []callSite
	var ingresses []ingressMarker
	fileNamespace := ""

	currentNamespace := func() string {
		var parts []string
		if fileNamespace != "" {
			parts = append(parts, fileNamespace)
		}
		for _, f := range stack {
			if f.nsName != "" {
				parts = append(parts, f.nsName)
			}
		}
		return joinDots(parts)
	}
	typeChain := func() []string {
		var out []string
		for _, f := range stack {
			if f.typeName != "" {
				out = append(out, f.typeName)
			}
		}
		return out
	}
	inTypeBody := func() bool {
		return len(stack) > 0 && stack[len(stack)-1].typeName != ""
	}
	innermostFunc := func() *scanFrame {
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i].funcName != "" {
				return &stack[i]
			}
		}
		return nil
	}

	// pendingIngress marks that an HTTP action attribute preceded the current member, so the
	// NEXT method declaration is a controller ingress. pendingSelector is its verb/route
	// attribute leaf. Both reset when a member, type, or block boundary consumes them.
	pendingIngress := false
	pendingSelector := ""

	i := 0
	for i < n {
		c := r[i]
		switch {
		case c == '{':
			stack = append(stack, scanFrame{})
			pendingIngress = false
			pendingSelector = ""
			i++

		case c == '}':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			pendingIngress = false
			pendingSelector = ""
			i++

		case c == '[':
			// An attribute group at type-body depth may mark the following method as an
			// ingress; anywhere else (array/collection/local attribute) it is skipped.
			sel, ok, after := attrHTTPMethod(r, i)
			if inTypeBody() && ok {
				pendingIngress = true
				pendingSelector = preferSelector(pendingSelector, sel)
			}
			i = after

		case isIdentStart(c):
			word, next := readWord(r, i)
			switch {
			case word == "namespace":
				name, openIdx, fileScoped, ok := parseNamespaceHeader(r, next)
				if !ok {
					i = next
					continue
				}
				if fileScoped {
					if fileNamespace == "" {
						fileNamespace = name
					} else {
						fileNamespace += "." + name
					}
				} else {
					stack = append(stack, scanFrame{nsName: name})
				}
				pendingIngress = false
				pendingSelector = ""
				i = openIdx + 1
				continue

			case typeKeywords[word]:
				name, openIdx, hasBody, ok := parseTypeHeader(r, next)
				if !ok {
					i = next
					continue
				}
				pendingIngress = false
				pendingSelector = ""
				if hasBody {
					stack = append(stack, scanFrame{typeName: name})
				}
				i = openIdx + 1
				continue

			default:
				if inTypeBody() {
					if mname, marity, contIdx, hasBlock, ok := methodDeclAt(r, i); ok {
						ns := currentNamespace()
						enc := typeChain()
						if in, isIn := attrIngress(pendingIngress, pendingSelector, ns, enc, mname, marity); isIn {
							ingresses = append(ingresses, in)
						}
						pendingIngress = false
						pendingSelector = ""
						if hasBlock {
							stack = append(stack, scanFrame{
								funcName:      mname,
								funcArity:     marity,
								funcNamespace: ns,
								funcEnclosing: enc,
							})
							i = contIdx + 1
						} else {
							i = contIdx
						}
						continue
					}
				}
				// Not a member declaration: try a call expression (a controller-body call,
				// a utility call, or a minimal-API map registration at any depth).
				if _, leaf, carity, handlerRef, after, isCall := callExprAt(r, i); isCall {
					if in, ok := minimalAPIIngress(leaf, handlerRef); ok {
						ingresses = append(ingresses, in)
					}
					if m := innermostFunc(); m != nil {
						calls = append(calls, callSite{
							callerNamespace: m.funcNamespace,
							callerEnclosing: append([]string(nil), m.funcEnclosing...),
							callerName:      m.funcName,
							callerArity:     m.funcArity,
							calleeName:      leaf,
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

// callExprAt reports whether the identifier run starting at i is a call expression
// ("Name(args)" or "a.b.Name(args)", with an optional generic witness "Name<T>(args)"). It
// returns the callee simple name (last segment), that same leaf (for ingress
// classification), the top-level argument arity, the named handler reference (the last
// argument when it is a bare method group, for minimal-API detection), the index just past
// the closing ')', and ok. C# keywords that take a parenthesized clause are excluded so
// control flow is never a call.
func callExprAt(r []rune, i int) (name, leaf string, arity int, handlerRef string, after int, ok bool) {
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
	if last == "" || csharpCallKeywords[last] {
		return "", "", 0, "", 0, false
	}
	p := skipSpace(r, pos)
	if p < n && r[p] == '<' { // optional generic call witness "Method<T>(...)"
		p = skipGroup(r, p)
		p = skipSpace(r, p)
	}
	if p >= n || r[p] != '(' {
		return "", "", 0, "", 0, false
	}
	ar, end := parseParamArity(r, p)
	return last, last, ar, lastArgNamedRef(r, p), end, true
}

// lastArgNamedRef returns the name of a call's LAST argument when that argument is a bare
// identifier reference (a named method group), else "". It binds a minimal-API route
// handler reference to its declared method. An inline lambda, a member expression
// ("Controllers.Get"), or a literal yields "". Given the position of the call's opening '(',
// it scans the top-level argument list.
func lastArgNamedRef(r []rune, open int) string {
	n := len(r)
	depth := 0
	lastStart := -1
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

// soleIdent returns the identifier spanning [start,end) iff that range is exactly one
// identifier token (optionally space-padded); otherwise "". A member expression ("a.b"), a
// lambda ("x =>"), or a literal is not a sole identifier. A C# keyword and the discard "_"
// are rejected.
func soleIdent(r []rune, start, end int) string {
	if start < 0 || start >= end {
		return ""
	}
	a := skipSpace(r, start)
	b := end
	for b > a && unicode.IsSpace(r[b-1]) {
		b--
	}
	if a >= b || !isIdentStart(r[a]) {
		return ""
	}
	word, np := readWord(r, a)
	if np != b {
		return ""
	}
	if csharpCallKeywords[word] || word == "_" {
		return ""
	}
	return word
}

// attrHTTPMethod scans the attribute group starting at the opening '[' at i. It returns the
// matched HTTP-action attribute leaf (verb preferred over "Route"), whether any HTTP-action
// attribute was found, and the index just past the matching ']'. Any identifier inside the
// group is checked against httpMethodAttributes, so a namespace-qualified attribute
// ("Microsoft.AspNetCore.Mvc.HttpGet") still matches on its leaf.
func attrHTTPMethod(r []rune, open int) (selector string, ok bool, after int) {
	end := skipGroup(r, open)
	limit := end - 1 // the ']' position
	for pos := open + 1; pos < limit && pos < len(r); {
		if isIdentStart(r[pos]) {
			w, np := readWord(r, pos)
			if httpMethodAttributes[w] {
				ok = true
				selector = preferSelector(selector, w)
			}
			pos = np
		} else {
			pos++
		}
	}
	return selector, ok, end
}

// preferSelector keeps a specific HTTP verb attribute ("HttpGet") over the generic "Route"
// when a method carries both, so the ingress selector names the verb.
func preferSelector(cur, next string) string {
	if cur == "" {
		return next
	}
	if cur == "Route" && next != "Route" {
		return next
	}
	return cur
}

// attrIngress builds a controller-action ingress marker for a method preceded by an HTTP
// action attribute. The handler is the method itself, so its namespace + enclosing chain +
// name + arity are known and its SCIP id is built directly.
func attrIngress(pending bool, selector, namespace string, enclosing []string, name string, arity int) (ingressMarker, bool) {
	if !pending {
		return ingressMarker{}, false
	}
	return ingressMarker{
		namespace: namespace,
		enclosing: append([]string(nil), enclosing...),
		name:      name,
		arity:     arity,
		kind:      "http_route",
		selector:  selector,
	}, true
}

// minimalAPIIngress builds a reference ingress marker for an app.MapGet-style registration
// whose handler argument is a named method group. The marker carries the handler reference
// name with the handlerRefArity sentinel; FindIngresses / CallGraph re-resolve it against
// the program's declared methods by name. An anonymous handler (no named reference) records
// no ingress.
func minimalAPIIngress(leaf, handlerRef string) (ingressMarker, bool) {
	if handlerRef == "" || !minimalAPIMapMethods[leaf] {
		return ingressMarker{}, false
	}
	return ingressMarker{name: handlerRef, arity: handlerRefArity, kind: "http_route", selector: leaf}, true
}

// joinDots joins namespace parts with '.'; an empty slice yields "".
func joinDots(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "."
		}
		out += p
	}
	return out
}
