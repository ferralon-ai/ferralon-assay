package jsanalysis

import (
	"strings"
	"unicode"
)

// declKind classifies a parsed JS/TS declaration.
type declKind int

const (
	kindFunc  declKind = iota // a named function: top-level function, const-arrow, or class method
	kindClass                 // a class declaration (carries methods)
)

// decl is one parsed JS/TS declaration with the chain of enclosing class names
// that locate it inside the file's module.
type decl struct {
	kind      declKind
	name      string
	enclosing []string // outer→inner class names; empty for a module-level declaration
	arity     int      // parameter count (kindFunc only)
}

// callSite is one call expression observed inside a function body: the enclosing
// function (caller) and the simple name + argument arity of the callee. The callee
// is named lexically (no scope resolution), so it is resolved to a concrete
// declaration later by name+arity (callgraph.go).
type callSite struct {
	callerEnclosing []string // enclosing class chain of the function the call appears in
	callerName      string   // simple name of the enclosing function
	callerArity     int      // arity of the enclosing function (disambiguation)
	calleeName      string   // simple name being invoked (last segment of a.b.name)
	calleeArity     int      // argument count at the call site
}

// ingressMarker is one entry-point signal found lexically: an Express/Koa route
// registration whose handler is a named function, a Node http.createServer handler,
// or a Next.js default-export handler. The marker names the HANDLER function (the
// call-graph node), so an ingress symbol coincides with a call-graph node.
type ingressMarker struct {
	enclosing []string // enclosing class chain of the handler function
	name      string   // handler function simple name
	arity     int      // handler arity
	kind      string   // plugin.Ingress Kind: "http_route" | "http_server" | "handler"
	selector  string   // route selector ("" — string literals are blanked by the lexer)
}

// parseResult holds the module-relative path and declarations parsed from one
// source file, plus a flag recording whether the scanner skipped a construct it
// does not model (surfaced as declared partiality).
type parseResult struct {
	module    string // source path relative to the build root, '/'-joined, no extension
	decls     []decl
	calls     []callSite
	ingresses []ingressMarker
	skipped   bool
}

// stripJS removes comments, string literals, template literals, char data, and
// regex literals from JS/TS source, replacing each with equivalent whitespace so
// byte offsets and newlines are preserved but no comment/string content can be
// mistaken for code. A string/template literal collapses to a single '_' token (a
// valid identifier char) so a literal-only argument still counts toward call-site
// arity. This is the lexical pre-pass every scanner relies on.
//
// Template literals are flattened (including ${...} interpolations) to a single
// '_' — interpolated calls inside a template are not modeled (a declared-partial
// limitation, conservative: it never fabricates an edge).
func stripJS(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	r := []rune(src)
	n := len(r)
	// prevSignif is the last non-space emitted rune; it disambiguates a '/' that
	// starts a regex literal (after an operator/'(') from a division operator.
	prevSignif := rune(0)
	emit := func(c rune) {
		b.WriteRune(c)
		if !unicode.IsSpace(c) {
			prevSignif = c
		}
	}
	for i := 0; i < n; {
		c := r[i]
		switch {
		case c == '/' && i+1 < n && r[i+1] == '/':
			for i < n && r[i] != '\n' {
				b.WriteByte(' ')
				i++
			}
		case c == '/' && i+1 < n && r[i+1] == '*':
			b.WriteString("  ")
			i += 2
			for i < n && !(r[i] == '*' && i+1 < n && r[i+1] == '/') {
				if r[i] == '\n' {
					b.WriteByte('\n')
				} else {
					b.WriteByte(' ')
				}
				i++
			}
			if i < n {
				b.WriteString("  ")
				i += 2
			}
		case c == '"' || c == '\'':
			// string literal → single '_' token
			b.WriteByte('_')
			i++
			for i < n && r[i] != c {
				if r[i] == '\\' && i+1 < n {
					b.WriteString("  ")
					i += 2
					continue
				}
				b.WriteByte(' ')
				i++
			}
			if i < n {
				b.WriteByte(' ')
				i++
			}
			prevSignif = '_'
		case c == '`':
			// template literal (with possible ${...}) → single '_' token, rest blanked
			b.WriteByte('_')
			i++
			depth := 0
			for i < n {
				if r[i] == '\\' && i+1 < n {
					b.WriteString("  ")
					i += 2
					continue
				}
				if depth == 0 && r[i] == '`' {
					break
				}
				if r[i] == '$' && i+1 < n && r[i+1] == '{' {
					depth++
					b.WriteString("  ")
					i += 2
					continue
				}
				if depth > 0 && r[i] == '}' {
					depth--
					b.WriteByte(' ')
					i++
					continue
				}
				if r[i] == '\n' {
					b.WriteByte('\n')
				} else {
					b.WriteByte(' ')
				}
				i++
			}
			if i < n {
				b.WriteByte(' ')
				i++
			}
			prevSignif = '_'
		case c == '/' && regexAllowed(prevSignif):
			// regex literal /.../flags → blanked to spaces
			b.WriteByte(' ')
			i++
			inClass := false
			for i < n && r[i] != '\n' {
				if r[i] == '\\' && i+1 < n {
					b.WriteString("  ")
					i += 2
					continue
				}
				if r[i] == '[' {
					inClass = true
				} else if r[i] == ']' {
					inClass = false
				} else if r[i] == '/' && !inClass {
					break
				}
				b.WriteByte(' ')
				i++
			}
			if i < n && r[i] == '/' {
				b.WriteByte(' ')
				i++
				// flags
				for i < n && isIdentPart(r[i]) {
					b.WriteByte(' ')
					i++
				}
			}
		default:
			emit(c)
			i++
		}
	}
	return b.String()
}

// regexAllowed reports whether a '/' at the current position begins a regex literal
// rather than a division operator, based on the previous significant rune. A regex
// may start at the program start, after an operator, '(', ',', '{', '[', ';', ':',
// '!', '&', '|', '?', '=', or a return/typeof-like context. We approximate with the
// punctuation set (the common cases); an identifier/')'/']'/'_' before '/' means
// division.
func regexAllowed(prev rune) bool {
	switch prev {
	case 0, '(', ',', '{', '[', ';', ':', '!', '&', '|', '?', '=', '+', '-', '*', '%', '<', '>', '^', '~':
		return true
	}
	return false
}

// declKeywords are the leading keywords that introduce a JS/TS class declaration.
var classKeywords = map[string]bool{"class": true}

// parseFile parses one JS/TS source file (already read into src, with module set to
// its build-root-relative path) and returns the module-level + class-method
// function declarations, the call sites, and the ingress markers. It works on a
// comment/string-stripped copy so no literal can be mistaken for code.
func parseFile(module, src string) parseResult {
	clean := stripJS(src)
	res := parseResult{module: module}
	r := []rune(clean)

	res.decls = parseDecls(r)
	res.calls, res.ingresses = parseCallsAndIngresses(r)
	return res
}

// frame is one entry on the brace-block stack used by the declaration scanner. A
// frame with className!="" is a class body (its members are methods); a bare frame
// is any other block (function body, object literal, control block) whose
// identifier-followed-by-'(' runs are NOT method declarations.
type frame struct {
	className string
}

// parseDecls scans the cleaned source for class declarations and the functions they
// or the module declare. Recognized function shapes:
//   - "function name (params) {"            — module/nested function declaration
//   - "const|let|var name = (params) => {"  — arrow assigned to a binding
//   - "const|let|var name = function (p) {" — function expression assigned
//   - "name (params) {"  at class-body depth — a class method
//
// async/* modifiers, generics "<...>", and TS return-type annotations are skipped.
// Anonymous functions (no binding name) are not declarations (they cannot be a
// call-graph node by name), so they are not recorded here; an Express handler that
// is an inline arrow is detected by the ingress pass only when it is a NAMED ref.
func parseDecls(r []rune) []decl {
	n := len(r)
	var stack []frame
	var decls []decl

	classChain := func() []string {
		var out []string
		for _, f := range stack {
			if f.className != "" {
				out = append(out, f.className)
			}
		}
		return out
	}
	inClassBody := func() bool {
		return len(stack) > 0 && stack[len(stack)-1].className != ""
	}

	i := 0
	for i < n {
		c := r[i]
		switch {
		case c == '{':
			stack = append(stack, frame{})
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
				decls = append(decls, decl{kind: kindClass, name: name, enclosing: classChain()})
				stack = append(stack, frame{className: name})
				i = openIdx + 1
				continue

			case word == "function":
				if name, arity, openIdx, ok := funcDeclAt(r, next); ok {
					decls = append(decls, decl{kind: kindFunc, name: name, enclosing: classChain(), arity: arity})
					stack = append(stack, frame{})
					i = openIdx + 1
					continue
				}
				i = next
				continue

			case word == "const" || word == "let" || word == "var":
				if name, arity, openIdx, ok := bindingFuncAt(r, next); ok {
					decls = append(decls, decl{kind: kindFunc, name: name, enclosing: classChain(), arity: arity})
					stack = append(stack, frame{})
					i = openIdx + 1
					continue
				}
				i = next
				continue

			case word == "import" || word == "export":
				// export may precede a declaration ("export function", "export class",
				// "export const f = () =>", "export default function handler") — fall
				// through by advancing one word so the following keyword is scanned.
				i = next
				continue

			default:
				// At class-body depth, a "name (params) {" run is a method declaration.
				if inClassBody() && !methodModifierSkip(word) {
					if name, arity, openIdx, ok := methodDeclAt(r, i); ok {
						decls = append(decls, decl{kind: kindFunc, name: name, enclosing: classChain(), arity: arity})
						stack = append(stack, frame{})
						i = openIdx + 1
						continue
					}
				}
				i = next
			}
		default:
			i++
		}
	}
	return decls
}

// methodModifierSkip reports whether word is a method modifier ("async", "static",
// "get", "set", "public", "private", "protected", "readonly", "abstract",
// "override") that precedes the real method name; the caller advances past it so
// the next word is tried as the method name.
func methodModifierSkip(word string) bool {
	switch word {
	case "async", "static", "get", "set", "public", "private", "protected",
		"readonly", "abstract", "override", "declare":
		return true
	}
	return false
}

// parseClassHeader reads the class name and scans to the body-opening '{', skipping
// an extends/implements clause and any generic "<...>" list.
func parseClassHeader(r []rune, pos int) (name string, openIdx int, ok bool) {
	n := len(r)
	pos = skipSpace(r, pos)
	if pos >= n || !isIdentStart(r[pos]) {
		return "", 0, false
	}
	name, pos = readWord(r, pos)
	for pos < n {
		switch r[pos] {
		case '{':
			return name, pos, true
		case ';':
			return "", 0, false
		case '<', '(':
			pos = skipGroup(r, pos)
		default:
			pos++
		}
	}
	return "", 0, false
}

// funcDeclAt parses a "name (params) {" run starting just AFTER the "function"
// keyword (a possible '*' generator marker and a leading "default"/name are
// handled). It returns the function name, arity, the body-opening '{' index, and
// ok. An anonymous function expression (no name before '(') is not a declaration.
func funcDeclAt(r []rune, pos int) (name string, arity, openIdx int, ok bool) {
	n := len(r)
	pos = skipSpace(r, pos)
	if pos < n && r[pos] == '*' { // generator
		pos = skipSpace(r, pos+1)
	}
	// "export default function name(...)" arrives here after "function"; an optional
	// leading "default" was already consumed by the export branch. Read the name.
	if pos >= n || !isIdentStart(r[pos]) {
		return "", 0, 0, false
	}
	name, pos = readWord(r, pos)
	pos = skipSpace(r, pos)
	if pos < n && r[pos] == '<' { // generic params
		pos = skipGroup(r, pos)
		pos = skipSpace(r, pos)
	}
	if pos >= n || r[pos] != '(' {
		return "", 0, 0, false
	}
	arity, after := parseParamArity(r, pos)
	open := scanToBrace(r, after)
	if open < 0 {
		return "", 0, 0, false
	}
	return name, arity, open, true
}

// bindingFuncAt parses a "name = (params) => {" or "name = function (params) {"
// (or "name = async (params) => {") run starting just AFTER the const/let/var
// keyword. It returns the bound name, arity, the body-opening '{' index, and ok.
// A non-function initializer (no "=> {" and no "function") is not a func decl.
func bindingFuncAt(r []rune, pos int) (name string, arity, openIdx int, ok bool) {
	n := len(r)
	pos = skipSpace(r, pos)
	if pos >= n || !isIdentStart(r[pos]) {
		return "", 0, 0, false
	}
	name, pos = readWord(r, pos)
	pos = skipSpace(r, pos)
	// Optional TS type annotation ": Type" before '='.
	if pos < n && r[pos] == ':' {
		for pos < n && r[pos] != '=' && r[pos] != ';' && r[pos] != '\n' {
			pos++
		}
	}
	if pos >= n || r[pos] != '=' {
		return "", 0, 0, false
	}
	pos = skipSpace(r, pos+1)
	// Optional "async".
	if w, nx := peekWord(r, pos); w == "async" {
		pos = skipSpace(r, nx)
	}
	// "function (params) {" form.
	if w, nx := peekWord(r, pos); w == "function" {
		pos = skipSpace(r, nx)
		if pos < n && r[pos] == '*' {
			pos = skipSpace(r, pos+1)
		}
		// optional name (named function expression) — skip it
		if pos < n && isIdentStart(r[pos]) {
			_, pos = readWord(r, pos)
			pos = skipSpace(r, pos)
		}
		if pos < n && r[pos] == '(' {
			ar, after := parseParamArity(r, pos)
			open := scanToBrace(r, after)
			if open < 0 {
				return "", 0, 0, false
			}
			return name, ar, open, true
		}
		return "", 0, 0, false
	}
	// Arrow form: "(params) =>" then "{". A single-identifier param without parens
	// ("x => {}") is arity 1.
	if pos < n && r[pos] == '(' {
		ar, after := parseParamArity(r, pos)
		after = skipSpace(r, after)
		// optional TS return type ": Type" before "=>"
		if after < n && r[after] == ':' {
			for after < n && !(r[after] == '=' && after+1 < n && r[after+1] == '>') && r[after] != ';' && r[after] != '\n' {
				after++
			}
		}
		if after+1 < n && r[after] == '=' && r[after+1] == '>' {
			open := scanToBrace(r, after+2)
			if open < 0 {
				return "", 0, 0, false // expression-bodied arrow (no block) — no body to scan
			}
			return name, ar, open, true
		}
		return "", 0, 0, false
	}
	if pos < n && isIdentStart(r[pos]) {
		// "x => {" single-param arrow
		_, np := readWord(r, pos)
		np = skipSpace(r, np)
		if np+1 < n && r[np] == '=' && r[np+1] == '>' {
			open := scanToBrace(r, np+2)
			if open < 0 {
				return "", 0, 0, false
			}
			return name, 1, open, true
		}
	}
	return "", 0, 0, false
}

// methodDeclAt parses a class-method "name (params) {" run at class-body depth,
// returning the method name, arity, the body-opening '{' index, and ok. It skips an
// optional generic "<...>" and a TS return-type annotation between ')' and '{'. A
// field ("name = ...;" / "name: Type;") is not a method (ok=false).
func methodDeclAt(r []rune, i int) (name string, arity, openIdx int, ok bool) {
	n := len(r)
	if !isIdentStart(r[i]) {
		return "", 0, 0, false
	}
	name, pos := readWord(r, i)
	pos = skipSpace(r, pos)
	if pos < n && r[pos] == '<' {
		pos = skipGroup(r, pos)
		pos = skipSpace(r, pos)
	}
	if pos >= n || r[pos] != '(' {
		return "", 0, 0, false
	}
	arity, after := parseParamArity(r, pos)
	open := scanToBraceSameStatement(r, after)
	if open < 0 {
		return "", 0, 0, false
	}
	return name, arity, open, true
}

// scanToBrace returns the index of the next '{' at or after pos, skipping a TS
// return-type annotation, or -1 if a ';' / statement boundary intervenes (an
// expression-bodied arrow or an abstract signature). It allows ':' and identifiers
// (the return type) but stops at ';'.
func scanToBrace(r []rune, pos int) int {
	n := len(r)
	for pos < n {
		switch r[pos] {
		case '{':
			return pos
		case ';':
			return -1
		case '(', '<', '[':
			pos = skipGroup(r, pos)
		default:
			pos++
		}
	}
	return -1
}

// scanToBraceSameStatement is scanToBrace but also stops at '=' (a class field
// initializer "name() = ..." never occurs, but "name = () => {}" must be parsed by
// bindingFuncAt, not as a method) so a field is not misread as a method.
func scanToBraceSameStatement(r []rune, pos int) int {
	n := len(r)
	for pos < n {
		switch r[pos] {
		case '{':
			return pos
		case ';', '=':
			return -1
		case '<', '[':
			pos = skipGroup(r, pos)
		default:
			pos++
		}
	}
	return -1
}

// --- low-level scanners over the cleaned rune slice ---

func isIdentStart(c rune) bool {
	return c == '_' || c == '$' || unicode.IsLetter(c)
}

func isIdentPart(c rune) bool {
	return c == '_' || c == '$' || unicode.IsLetter(c) || unicode.IsDigit(c)
}

// readWord reads a JS identifier/keyword starting at i and returns it with the
// index just past it.
func readWord(r []rune, i int) (string, int) {
	start := i
	for i < len(r) && isIdentPart(r[i]) {
		i++
	}
	return string(r[start:i]), i
}

// peekWord reads the identifier at the (already space-skipped) position pos without
// committing; it returns "" when pos is not at an identifier.
func peekWord(r []rune, pos int) (string, int) {
	if pos >= len(r) || !isIdentStart(r[pos]) {
		return "", pos
	}
	return readWord(r, pos)
}

func skipSpace(r []rune, i int) int {
	for i < len(r) && unicode.IsSpace(r[i]) {
		i++
	}
	return i
}

// parseParamArity counts the comma-separated parameters of a call/parameter list,
// given the position of the opening '('. An empty "()" is arity 0. It returns the
// arity and the index just past the matching ')'.
func parseParamArity(r []rune, open int) (int, int) {
	n := len(r)
	depth := 0
	count := 0
	seenToken := false
	pos := open
	for pos < n {
		switch r[pos] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				if seenToken {
					count++
				}
				return count, pos + 1
			}
		case ',':
			if depth == 1 {
				count++
			}
		default:
			if depth == 1 && !unicode.IsSpace(r[pos]) {
				seenToken = true
			}
		}
		pos++
	}
	return count, pos
}

// skipGroup skips a balanced (), <>, [], or {} group starting at the opening rune
// at i and returns the index just past the matching close. Mismatched/unterminated
// groups advance to EOF.
func skipGroup(r []rune, i int) int {
	n := len(r)
	open := r[i]
	var close rune
	switch open {
	case '(':
		close = ')'
	case '<':
		close = '>'
	case '[':
		close = ']'
	case '{':
		close = '}'
	default:
		return i + 1
	}
	depth := 0
	for i < n {
		switch r[i] {
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return i + 1
			}
		}
		i++
	}
	return n
}

// skipTo returns the index just past the next occurrence of ch at or after i, or
// len(r) if not found.
func skipTo(r []rune, i int, ch rune) int {
	for i < len(r) {
		if r[i] == ch {
			return i + 1
		}
		i++
	}
	return len(r)
}
