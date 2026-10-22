package jsanalysis

import (
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
	receiver        string   // immediate receiver identifier of a `recv.name(...)` method call ("" for a bare call)
	receiverThis    bool     // true when the call is `this.name(...)`
	head            string   // first segment of a dotted chain ("JSON5" in JSON5.parse); "" for a bare call
	calleeFrame     bool     // callee is a synthetic frame minted by the scanner (an inline handler), not a name to resolve
	calleeEnclosing []string // enclosing class chain of a calleeFrame callee
	chain           []string // every segment of the callee expression ("express","Router" in express.Router()); nil for a calleeFrame
	headParam       paramRef // the enclosing function parameter the chain's head names; idx<0 when it names none
}

// paramRef names one positional parameter of a function frame: the frame (enclosing chain,
// name, arity, as funcSCIP takes them) and the parameter's index. idx<0 means no parameter.
type paramRef struct {
	enclosing []string
	name      string
	arity     int
	idx       int
}

// ingressMarker is one entry-point signal found lexically: an Express/Koa route
// registration or Node http.createServer call and its handler (a named function or an
// inline function expression), or a Next.js default-export handler. The marker names
// the HANDLER function (the call-graph node), so an ingress symbol coincides with a
// call-graph node.
type ingressMarker struct {
	enclosing []string // enclosing class chain of the handler function
	name      string   // handler function simple name (resolved to a declaration by ResolveRef unless frame)
	kind      string   // plugin.Ingress Kind: "http_route" | "http_server" | "handler"
	selector  string   // route selector ("" — string literals are blanked by the lexer)
	arity     int      // handler arity; read only when frame is set
	frame     bool     // the handler is an inline function frame whose SCIP id is minted directly
	router    []string // the value the route method was called on ("app" in app.get); nil when not a plain identifier chain
}

// parseResult holds the module-relative path and declarations parsed from one
// source file, plus a flag recording whether the scanner skipped a construct it
// does not model (surfaced as declared partiality).
type parseResult struct {
	module    string // source path relative to the build root, '/'-joined, no extension
	decls     []decl
	calls     []callSite
	ingresses []ingressMarker
	bindings  moduleBindings // import/require/export-from bindings + instances (resolve.go input)
	skipped   bool
}

// stripJS removes comments, string literals, template literal text, and regex literals
// from JS/TS source, replacing each with equivalent whitespace so rune offsets and
// newlines are preserved but no comment/string content can be mistaken for code. A
// string or template literal's opening quote becomes a single '_' token (a valid
// identifier char) so a literal-only argument still counts toward call-site arity; a
// template directly after an identifier character (a tagged template, tag`x`) becomes
// '`' instead, so the tag's name does not absorb the marker. This is the lexical
// pre-pass every scanner relies on.
//
// A template's ${...} substitutions are code and stay in place: only the literal text
// around them is blanked, so a call, require, eval or import inside a substitution is
// seen. Substitutions nest (a template inside a substitution is lexed the same way).
//
// The lexer must never hide code it cannot classify, so every literal it opens has to
// close where JS would close it:
//   - a ' or " string ends at an unescaped line break (JS forbids one there; a
//     backslash-newline continuation still continues), so a misread quote blanks at
//     most the rest of its line, and that text is still read for loads (lexJS);
//   - a regex never spans a line: a '/' whose regex would not close on its line is a
//     division, and lexing continues after it;
//   - a block comment or template literal that would run to end of file without
//     closing is not one: its opener is lexed as code instead.
func stripJS(src string) string {
	clean, _ := lexJS(src)
	return string(clean)
}

// span is a rune range [from, to) of source text.
type span struct{ from, to int }

// lexJS is stripJS returning runes, plus the text of every block comment and template it
// blanked (between the delimiters), the two literals that span lines and so the two whose
// misread opener can blank code far from it; of every string that ended at a line break
// or end of file unclosed, which only a misread quote does; and of every line comment
// opened by the "//" of "://", "\//" or "[//", which is URL text or a regex body far more
// often than a comment.
func lexJS(src string) ([]rune, []span) {
	r := []rune(src)
	n := len(r)
	out := make([]rune, 0, n)
	var hidden []span
	hide := func(from, to int) {
		if from < to {
			hidden = append(hidden, span{from, to})
		}
	}
	// prev is the last significant code rune; it decides whether a '/' starts a regex.
	// litEnd stands for a just-closed string or template, after which '/' divides.
	const litEnd = rune(-1)
	prev := rune(0)
	emit := func(c rune) {
		out = append(out, c)
		if !unicode.IsSpace(c) {
			prev = c
		}
	}
	blank := func(from, to int) {
		for k := from; k < to; k++ {
			if r[k] == '\n' {
				out = append(out, '\n')
			} else {
				out = append(out, ' ')
			}
		}
	}
	// subst holds, per open template substitution (innermost last), the depth of
	// code braces opened inside it; the '}' that meets depth 0 resumes the template.
	var subst []int
	// parens records, per open '(', the if/while/for/with keyword whose condition it
	// opens ("" for any other); afterCond is whether the last ')' closed one (a regex may
	// start a statement there).
	var parens []string
	afterCond := false
	noCommentClose := false
	// templateEnd finds where template text starting at i stops: the index of the
	// closing '`' or of the next "${", or -1 when neither follows before end of file.
	templateEnd := func(i int) int {
		for i < n && r[i] != '`' && !(r[i] == '$' && i+1 < n && r[i+1] == '{') {
			if r[i] == '\\' && i+1 < n {
				i++
			}
			i++
		}
		if i >= n {
			return -1
		}
		return i
	}
	// templateText blanks template text from i to its stop j (from templateEnd) and
	// the closing '`' or "${" there, and returns where lexing resumes.
	templateText := func(i, j int) int {
		hide(i, j)
		if r[j] == '`' {
			blank(i, j+1)
			prev = litEnd
			return j + 1
		}
		blank(i, j+2)
		subst = append(subst, 0)
		prev = '{'
		return j + 2
	}
	for i := 0; i < n; {
		c := r[i]
		switch {
		case c == '/' && i+1 < n && r[i+1] == '/':
			j := i
			for j < n && !isLineTerminator(r[j]) {
				j++
			}
			if i > 0 && (r[i-1] == ':' || r[i-1] == '\\' || r[i-1] == '[') {
				// "://" is URL text (http://x in JSX text); "\//" and "[//" are almost
				// always the body of a regex read as a division (/\//, /[//]/). Either
				// way what follows on the line may be code.
				hide(i+2, j)
			}
			blank(i, j)
			i = j
		case c == '/' && i+1 < n && r[i+1] == '*' && !noCommentClose:
			j := i + 2
			for j < n && !(r[j] == '*' && j+1 < n && r[j+1] == '/') {
				j++
			}
			if j >= n {
				noCommentClose = true
				emit(c)
				i++
				continue
			}
			hide(i+2, j)
			blank(i, j+2)
			i = j + 2
		case c == '"' || c == '\'':
			j := i + 1
			for j < n && r[j] != c && r[j] != '\n' && r[j] != '\r' {
				if r[j] == '\\' && j+1 < n {
					j++
					if r[j] == '\r' && j+1 < n && r[j+1] == '\n' {
						j++
					}
				}
				j++
			}
			out = append(out, '_')
			if j < n && r[j] == c {
				j++
			} else {
				// A valid string closes on its line, so this one was a misread quote (an
				// apostrophe in JSX text, or in a regex read as a division): its text may
				// be code.
				hide(i+1, j)
			}
			blank(i+1, j)
			prev = litEnd
			i = j
		case c == '`':
			if len(out) > 0 && isIdentPart(out[len(out)-1]) {
				// A tag written flush against its template (require`x`) keeps its name:
				// a '_' here would read as part of it.
				out = append(out, '`')
			} else {
				out = append(out, '_')
			}
			prev = litEnd
			j := templateEnd(i + 1)
			if j < 0 {
				i++
				continue
			}
			i = templateText(i+1, j)
		case c == '}' && len(subst) > 0 && subst[len(subst)-1] == 0:
			j := templateEnd(i + 1)
			if j < 0 {
				// The template never closes, so none of the open ones do: what
				// follows is code.
				subst = subst[:0]
				emit(c)
				i++
				continue
			}
			subst = subst[:len(subst)-1]
			out = append(out, ' ')
			i = templateText(i+1, j)
		case c == '/' && regexStarts(out, prev, afterCond, len(parens) > 0 && parens[len(parens)-1] == "for"):
			j := i + 1
			inClass, closed := false, false
			for j < n && !isLineTerminator(r[j]) {
				if r[j] == '\\' {
					if j+1 < n && !isLineTerminator(r[j+1]) {
						j += 2
						continue
					}
					break
				}
				if r[j] == '[' {
					inClass = true
				} else if r[j] == ']' {
					inClass = false
				} else if r[j] == '/' && !inClass {
					closed = true
					break
				}
				j++
			}
			if !closed {
				emit(c)
				i++
				continue
			}
			j++
			for j < n && isIdentPart(r[j]) {
				j++
			}
			blank(i, j)
			prev = litEnd
			i = j
		default:
			switch c {
			case '{':
				if len(subst) > 0 {
					subst[len(subst)-1]++
				}
			case '}':
				if len(subst) > 0 {
					subst[len(subst)-1]--
				}
			case '(':
				w, member := lastWord(out)
				if member || !condKeywords[w] {
					w = ""
				}
				parens = append(parens, w)
			case ')':
				afterCond = false
				if len(parens) > 0 {
					afterCond = parens[len(parens)-1] != ""
					parens = parens[:len(parens)-1]
				}
			}
			emit(c)
			i++
		}
	}
	return out, hidden
}

// regexStarts reports whether a '/' at the end of out begins a regex literal rather
// than a division, from the previous significant rune and, where that rune is ambiguous,
// the token it ends: a keyword after which an expression starts, a postfix ++/--, or
// the ')' of a statement condition (afterCond). of is a keyword only inside a for
// head (inFor); elsewhere it is an identifier, and so are yield and await outside a
// generator or async function, so none of the three is in regexKeywords.
func regexStarts(out []rune, prev rune, afterCond, inFor bool) bool {
	switch {
	case prev == ')':
		return afterCond
	case prev == '+' || prev == '-':
		k := len(out) - 1
		for k > 0 && unicode.IsSpace(out[k]) {
			k--
		}
		return !(k > 0 && out[k-1] == prev)
	case prev > 0 && isIdentPart(prev):
		w, member := lastWord(out)
		return !member && (regexKeywords[w] || inFor && w == "of")
	case prev == '.':
		// A spread (...) is an operator; a lone '.' cannot precede a '/'.
		k := len(out)
		for k > 0 && unicode.IsSpace(out[k-1]) {
			k--
		}
		return k >= 3 && string(out[k-3:k]) == "..."
	case prev == '<':
		// "</" is a JSX closing tag; "< /" is a comparison with a regex.
		return unicode.IsSpace(out[len(out)-1])
	}
	return regexAllowed(prev)
}

// regexAllowed reports whether a '/' after the punctuation prev begins a regex literal: at
// the program start, or after an operator or an opening '(', '[', '{', ',', ';' or ':'.
// '<' and '.' are decided by regexStarts, which sees what precedes them.
func regexAllowed(prev rune) bool {
	switch prev {
	case 0, '(', ',', '{', '[', ';', ':', '!', '&', '|', '?', '=', '+', '-', '*', '%', '>', '^', '~':
		return true
	}
	return false
}

// regexKeywords are the keywords after which an expression, and so a regex, may start.
var regexKeywords = map[string]bool{
	"return": true, "typeof": true, "case": true, "do": true, "else": true, "in": true,
	"new": true, "delete": true, "void": true, "throw": true, "instanceof": true,
	"default": true,
}

// condKeywords open a parenthesized statement condition, after whose ')' a statement,
// and so a regex, may start.
var condKeywords = map[string]bool{"if": true, "while": true, "for": true, "with": true}

// lastWord returns the identifier or keyword that out ends with (after trailing space),
// and whether it is a property name (preceded by '.').
func lastWord(out []rune) (string, bool) {
	k := len(out)
	for k > 0 && unicode.IsSpace(out[k-1]) {
		k--
	}
	end := k
	for k > 0 && isIdentPart(out[k-1]) {
		k--
	}
	j := k
	for j > 0 && unicode.IsSpace(out[j-1]) {
		j--
	}
	return string(out[k:end]), j > 0 && out[j-1] == '.'
}

func isLineTerminator(c rune) bool {
	return c == '\n' || c == '\r' || c == '\u2028' || c == '\u2029'
}

// declKeywords are the leading keywords that introduce a JS/TS class declaration.
var classKeywords = map[string]bool{"class": true}

// parseFile parses one JS/TS source file (already read into src, with module set to
// its build-root-relative path) and returns the module-level + class-method
// function declarations, the call sites, and the ingress markers. It works on a
// comment/string-stripped copy so no literal can be mistaken for code.
func parseFile(module, src string) parseResult {
	r, hidden := lexJS(src)
	raw := []rune(src)
	res := parseResult{module: module}

	res.decls = parseDecls(r)
	res.calls, res.ingresses = parseCallsAndIngresses(r)
	// Binding extraction scans the cleaned runes for structure and reads specifier
	// literals from the position-identical raw source (stripJS is length-preserving).
	res.bindings = extractModuleBindings(r, raw)
	res.bindings.addLoads(hiddenLoads(r, raw, hidden))
	return res
}

// hiddenLoads reads the text lexJS reports blanking (block-comment and template text,
// unclosed strings, and line comments after "://", "\//" or "[//") as if it were code, and returns the loads that reading finds. Lexing
// JS without a parser cannot always tell a literal's opener from text (a quote, backtick
// or "/*" in JSX text, or in a regex read as a division), and a misread opener either
// pairs with a later real closer or runs to the end of its line, so the text it blanks
// can be code. The text is read on its own, everything else blank, so a
// real literal never changes how the code around it reads; the loader aliases the code
// declares (clean) still apply to it. Text that the reading blanks in turn is read the
// same way, one layer at a time. The reading adds no binding or edge, so text that really
// was a comment or template can only over-declare; proseLoaders drops the two shapes
// that cannot be code to keep that cost down.
func hiddenLoads(clean, raw []rune, hidden []span) moduleBindings {
	loads := newModuleBindings()
	req, cr := loaderNames(clean)
	for layer := 0; len(hidden) > 0; layer++ {
		view := make([]rune, len(raw))
		for k, c := range raw {
			if c == '\n' {
				view[k] = '\n'
			} else {
				view[k] = ' '
			}
		}
		var next []span
		for _, h := range hidden {
			if layer >= maxHiddenLayers {
				// Past the bound, the text is read unlexed, which can only expose more.
				copy(view[h.from:h.to], raw[h.from:h.to])
				continue
			}
			sub, inner := lexJS(string(raw[h.from:h.to]))
			if len(sub) != h.to-h.from {
				copy(view[h.from:h.to], raw[h.from:h.to])
				continue
			}
			copy(view[h.from:h.to], sub)
			for _, in := range inner {
				next = append(next, span{h.from + in.from, h.from + in.to})
			}
		}
		proseLoaders(view)
		loads.addLoads(extractBindings(view, raw, req, cr))
		// A loader alias the text declares may be used in the code.
		if hreq, hcr := loaderNames(view); len(hreq) > 1 || len(hcr) > 1 {
			loads.addLoads(extractBindings(clean, raw, hreq, hcr))
		}
		hidden = next
	}
	return loads
}

// maxHiddenLayers bounds how deep hiddenLoads lexes text nested in blanked text.
const maxHiddenLayers = 8

// proseLoaders blanks, in a view of blanked text, the loader names that cannot be code
// there: a JSDoc type expression on its tag's line (`@param {Function} f`,
// `@type {import('x').T}`), since `@tag {` is a syntax error in JS and plain text in
// JSX; and a name in proseNames followed on the same line by another name ("Function
// that", "this returns") or ending a sentence ("to require."), since a name after a value
// is a syntax error unless it is one of the operators in proseFollowers, and a member
// access needs a member name.
func proseLoaders(view []rune) {
	n := len(view)
	for i := 0; i < n; i++ {
		c := view[i]
		if c == '@' {
			w, e := peekWord(view, i+1)
			if !jsdocTypeTags[w] {
				continue
			}
			p := skipBlank(view, e)
			if p >= n || view[p] != '{' {
				continue
			}
			depth := 0
			for q := p; q < n && view[q] != '\n'; q++ {
				if view[q] == '{' {
					depth++
				} else if view[q] == '}' {
					if depth--; depth == 0 {
						blankRunes(view, p, q+1)
						i = q
						break
					}
				}
			}
			continue
		}
		if !isIdentStart(c) || i > 0 && (isIdentPart(view[i-1]) || view[i-1] == '.') {
			continue
		}
		w, e := readWord(view, i)
		if proseNames[w] {
			p := skipBlank(view, e)
			f, _ := peekWord(view, p)
			switch {
			case p > e && f != "" && !proseFollowers[f]: // "this returns", "require the"
				blankRunes(view, i, e)
			case p == e && p < n && view[p] == '.' && !identAt(view, skipSpace(view, p+1)): // "to require."
				blankRunes(view, i, e)
			}
		}
		i = e - 1
	}
}

// jsdocTypeTags are the JSDoc tags that take a {type} on their line.
var jsdocTypeTags = map[string]bool{
	"type": true, "param": true, "arg": true, "argument": true, "returns": true, "return": true,
	"typedef": true, "property": true, "prop": true, "template": true, "throws": true,
	"exception": true, "yields": true, "yield": true, "enum": true, "this": true,
	"satisfies": true, "augments": true, "extends": true, "implements": true,
	"callback": true, "member": true, "var": true, "const": true, "constant": true,
}

// proseNames are the loader and global-object names proseLoaders reads as prose. module
// and import are not among them: `module Foo {` and `import x from` are code.
var proseNames = map[string]bool{
	"require": true, "createRequire": true, "eval": true, "Function": true, "this": true,
	"globalThis": true, "global": true, "window": true, "self": true, "process": true,
}

// proseFollowers are the words that may follow a value on the same line in JS or TS.
// A type predicate's `this is T` is a type, not a use of this, so "is" is not one.
var proseFollowers = map[string]bool{
	"in": true, "instanceof": true, "of": true, "as": true, "satisfies": true,
	"implements": true, "extends": true,
}

func identAt(r []rune, i int) bool { return i < len(r) && isIdentStart(r[i]) }

// skipBlank skips spaces and tabs, never a line break.
func skipBlank(r []rune, i int) int {
	for i < len(r) && (r[i] == ' ' || r[i] == '\t') {
		i++
	}
	return i
}

func blankRunes(r []rune, from, to int) {
	for k := from; k < to; k++ {
		if r[k] != '\n' {
			r[k] = ' '
		}
	}
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
