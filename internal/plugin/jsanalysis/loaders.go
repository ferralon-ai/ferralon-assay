package jsanalysis

import (
	"strings"
	"unicode"
)

// Node's module loader can be reached under other names than a direct require('x') call:
// require itself passed around or aliased (`const r = require`), module.require, and the
// function createRequire(...) returns. A load through any of them runs code this lane may
// not open, so every use is either a static specifier the module loads or a computed one.

// loaderNames returns the local names that are require-like (require and every binding
// initialised from a createRequire(...) call) and createRequire-like (createRequire and its
// import/destructure renames). Bindings may be declared after their first use, so the
// names are collected before the module is scanned for uses.
func loaderNames(clean []rune) (req, cr map[string]bool) {
	req = map[string]bool{"require": true}
	cr = map[string]bool{"createRequire": true}
	n := len(clean)
	for i := 0; i < n; {
		if !isIdentStart(clean[i]) {
			i++
			continue
		}
		word, next := readWord(clean, i)
		if word == "createRequire" {
			p := skipSpace(clean, next)
			if w, nx := peekWord(clean, p); w == "as" { // import { createRequire as cr }
				if local, _ := peekWord(clean, skipSpace(clean, nx)); local != "" {
					cr[local] = true
				}
			} else if p < n && clean[p] == ':' { // const { createRequire: cr } = ...
				if local, _ := peekWord(clean, skipSpace(clean, p+1)); local != "" {
					cr[local] = true
				}
			}
		}
		i = next
	}
	for i := 0; i < n; {
		if !isIdentStart(clean[i]) {
			i++
			continue
		}
		word, next := readWord(clean, i)
		if cr[word] {
			if p := skipSpace(clean, next); p < n && clean[p] == '(' {
				if name, ok := declBoundName(clean, i); ok {
					req[name] = true
				}
			}
		}
		i = next
	}
	return req, cr
}

// requireUse records one occurrence of a require-like name whose identifier ends at next.
// A call loads its argument; `.resolve` only computes a path. Any other use hands the
// loader on, so the module can load targets this lane never sees. Declaring the name
// (a parameter or `function require(...)`) and testing it hand nothing on: every call
// through the declared name is judged where it occurs.
func (mb *moduleBindings) requireUse(clean, src []rune, i, next int) {
	p := skipSpace(clean, next)
	call := p < len(clean) && clean[p] == '('
	switch w, _ := wordBefore(clean, skipSpaceBack(clean, i-1)); {
	case w == "typeof" && !call: // a type test of the loader; `typeof require('x')` still loads x
		return
	case w == "const", w == "let", w == "var": // the declaration of a createRequire result
		return
	case w == "function": // `function require(...)` declares a parameter list, not a call
		return
	}
	if !call && (declaredParam(clean, i, next) || loaderTested(clean, i, next)) {
		return
	}
	switch {
	case call:
		mb.loaderCall(clean, src, p, true)
	case p < len(clean) && clean[p] == '.':
		if w, _ := peekWord(clean, skipSpace(clean, p+1)); w != "resolve" {
			mb.computedReq = true
		}
	default:
		mb.computedReq = true
	}
}

// createRequireUse records one occurrence of a createRequire-like name. Calling the result
// immediately loads its argument, and binding the result to a declared name makes that name
// require-like (loaderNames). Anything else lets a require function escape where this lane
// cannot follow its calls.
func (mb *moduleBindings) createRequireUse(clean, src []rune, i, next int) {
	p := skipSpace(clean, next)
	call := p < len(clean) && clean[p] == '('
	if w, _ := wordBefore(clean, skipSpaceBack(clean, i-1)); w == "typeof" && !call {
		return
	}
	if !call {
		mb.computedReq = true
		return
	}
	_, end := parseParamArity(clean, p)
	if q := skipSpace(clean, end); q < len(clean) && clean[q] == '(' {
		mb.loaderCall(clean, src, q, true)
		return
	}
	if _, ok := declBoundName(clean, i); !ok {
		mb.computedReq = true
	}
}

// Code also runs unread through entry points that never spell require: Module._load, which
// require wraps; process.dlopen, which loads a native addon; eval and the Function
// constructor, which run source built at run time; and any of these reached by a string
// key (`module['require']`). Each sets a flag rather than a specifier, because what it
// loads is never statically known.

// memberUse records an identifier at i that is a loader entry point when reached as a
// member: `._load` loads a module as require does, `.dlopen` loads a native addon, and
// `.eval` on the global object is eval.
func (mb *moduleBindings) memberUse(clean []rune, i int, word string) {
	p := skipSpaceBack(clean, i-1)
	if p < 0 || clean[p] != '.' {
		if word == "eval" {
			mb.evaluated = true
		}
		return
	}
	switch word {
	case "_load":
		mb.computedReq = true
	case "dlopen":
		mb.nativeLoad = true
	case "eval":
		// A call of .eval on any receiver may be the global's eval; a read of .eval is
		// judged by globalUse when the receiver is the global.
		if q := skipSpace(clean, i+len("eval")); q < len(clean) && clean[q] == '(' || optionalCall(clean, q) {
			mb.evaluated = true
		}
	}
}

// functionUse records a use of the Function constructor at i: a call, `new Function`, a
// `.call`/`.apply`/`.bind` on it, or an assignment that aliases it. A TypeScript type
// annotation (`cb: Function`) and `Function.prototype` are not uses. A direct call whose
// source is all plain literals with no way to run other code (literalFunction) is not one
// either; when it is called at once, its result is judged as the global it can be.
func (mb *moduleBindings) functionUse(clean, src []rune, i, next int, gs *globalScope) {
	b := skipSpaceBack(clean, i-1)
	p := skipSpace(clean, next)
	if b >= 0 && clean[b] == '.' {
		// A call of .Function on any receiver may be the global's Function constructor.
		if p < len(clean) && clean[p] == '(' || optionalCall(clean, p) {
			mb.evaluated = true
		}
		return
	}
	switch {
	case p < len(clean) && clean[p] == '(':
		if ok, open := literalFunction(clean, src, p); ok {
			if q := skipSpace(clean, closeParen(clean, p)+1); q < len(clean) && clean[q] == '(' {
				start := i
				if w, s := wordBefore(clean, b); w == "new" {
					start = s
				}
				mb.globalUse(clean, start, closeParen(clean, q)+1, false, gs)
				return
			}
			if !open {
				return
			}
		}
	case optionalCall(clean, p):
	case p < len(clean) && clean[p] == '.', optionalDot(clean, p):
		// call, apply and bind are Function.prototype methods every function shares; only
		// calling one with Function as its receiver reaches the constructor. A chain or a
		// value use (`Function.call.bind(f)`, `Function.bind || polyfill`) calls something else.
		q := p + 1
		if clean[p] == '?' {
			q = p + 2
		}
		w, e := peekWord(clean, skipSpace(clean, q))
		switch w {
		case "call", "apply", "bind":
		default:
			return
		}
		if c := skipSpace(clean, e); !(c < len(clean) && clean[c] == '(') && !optionalCall(clean, c) {
			return
		}
	default:
		w, _ := wordBefore(clean, b)
		assigned := b >= 1 && clean[b] == '=' && !strings.ContainsRune("=!<>", clean[b-1])
		if w != "new" && !assigned && !escapesAsValue(clean, b, p) {
			return
		}
	}
	mb.evaluated = true
}

// literalFunction reports whether the Function constructor call whose argument list opens
// at p builds a function that runs no code but its own operators: every argument is one
// plain string literal (no escape, no template), the leading ones lists of parameter
// names, and the body has no call, construction, tagged template, member or index access,
// assignment, update, `arguments`, `with`, or loader or evaluator name. open reports
// whether the body reads `this` or a name that is not a parameter, through which a
// later call could reach the global.
func literalFunction(clean, src []rune, p int) (ok, open bool) {
	e := closeParen(clean, p)
	if e >= len(clean) {
		return false, false
	}
	var lits []string
	for a := skipSpace(clean, p+1); a < e; {
		if clean[a] != '_' || (src[a] != '\'' && src[a] != '"') {
			return false, false
		}
		lit, ok := plainLiteral(src, a)
		if !ok {
			return false, false
		}
		lits = append(lits, lit)
		a = skipSpace(clean, a+1)
		if a < e && clean[a] == ',' {
			a = skipSpace(clean, a+1)
		} else if a < e {
			return false, false
		}
	}
	if len(lits) == 0 {
		return true, false
	}
	params := map[string]bool{}
	for _, l := range lits[:len(lits)-1] {
		if strings.TrimSpace(l) == "" {
			continue
		}
		for _, name := range strings.Split(l, ",") {
			name = strings.TrimSpace(name)
			r := []rune(name)
			if len(r) == 0 || !isIdentStart(r[0]) {
				return false, false
			}
			if w, end := readWord(r, 0); end != len(r) || functionBodyWords[w] {
				return false, false
			}
			params[name] = true
		}
	}
	body := []rune(lits[len(lits)-1])
	if strings.ContainsRune(string(body), '`') {
		return false, false
	}
	bc := []rune(stripJS(string(body)))
	for k := 0; k < len(bc); {
		c := bc[k]
		switch {
		case c == '(' || c == '[' || c == '.':
			return false, false
		case c == '=':
			prev, nxt := rune(0), rune(0)
			if k > 0 {
				prev = bc[k-1]
			}
			if k+1 < len(bc) {
				nxt = bc[k+1]
			}
			if !strings.ContainsRune("=!<>", prev) && nxt != '=' && nxt != '>' {
				return false, false
			}
			if strings.ContainsRune("<>", prev) && k > 1 && bc[k-2] == prev {
				return false, false // <<= or >>=
			}
		case (c == '+' || c == '-') && k+1 < len(bc) && bc[k+1] == c:
			return false, false
		case c == '_' && body[k] != '_':
			// a string literal inside the body
		case isIdentStart(c):
			w, end := readWord(bc, k)
			switch {
			case functionBodyWords[w]:
				return false, false
			case w == "this":
				open = true
			case !params[w] && !functionBodyKeywords[w]:
				open = true
			}
			k = end
			continue
		}
		k++
	}
	return true, open
}

// functionBodyWords may not appear in a literal Function body: each constructs, loads,
// evaluates, or reaches the caller's arguments or a dynamic scope.
var functionBodyWords = map[string]bool{
	"new": true, "import": true, "require": true, "eval": true, "Function": true,
	"arguments": true, "with": true,
}

// functionBodyKeywords are the words a literal Function body may use without reading a
// name from its scope.
var functionBodyKeywords = map[string]bool{
	"return": true, "typeof": true, "void": true, "in": true, "instanceof": true,
	"true": true, "false": true, "null": true, "undefined": true, "if": true, "else": true,
}

// plainLiteral reads the string literal whose quote is at src[a]: its text, and false when
// it holds an escape or is unterminated.
func plainLiteral(src []rune, a int) (string, bool) {
	quote := src[a]
	for k := a + 1; k < len(src); k++ {
		switch src[k] {
		case quote:
			return string(src[a+1 : k]), true
		case '\\', '\n':
			return "", false
		}
	}
	return "", false
}

// optionalCall reports whether `?.(` starts at p.
func optionalCall(clean []rune, p int) bool {
	return optionalDot(clean, p) && p+2 < len(clean) && clean[p+2] == '('
}

// optionalDot reports whether `?.` starts at p.
func optionalDot(clean []rune, p int) bool {
	return p+1 < len(clean) && clean[p] == '?' && clean[p+1] == '.'
}

// escapesAsValue reports whether a value whose previous token ends at b and whose next
// token starts at p is handed on: a call argument or array element, a return or yield
// value, an arrow body, or an operand of ||, && or ?? (which can yield it), or the
// value of a ternary branch after '?'. An equality test after it yields a boolean.
func escapesAsValue(clean []rune, b, p int) bool {
	if p+1 < len(clean) && (clean[p] == '=' || clean[p] == '!') && clean[p+1] == '=' {
		return false
	}
	if b < 0 {
		return false
	}
	switch clean[b] {
	case '(', ',', '[':
		return true
	case '?':
		return true // ternary branch or ??; `?.` cannot precede an identifier
	case '|', '&':
		return b >= 1 && clean[b-1] == clean[b]
	case '>':
		return b >= 1 && clean[b-1] == '='
	}
	switch w, _ := wordBefore(clean, b); w {
	case "return", "yield", "await":
		return true
	}
	return false
}

// maxParamScan bounds the scan for the bracket enclosing a parameter; a list longer than
// this is not recognised as one, which keeps the name flagged.
const maxParamScan = 4096

// declaredParam reports whether the identifier spanning [i, next) is a formal parameter:
// a lone arrow parameter (`require => ...`), or a name directly inside the parentheses of
// a function (`function [name](...)`) or arrow (`(...) =>`) parameter list. Destructured
// and defaulted-into names are not: only a name the list itself binds.
func declaredParam(clean []rune, i, next int) bool {
	n := len(clean)
	p := skipSpace(clean, next)
	if p+1 < n && clean[p] == '=' && clean[p+1] == '>' {
		return true
	}
	b := skipSpaceBack(clean, i-1)
	if b < 0 || (clean[b] != '(' && clean[b] != ',') {
		return false
	}
	if p >= n || (clean[p] != ',' && clean[p] != ')' && !(clean[p] == '=' && p+1 < n && clean[p+1] != '=' && clean[p+1] != '>')) {
		return false
	}
	open := b
	for depth := 0; clean[open] != '(' || depth > 0; {
		switch clean[open] {
		case ')', ']', '}':
			depth++
		case '(', '[', '{':
			if depth == 0 {
				return false // directly inside an array or object, not a parameter list
			}
			depth--
		}
		open--
		if open < 0 || b-open > maxParamScan {
			return false
		}
	}
	end := open
	for depth := 0; ; {
		switch clean[end] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		}
		if depth == 0 {
			break
		}
		end++
		if end >= n || end-open > maxParamScan {
			return false
		}
	}
	if a := skipSpace(clean, end+1); a+1 < n && clean[a] == '=' && clean[a+1] == '>' {
		return true
	}
	q := skipSpaceBack(clean, open-1)
	if w, s := wordBefore(clean, q); w != "" && w != "function" {
		q = skipSpaceBack(clean, s-1) // the function's name
	}
	if q >= 0 && clean[q] == '*' {
		q = skipSpaceBack(clean, q-1)
	}
	w, _ := wordBefore(clean, q)
	return w == "function"
}

// loaderTested reports whether the require-like name at [i, next), with any plain member
// chain after it (`require.main`), is only tested: the operand of !, ==, ===, != or !==,
// or the left operand of && or of a ternary. A test yields a boolean or the other
// operand, never the loader.
func loaderTested(clean []rune, i, next int) bool {
	n := len(clean)
	p := skipSpace(clean, next)
	for p < n && clean[p] == '.' {
		w, e := peekWord(clean, skipSpace(clean, p+1))
		if w == "" {
			return false
		}
		p = skipSpace(clean, e)
	}
	if p < n && (clean[p] == '(' || clean[p] == '[' || clean[p] == '.' || clean[p] == '_') {
		return false // called, indexed or tagged: the chain is used, not tested
	}
	switch {
	case p+1 < n && clean[p] == '&' && clean[p+1] == '&' && (p+2 >= n || clean[p+2] != '='):
		return true
	case p < n && clean[p] == '?' && (p+1 >= n || (clean[p+1] != '.' && clean[p+1] != '?')):
		return true
	case p+1 < n && (clean[p] == '=' || clean[p] == '!') && clean[p+1] == '=':
		return true
	}
	b := skipSpaceBack(clean, i-1)
	switch {
	case b >= 0 && clean[b] == '!':
		return true
	case b >= 1 && clean[b] == '=' && (clean[b-1] == '=' || clean[b-1] == '!'):
		return true
	}
	return false
}

// keyedUse records the string literal at a (clean marks it '_') when it is the whole key of
// a bracket access, `x['require']`, naming a loader entry point; module itself indexed by a
// computed key is treated the same way, since the key can name any of them.
func (mb *moduleBindings) keyedUse(clean, src []rune, a int) {
	if b := skipSpaceBack(clean, a-1); b < 0 || clean[b] != '[' {
		return
	}
	if e := skipSpace(clean, a+1); e >= len(clean) || clean[e] != ']' {
		return
	}
	switch specifierAt(src, a) {
	case "require", "createRequire", "_load":
		mb.computedReq = true
	case "dlopen":
		mb.nativeLoad = true
	case "eval", "Function":
		mb.evaluated = true
	}
}

// moduleIndexUse records `module[expr]` with a key that is not a literal: the key can name
// require or the Module constructor's loaders.
func (mb *moduleBindings) moduleIndexUse(clean []rune, i, next int) {
	if b := skipSpaceBack(clean, i-1); b >= 0 && clean[b] == '.' {
		return
	}
	p := skipSpace(clean, next)
	if p >= len(clean) || clean[p] != '[' {
		return
	}
	if a := skipSpace(clean, p+1); a < len(clean) && clean[a] == '_' {
		return // a literal key; keyedUse judges it
	}
	mb.computedReq = true
}

// loaderCall records the argument of a require() (viaRequire) or import() call whose '(' is
// at open: a string literal that is the whole argument is a specifier the module loads;
// anything else, including a literal concatenated with a value or a template with an
// interpolation, is a target computed at run time.
func (mb *moduleBindings) loaderCall(clean, src []rune, open int, viaRequire bool) {
	n := len(clean)
	a := skipSpace(clean, open+1)
	if a >= n || clean[a] == ')' {
		return
	}
	if clean[a] == '_' && wholeLiteralArg(clean, src, a) {
		mb.specifiers = append(mb.specifiers, loadSpec{spec: specifierAt(src, a), viaRequire: viaRequire})
		return
	}
	if viaRequire {
		mb.computedReq = true
	} else {
		mb.dynImport = true
	}
}

// wholeLiteralArg reports whether the string literal at a (clean marks it '_') is the entire
// call argument: the next token closes the call or starts another argument, and a template
// literal carries no interpolation.
func wholeLiteralArg(clean, src []rune, a int) bool {
	e := skipSpace(clean, a+1)
	if e >= len(clean) || (clean[e] != ')' && clean[e] != ',') {
		return false
	}
	return src[a] != '`' || !strings.Contains(specifierAt(src, a), "${")
}

// declBoundName returns NAME when the call starting at the identifier at i is the
// initialiser of `const|let|var NAME [: Type] = [await] [a.b.]ident(...)`.
func declBoundName(clean []rune, i int) (string, bool) {
	p := skipSpaceBack(clean, i-1)
	for p >= 0 && clean[p] == '.' { // member chain: module.constructor.createRequire
		w, s := wordBefore(clean, skipSpaceBack(clean, p-1))
		if w == "" {
			return "", false
		}
		p = skipSpaceBack(clean, s-1)
	}
	if w, s := wordBefore(clean, p); w == "await" {
		p = skipSpaceBack(clean, s-1)
	}
	if p < 1 || clean[p] != '=' || strings.ContainsRune("=!<>+-*/%&|^?", clean[p-1]) {
		return "", false
	}
	name, s := wordBefore(clean, skipSpaceBack(clean, p-1))
	if name == "" {
		return "", false
	}
	q := skipSpaceBack(clean, s-1)
	if q >= 0 && clean[q] == ':' { // TS annotation: the word read was the type
		name, s = wordBefore(clean, skipSpaceBack(clean, q-1))
		if name == "" {
			return "", false
		}
		q = skipSpaceBack(clean, s-1)
	}
	switch kw, _ := wordBefore(clean, q); kw {
	case "const", "let", "var":
		return name, true
	}
	return "", false
}

// wordBefore returns the identifier ending at p (inclusive) and its start index, or "" when
// p is not inside an identifier.
func wordBefore(r []rune, p int) (string, int) {
	if p < 0 || p >= len(r) || !isIdentPart(r[p]) {
		return "", p
	}
	s := p
	for s > 0 && isIdentPart(r[s-1]) {
		s--
	}
	return string(r[s : p+1]), s
}

// skipSpaceBack returns the last non-space index at or before i, or -1.
func skipSpaceBack(r []rune, i int) int {
	for i >= 0 && unicode.IsSpace(r[i]) {
		i--
	}
	return i
}
