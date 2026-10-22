package jsanalysis

import (
	"strings"
	"unicode"
	"unicode/utf8"
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
// The accepted forms are a call, whose argument loadCall judges; `.resolve`, which only
// computes a path; the name declared (a parameter, `function require(...)`, a const, let or
// var) or written as an object key; a test of the name (typeof of the name or of a plain
// member chain, !, ==, &&, a ternary test); and a property of that name read from an object
// that cannot hold a loader (propertyOfPlainObject). Every other use hands the loader on,
// so the module can load targets this lane never sees, and declares a computed target.
func (mb *moduleBindings) requireUse(clean, src []rune, i, next int, ls *loaderScope) {
	n := len(clean)
	b := skipSpaceBack(clean, i-1)
	p := skipSpace(clean, next)
	call := p < n && clean[p] == '('
	if ls.propertyOfPlainObject(clean, i) {
		return
	}
	switch w, s := wordBefore(clean, b); {
	case w == "typeof" && !chainUsed(clean, next): // `typeof require('x')` still loads x
		return
	case w == "const", w == "let", w == "var": // the declaration of a createRequire result
		return
	case w == "function" && (s == 0 || !strings.ContainsRune(".#", clean[max(skipSpaceBack(clean, s-1), 0)])):
		// `function require(...)` declares a parameter list, not a call; `o.function` and
		// `this.#function` are members
		return
	}
	if !call && (objectKey(clean, b, p) || declaredParam(clean, i, next) || loaderTested(clean, i, next)) {
		return
	}
	switch {
	case call:
		mb.loaderCall(clean, src, p, true)
	case p < n && clean[p] == '.':
		if w, _ := peekWord(clean, skipSpace(clean, p+1)); w != "resolve" {
			mb.computedReq = true
		}
	default:
		mb.computedReq = true
	}
}

// chainUsed reports whether the name ending at next, with any plain member chain after it,
// is called, indexed, tagged or reached by optional chaining rather than only read.
func chainUsed(clean []rune, next int) bool {
	n := len(clean)
	p := skipSpace(clean, next)
	for p < n && clean[p] == '.' {
		w, e := peekWord(clean, skipSpace(clean, p+1))
		if w == "" {
			return true
		}
		p = skipSpace(clean, e)
	}
	return p < n && (clean[p] == '(' || clean[p] == '[' || clean[p] == '_' || optionalDot(clean, p))
}

// objectKey reports whether the name between the token ending at b and the one starting at p
// is a key in an object literal or pattern (`{ require: [...] }`), not a value.
func objectKey(clean []rune, b, p int) bool {
	n := len(clean)
	return p < n && clean[p] == ':' && !(p+1 < n && clean[p+1] == ':') && b >= 0 && (clean[b] == '{' || clean[b] == ',')
}

// createRequireUse records one occurrence of a createRequire-like name. Calling the result
// immediately loads its argument, and binding the result to a declared name makes that name
// require-like (loaderNames). Anything else lets a require function escape where this lane
// cannot follow its calls.
func (mb *moduleBindings) createRequireUse(clean, src []rune, i, next int) {
	p := skipSpace(clean, next)
	call := p < len(clean) && clean[p] == '('
	if w, _ := wordBefore(clean, skipSpaceBack(clean, i-1)); w == "typeof" && !chainUsed(clean, next) {
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

// memberUse records an identifier at i that is a loader entry point: `_load` loads a module
// as require does and `dlopen` loads a native addon, wherever the name occurs (a member, a
// destructured key, a local renaming one), since no form of either is known to load only
// code this lane reads; eval is judged as a bare name or as a member.
func (mb *moduleBindings) memberUse(clean []rune, i int, word string) {
	p := skipSpaceBack(clean, i-1)
	switch word {
	case "_load":
		mb.computedReq = true
		return
	case "dlopen":
		mb.nativeLoad = true
		return
	}
	if p < 0 || clean[p] != '.' {
		mb.evaluated = true
		return
	}
	// A call of .eval on any receiver may be the global's eval; a read of .eval is judged by
	// globalUse when the receiver is the global. A read of .eval on a global's name flags even
	// when a local shadows the name, since the local may hold the global by a path globalUse
	// does not follow, and so does a read from a receiver that is not a name (`(globalThis).eval`).
	if q := skipSpace(clean, i+len("eval")); q < len(clean) && clean[q] == '(' || optionalCall(clean, q) || !namedReceiver(clean, p) {
		mb.evaluated = true
	}
	switch recv, _ := wordBefore(clean, skipSpaceBack(clean, memberDot(clean, p)-1)); recv {
	case "globalThis", "global", "window", "self":
		mb.evaluated = true
	}
}

// memberDot returns the start of the member operator whose '.' is at b: b itself, or the '?'
// of `?.`.
func memberDot(clean []rune, b int) int {
	if b >= 1 && clean[b-1] == '?' {
		return b - 1
	}
	return b
}

// namedReceiver reports whether the member access whose '.' is at b reads from a name or a
// plain chain of names, rather than from a call, an index, a literal or a parenthesised
// expression, whose value this lane does not know.
func namedReceiver(clean []rune, b int) bool {
	k := skipSpaceBack(clean, memberDot(clean, b)-1)
	return k >= 0 && isIdentPart(clean[k]) && clean[k] != '_'
}

// functionUse records a use of the Function constructor at i. Every reference to Function
// counts, whatever follows it: a call, `new Function`, a member, an alias or a value handed
// on may each reach the constructor by a path the walk does not follow. The one exception is
// a direct call whose source is all plain literals with no way to run other code
// (literalFunction) and whose result is not called at once.
func (mb *moduleBindings) functionUse(clean, src []rune, i, next int) {
	b := skipSpaceBack(clean, i-1)
	p := skipSpace(clean, next)
	if b >= 0 && clean[b] == '.' {
		// A call of .Function on any receiver may be the global's Function constructor, and so
		// may a read from a receiver that is not a name (`(globalThis).Function`); a read from
		// a global's name is judged by globalUse.
		if p < len(clean) && clean[p] == '(' || optionalCall(clean, p) || !namedReceiver(clean, b) {
			mb.evaluated = true
		}
		return
	}
	if p < len(clean) && clean[p] == '(' {
		if ok, open := literalFunction(clean, src, p); ok && !open {
			if q := skipSpace(clean, closeParen(clean, p)+1); !(q < len(clean) && clean[q] == '(' || optionalCall(clean, q)) {
				return
			}
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
		// JS names admit non-ASCII runes readWord does not (Nl letters, combining marks,
		// ZWNJ), so a literal holding one may read a name the scan never sees.
		for _, r := range lit {
			if r >= utf8.RuneSelf {
				return false, false
			}
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
	// stripJS cannot tell a regular expression from a division after a keyword, nor end a
	// comment at U+2028 or U+2029, so a body with a backtick or a slash is not read at all.
	if strings.ContainsAny(string(body), "`/") {
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

// optionalCall reports whether `?.(` starts at p, with any space after the `?.`.
func optionalCall(clean []rune, p int) bool {
	q := skipSpace(clean, p+2)
	return optionalDot(clean, p) && q < len(clean) && clean[q] == '('
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
		return true // a ternary branch or ??; `?.` cannot precede an identifier
	case ':':
		return ternaryElse(clean, b)
	case '=':
		return memberStore(clean, b)
	case '|', '&':
		return b >= 1 && clean[b-1] == clean[b]
	case '>':
		return b >= 1 && clean[b-1] == '='
	}
	switch w, _ := wordBefore(clean, b); w {
	case "return", "yield", "await", "throw":
		return true
	}
	return false
}

// ternaryElse reports whether the ':' at b separates a ternary's branches: a '?' that is neither
// `?.`, `??` nor an optional-property marker (`cb?:`) precedes it at bracket depth zero within the
// same expression. A type annotation's or an object key's ':' does not.
func ternaryElse(clean []rune, b int) bool {
	if q := skipSpaceBack(clean, b-1); q >= 0 && clean[q] == '?' {
		return false
	}
	depth := 0
	for k := b - 1; k >= 0 && b-k < maxParamScan; k-- {
		switch clean[k] {
		case ')', ']', '}':
			depth++
		case '(', '[', '{':
			if depth == 0 {
				return false
			}
			depth--
		case ',', ';', '=':
			if depth == 0 {
				return false
			}
		case '?':
			if depth > 0 || optionalDot(clean, k) || k+1 < len(clean) && clean[k+1] == '?' || k > 0 && clean[k-1] == '?' {
				continue
			}
			return true
		}
	}
	return false
}

// memberStore reports whether the '=' at b assigns to a member (`o.g =`, `o[k] =`) or to a
// destructuring pattern (`({ [k]: f } =`), which stores the value where this lane does not
// follow it. A compound or comparison operator is not one.
func memberStore(clean []rune, b int) bool {
	k := skipSpaceBack(clean, b-1)
	if k < 0 {
		return false
	}
	if clean[k] == ']' || clean[k] == '}' {
		return true
	}
	_, s := wordBefore(clean, k)
	if s == k && !isIdentPart(clean[k]) {
		return false
	}
	d := skipSpaceBack(clean, s-1)
	return d >= 0 && clean[d] == '.'
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
	w, s := wordBefore(clean, q)
	if d := skipSpaceBack(clean, s-1); d >= 0 && clean[d] == '.' {
		return false // a member named function
	}
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
// a bracket access, `x['require']`, naming a loader entry point. A key on the module object
// or process is judged by objectUse whatever it is.
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
	case "dlopen", "process":
		mb.nativeLoad = true
	case "mainModule":
		mb.computedReq = true
	case "eval", "Function":
		mb.evaluated = true
	}
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

// loaderScope is what a module's loader uses are judged by: the require-like and
// createRequire-like names (loaderNames), the module object and process with their local
// aliases (objectAliases), and the global scope.
type loaderScope struct {
	req, cr map[string]bool
	module  loaderObject
	process loaderObject
	globals *globalScope
}

func newLoaderScope(clean []rune, globals *globalScope) *loaderScope {
	ls := &loaderScope{globals: globals}
	ls.req, ls.cr = loaderNames(clean)
	ls.module = objectAliases(clean, "module", moduleMember, moduleKey)
	ls.process = objectAliases(clean, "process", processMember, processKey)
	return ls
}

// propertyOfPlainObject reports whether the name at i is read as a property of an object
// that cannot hold a loader (`opts.require`, `cfg.loader.require`): the member chain before
// it starts at a name that is not the module object, process, a require-like name, `this`,
// `super` or a global. Each of those reaches the loader by a use this lane declares wherever
// it is handed on, so a plain object's property of the same name is not the loader. The
// module object's or process's own member is judged as the loader.
func (ls *loaderScope) propertyOfPlainObject(clean []rune, i int) bool {
	b := skipSpaceBack(clean, i-1)
	if b < 0 || clean[b] != '.' || b >= 1 && clean[b-1] == '.' {
		return false
	}
	immediate := true
	for {
		k := skipSpaceBack(clean, memberDot(clean, b)-1)
		if k < 0 || !isIdentPart(clean[k]) || clean[k] == '_' {
			return false // a call, index, literal or parenthesised receiver
		}
		w, s := wordBefore(clean, k)
		if d := skipSpaceBack(clean, s-1); d >= 0 && clean[d] == '.' && !(d >= 1 && clean[d-1] == '.') {
			b, immediate = d, false
			continue
		}
		switch {
		case immediate && (ls.module.names[w] || ls.process.names[w]):
			return false
		case ls.req[w], ls.cr[w], w == "this", w == "super", isGlobalBase(w), ls.globals.isGlobal(w, s):
			return false
		}
		return w[0] < '0' || w[0] > '9'
	}
}

// loaderObject is the module object or process, which hold loader entry points as members
// (module.require, module.constructor._load, module._compile, process.dlopen,
// process.mainModule). A use of either is accepted only in a recognized form (objectUse);
// any other use hands the object on or reaches a member this lane does not follow.
type loaderObject struct {
	names  map[string]bool // the object's name and every local whose initialiser yields it
	tails  map[int]bool    // occurrences that are such a local's initialiser value
	member func(clean []rune, name string, after int) (ok, nativeLoad bool)
	key    func(name string) bool // a whole string-literal key, or a destructured key, that is accepted
}

// moduleMember accepts a member of the module object: its own exports and data, require
// (judged by requireUse as a loader use), and constructor.createRequire (judged by
// createRequireUse). Any other member (constructor, _compile, parent, children) reaches
// the Module API or another module's loader.
func moduleMember(clean []rune, name string, after int) (bool, bool) {
	switch name {
	case "require":
		return true, false
	case "constructor":
		if q := skipSpace(clean, after); q < len(clean) && clean[q] == '.' {
			w, _ := peekWord(clean, skipSpace(clean, q+1))
			return w == "createRequire", false
		}
		return false, false
	}
	return moduleKey(name), false
}

// moduleKey accepts the module object's data members, read by a literal key or destructured.
// module.paths is left out: writing it changes where this module's bare specifiers resolve.
func moduleKey(name string) bool {
	switch name {
	case "exports", "id", "filename", "loaded", "path", "hot":
		return true
	}
	return false
}

// processMember accepts every member of process but dlopen, which loads a native addon, and
// mainModule, the main module object.
func processMember(_ []rune, name string, _ int) (bool, bool) {
	switch name {
	case "dlopen":
		return false, true
	case "mainModule":
		return false, false
	}
	return true, false
}

func processKey(name string) bool {
	ok, _ := processMember(nil, name, 0)
	return ok
}

// objectUse records one occurrence of a name in obj.names. The accepted forms are a property
// of that name on another object; a declaration of the name, a parameter, an object key or a
// TypeScript `module 'x'` declaration; the initialiser value of a local tracked as an alias
// (objectAliases); a test (typeof of the bare name, !, ==, &&, a ternary or an if condition);
// an accepted member read with `.`, `?.` or a whole literal key; and the whole value
// destructured by a pattern whose keys are all accepted. Any other use, including a computed
// key, a member outside the accepted set and the object handed on as a value, declares a
// computed require target, or an unread native module for process.
func (mb *moduleBindings) objectUse(clean, src []rune, i, next int, obj *loaderObject, globals *globalScope) {
	n := len(clean)
	b := skipSpaceBack(clean, i-1)
	p := skipSpace(clean, next)
	start := i
	if b >= 0 && clean[b] == '.' && !(b >= 1 && clean[b-1] == '.') {
		s, ok := globalMember(clean, b, globals)
		if !ok {
			return // a property of that name on another object
		}
		start = s
		if objectTested(clean, s, next, skipSpaceBack(clean, s-1)) || negatedGroupTail(clean, s, p) {
			return
		}
	} else if obj.tails[i] || bindingSite(clean, i, next, b, p) || objectTested(clean, i, next, b) || negatedGroupTail(clean, i, p) {
		return
	}
	b = skipSpaceBack(clean, start-1)
	if w, _ := wordBefore(clean, b); w == "typeof" && !chainUsed(clean, next) &&
		!(p < n && clean[p] == '.') {
		return
	}
	native := false
	switch {
	case optionalDot(clean, p) && skipSpace(clean, p+2) < n && clean[skipSpace(clean, p+2)] == '[':
		p = skipSpace(clean, p+2)
		fallthrough
	case p < n && clean[p] == '[':
		a := skipSpace(clean, p+1)
		if a < n && clean[a] == '_' && src[a] != '_' && wholeKey(clean, src, a) && obj.key(specifierAt(src, a)) {
			return
		}
	case p < n && clean[p] == '.' || optionalDot(clean, p):
		q := p + 1
		if clean[p] == '?' {
			q = p + 2
		}
		if w, e := peekWord(clean, skipSpace(clean, q)); w != "" {
			ok, nl := obj.member(clean, w, e)
			if ok {
				return
			}
			native = nl
		}
	case destructuredWhole(clean, b, next, obj):
		return
	}
	if native || obj.names["process"] {
		mb.nativeLoad = true
		return
	}
	mb.computedReq = true
}

// globalMember reports whether the '.' at b reads a property of the global object
// (`global.process`), which is the object itself rather than a property of that name, and
// where that receiver starts.
func globalMember(clean []rune, b int, globals *globalScope) (int, bool) {
	k := skipSpaceBack(clean, memberDot(clean, b)-1)
	if k < 0 || !isIdentPart(clean[k]) {
		return 0, false
	}
	w, s := wordBefore(clean, k)
	if d := skipSpaceBack(clean, s-1); d >= 0 && clean[d] == '.' {
		return 0, false
	}
	return s, isGlobalBase(w) || globals.isGlobal(w, s)
}

// negatedGroupTail reports whether the operand starting at start and ending before p is the
// last operand of an && chain that is the whole of a negated group, `!!(a && window.process)`:
// its value is only coerced to a boolean.
func negatedGroupTail(clean []rune, start, p int) bool {
	if p >= len(clean) || clean[p] != ')' {
		return false
	}
	b := skipSpaceBack(clean, start-1)
	if b < 1 || clean[b] != '&' || clean[b-1] != '&' {
		return false
	}
	depth := 0
	for k := p - 1; k >= 0; k-- {
		switch clean[k] {
		case ')', ']', '}':
			depth++
		case '[', '{':
			depth--
		case '(':
			if depth == 0 {
				o := skipSpaceBack(clean, k-1)
				return o >= 0 && clean[o] == '!'
			}
			depth--
		case ';', ',', '?', ':', '=':
			if depth == 0 && !(clean[k] == '=' && k >= 1 && strings.ContainsRune("=!", clean[k-1])) &&
				!(clean[k] == '=' && k+1 < len(clean) && clean[k+1] == '=') {
				return false
			}
		}
	}
	return false
}

// wholeKey reports whether the string literal at a is the whole key of a bracket access and
// holds no interpolation.
func wholeKey(clean, src []rune, a int) bool {
	e := skipSpace(clean, a+1)
	return e < len(clean) && clean[e] == ']' && (src[a] != '`' || !strings.Contains(specifierAt(src, a), "${"))
}

// bindingSite reports whether the name at [i, next) is declared rather than used: a const,
// let, var, function, class or import binding of it, a parameter, an object key, or a
// TypeScript `declare module 'x'` / `module N {` declaration. Uses of a local so declared
// are judged as uses of the object, since its value may be the object.
func bindingSite(clean []rune, i, next, b, p int) bool {
	switch w, s := wordBefore(clean, b); w {
	case "const", "let", "var", "class", "import", "as":
		return true
	case "function":
		if d := skipSpaceBack(clean, s-1); d < 0 || clean[d] != '.' {
			return true
		}
	}
	if objectKey(clean, b, p) || declaredParam(clean, i, next) {
		return true
	}
	if p < len(clean) && clean[p] == '_' {
		return true // `module 'x'`: a string cannot follow the object in an expression
	}
	if w, e := peekWord(clean, p); w != "" && w != "in" && w != "instanceof" {
		q := skipSpace(clean, e)
		return q < len(clean) && (clean[q] == '{' || clean[q] == '.') && sameLine(clean, i, p)
	}
	return false
}

// objectTested reports whether the name at [i, next), with any plain member chain after it,
// is only tested: loaderTested, or the whole condition of an if or while.
func objectTested(clean []rune, i, next, b int) bool {
	if loaderTested(clean, i, next) {
		return true
	}
	if b < 0 || clean[b] != '(' {
		return false
	}
	if w, _ := wordBefore(clean, skipSpaceBack(clean, b-1)); w != "if" && w != "while" {
		return false
	}
	n := len(clean)
	p := skipSpace(clean, next)
	for p < n && clean[p] == '.' {
		w, e := peekWord(clean, skipSpace(clean, p+1))
		if w == "" {
			return false
		}
		p = skipSpace(clean, e)
	}
	return p < n && clean[p] == ')'
}

// destructuredWhole reports whether the name at [?, next) preceded by the token ending at b
// is the whole value of a destructuring `{ ... } = name` whose keys obj accepts. A rest
// element, a computed or quoted key, or any other key declares, since the pattern then
// takes a member this lane does not follow under a local name.
func destructuredWhole(clean []rune, b, next int, obj *loaderObject) bool {
	if b < 1 || clean[b] != '=' || strings.ContainsRune("=!<>+-*/%&|^?", clean[b-1]) || !valueTail(clean, next) {
		return false
	}
	c := skipSpaceBack(clean, b-1)
	if c < 0 || clean[c] != '}' {
		return false
	}
	depth, open := 0, -1
	for k := c; k >= 0; k-- {
		switch clean[k] {
		case '}':
			depth++
		case '{':
			depth--
		}
		if depth == 0 {
			open = k
			break
		}
	}
	if open < 0 {
		return false
	}
	depth = 0
	expectKey := true
	for k := open + 1; k < c; k++ {
		switch r := clean[k]; {
		case r == '[' || r == '_' || r == '.':
			return false // a computed key, a quoted key or a rest element
		case r == '{' || r == '(':
			depth++
		case r == '}' || r == ')':
			depth--
		case r == ',' && depth == 0:
			expectKey = true
		case expectKey && depth == 0 && isIdentStart(r):
			w, e := readWord(clean, k)
			if !obj.key(w) {
				return false
			}
			expectKey = false
			k = e - 1
		}
	}
	return true
}

// valueTail reports whether the expression ending at next ends there: the next token closes
// the statement, a declarator, a group or a block, or starts a new statement on a later line.
func valueTail(clean []rune, next int) bool {
	q := skipSpace(clean, next)
	if q >= len(clean) || strings.ContainsRune(";,)}", clean[q]) {
		return true
	}
	if !sameLine(clean, next, q) && isIdentStart(clean[q]) && clean[q] != '_' {
		w, _ := readWord(clean, q)
		return w != "in" && w != "instanceof"
	}
	return false
}

// objectAliases returns a loaderObject for base: its name and every local declared with
// const, let or var whose initialiser's value can be the object, through a name already
// tracked as the whole value or the last operand of an &&, || or ?? chain
// (`var freeModule = typeof module == 'object' && module`). Uses of such a local are judged
// as uses of the object; an alias of an alias is followed too.
func objectAliases(clean []rune, base string, member func([]rune, string, int) (bool, bool), key func(string) bool) loaderObject {
	obj := loaderObject{names: map[string]bool{base: true}, tails: map[int]bool{}, member: member, key: key}
	n := len(clean)
	for changed := true; changed; {
		changed = false
		for i := 0; i < n; {
			if !isIdentStart(clean[i]) {
				i++
				continue
			}
			word, next := readWord(clean, i)
			if obj.names[word] && !obj.tails[i] && !memberName(clean, i) {
				if name, ok := aliasOf(clean, i, next); ok {
					obj.tails[i] = true
					if !obj.names[name] {
						obj.names[name] = true
						changed = true
					}
				}
			}
			i = next
		}
	}
	return obj
}

// aliasOf returns NAME when the identifier at [i, next) is the value of the initialiser of
// `const|let|var NAME = ...`: the whole initialiser, or the last operand of a chain of &&,
// || and ?? at the initialiser's top level.
func aliasOf(clean []rune, i, next int) (string, bool) {
	if !valueTail(clean, next) {
		return "", false
	}
	k := skipSpaceBack(clean, i-1)
	if k >= 1 && (clean[k] == '&' && clean[k-1] == '&' || clean[k] == '|' && clean[k-1] == '|' || clean[k] == '?' && clean[k-1] == '?') {
		depth := 0
		for k -= 2; k >= 0; k-- {
			r := clean[k]
			switch {
			case r == ')' || r == ']' || r == '}':
				depth++
				continue
			case r == '(' || r == '[' || r == '{':
				if depth == 0 {
					return "", false
				}
				depth--
				continue
			case depth > 0:
				continue
			case r == ';' || r == ',' || r == ':':
				return "", false
			case r == '?' && !(k >= 1 && clean[k-1] == '?') && !(k+1 < len(clean) && clean[k+1] == '?'):
				return "", false // a ternary
			case r == '=':
				if k+1 < len(clean) && (clean[k+1] == '=' || clean[k+1] == '>') || k >= 1 && strings.ContainsRune("=!<>", clean[k-1]) {
					if k+1 < len(clean) && clean[k+1] == '>' {
						return "", false // an arrow body
					}
					continue
				}
			default:
				continue
			}
			break
		}
		if k < 0 {
			return "", false
		}
	}
	if k < 1 || clean[k] != '=' || strings.ContainsRune("=!<>+-*/%&|^?", clean[k-1]) || k+1 < len(clean) && (clean[k+1] == '=' || clean[k+1] == '>') {
		return "", false
	}
	name, s := wordBefore(clean, skipSpaceBack(clean, k-1))
	if name == "" {
		return "", false
	}
	switch kw, _ := wordBefore(clean, skipSpaceBack(clean, s-1)); kw {
	case "const", "let", "var":
		return name, true
	}
	return "", false
}
