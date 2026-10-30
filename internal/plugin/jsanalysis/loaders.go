package jsanalysis

import (
	"strconv"
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
	req = map[string]bool{"require": true, "__non_webpack_require__": true} // the latter is the runtime require under webpack
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
// var that is not exported), written as an object key or named after `as`; a test of the
// name (typeof of the name or of a plain member chain, !, ==, &&, a ternary test); and a
// property of that name read from an object that cannot hold a loader
// (propertyOfPlainObject). Every other use hands the loader on, so the module can load
// targets this lane never sees, and declares a computed target.
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
		if kw, _ := wordBefore(clean, skipSpaceBack(clean, s-1)); kw == "export" {
			mb.computedReq = true // an exported result is called by importers this lane does not judge
		}
		return
	case w == "as" && sameLine(clean, s, i): // the exported name of `export { r as require }`, or a type
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
		mb.loaderCall(clean, src, i, p, false)
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
	return p < n && (clean[p] == '(' || clean[p] == '[' || clean[p] == '_' || clean[p] == '`' || optionalDot(clean, p))
}

// objectKey reports whether the name between the token ending at b and the one starting at p
// is a key in an object literal or pattern (`{ require: [...] }`), not a value.
func objectKey(clean []rune, b, p int) bool {
	n := len(clean)
	return p < n && clean[p] == ':' && !(p+1 < n && clean[p+1] == ':') && b >= 0 && (clean[b] == '{' || clean[b] == ',')
}

// argumentsUse records an `arguments` at i outside every function body (arrow bodies and
// class bodies included, since neither binds arguments). In a CommonJS module that is the
// module wrapper's argument list, whose second entry is require, so any use but a member
// name or an object key may hand require on where this lane cannot follow its calls
// (`arguments[1](x)`).
func (mb *moduleBindings) argumentsUse(clean []rune, i, next int, frames *thisFrames) {
	if !frames.outsideFunctions(i) || memberName(clean, i) || objectKey(clean, skipSpaceBack(clean, i-1), skipSpace(clean, next)) {
		return
	}
	mb.computedReq = true
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
		mb.loaderCall(clean, src, i, q, false)
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
// as require does, `dlopen` loads a native addon, `getBuiltinModule` returns any core module
// (vm and module included) and `_linkedBinding` returns a native binding, wherever the name
// occurs (a member, a destructured key, a local renaming one) and whatever the receiver,
// since no form of any is known to load only code this lane reads; eval is judged by
// evaluatorTested.
func (mb *moduleBindings) memberUse(clean []rune, i int, word string) {
	if hazardMember(mb, word) {
		return
	}
	if word == "_load" {
		mb.computedReq = true
		return
	}
	if !evaluatorTested(clean, i, i+len(word)) {
		mb.evaluated = true
	}
}

// hazardMember records a member name that hands back a loader or native internals whatever
// its receiver: dlopen, getBuiltinModule, _linkedBinding and binding declare an unread native
// module, mainModule a computed require target. It reports whether name is one. binding and
// mainModule are common enough as local names that only a member, a destructured key or a
// literal key counts; the global object reaches a receiver through flows this lane does not
// track, so the receiver is never judged.
func hazardMember(mb *moduleBindings, name string) bool {
	switch name {
	case "dlopen", "getBuiltinModule", "_linkedBinding", "binding":
		mb.nativeLoad = true
	case "mainModule":
		mb.computedReq = true
	default:
		return false
	}
	return true
}

// evaluatorTested reports whether the eval or Function at [i, next) is a member whose value
// is neither called nor handed on: the target of a plain assignment (`cfg.eval = false`),
// only tested (objectTested) or read for a further member other than constructor, call,
// apply or bind. Any other read may hand on the global's
// evaluator through a receiver whose value this lane does not know
// (`const e = frame.contentWindow.eval`), and a member of a global's name may be the
// evaluator itself, so both flag, as does the bare name.
func evaluatorTested(clean []rune, i, next int) bool {
	b := skipSpaceBack(clean, i-1)
	if b < 0 || clean[b] != '.' {
		return false
	}
	op := memberDot(clean, b)
	switch recv, _ := wordBefore(clean, skipSpaceBack(clean, op-1)); recv {
	case "globalThis", "global", "window", "self":
		return false
	}
	start := receiverStart(clean, op)
	if start < 0 {
		return false
	}
	if assignTarget(clean, skipSpace(clean, next)) {
		return true
	}
	if ok, member := memberReadAt(clean, skipSpace(clean, next)); member {
		return ok
	}
	return objectTested(clean, start, next, skipSpaceBack(clean, start-1))
}

// memberDot returns the start of the member operator whose '.' is at b: b itself, or the '?'
// of `?.`.
func memberDot(clean []rune, b int) int {
	if b >= 1 && clean[b-1] == '?' {
		return b - 1
	}
	return b
}

// functionUse records a use of the Function constructor at i. Every reference to Function
// counts, whatever follows it: a call, `new Function`, a member, an alias or a value handed
// on may each reach the constructor by a path the walk does not follow. The exceptions are
// a direct call whose source is all plain literals with no way to run other code
// (literalFunction) and whose result is not called at once, and the two consumed shapes
// functionConsumed accepts.
func (mb *moduleBindings) functionUse(clean, src []rune, i, next int) {
	b := skipSpaceBack(clean, i-1)
	p := skipSpace(clean, next)
	if b >= 0 && clean[b] == '.' {
		if !evaluatorTested(clean, i, next) {
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
	if functionConsumed(clean, src, b, p) {
		return
	}
	mb.evaluated = true
}

// functionConsumed reports whether the bare Function whose previous token ends at b and
// whose next token starts at p is used up where it stands, never reaching a value that can
// run code. That holds for the right operand of instanceof, and for Function.prototype read
// at once for one of its builtins: apply, call, bind or toString called on the spot (or
// through .call, .apply or .bind), or [Symbol.hasInstance] when Symbol is the global's. The
// hasInstance builtin may be stored, since reaching the constructor from it takes
// .constructor, the residue every function value shares. Function as instanceof's operand,
// and the hasInstance builtin unless it is called, must end the operand (endsOperand):
// anything else after them may read from, call or tag them. A line break after instanceof
// may end its statement (ASI after a member, a hashbang or an HTML-like comment line), so
// Function on the next line starts a new one.
func functionConsumed(clean, src []rune, b, p int) bool {
	if w, _ := wordBefore(clean, b); w == "instanceof" {
		return !lineBreakAfter(clean, src, b) && endsOperand(clean, p)
	}
	w, q := dotWord(clean, p)
	if w != "prototype" {
		return false
	}
	switch w, q := dotWord(clean, q); w {
	case "apply", "call", "bind", "toString":
		return calledHere(clean, q)
	case "":
		e, ok := hasInstanceKey(clean, q)
		if !ok {
			return false
		}
		q = skipSpace(clean, e+1)
		return (endsOperand(clean, q) || calledHere(clean, q)) && symbolPlain(clean, src)
	}
	return false
}

// hasInstanceKey reports whether `[Symbol.hasInstance]` opens at p, and returns the index of
// its closing bracket.
func hasInstanceKey(clean []rune, p int) (int, bool) {
	if p >= len(clean) || clean[p] != '[' {
		return 0, false
	}
	w, e := peekWord(clean, skipSpace(clean, p+1))
	if w != "Symbol" {
		return 0, false
	}
	if w, e = dotWord(clean, skipSpace(clean, e)); w != "hasInstance" {
		return 0, false
	}
	if e >= len(clean) || clean[e] != ']' {
		return 0, false
	}
	return e, true
}

// dotWord reads `.name` at p, a static member and not an optional one, and returns the name
// and the next token's start, or "" and p when no static member starts there.
func dotWord(clean []rune, p int) (string, int) {
	if p >= len(clean) || clean[p] != '.' {
		return "", p
	}
	w, e := peekWord(clean, skipSpace(clean, p+1))
	if w == "" {
		return "", p
	}
	return w, skipSpace(clean, e)
}

// calledHere reports whether the builtin read just before p is called at once: `(` at p, or
// `.call(`, `.apply(` or `.bind(`.
func calledHere(clean []rune, p int) bool {
	if p < len(clean) && clean[p] == '(' {
		return true
	}
	switch w, q := dotWord(clean, p); w {
	case "call", "apply", "bind":
		return q < len(clean) && clean[q] == '('
	}
	return false
}

// lineBreakAfter reports whether a line terminator lies in the space that follows b. It
// reads src, since a block comment blanked in clean keeps only its line feeds and any line
// terminator inside one breaks the line.
func lineBreakAfter(clean, src []rune, b int) bool {
	for k := b + 1; k < len(clean) && unicode.IsSpace(clean[k]); k++ {
		switch src[k] {
		case '\n', '\r', '\u2028', '\u2029':
			return true
		}
	}
	return false
}

// endsOperand reports whether the token at p ends the operand before it without reading
// from, calling or tagging it: the end of the source, a closing bracket, a separator, a
// ternary's `?` or `:`, `&&`, `||`, `??`, or an equality test.
func endsOperand(clean []rune, p int) bool {
	n := len(clean)
	if p >= n {
		return true
	}
	var next rune
	if p+1 < n {
		next = clean[p+1]
	}
	switch clean[p] {
	case ')', ']', '}', ';', ',', ':':
		return true
	case '?':
		return next != '.'
	case '&', '|':
		return next == clean[p]
	case '=', '!':
		return next == '='
	}
	return false
}

// symbolPlain reports whether every Symbol in the module appears where it cannot be bound
// or assigned, so that it is the global's. Each Symbol, bare or a member (whose object may
// be the global), must be followed by `.` or `(` and not name a function, or a TS namespace
// or module (dotted or not), or be read by a typeof on the same line. A with statement may
// put any object's Symbol in scope; an escaped identifier may spell Symbol unseen; and an
// HTML-like comment, which a script reads to the end of its line, may show the scan a
// token the runtime skips. The scan reads clean, which stripJS lexes by approximation, so
// the module also counts only when no escape in the source spells Symbol, clean shows
// every Symbol of the source and every with a parenthesis or comment follows, and clean
// hides nothing between a Symbol (or the head of its dotted name) and its neighbouring
// tokens. U+FEFF, which is space to the runtime but not to the scan, is refused outright.
// These checks hold where stripJS reads the module as the runtime does, the bound every
// check in this lane shares: a module that stripJS misreads can hide a binding of Symbol
// from them, as it can hide an eval.
func symbolPlain(clean, src []rune) bool {
	if text := string(clean); strings.ContainsRune(text, '\\') || strings.Contains(text, "<!--") || strings.Contains(text, "-->") {
		return false
	}
	if strings.ContainsRune(string(src), '\uFEFF') || !wordsShown(clean, src) {
		return false
	}
	for i := 0; i < len(clean); {
		if !isIdentPart(clean[i]) {
			i++
			continue
		}
		w, next := readWord(clean, i)
		switch {
		case w == "Symbol":
			if !symbolRead(clean, src, i, next) || blanked(clean, src, skipSpaceBack(clean, chainHead(clean, i)-1)+1, i) || blanked(clean, src, next, skipSpace(clean, next)) {
				return false
			}
		case w == "with" && !memberName(clean, i):
			if q := skipSpace(clean, next); q < len(clean) && clean[q] == '(' {
				return false
			}
		}
		i = next
	}
	return true
}

// symbolRead reports whether the Symbol word at i, ending before next, is only read.
func symbolRead(clean, src []rune, i, next int) bool {
	b := skipSpaceBack(clean, i-1)
	prev, _ := wordBefore(clean, b)
	if prev == "typeof" && !lineBreakAfter(clean, src, b) {
		return true
	}
	if prev == "function" || b >= 0 && clean[b] == '*' {
		return false
	}
	if head, _ := wordBefore(clean, skipSpaceBack(clean, chainHead(clean, i)-1)); head == "namespace" || head == "module" {
		return false
	}
	q := skipSpace(clean, next)
	return q < len(clean) && (clean[q] == '(' || clean[q] == '.')
}

// chainHead returns the start of the dotted name the word at i ends, so that the Symbol in
// `namespace A.Symbol.x` is seen to be named by the namespace.
func chainHead(clean []rune, i int) int {
	for {
		b := skipSpaceBack(clean, i-1)
		if b < 1 || clean[b] != '.' || clean[b-1] == '.' {
			return i
		}
		w, s := wordBefore(clean, skipSpaceBack(clean, b-1))
		if w == "" {
			return i
		}
		i = s
	}
}

// wordsShown reports whether clean shows, as itself, every Symbol word of src and every
// with that a parenthesis or a comment (`//`, `/*`, `<!--` or `-->`) follows. A Symbol
// spelled with an escape is never shown, since clean either keeps the escape or blanks it.
func wordsShown(clean, src []rune) bool {
	for i := 0; i < len(src); {
		if !isIdentPart(src[i]) && src[i] != '\\' {
			i++
			continue
		}
		w, next := readEscapedWord(src, i)
		switch {
		case w == "Symbol" && string(clean[i:next]) != w:
			return false
		case w == "with" && string(clean[i:next]) != w:
			if q := skipSpace(src, next); q < len(src) && strings.ContainsRune("(/<-", src[q]) {
				return false
			}
		}
		i = next
	}
	return true
}

// readEscapedWord reads the identifier at i as the runtime names it, decoding its \uXXXX
// and \u{...} escapes.
func readEscapedWord(r []rune, i int) (string, int) {
	var b strings.Builder
	start := i
	for i < len(r) {
		if isIdentPart(r[i]) {
			b.WriteRune(r[i])
			i++
			continue
		}
		c, next, ok := identEscape(r, i)
		if !ok {
			break
		}
		b.WriteRune(c)
		i = next
	}
	if i == start {
		return "", i + 1
	}
	return b.String(), i
}

// identEscape decodes the \uXXXX or \u{...} escape at i.
func identEscape(r []rune, i int) (rune, int, bool) {
	if i+1 >= len(r) || r[i] != '\\' || r[i+1] != 'u' {
		return 0, i, false
	}
	j, end := i+2, i+6
	if j < len(r) && r[j] == '{' {
		j++
		end = j
		for end < len(r) && isHexDigit(r[end]) {
			end++
		}
		if end == len(r) || r[end] != '}' {
			return 0, i, false
		}
	}
	if end > len(r) {
		return 0, i, false
	}
	v, err := strconv.ParseUint(string(r[j:end]), 16, 32)
	if err != nil {
		return 0, i, false
	}
	if r[i+2] == '{' {
		end++
	}
	return rune(v), end, true
}

// blanked reports whether clean blanks to space any source that is not space in [from, to).
func blanked(clean, src []rune, from, to int) bool {
	for k := max(from, 0); k < to && k < len(clean); k++ {
		if unicode.IsSpace(clean[k]) && !unicode.IsSpace(src[k]) {
			return true
		}
	}
	return false
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
	// stripJS cannot always tell a regular expression from a division, so a body with a
	// backtick or a slash is not read at all.
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
	if !operandEnds(clean, p) {
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

// operandEnds reports whether the expression before the token at p ends there rather than
// being called, indexed, tagged, reached by optional chaining or asserted non-null and
// called (`x!(...)`).
func operandEnds(clean []rune, p int) bool {
	n := len(clean)
	if p >= n {
		return true
	}
	switch clean[p] {
	case '(', '[', '.', '_', '`':
		return false
	case '!':
		return p+1 < n && clean[p+1] == '='
	}
	return !optionalDot(clean, p)
}

// keyedUse records the string literal at a (clean marks it '_') when it is the whole key of
// a bracket access, `x['require']`, or the key of a reflective read (reflectiveKey), naming
// a loader entry point. A reflective read hands the member's value on, so a constructor
// key there flags whatever the receiver, and so does a quoted or computed constructor key
// in a destructuring pattern (destructuredLiteralKey) or a constructor key passed as an
// argument (literalArgument), since any callee may read the member it names (`get(g,
// 'constructor')` for a destructured Reflect.get). A key on the module object
// or process is judged by objectUse whatever it is.
func (mb *moduleBindings) keyedUse(clean, src []rune, a int) {
	if reflectiveKey(clean, a) {
		switch specifierAt(src, a) {
		case "require", "createRequire", "_load", "mainModule":
			mb.computedReq = true
		case "dlopen", "process", "getBuiltinModule", "_linkedBinding", "binding":
			mb.nativeLoad = true
		case "eval", "Function", "constructor":
			mb.evaluated = true
		}
		return
	}
	if specifierAt(src, a) == "constructor" && (destructuredLiteralKey(clean, a) || literalArgument(clean, a) || arrayElement(clean, a) && !denyListSearch(clean, a)) {
		mb.evaluated = true
		return
	}
	// A quoted or literal computed pattern key naming a hazard member takes it under a local
	// name whatever the pattern's source (`const { 'getBuiltinModule': gb } = o.g.process`).
	if destructuredLiteralKey(clean, a) && !interpolated(src, a) && hazardMember(mb, specifierAt(src, a)) {
		return
	}
	if b := skipSpaceBack(clean, a-1); b < 0 || clean[b] != '[' {
		return
	}
	if e := skipSpace(clean, a+1); e >= len(clean) || clean[e] != ']' {
		return
	}
	switch specifierAt(src, a) {
	case "require", "createRequire", "_load":
		mb.computedReq = true
	case "dlopen", "process", "getBuiltinModule", "_linkedBinding", "binding":
		mb.nativeLoad = true
	case "mainModule":
		mb.computedReq = true
	case "eval", "Function":
		mb.evaluated = true
	case "constructor":
		b := skipSpaceBack(clean, a-1)
		op, ok := indexOperator(clean, b)
		if !ok {
			return // a computed key, or a deny list (denyListSearch)
		}
		if constructorReachesFunction(clean, src, b) || !constructorRead(clean, op, skipSpace(clean, a+1)+1) {
			mb.evaluated = true
		}
	}
}

// arrayElement reports whether the string literal at a is a whole element of an array
// literal, which any code may index or iterate to take the key; a computed object or class
// key (`{ ['k']: v }`, `['k']() {}`) is not one.
func arrayElement(clean []rune, a int) bool {
	b := skipSpaceBack(clean, a-1)
	if b < 0 || clean[b] != '[' && clean[b] != ',' {
		return false
	}
	if e := skipSpace(clean, a+1); e >= len(clean) || clean[e] != ']' && clean[e] != ',' {
		return false
	}
	o := b
	if clean[b] == ',' {
		o = enclosingOpen(clean, b)
	}
	if o < 0 || clean[o] != '[' {
		return false
	}
	if _, ok := indexOperator(clean, o); ok {
		return false
	}
	q := skipSpace(clean, closeOf(clean, o)+1)
	return !(q < len(clean) && (clean[q] == ':' || clean[q] == '('))
}

// denyListSearch reports whether the array literal holding the element at a is searched in
// place by includes, indexOf or some, which compare the key against it rather than read it.
func denyListSearch(clean []rune, a int) bool {
	o := enclosingOpen(clean, a)
	p := skipSpace(clean, closeOf(clean, o)+1)
	switch {
	case optionalDot(clean, p):
		p = skipSpace(clean, p+2)
	case p < len(clean) && clean[p] == '.':
		p = skipSpace(clean, p+1)
	default:
		return false
	}
	w, e := peekWord(clean, p)
	if w != "includes" && w != "indexOf" && w != "some" {
		return false
	}
	q := skipSpace(clean, e)
	return q < len(clean) && clean[q] == '('
}

// destructuredLiteralKey reports whether the string literal at a is a quoted key
// (`{ 'k': x } =`) or a computed key (`{ ['k']: x } =`) of an object destructuring pattern
// (destructuredKey), which takes the member under a local name.
func destructuredLiteralKey(clean []rune, a int) bool {
	i, next := a, a+1
	if b := skipSpaceBack(clean, a-1); b >= 0 && clean[b] == '[' {
		e := skipSpace(clean, a+1)
		if e >= len(clean) || clean[e] != ']' {
			return false
		}
		i, next = b, e+1
	}
	p := skipSpace(clean, next)
	if p >= len(clean) || clean[p] != ':' || p+1 < len(clean) && clean[p+1] == ':' {
		return false
	}
	return destructuredKey(clean, i, next)
}

// literalArgument reports whether the string literal at a is a whole argument of a call or
// construction, whatever the callee, or the whole of a parenthesised expression: it is
// delimited by '(' or ',' and by ')' or ',' inside a parenthesis.
func literalArgument(clean []rune, a int) bool {
	b := skipSpaceBack(clean, a-1)
	if b < 0 || clean[b] != '(' && clean[b] != ',' {
		return false
	}
	if e := skipSpace(clean, a+1); e >= len(clean) || clean[e] != ')' && clean[e] != ',' {
		return false
	}
	o := b
	if clean[b] == ',' {
		o = enclosingOpen(clean, b)
	}
	return o >= 0 && clean[o] == '('
}

// reflectiveKey reports whether the string literal at a is the whole second argument of
// Reflect.get, Reflect.getOwnPropertyDescriptor or Object.getOwnPropertyDescriptor, each of
// which reads the member that literal names from its first argument.
func reflectiveKey(clean []rune, a int) bool {
	b := skipSpaceBack(clean, a-1)
	if b < 0 || clean[b] != ',' {
		return false
	}
	if e := skipSpace(clean, a+1); e >= len(clean) || clean[e] != ')' && clean[e] != ',' {
		return false
	}
	o := enclosingOpen(clean, b)
	if o < 0 || clean[o] != '(' {
		return false
	}
	depth := 0
	for k := o + 1; k < b; k++ { // the literal is the second argument, not a later one
		switch clean[k] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				return false
			}
		}
	}
	method, s := wordBefore(clean, skipSpaceBack(clean, o-1))
	d := skipSpaceBack(clean, s-1)
	if d < 0 || clean[d] != '.' || d > 0 && clean[d-1] == '?' {
		return false
	}
	recv, _ := wordBefore(clean, skipSpaceBack(clean, d-1))
	switch {
	case recv == "Reflect":
		return method == "get" || method == "getOwnPropertyDescriptor"
	case recv == "Object":
		return method == "getOwnPropertyDescriptor"
	}
	return false
}

// computedKey reports whether the bracket access opening at p has a key this lane does not
// know: anything but one string literal with no interpolation or one run of digits.
func computedKey(clean, src []rune, p int) bool {
	a := skipSpace(clean, p+1)
	if a >= len(clean) {
		return false
	}
	if clean[a] == '_' && src[a] != '_' {
		return !wholeKey(clean, src, a)
	}
	e := a
	for e < len(clean) && clean[e] >= '0' && clean[e] <= '9' {
		e++
	}
	return e == a || skipSpace(clean, e) >= len(clean) || clean[skipSpace(clean, e)] != ']'
}

// indexPairRead reports whether the value of a computed index pair, whose chain starts at
// start and ends before next, is used only where it is neither called nor handed on: indexed
// again (the next pair is judged in turn); read for a member other than constructor, call,
// apply or bind; tested (objectTested); written by an assignment, an update or a compound
// assignment that does not yield the old value; an operand of an arithmetic, bitwise or
// comparison operator, typeof, void, delete, in or instanceof; a case label; or iterated by
// for-of. None of these calls a function operand's body or yields it.
func indexPairRead(clean []rune, start, next int) bool {
	n := len(clean)
	if start < 0 {
		return false
	}
	p := skipSpace(clean, next)
	if p < n && clean[p] == '[' || optionalDot(clean, p) && skipSpace(clean, p+2) < n && clean[skipSpace(clean, p+2)] == '[' {
		return true
	}
	if ok, member := memberReadAt(clean, p); member {
		return ok
	}
	if !operandEnds(clean, p) {
		return false
	}
	prev := skipSpaceBack(clean, start-1)
	if w, _ := wordBefore(clean, prev); w == "new" {
		return false
	}
	if objectTested(clean, start, next, prev) {
		return true
	}
	if assignTarget(clean, p) || safeOperatorAfter(clean, p) {
		return true
	}
	if w, _ := wordBefore(clean, prev); w != "" {
		switch w {
		case "typeof", "void", "delete", "in", "instanceof", "of", "case":
			return true
		}
		return false
	}
	return safeOperatorBefore(clean, prev)
}

// operatorRunes are the runes that make up JS punctuator operators.
const operatorRunes = "+-*/%&|^~!<>=?"

// safeOperatorAfter reports whether the operator at p, following a value, consumes that value
// without calling or yielding it: an update, a compound assignment other than ||= and ??=, or
// an arithmetic, bitwise or comparison operator, `in` or `instanceof`. A lone '<' may open a
// TypeScript type argument list of a call (`f<T>(x)`), so it counts only when no '>' follows
// before the expression ends.
func safeOperatorAfter(clean []rune, p int) bool {
	n := len(clean)
	if w, _ := peekWord(clean, p); w == "in" || w == "instanceof" {
		return true
	}
	e := p
	for e < n && strings.ContainsRune(operatorRunes, clean[e]) {
		e++
	}
	op := string(clean[p:e])
	switch {
	case op == "":
		return false
	case strings.HasPrefix(op, "==") || strings.HasPrefix(op, "!="):
		return true
	case strings.HasPrefix(op, "&&") || strings.HasPrefix(op, "||") || op[0] == '?' || op[0] == '!' || op[0] == '=' || op[0] == '~':
		return false
	case op == "<":
		for k := p + 1; k < n; k++ {
			switch clean[k] {
			case '>':
				return false
			case ';', ')', ',', '\n', '}', ']':
				return true
			}
		}
		return true
	}
	return true // + - * / % ^ & | < > and their doubled, compound and update forms
}

// safeOperatorBefore reports whether the operator run ending at prev, preceding a value,
// consumes it without calling or yielding it: a unary or binary arithmetic, bitwise or
// comparison operator, an update, or a compound assignment other than ||=, &&= and ??=. A
// lone '>' may end a TypeScript type assertion (`<T>x`) or an arrow, which yield the value.
func safeOperatorBefore(clean []rune, prev int) bool {
	if prev < 0 || !strings.ContainsRune(operatorRunes, clean[prev]) {
		return false
	}
	s := prev
	for s > 0 && strings.ContainsRune(operatorRunes, clean[s-1]) {
		s--
	}
	op := string(clean[s : prev+1])
	switch last := clean[prev]; last {
	case '+', '-', '*', '/', '%', '^', '~', '!', '<':
		return true
	case '&', '|':
		return !strings.HasSuffix(op, string([]rune{last, last}))
	case '>':
		return strings.HasSuffix(op, ">>")
	case '=':
		switch op {
		case "=", "&&=", "||=", "??=":
			return false
		}
		return len(op) > 1 && op[len(op)-2] != '>' || strings.HasSuffix(op, ">>=") || op == ">="
	}
	return false
}

// indexOperator reports whether the '[' at b indexes a value (`x[k]`, `f()[k]`, `x?.[k]`)
// rather than opening an array literal, and where its member operator starts: b, or the '?'
// of `?.[`.
func indexOperator(clean []rune, b int) (int, bool) {
	op := b
	k := skipSpaceBack(clean, b-1)
	if k >= 1 && clean[k] == '.' && clean[k-1] == '?' {
		op = k - 1
		k = skipSpaceBack(clean, k-2)
	}
	if k < 0 {
		return 0, false
	}
	switch c := clean[k]; {
	case c == ')' || c == ']' || c == '}':
		return op, true
	case isIdentPart(c):
		return op, !operatorWord(clean, k)
	}
	return 0, false
}

// constructorUse records `.constructor` (or `?.constructor`) at i. The constructor of a
// function is Function, which runs source built at run time, and this lane cannot tell a
// function receiver from any other value, so the member is accepted only when it does not
// reach a function constructor on any receiver (constructorReachesFunction) and its value is
// neither called nor handed on (constructorRead).
func (mb *moduleBindings) constructorUse(clean, src []rune, i int) {
	b := skipSpaceBack(clean, i-1)
	if b < 0 || clean[b] != '.' || b >= 2 && clean[b-1] == '.' && clean[b-2] == '.' {
		// A destructured key takes the member under a local name (`const { constructor: F } =
		// g`); a constructor method, an object-literal key, a local name or a spread does not.
		if destructuredKey(clean, i, i+len("constructor")) {
			mb.evaluated = true
		}
		return
	}
	op := memberDot(clean, b)
	if constructorReachesFunction(clean, src, op) || !constructorRead(clean, op, i+len("constructor")) {
		mb.evaluated = true
	}
}

// destructuredKey reports whether the name at [i, next) is a key, shorthand or defaulted
// entry of an object destructuring pattern: a `{...}`, possibly nested in further patterns,
// that is assigned from (`{...} =`), declared by const, let or var, the head of a for-of or
// for-in, a catch binding, or a parameter of a function, method or arrow.
func destructuredKey(clean []rune, i, next int) bool {
	n := len(clean)
	p := skipSpace(clean, next)
	if p >= n {
		return false
	}
	switch c := clean[p]; {
	case c == ':' && !(p+1 < n && clean[p+1] == ':'), c == ',', c == '}':
	case c == '=' && !(p+1 < n && (clean[p+1] == '=' || clean[p+1] == '>')):
	default:
		return false
	}
	o := enclosingOpen(clean, i)
	if o < 0 || clean[o] != '{' {
		return false
	}
	for o >= 0 && (clean[o] == '{' || clean[o] == '[') {
		q := skipSpace(clean, closeOf(clean, o)+1)
		if q < n && clean[q] == '=' && !(q+1 < n && (clean[q+1] == '=' || clean[q+1] == '>')) {
			return true
		}
		if w, _ := peekWord(clean, q); w == "of" || w == "in" {
			return true
		}
		b := skipSpaceBack(clean, o-1)
		if b < 0 {
			return false
		}
		if w, _ := wordBefore(clean, b); w == "const" || w == "let" || w == "var" {
			return true
		}
		switch clean[b] {
		case ':', ',', '[', '{', '(':
		default:
			return false
		}
		o = enclosingOpen(clean, o)
	}
	return o >= 0 && clean[o] == '(' && parameterList(clean, o)
}

// parameterList reports whether the parenthesis at o opens a parameter list: of an arrow
// (`(...) =>`), a function (`function [name](...)`), a method (`name(...) {`) or a catch
// clause.
func parameterList(clean []rune, o int) bool {
	n := len(clean)
	q := skipSpace(clean, closeOf(clean, o)+1)
	if q+1 < n && clean[q] == '=' && clean[q+1] == '>' {
		return true
	}
	b := skipSpaceBack(clean, o-1)
	w, s := wordBefore(clean, b)
	switch w {
	case "function", "catch":
		return true
	case "", "if", "while", "for", "switch", "with", "return", "typeof", "void", "await", "yield", "new", "in", "of", "case":
		return false
	}
	if v, _ := wordBefore(clean, skipSpaceBack(clean, s-1)); v == "function" {
		return true
	}
	d := skipSpaceBack(clean, s-1)
	return q < n && clean[q] == '{' && (d < 0 || clean[d] != '.')
}

// enclosingOpen returns the index of the innermost bracket that opens before i and is not
// closed before it, or -1.
func enclosingOpen(clean []rune, i int) int {
	depth := 0
	for k := i - 1; k >= 0; k-- {
		switch clean[k] {
		case ')', ']', '}':
			depth++
		case '(', '[', '{':
			if depth == 0 {
				return k
			}
			depth--
		}
	}
	return -1
}

// closeOf returns the index of the bracket that closes the one opened at o, or len(clean).
func closeOf(clean []rune, o int) int {
	depth := 0
	for k := o; k < len(clean); k++ {
		switch clean[k] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return k
			}
		}
	}
	return len(clean)
}

// bracketIndex answers enclosingOpen and closeOf for one text in constant time. Both walks
// pair brackets regardless of kind, each closer with the nearest unpaired opener before it,
// and that pairing does not depend on which end it is read from, so one forward pass with a
// stack gives the same answers; a closer with nothing open pairs with nothing.
type bracketIndex struct {
	encl  []int32 // position → enclosingOpen
	close []int32 // position of an opening bracket → closeOf
}

func newBracketIndex(clean []rune) *bracketIndex {
	n := len(clean)
	bi := &bracketIndex{encl: make([]int32, n), close: make([]int32, n)}
	var open []int32
	for i, c := range clean {
		bi.encl[i] = -1
		if k := len(open); k > 0 {
			bi.encl[i] = open[k-1]
		}
		switch c {
		case '(', '[', '{':
			bi.close[i] = int32(n)
			open = append(open, int32(i))
		case ')', ']', '}':
			if k := len(open); k > 0 {
				bi.close[open[k-1]] = int32(i)
				open = open[:k-1]
			}
		}
	}
	return bi
}

// enclosingOpen is enclosingOpen(clean, i) for 0 <= i < len(clean).
func (bi *bracketIndex) enclosingOpen(i int) int { return int(bi.encl[i]) }

// closeOf is closeOf(clean, o) for an opening bracket at o.
func (bi *bracketIndex) closeOf(o int) int { return int(bi.close[o]) }

// constructorRead reports whether the constructor member read by the operator starting at
// op ('.', the '?' of `?.`, or the '[' of a literal key) and ending before next is used only
// where its value is neither called nor handed on: read for a further member other than
// constructor, call, apply, bind, valueOf, or the value or get of a property descriptor
// (`getOwnPropertyDescriptors(p).constructor.value`); tested (objectTested: !, ==, ===, !=, !==, the left
// operand of && or of a ternary, an if or while condition); the right operand of instanceof;
// the target of a plain assignment (`F.prototype.constructor = F`); or constructed as
// `new this.constructor` with no arguments. Any function can be called with this bound to a
// function (`.call`, `Reflect.apply`, a member copied onto a function), where
// this.constructor is Function, so a construction with arguments may build code. A call, an
// alias, an argument, a computed index or any other use may reach Function.
func constructorRead(clean []rune, op, next int) bool {
	start := receiverStart(clean, op)
	if start < 0 {
		return false
	}
	p := skipSpace(clean, next)
	if ok, member := memberReadAt(clean, p); member {
		q := p + 1
		if optionalDot(clean, p) {
			q = p + 2
		}
		w, _ := peekWord(clean, skipSpace(clean, q))
		return ok && w != "value" && w != "get"
	}
	if assignTarget(clean, p) {
		return true
	}
	prev := skipSpaceBack(clean, start-1)
	if objectTested(clean, start, next, prev) {
		return true
	}
	w, _ := wordBefore(clean, prev)
	if w == "instanceof" && operandEnds(clean, p) {
		return true
	}
	if w == "new" && clean[op] == '.' {
		if recv, rs := wordBefore(clean, skipSpaceBack(clean, op-1)); recv == "this" && rs == start {
			return noArguments(clean, p)
		}
	}
	return false
}

// noArguments reports whether the construction whose callee ends before p passes no
// arguments (`new C`, `new C()`): Function so constructed is an empty function. A literal
// after the callee can only be a tagged template, which passes arguments.
func noArguments(clean []rune, p int) bool {
	if p < len(clean) && (clean[p] == '_' || clean[p] == '`') {
		return false
	}
	if p >= len(clean) || clean[p] != '(' {
		return true
	}
	q := skipSpace(clean, p+1)
	return q < len(clean) && clean[q] == ')'
}

// memberReadAt reports whether a member is read with `.` or `?.` at p (member), and whether
// that member is one through which a function's constructor is not reached or invoked:
// any name but constructor, call, apply, bind and valueOf, which returns Function itself.
func memberReadAt(clean []rune, p int) (ok, member bool) {
	n := len(clean)
	q := -1
	switch {
	case optionalDot(clean, p):
		q = p + 2
	case p < n && clean[p] == '.' && !(p+1 < n && clean[p+1] == '.'):
		q = p + 1
	default:
		return false, false
	}
	w, _ := peekWord(clean, skipSpace(clean, q))
	switch w {
	case "", "constructor", "call", "apply", "bind", "valueOf":
		return false, true
	}
	return true, true
}

// assignTarget reports whether the token at p is a plain assignment, so the expression
// before it is written, not read.
func assignTarget(clean []rune, p int) bool {
	n := len(clean)
	return p < n && clean[p] == '=' && !(p+1 < n && (clean[p+1] == '=' || clean[p+1] == '>'))
}

// receiverStart returns where the member chain whose operator starts at op begins: the
// first name, literal or group of a run of names, members, calls and indexes
// (`a.b(c)[d].constructor`), or -1 when no receiver precedes op.
func receiverStart(clean []rune, op int) int {
	k := skipSpaceBack(clean, op-1)
	for k >= 0 {
		var s int
		switch c := clean[k]; {
		case c == ')' || c == ']':
			s = openBefore(clean, k)
			if s < 0 {
				return -1
			}
		case isIdentPart(c):
			_, s = wordBefore(clean, k)
		default:
			return -1
		}
		d := skipSpaceBack(clean, s-1)
		switch {
		case d >= 0 && clean[d] == '.' && !(d >= 1 && clean[d-1] == '.'):
			k = skipSpaceBack(clean, memberDot(clean, d)-1)
		case (clean[k] == ')' || clean[k] == ']') && d >= 0 && (clean[d] == ')' || clean[d] == ']' || isIdentPart(clean[d]) && !operatorWord(clean, d)):
			k = d // a call or an index applied to what precedes it
		default:
			return s
		}
	}
	return -1
}

// operatorWord reports whether the identifier ending at k is a keyword after which a
// bracket opens a new expression rather than calling or indexing a value.
func operatorWord(clean []rune, k int) bool {
	switch w, _ := wordBefore(clean, k); w {
	case "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw",
		"case", "do", "else", "yield", "await":
		return true
	}
	return false
}

// openBefore returns the index of the bracket that opens the group closing at close, or -1.
func openBefore(clean []rune, close int) int {
	depth := 0
	for k := close; k >= 0; k-- {
		switch clean[k] {
		case ')', ']', '}':
			depth++
		case '(', '[', '{':
			depth--
			if depth == 0 {
				return k
			}
		}
	}
	return -1
}

// constructorReachesFunction reports whether a constructor member, accessed by the operator
// starting at op ('.', the '?' of `?.`, or the '[' of a literal key), reads the constructor
// of a function, which is Function or AsyncFunction/GeneratorFunction and runs source built
// at run time: a `.constructor.constructor` chain on any receiver (`[].constructor.constructor`),
// or the constructor of a function, async function, generator or arrow expression, directly
// or through Object.getPrototypeOf, Reflect.getPrototypeOf or `__proto__`. A single
// `x.constructor` on any other receiver is the class of a value and is not judged.
func constructorReachesFunction(clean, src []rune, op int) bool {
	if op >= 1 && clean[op] == '[' && clean[op-1] == '.' && op >= 2 && clean[op-2] == '?' {
		op -= 2
	}
	k := skipSpaceBack(clean, op-1)
	if k < 0 {
		return false
	}
	switch {
	case clean[k] == ']':
		a := skipSpaceBack(clean, k-1)
		if a >= 0 && clean[a] == '_' && src[a] != '_' && specifierAt(src, a) == "constructor" {
			return true // `x['constructor'].constructor`
		}
		return false
	case clean[k] == ')':
		return functionGroup(clean, k)
	case !isIdentPart(clean[k]):
		return false
	}
	w, s := wordBefore(clean, k)
	d := skipSpaceBack(clean, s-1)
	if d < 0 || clean[d] != '.' || d >= 1 && clean[d-1] == '.' {
		return false
	}
	switch w {
	case "constructor":
		return true
	case "__proto__":
		r := skipSpaceBack(clean, memberDot(clean, d)-1)
		return r >= 0 && clean[r] == ')' && functionGroup(clean, r)
	}
	return false
}

// functionGroup reports whether the parenthesised group or argument list closing at close
// holds a function expression at its top level: a `function` or `async` keyword or an arrow,
// as in `(async () => {})` or `Object.getPrototypeOf(function* () {})`.
func functionGroup(clean []rune, close int) bool {
	depth := 0
	for k := close - 1; k >= 0; k-- {
		switch r := clean[k]; {
		case r == ')' || r == ']' || r == '}':
			depth++
		case r == '(' || r == '[' || r == '{':
			if depth == 0 {
				return false // the group's own opening bracket
			}
			depth--
		case depth > 0:
		case r == '>' && k >= 1 && clean[k-1] == '=':
			return true
		case isIdentStart(r) && (k == 0 || !isIdentPart(clean[k-1])):
			if w, _ := readWord(clean, k); w == "function" || w == "async" {
				return true
			}
		}
	}
	return false
}

// loaderCall records the argument of a loader call whose '(' is at open; at is the index
// of the loader name, kept to find the frame the load runs in. A whole string literal is a
// specifier the module loads, a literal prefix followed by a runtime value is a static-prefix
// load, and anything else is a target computed at run time (recordLoad).
func (mb *moduleBindings) loaderCall(clean, src []rune, at, open int, dyn bool) {
	recordLoad(clean, src, at, skipSpace(clean, open+1), dyn, mb)
}

// interpolated reports whether the literal whose opening quote is at src[a] is a template
// holding an interpolation, read from the raw text so a malformed escape before it cannot
// hide it.
func interpolated(src []rune, a int) bool {
	if src[a] != '`' {
		return false
	}
	for k := a + 1; k < len(src) && src[k] != '`'; k++ {
		switch {
		case src[k] == '\\':
			k++
		case src[k] == '$' && k+1 < len(src) && src[k+1] == '{':
			return true
		}
	}
	return false
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
	ls.module = objectAliases(clean, "module", moduleMember, moduleKey, globals)
	ls.process = objectAliases(clean, "process", processMember, processKey, globals)
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

// processMember accepts every member of process but those that hand back a loader or native
// internals: dlopen, which loads a native addon; binding and _linkedBinding, which return
// native bindings (contextify's ContextifyScript and compileFunction evaluate code);
// mainModule, the main module object; and getBuiltinModule, which returns any core module,
// vm and module included.
func processMember(_ []rune, name string, _ int) (bool, bool) {
	switch name {
	case "dlopen", "binding", "_linkedBinding":
		return false, true
	case "mainModule", "getBuiltinModule":
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
		if p < n && clean[p] == '(' || optionalCall(clean, p) {
			// Neither process nor the module object is a function, so a call is never of them.
			return
		}
		if !ok {
			// The global object reaches a receiver through flows this lane does not track
			// (`o.g.process` with `o = { g: globalThis }`), so any `.process` read counts as
			// process whatever the receiver. Writing the property reads nothing. A `.module`
			// off another object is a property of that name.
			if !obj.names["process"] || string(clean[i:next]) != "process" || plainAssignTarget(clean, p) {
				return
			}
			if s = receiverStart(clean, memberDot(clean, b)); s < 0 {
				s = i
			}
		}
		start = s
		if objectTested(clean, s, next, skipSpaceBack(clean, s-1)) || negatedGroupTail(clean, s, p) {
			return
		}
	} else if v, ok := globalPatternKey(clean, b, p, globals); ok {
		// `{ process: pr } = globalThis` reads the object itself: a renaming local is an alias
		// (objectAliases) and a nested pattern is judged like a whole destructure.
		if obj.tails[v] || clean[v] == '{' && patternKeysAccepted(clean, v, matchingClose(clean, v), obj) {
			return
		}
		if obj.names["process"] {
			mb.nativeLoad = true
			return
		}
		mb.computedReq = true
		return
	} else if objectKey(clean, b, p) && patternKeyUnclassified(clean, i, globals) {
		if obj.names["process"] {
			mb.nativeLoad = true
			return
		}
		mb.computedReq = true
		return
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
	default:
		if start == i && globals.plainObject(clean, string(clean[i:next]), i) {
			return // a local holding an object literal, handed on as a plain value
		}
	}
	if native || obj.names["process"] {
		mb.nativeLoad = true
		return
	}
	mb.computedReq = true
}

// plainAssignTarget reports whether the token at p is a plain `=`, so the expression before
// it is the target of an assignment rather than read.
func plainAssignTarget(clean []rune, p int) bool {
	return p < len(clean) && clean[p] == '=' && !(p+1 < len(clean) && (clean[p+1] == '=' || clean[p+1] == '>'))
}

// processComputedKey reports whether a receiver derived from process (a name tracked as
// process, or any `.process` member) is read by a key this lane does not know: a computed
// member whose key is not one whole literal (`pr['getBuiltin' + 'Module']`), or the key of
// Reflect.get, Reflect.getOwnPropertyDescriptor or Object.getOwnPropertyDescriptor when it
// is not one whole literal. It judges the key alone, independent of objectUse.
func processComputedKey(clean, src []rune, names map[string]bool) bool {
	n := len(clean)
	derived := func(k int) bool { // the receiver ends at k
		if k < 0 || !isIdentPart(clean[k]) {
			return false
		}
		w, s := wordBefore(clean, k)
		if d := skipSpaceBack(clean, s-1); d >= 0 && clean[d] == '.' && !(d >= 1 && clean[d-1] == '.') {
			return w == "process"
		}
		return names[w]
	}
	for p := 0; p < n; p++ {
		switch clean[p] {
		case '[':
			if !computedKey(clean, src, p) {
				continue
			}
			if op, ok := indexOperator(clean, p); ok && derived(skipSpaceBack(clean, op-1)) {
				return true
			}
		case '(':
			method, s := wordBefore(clean, skipSpaceBack(clean, p-1))
			d := skipSpaceBack(clean, s-1)
			if d < 0 || clean[d] != '.' {
				continue
			}
			recv, _ := wordBefore(clean, skipSpaceBack(clean, memberDot(clean, d)-1))
			if !(recv == "Reflect" && (method == "get" || method == "getOwnPropertyDescriptor") ||
				recv == "Object" && method == "getOwnPropertyDescriptor") {
				continue
			}
			c := topLevelComma(clean, p)
			if c < 0 || !derived(skipSpaceBack(clean, c-1)) {
				continue
			}
			a := skipSpace(clean, c+1)
			e := skipSpace(clean, a+1)
			whole := a < n && clean[a] == '_' && src[a] != '_' && e < n && (clean[e] == ',' || clean[e] == ')') && !interpolated(src, a)
			if !whole {
				return true
			}
		}
	}
	return false
}

// topLevelComma returns the position of the first comma directly inside the parenthesis
// opening at o, or -1 when it closes first.
func topLevelComma(clean []rune, o int) int {
	depth := 0
	for k := o + 1; k < len(clean); k++ {
		switch clean[k] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return -1
			}
			depth--
		case ',':
			if depth == 0 {
				return k
			}
		}
	}
	return -1
}

// globalMember reports whether the '.' at b may read a property of the global object, which
// is the object itself rather than a property of that name, and where that receiver starts:
// a name that resolves to the global, a chain of global names off one
// (`global.globalThis.process`), or a receiver ending in a group, call or index
// (`(globalThis).process`, `(0, globalThis).process`), whose value this lane does not know.
// A property of a plain name (`queue.process`) is not one.
func globalMember(clean []rune, b int, globals *globalScope) (int, bool) {
	return globals.globalChain(clean, memberDot(clean, b), true)
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
	return e < len(clean) && clean[e] == ']' && !interpolated(src, a)
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
	return patternKeysAccepted(clean, open, c, obj)
}

// patternKeysAccepted reports whether every top-level key of the pattern between the braces
// at open and c is one obj accepts.
func patternKeysAccepted(clean []rune, open, c int, obj *loaderObject) bool {
	if c < 0 {
		return false
	}
	depth := 0
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
func objectAliases(clean []rune, base string, member func([]rune, string, int) (bool, bool), key func(string) bool, globals *globalScope) loaderObject {
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
			if word == base {
				if v, ok := globalPatternKey(clean, skipSpaceBack(clean, i-1), skipSpace(clean, next), globals); ok && !obj.tails[v] {
					if name, e := readWord(clean, v); isIdentStart(clean[v]) && clean[v] != '_' && patternValueEnds(clean, e) {
						obj.tails[v] = true
						if !obj.names[name] {
							obj.names[name] = true
							changed = true
						}
					}
				}
			}
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

// globalPatternKey reports whether the name between the token ending at b and the one
// starting at p is a top-level key of a destructuring pattern whose source is the global
// object (`const { process: pr } = globalThis`), and returns where the key's value starts.
func globalPatternKey(clean []rune, b, p int, globals *globalScope) (int, bool) {
	if !objectKey(clean, b, p) {
		return 0, false
	}
	depth, open := 0, -1
	for k := b; k >= 0 && open < 0; k-- {
		switch clean[k] {
		case ')', ']', '}':
			depth++
		case '(', '[':
			if depth == 0 {
				return 0, false
			}
			depth--
		case '{':
			if depth == 0 {
				open = k
			}
			depth--
		}
	}
	c := matchingClose(clean, open)
	if c < 0 {
		return 0, false
	}
	q := skipSpace(clean, c+1)
	if q >= len(clean) || clean[q] != '=' || q+1 < len(clean) && (clean[q+1] == '=' || clean[q+1] == '>') {
		return 0, false
	}
	s := skipSpace(clean, q+1)
	if s >= len(clean) || !isIdentStart(clean[s]) || clean[s] == '_' {
		return 0, false
	}
	w, e := readWord(clean, s)
	if !valueTail(clean, e) || !globals.isGlobal(w, s) {
		return 0, false
	}
	return skipSpace(clean, p+1), true
}

// patternKeyUnclassified reports whether the object key at i sits in a destructuring pattern
// whose source this lane cannot show is not the global object. Only a top-level key of a
// pattern declared or assigned from a bare name that does not resolve to the global is
// classified (`const { process: pr } = opts`); a pattern off the global by name is judged by
// globalPatternKey first. Any other source is not: a group, comma, ??, ||, ternary, call or
// member chain, an enclosing pattern (`{ globalThis: { process: pr } } = globalThis`), a
// parameter, whose value is what a caller passes, and a for-of or for-in head.
func patternKeyUnclassified(clean []rune, i int, globals *globalScope) bool {
	o := enclosingOpen(clean, i)
	if o < 0 || clean[o] != '{' {
		return false
	}
	src, end, pattern := patternSource(clean, o)
	return pattern && !(src >= 0 && plainSource(clean, src, end, globals))
}

// patternKeys declares a quoted or computed key that may read process or the module object
// in a destructuring pattern whose source patternKeyUnclassified cannot classify: a quoted
// key spelled process or module, a computed key whose whole literal is one of them, and a
// computed key of any other expression, whose value may be either.
func (mb *moduleBindings) patternKeys(clean, src []rune, globals *globalScope) {
	n := len(clean)
	for k := 0; k < n; k++ {
		if clean[k] != '_' && clean[k] != '[' || clean[k] == '_' && (k >= len(src) || src[k] == '_') {
			continue
		}
		b := skipSpaceBack(clean, k-1)
		if b < 0 || clean[b] != '{' && clean[b] != ',' {
			continue
		}
		key, e := "", k
		if clean[k] == '[' {
			e = closeBracket(clean, k)
			if a := skipSpace(clean, k+1); a < n && clean[a] == '_' && a < len(src) && src[a] != '_' && wholeKey(clean, src, a) {
				key = specifierAt(src, a)
				if key != "process" && key != "module" {
					continue
				}
			}
		} else {
			key = specifierAt(src, k)
			if key != "process" && key != "module" {
				continue
			}
		}
		q := skipSpace(clean, e+1)
		if q >= n || clean[q] != ':' || q+1 < n && clean[q+1] == ':' || !patternKeyUnclassified(clean, k, globals) {
			continue
		}
		if key == "module" {
			mb.computedReq = true
		} else {
			mb.nativeLoad = true
		}
	}
}

// patternSource reports whether the object brace at o opens a destructuring pattern, and
// returns the start and end of the source it is declared or assigned from when o is the
// pattern's outermost level and that source is the pattern's whole value; otherwise src is
// -1. A brace that is an object literal, a TypeScript type literal or a block is no pattern.
func patternSource(clean []rune, o int) (src, end int, pattern bool) {
	n := len(clean)
	top := true
	for {
		c := closeOf(clean, o)
		if c >= n {
			return -1, -1, false
		}
		q := skipSpace(clean, c+1)
		if top && q < n && clean[q] == ':' && !(q+1 < n && clean[q+1] == ':') {
			q = skipSpace(clean, typeEnd(clean, q+1)) // `const { ... }: T = src`
		}
		if w, _ := peekWord(clean, q); w == "of" || w == "in" {
			return -1, -1, true // a for-of or for-in head
		}
		assign := q < n && clean[q] == '=' && !(q+1 < n && (clean[q+1] == '=' || clean[q+1] == '>'))
		from := func() (int, int, bool) {
			if top && assign {
				return skipSpace(clean, q+1), initEnd(clean, q+1), true
			}
			return -1, -1, true
		}
		bb := skipSpaceBack(clean, o-1)
		if w, _ := wordBefore(clean, bb); w == "const" || w == "let" || w == "var" {
			return from()
		}
		o2 := enclosingOpen(clean, o)
		switch {
		case bb < 0 || o2 < 0:
			if clean[o] == '[' && assign {
				return from()
			}
			return -1, -1, false
		case clean[bb] == ':' && clean[o2] == '{':
			// the value of a key in an enclosing pattern, or of a property in an object literal
		case (clean[bb] == ',' || clean[bb] == '[') && clean[o2] == '[':
			// an element of an enclosing array pattern, or of an array literal
		case (clean[bb] == ',' || clean[bb] == '(') && clean[o2] == '(':
			if parameterList(clean, o2) {
				return -1, -1, true
			}
			if clean[bb] == '(' && assign {
				return from() // `({ ... } = src)`
			}
			return -1, -1, false
		default:
			if clean[o] == '[' && assign && strings.ContainsRune(";{}", clean[bb]) {
				return from() // `[a, { ... }] = src` as a statement
			}
			return -1, -1, false
		}
		o, top = o2, false
	}
}

// plainSource reports whether clean[src:end] is a bare name that does not resolve to the
// global object and is the whole source.
func plainSource(clean []rune, src, end int, globals *globalScope) bool {
	if src >= len(clean) || !isIdentStart(clean[src]) || clean[src] == '_' {
		return false
	}
	w, e := readWord(clean, src)
	if w == "this" || w == "super" || isGlobalBase(w) || globals.isGlobal(w, src) {
		return false
	}
	return skipSpace(clean, e) >= end || valueTail(clean, e)
}

// matchingClose returns the index of the brace closing the one at open, or -1.
func matchingClose(clean []rune, open int) int {
	if open < 0 || open >= len(clean) || clean[open] != '{' {
		return -1
	}
	depth := 0
	for k := open; k < len(clean); k++ {
		switch clean[k] {
		case '{', '(', '[':
			depth++
		case '}', ')', ']':
			depth--
			if depth == 0 {
				return k
			}
		}
	}
	return -1
}

// patternValueEnds reports whether a pattern element's value ending at e is a plain binding:
// the next token ends the element, closes the pattern or starts a default value.
func patternValueEnds(clean []rune, e int) bool {
	q := skipSpace(clean, e)
	if q >= len(clean) {
		return false
	}
	switch clean[q] {
	case ',', '}':
		return true
	case '=':
		return !(q+1 < len(clean) && (clean[q+1] == '=' || clean[q+1] == '>'))
	}
	return false
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
