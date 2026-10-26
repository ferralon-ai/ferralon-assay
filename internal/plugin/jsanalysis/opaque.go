package jsanalysis

import (
	"strings"
	"unicode"
)

// Opaque call sites.
//
// The call scanner resolves a callee written as a name or a dotted chain (f(), a.b.f()). Every
// other call expression has a callee the lane does not track, so the call may run any frame a
// value can carry: call-on-call (get()(1)), a computed member or index (t[k](1), hs[0](1)), a
// parenthesized or comma expression ((0, f)(1)), an optional call on any of those (t[k]?.(1)), a
// TypeScript non-null call (f!(1)), a tagged template (tag`x`), a `new` with no argument list
// (new C), a super constructor call (super(x)) and a bare decorator (@dec). Each is an opaque
// site: listed in Unresolved without Targets, never an edge. A function value reaching such a
// callee is an escape root (escape.go: passed, stored, returned or used as a template tag), so an
// unbounded entry covers it.
//
// A parenthesized function expression called in place ((function () {…})(), (() => …)()) is not
// opaque: the scanner reads its body in the enclosing frame, so the call hides no edge.

// opaqueSite is one call whose callee is not a name or a dotted chain.
type opaqueSite struct {
	written string // the callee as the source spells it, whitespace collapsed
	arity   int    // the argument count; a tagged template counts its strings and substitutions
}

// maxWritten bounds an opaque callee's text; a longer one keeps its head and ends in "…".
const maxWritten = 80

// opaqueSiteAt reports whether clean[i] starts an opaque site: the '(' of a call whose callee
// is not a name or chain, the opener of a tagged template, a `new` with no argument list, a
// super(…) call or a bare decorator. raw is the position-identical source (nil when only the
// cleaned runes are at hand: a template set off from its tag by a space is then not seen).
func opaqueSiteAt(clean, raw []rune, i int) (opaqueSite, bool) {
	n := len(clean)
	c := clean[i]
	switch {
	case c == '(':
		e, ok := opaqueCalleeEnd(clean, i)
		if !ok {
			return opaqueSite{}, false
		}
		arity, _ := parseParamArity(clean, i)
		return opaqueSite{written: writtenSpan(clean, raw, calleeStart(clean, e), e), arity: arity}, true
	case c == '`' || c == '_' && raw != nil && i < len(raw) && raw[i] == '`':
		e, ok := tagEnd(clean, i)
		if !ok {
			return opaqueSite{}, false
		}
		arity := 1
		if raw != nil {
			if _, _, subs, ok := templateScan(clean, raw, i); ok {
				arity += subs
			}
		}
		return opaqueSite{written: writtenSpan(clean, raw, calleeStart(clean, e), e), arity: arity}, true
	case c == '@':
		chain, end := decoratorAt(clean, i)
		if chain == "" {
			return opaqueSite{}, false
		}
		if p := skipSpace(clean, end); p < n && (clean[p] == '(' || clean[p] == '<') {
			return opaqueSite{}, false // @dec(…): a call the chain scan reads
		}
		return opaqueSite{written: "@" + chain, arity: 1}, true
	case (c == 'n' || c == 's') && (i == 0 || !isIdentPart(clean[i-1])):
		word, next := readWord(clean, i)
		if b := skipSpaceBack(clean, i-1); b >= 0 && clean[b] == '.' {
			return opaqueSite{}, false // a member named new or super
		}
		switch word {
		case "super":
			if p := skipSpace(clean, next); p < n && clean[p] == '(' {
				arity, _ := parseParamArity(clean, p)
				return opaqueSite{written: "super", arity: arity}, true
			}
		case "new":
			p := skipSpace(clean, next)
			if p >= n || !isIdentStart(clean[p]) {
				return opaqueSite{}, false // new.target, new (expr), a TypeScript constructor type
			}
			chain, end := dottedChain(clean, p)
			q := skipSpace(clean, end)
			if q < n && clean[q] == '<' {
				q = skipSpace(clean, skipGroup(clean, q))
			}
			if q < n && clean[q] == '(' {
				return opaqueSite{}, false // new C(…): the chain scan reads C(…)
			}
			return opaqueSite{written: "new " + chain, arity: 0}, true
		}
	}
	return opaqueSite{}, false
}

// opaqueCalleeEnd reports whether the '(' at open calls an opaque callee, and where that callee
// ends: after a ')' or ']' (call-on-call, a parenthesized expression, an index), after `?.` on
// one of those, or after a TypeScript non-null '!'. A '(' after a name or chain is the chain
// scan's, and a '(' after a statement's condition, a computed method name or an in-place
// function expression is no call of an opaque value.
func opaqueCalleeEnd(clean []rune, open int) (int, bool) {
	q := skipSpaceBack(clean, open-1)
	if q < 0 {
		return 0, false
	}
	switch {
	case clean[q] == '.' && q >= 1 && clean[q-1] == '?':
		e := skipSpaceBack(clean, q-2)
		if e < 0 || clean[e] != ')' && clean[e] != ']' {
			return 0, false // name?.(…) is the chain scan's
		}
		return e, groupCallee(clean, e)
	case clean[q] == '!' && q == open-1 && q >= 1 && exprEnd(clean, q-1):
		return q - 1, true
	case clean[q] == ')' || clean[q] == ']':
		if !groupCallee(clean, q) {
			return 0, false
		}
		if clean[q] == ']' {
			if c := skipSpace(clean, closeOf(clean, open)+1); c < len(clean) && clean[c] == '{' {
				return 0, false // [key](…) { … }: a computed method name
			}
		}
		return q, true
	}
	return 0, false
}

// groupCallee reports whether the ')' or ']' at e ends a value that may be called: not a
// statement's condition (if (x) (…)), a function expression called in place, or an array
// literal or computed key.
func groupCallee(clean []rune, e int) bool {
	o := enclosingOpen(clean, e)
	if o < 0 {
		return false
	}
	if clean[e] == ']' {
		// An index, not an array literal or a computed member name.
		b := skipSpaceBack(clean, o-1)
		if word, _ := wordBefore(clean, b); memberModifier[word] {
			return false
		}
		return exprEnd(clean, b)
	}
	if conditionParen(clean, o) {
		return false
	}
	if _, ok := funcExprAt(clean, o+1, e); ok && !exprEnd(clean, skipSpaceBack(clean, o-1)) {
		return false // (function () {…})(): its body is read in the enclosing frame
	}
	return true
}

// tagEnd reports whether the template opening at clean[open] is tagged, and where its tag
// ends: a name or chain, a call, a parenthesized expression or an index directly before it.
func tagEnd(clean []rune, open int) (int, bool) {
	e := skipSpaceBack(clean, open-1)
	if e < 0 || !exprEnd(clean, e) {
		return 0, false
	}
	if clean[e] == ')' || clean[e] == ']' {
		return e, groupCallee(clean, e)
	}
	return e, true
}

// exprEnd reports whether clean[e] ends an expression a call or index may follow: a name
// that is not an operator keyword or a member modifier, or a ')' or ']' closing a group that
// is not a statement's condition.
func exprEnd(clean []rune, e int) bool {
	if e < 0 {
		return false
	}
	switch c := clean[e]; {
	case c == ')':
		o := enclosingOpen(clean, e)
		return o >= 0 && !conditionParen(clean, o)
	case c == ']':
		return true
	case isIdentPart(c):
		word, _ := wordBefore(clean, e)
		return !notOperand[word]
	}
	return false
}

// notOperand are the words that precede an expression rather than end one: operator and
// statement keywords.
var notOperand = map[string]bool{
	"return": true, "typeof": true, "await": true, "yield": true, "case": true, "delete": true,
	"void": true, "throw": true, "new": true, "in": true, "of": true, "instanceof": true,
	"else": true, "do": true, "extends": true, "default": true, "export": true, "import": true,
	"let": true, "const": true, "var": true, "as": true, "satisfies": true, "keyof": true,
}

// memberModifier are the words a computed member name may follow in a class body or object
// literal (static [k]() {}): a '[' after one opens a key, not an index.
var memberModifier = map[string]bool{
	"static": true, "get": true, "set": true, "async": true, "public": true, "private": true,
	"protected": true, "readonly": true, "override": true, "abstract": true, "declare": true,
	"accessor": true,
}

// conditionParen reports whether the '(' at o opens a statement's condition or header: if,
// while, for (and for await), switch, catch or with.
func conditionParen(clean []rune, o int) bool {
	b := skipSpaceBack(clean, o-1)
	word, s := wordBefore(clean, b)
	if word == "await" {
		word, _ = wordBefore(clean, skipSpaceBack(clean, s-1))
	}
	switch word {
	case "if", "while", "for", "switch", "catch", "with":
		return true
	}
	return false
}

// calleeStart walks back from the callee's last rune e over the postfix expression it ends:
// names joined by '.' or '?.', and call or index groups after an operand. It stops at the
// operand that starts the expression: a name, or a parenthesized expression or array literal.
func calleeStart(clean []rune, e int) int {
	pos := e
	for {
		var start int
		switch c := clean[pos]; {
		case c == ')' || c == ']':
			start = enclosingOpen(clean, pos)
			if start < 0 {
				return pos
			}
		case isIdentPart(c):
			_, start = wordBefore(clean, pos)
		default:
			return pos
		}
		b := skipSpaceBack(clean, start-1)
		switch {
		case b >= 0 && clean[b] == '.' && !(b >= 1 && clean[b-1] == '.'):
			// a member: carry on over the object it is read from
			if b >= 1 && clean[b-1] == '?' {
				b--
			}
			if prev := skipSpaceBack(clean, b-1); prev >= 0 && (exprEnd(clean, prev) || isIdentPart(clean[prev])) {
				pos = prev
				continue
			}
			return start
		case (clean[pos] == ')' || clean[pos] == ']') && exprEnd(clean, b):
			pos = b // a call's arguments or an index, after their operand
			continue
		}
		return start
	}
}

// dottedChain reads a name and any `.name` members after it from p, returning the chain as
// written and the index past it.
func dottedChain(clean []rune, p int) (string, int) {
	var segs []string
	for {
		w, e := readWord(clean, p)
		if w == "" {
			break
		}
		segs = append(segs, w)
		d := skipSpace(clean, e)
		if d+1 < len(clean) && clean[d] == '.' && isIdentStart(clean[skipSpace(clean, d+1)]) {
			p = skipSpace(clean, d+1)
			continue
		}
		return strings.Join(segs, "."), e
	}
	return strings.Join(segs, "."), p
}

// decoratorAt reads the decorator whose '@' is at i: the chain after it, when the '@' starts a
// decorator (at a statement, member or parameter boundary, or after another decorator) and the
// chain is followed by what a decorator applies to. It returns "" for any other '@' (text in
// JSX, which the lexer keeps).
func decoratorAt(clean []rune, i int) (string, int) {
	n := len(clean)
	b := skipSpaceBack(clean, i-1)
	switch {
	case b < 0:
	case strings.ContainsRune(";{}(),", clean[b]):
	case isIdentPart(clean[b]):
		word, s := wordBefore(clean, b)
		if word != "export" && word != "default" && word != "declare" && word != "abstract" && !afterDecorator(clean, s) {
			return "", i
		}
	default:
		return "", i
	}
	p := i + 1
	if p >= n || !isIdentStart(clean[p]) {
		return "", i
	}
	chain, end := dottedChain(clean, p)
	q := skipSpace(clean, end)
	if q < n && (clean[q] == '(' || clean[q] == '<') {
		return chain, end
	}
	if q >= n || !(isIdentStart(clean[q]) || strings.ContainsRune("@[#*", clean[q])) {
		return "", i
	}
	return chain, end
}

// afterDecorator reports whether the name chain ending just before s is itself a bare
// decorator (@a @b class C …).
func afterDecorator(clean []rune, s int) bool {
	p := s - 1
	for p >= 0 && (isIdentPart(clean[p]) || clean[p] == '.') {
		p--
	}
	return p >= 0 && clean[p] == '@'
}

// writtenSpan renders source[from:to] (inclusive) with whitespace runs collapsed, bounded by
// maxWritten. It reads raw when it has it, so a literal in the callee keeps its text.
func writtenSpan(clean, raw []rune, from, to int) string {
	src := clean
	if raw != nil && len(raw) == len(clean) {
		src = raw
	}
	var b strings.Builder
	space := false
	count := 0
	for _, c := range src[from : to+1] {
		if unicode.IsSpace(c) {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteRune(' ')
			count++
		}
		space = false
		if count >= maxWritten-1 {
			b.WriteRune('…')
			return b.String()
		}
		b.WriteRune(c)
		count++
	}
	return b.String()
}
