package jsanalysis

import "sort"

// The global object holds eval and the Function constructor, so any access to it that
// can name one of them runs code built at run time: a computed key (`globalThis[k](s)`),
// `.eval` or `.Function`, or the object handed to code that indexes it
// (`Reflect.get(g, k)`). The global is reached by name (globalThis, global, window,
// self), through a local alias of one, through `this` where it is the global, and
// through `Function('return this')()`.
//
// This tracking is lexical and bounded. It follows a name declared from a global value;
// it does not follow the global into an object property or through a parameter, and an
// unknown receiver indexed by a computed key is not treated as the global.

// globalBase are the names that hold the global object in Node and in browsers.
var globalBase = []string{"globalThis", "global", "window", "self"}

// globalNames returns globalBase plus every name a const/let/var declaration
// initialises from an expression that can yield the global: one of these names in value
// position, `this` where thisIsGlobal reports it (top level only), or a call of the Function constructor
// (`Function('return this')()`). Aliases of aliases are followed to a fixpoint.
func globalNames(clean []rune, thisIsGlobal func(int) bool) map[string]bool {
	g := map[string]bool{}
	for _, name := range globalBase {
		g[name] = true
	}
	type decl struct {
		name       string
		start, end int
	}
	var decls []decl
	n := len(clean)
	for i := 0; i < n; {
		if !isIdentStart(clean[i]) {
			i++
			continue
		}
		word, next := readWord(clean, i)
		i = next
		if word != "const" && word != "let" && word != "var" {
			continue
		}
		for p := next; ; {
			name, nx := peekWord(clean, skipSpace(clean, p))
			if name == "" {
				break
			}
			q := skipSpace(clean, nx)
			if q >= n || clean[q] != '=' || (q+1 < n && (clean[q+1] == '=' || clean[q+1] == '>')) {
				break
			}
			end := initEnd(clean, q+1)
			decls = append(decls, decl{name, q + 1, end})
			if end >= n || clean[end] != ',' {
				break
			}
			p = end + 1
		}
	}
	for changed := true; changed; {
		changed = false
		for _, d := range decls {
			if !g[d.name] && yieldsGlobal(clean, d.start, d.end, g, thisIsGlobal) {
				g[d.name] = true
				changed = true
			}
		}
	}
	return g
}

// initEnd returns the index of the ',' or ';' that ends the initialiser starting at p at
// bracket depth zero, or of the bracket that closes the enclosing one.
func initEnd(clean []rune, p int) int {
	depth := 0
	for ; p < len(clean); p++ {
		switch clean[p] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return p
			}
			depth--
		case ',', ';':
			if depth == 0 {
				return p
			}
		}
	}
	return p
}

// yieldsGlobal reports whether the expression in clean[start:end] can evaluate to the
// global: a global-valued name or global `this` in value position (not a member read,
// call or index of it, and not under typeof), or a call of a Function constructor call.
func yieldsGlobal(clean []rune, start, end int, g map[string]bool, thisIsGlobal func(int) bool) bool {
	for i := start; i < end; {
		if !isIdentStart(clean[i]) {
			i++
			continue
		}
		word, next := readWord(clean, i)
		b := skipSpaceBack(clean, i-1)
		member := b >= 0 && clean[b] == '.'
		switch {
		case member:
		case word == "Function":
			if p := skipSpace(clean, next); p < end && clean[p] == '(' {
				if _, e := parseParamArity(clean, p); skipSpace(clean, e) < end && clean[skipSpace(clean, e)] == '(' {
					return true
				}
			}
		case g[word] || (word == "this" && thisIsGlobal(i)):
			if w, _ := wordBefore(clean, b); w == "typeof" {
				break
			}
			p := skipSpace(clean, next)
			if p < end && (clean[p] == '.' || clean[p] == '[' || clean[p] == '(') {
				break
			}
			if p+1 < end && (clean[p] == '=' || clean[p] == '!') && clean[p+1] == '=' {
				break
			}
			return true
		}
		i = next
	}
	return false
}

// globalUse records a use of the global-valued name or global `this` at [i, next): a
// computed key on it, `.eval` or `.Function` read from it, or the object handed on as a
// value. A literal key is judged by keyedUse. For a function's own `this` (callOnly), which
// is the global only when the function is called plainly, just a computed key that is
// called and `.eval`/`.Function` count: handing that `this` on (`fn.apply(this, args)`)
// and indexing it without a call are how methods written as functions use their receiver.
func (mb *moduleBindings) globalUse(clean []rune, i, next int, callOnly bool) {
	n := len(clean)
	b := skipSpaceBack(clean, i-1)
	if b >= 0 && clean[b] == '.' {
		return
	}
	p := skipSpace(clean, next)
	if optionalDot(clean, p) {
		p++
		if q := skipSpace(clean, p+1); q < n && clean[q] == '[' {
			p = q
		}
	}
	switch {
	case p < n && clean[p] == '[':
		if a := skipSpace(clean, p+1); a < n && clean[a] == '_' {
			if e := skipSpace(clean, a+1); e < n && clean[e] == ']' {
				return // a literal key; keyedUse judges it
			}
		}
		if !callOnly {
			mb.evaluated = true
		} else if e := closeBracket(clean, p); e < n {
			if q := skipSpace(clean, e+1); q < n && clean[q] == '(' || optionalCall(clean, q) {
				mb.evaluated = true
			}
		}
	case p < n && clean[p] == '.':
		switch w, _ := peekWord(clean, skipSpace(clean, p+1)); w {
		case "eval", "Function":
			mb.evaluated = true
		}
	case !callOnly && escapesAsValue(clean, b, p):
		mb.evaluated = true
	}
}

// thisFrames classifies, for every '{' in clean, whether `this` directly inside that
// brace block is the global object, so thisGlobalAt can answer for any position.
type thisFrames struct {
	opens  []int  // positions of '{', ascending
	closes []int  // matching '}' position for each open, or len(clean) when unclosed
	parent []int  // index of the enclosing block, or -1
	fn     []bool // the block is a function body (not an arrow body, which keeps this)
	global []bool // this inside the block (not in a nested function) is the global
}

// newThisFrames scans clean once. A block is a function body when its '{' follows a
// parameter list; `function [name](...)` makes this the global (a plain call in sloppy
// mode); a method (`name(...) {`, a getter or setter) or a class body binds it to an
// object; an arrow body and any other block inherit it from the enclosing block. At top
// level this is treated as the global, because a script (a UMD bundle loaded by a tag)
// runs there with this bound to it.
func newThisFrames(clean []rune) *thisFrames {
	n := len(clean)
	tf := &thisFrames{}
	type open struct {
		k      int // index into tf.opens
		global bool
	}
	var stack []open
	var parens []int
	matchParen := map[int]int{} // ')' → '('
	for i := 0; i < n; i++ {
		switch clean[i] {
		case '(':
			parens = append(parens, i)
		case ')':
			if len(parens) > 0 {
				matchParen[i] = parens[len(parens)-1]
				parens = parens[:len(parens)-1]
			}
		case '{':
			outer := true
			if len(stack) > 0 {
				outer = stack[len(stack)-1].global
			}
			g := outer
			fn := false
			b := skipSpaceBack(clean, i-1)
			switch {
			case b >= 1 && clean[b] == '>' && clean[b-1] == '=': // arrow body
			case b >= 0 && clean[b] == ')':
				if o, ok := matchParen[b]; ok {
					q := skipSpaceBack(clean, o-1)
					w, s := wordBefore(clean, q)
					switch w {
					case "if", "for", "while", "switch", "catch", "with":
					case "function":
						g, fn = true, true
					case "":
						if q >= 0 && clean[q] == '*' { // function* (...) or *method(...)
							if w2, _ := wordBefore(clean, skipSpaceBack(clean, q-1)); w2 == "function" {
								g = true
							} else {
								g = false
							}
							fn = true
						}
					default:
						if w2, _ := wordBefore(clean, skipSpaceBack(clean, s-1)); w2 == "function" {
							g = true
						} else {
							g = false // a method, getter or setter
						}
						fn = true
					}
				}
			default:
				if classBody(clean, b) {
					g, fn = false, true
				}
			}
			parent := -1
			if len(stack) > 0 {
				parent = stack[len(stack)-1].k
			}
			stack = append(stack, open{len(tf.opens), g})
			tf.opens = append(tf.opens, i)
			tf.closes = append(tf.closes, n)
			tf.parent = append(tf.parent, parent)
			tf.fn = append(tf.fn, fn)
			tf.global = append(tf.global, g)
		case '}':
			if len(stack) > 0 {
				tf.closes[stack[len(stack)-1].k] = i
				stack = stack[:len(stack)-1]
			}
		}
	}
	return tf
}

// classBody reports whether the '{' after position b opens a class body:
// `class [Name] [extends Expr] {`.
func classBody(clean []rune, b int) bool {
	for k, steps := b, 0; k >= 0 && steps < 8; steps++ {
		w, s := wordBefore(clean, k)
		if w == "" {
			return false
		}
		if w == "class" {
			return true
		}
		k = skipSpaceBack(clean, s-1)
		if k >= 0 && clean[k] == '.' {
			k = skipSpaceBack(clean, k-1)
		}
	}
	return false
}

// closeBracket returns the index of the ']' that closes the '[' at p, or len(clean).
func closeBracket(clean []rune, p int) int {
	depth := 0
	for ; p < len(clean); p++ {
		switch clean[p] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return p
			}
		}
	}
	return p
}

// topLevel reports whether position i is outside every function body, where this is the
// global object itself rather than a function's receiver.
func (tf *thisFrames) topLevel(i int) bool {
	k := sort.SearchInts(tf.opens, i) - 1
	for k >= 0 && tf.closes[k] < i {
		k = tf.parent[k]
	}
	for ; k >= 0; k = tf.parent[k] {
		if tf.fn[k] {
			return false
		}
	}
	return true
}

// globalAt reports whether this at position i is the global object.
func (tf *thisFrames) globalAt(i int) bool {
	k := sort.SearchInts(tf.opens, i) - 1 // the last block opened before i
	for k >= 0 && tf.closes[k] < i {
		k = tf.parent[k]
	}
	if k < 0 {
		return true
	}
	return tf.global[k]
}
