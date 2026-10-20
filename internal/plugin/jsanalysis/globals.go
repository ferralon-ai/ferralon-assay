package jsanalysis

import "sort"

// The global object holds eval and the Function constructor, so any access to it that
// can name one of them runs code built at run time: a computed key (`globalThis[k](s)`),
// `.eval` or `.Function`, or the object handed to code that indexes it
// (`Reflect.get(g, k)`). The global is reached by name (globalThis, global, window,
// self), through a local alias of one, through `this` where it is the global, and
// through `Function('return this')()`.
//
// This tracking is lexical and bounded. It follows a name declared from a global value,
// and a local declaration of a global name shadows it;
// it does not follow the global into an object property or through a parameter, and an
// unknown receiver indexed by a computed key is not treated as the global.

// globalBase are the names that hold the global object in Node and in browsers.
var globalBase = []string{"globalThis", "global", "window", "self"}

// globalScope resolves a name at a position to the global object or to something else.
// A name resolves through the innermost enclosing scope that declares it: a function
// parameter, a function declaration, a var (scoped to its function), or a let/const
// (scoped to its block). It is the global when that declaration initialises it from an
// expression that can yield the global, and otherwise is a local that shadows the global
// (`var self = this` in a constructor). A name no scope declares is the global only when it
// is one of globalBase. At the top level a var of a globalBase name stays the global: in a
// script it binds the global object's own property.
type globalScope struct {
	tf      *thisFrames
	decls   []globalDecl
	byScope map[int]map[string][]int // scope (a block index, or -1 for the top level) → name → decls
	sites   map[int]bool             // positions of declared names, which are not uses
	yields  []bool                   // decl initialises its name from a global-yielding expression
}

// globalDecl is one declared name; start == end when it has no initialiser.
type globalDecl struct {
	name       string
	start, end int
	topVar     bool // a var at the top level
}

func newGlobalScope(clean []rune, tf *thisFrames) *globalScope {
	gs := &globalScope{tf: tf, byScope: map[int]map[string][]int{}, sites: map[int]bool{}}
	add := func(scope, at int, name string, start, end int, topVar bool) {
		if gs.byScope[scope] == nil {
			gs.byScope[scope] = map[string][]int{}
		}
		gs.byScope[scope][name] = append(gs.byScope[scope][name], len(gs.decls))
		gs.decls = append(gs.decls, globalDecl{name, start, end, topVar})
		gs.sites[at] = true
	}
	n := len(clean)
	for k, pr := range tf.params {
		if pr[0] < 0 {
			continue
		}
		for _, at := range paramSites(clean, pr[0], pr[1]) {
			name, _ := readWord(clean, at)
			add(k, at, name, 0, 0, false)
		}
	}
	for i := 0; i < n; {
		if !isIdentStart(clean[i]) {
			i++
			continue
		}
		word, next := readWord(clean, i)
		if b := skipSpaceBack(clean, i-1); b >= 0 && clean[b] == '.' {
			i = next
			continue
		}
		switch word {
		case "function":
			b := skipSpaceBack(clean, i-1)
			if b >= 0 && clean[b] != ';' && clean[b] != '{' && clean[b] != '}' {
				break // a function expression's name is scoped to its own body
			}
			at := skipSpace(clean, next)
			if name, _ := peekWord(clean, at); name != "" {
				add(tf.varScope(tf.block(i)), at, name, 0, 0, false)
			}
		case "var", "let", "const":
			scope := tf.block(i)
			if word == "var" {
				scope = tf.varScope(scope)
			}
			for p := next; ; {
				at := skipSpace(clean, p)
				name, nx := peekWord(clean, at)
				if name == "" {
					break
				}
				q := skipSpace(clean, nx)
				start, end := q, q
				if q < n && clean[q] == '=' && !(q+1 < n && (clean[q+1] == '=' || clean[q+1] == '>')) {
					start, end = q+1, initEnd(clean, q+1)
				}
				add(scope, at, name, start, end, word == "var" && scope < 0)
				if end >= n || clean[end] != ',' {
					break
				}
				p = end + 1
			}
		}
		i = next
	}
	gs.yields = make([]bool, len(gs.decls))
	for changed := true; changed; {
		changed = false
		for d, decl := range gs.decls {
			if !gs.yields[d] && decl.start < decl.end && gs.yieldsGlobal(clean, decl.start, decl.end) {
				gs.yields[d] = true
				changed = true
			}
		}
	}
	return gs
}

// paramSites returns the positions of the plain names declared by the parameter list in
// clean[start:end]: each name at depth zero that opens a parameter, after `(`, `,` or
// `...`. A destructured parameter declares nothing here.
func paramSites(clean []rune, start, end int) []int {
	var out []int
	depth := 0
	expect := true
	for p := start; p < end; p++ {
		r := clean[p]
		switch {
		case r == '(' || r == '[' || r == '{':
			depth++
			expect = false
		case r == ')' || r == ']' || r == '}':
			depth--
		case r == ',' && depth == 0:
			expect = true
		case r == '.' || r == ' ' || r == '\t' || r == '\n' || r == '\r':
		case isIdentStart(r):
			_, nx := readWord(clean, p)
			if expect && depth == 0 {
				out = append(out, p)
			}
			expect = false
			p = nx - 1
		default:
			expect = false
		}
	}
	return out
}

// isGlobal reports whether the name at position i is the global object.
func (gs *globalScope) isGlobal(name string, i int) bool {
	if gs.sites[i] {
		return false
	}
	base := false
	for _, b := range globalBase {
		base = base || name == b
	}
	for k := gs.tf.block(i); ; k = gs.tf.parent[k] {
		if ds := gs.byScope[k][name]; len(ds) > 0 {
			for _, d := range ds {
				if gs.yields[d] || (base && gs.decls[d].topVar) {
					return true
				}
			}
			return false
		}
		if k < 0 {
			return base
		}
	}
}

// yieldsGlobal reports whether the expression in clean[start:end] can evaluate to the
// global: a global-valued name or top-level `this` in value position (not a member read,
// call or index of it, and not under typeof), or a call of a Function constructor call.
func (gs *globalScope) yieldsGlobal(clean []rune, start, end int) bool {
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
		case (word == "this" && gs.tf.topLevel(i)) || (word != "this" && gs.isGlobal(word, i)):
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
	opens  []int    // positions of '{', ascending
	closes []int    // matching '}' position for each open, or len(clean) when unclosed
	parent []int    // index of the enclosing block, or -1
	fn     []bool   // the block is a function body (not an arrow body, which keeps this)
	scope  []bool   // the block is a function or arrow body, which scopes a var
	params [][2]int // the parameter list [start, end) declaring names in the block, or {-1, -1}
	global []bool   // this inside the block (not in a nested function) is the global
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
			fn, scope := false, false
			params := [2]int{-1, -1}
			b := skipSpaceBack(clean, i-1)
			switch {
			case b >= 1 && clean[b] == '>' && clean[b-1] == '=': // arrow body
				scope = true
				if q := skipSpaceBack(clean, b-2); q >= 0 && clean[q] == ')' {
					if o, ok := matchParen[q]; ok {
						params = [2]int{o + 1, q}
					}
				} else if w, s := wordBefore(clean, q); w != "" {
					params = [2]int{s, q + 1}
				}
			case b >= 0 && clean[b] == ')':
				if o, ok := matchParen[b]; ok {
					q := skipSpaceBack(clean, o-1)
					w, s := wordBefore(clean, q)
					switch w {
					case "catch":
						params = [2]int{o + 1, b}
					case "if", "for", "while", "switch", "with":
					case "function":
						g, fn, scope = true, true, true
						params = [2]int{o + 1, b}
					case "":
						if q >= 0 && clean[q] == '*' { // function* (...) or *method(...)
							if w2, _ := wordBefore(clean, skipSpaceBack(clean, q-1)); w2 == "function" {
								g = true
							} else {
								g = false
							}
							fn, scope = true, true
							params = [2]int{o + 1, b}
						}
					default:
						if w2, _ := wordBefore(clean, skipSpaceBack(clean, s-1)); w2 == "function" {
							g = true
						} else {
							g = false // a method, getter or setter
						}
						fn, scope = true, true
						params = [2]int{o + 1, b}
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
			tf.scope = append(tf.scope, scope)
			tf.params = append(tf.params, params)
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

// block returns the index of the innermost block enclosing position i, or -1.
func (tf *thisFrames) block(i int) int {
	k := sort.SearchInts(tf.opens, i) - 1 // the last block opened before i
	for k >= 0 && tf.closes[k] < i {
		k = tf.parent[k]
	}
	return k
}

// varScope returns the function or arrow body enclosing block k (k itself if it is one),
// or -1 for the top level.
func (tf *thisFrames) varScope(k int) int {
	for k >= 0 && !tf.scope[k] {
		k = tf.parent[k]
	}
	return k
}

// topLevel reports whether position i is outside every function body, where this is the
// global object itself rather than a function's receiver.
func (tf *thisFrames) topLevel(i int) bool {
	for k := tf.block(i); k >= 0; k = tf.parent[k] {
		if tf.fn[k] {
			return false
		}
	}
	return true
}

// globalAt reports whether this at position i is the global object.
func (tf *thisFrames) globalAt(i int) bool {
	k := tf.block(i)
	if k < 0 {
		return true
	}
	return tf.global[k]
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
