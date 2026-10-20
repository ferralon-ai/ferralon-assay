package jsanalysis

import (
	"sort"
	"strings"
	"unicode"
)

// The global object holds eval and the Function constructor, so any access to it that
// can name one of them runs code built at run time: a computed key (`globalThis[k](s)`),
// `.eval` or `.Function`, or the object handed to code that indexes it
// (`Reflect.get(g, k)`). The global is reached by name (see globalBase), through a local
// alias of one, through `this` where it is the global, and through
// `Function('return this')()`.
//
// This tracking is lexical and bounded. It follows the global into a name that is
// declared, assigned, defaulted or destructured from it, and into the parameter of a
// function called in place; a local declaration or import of a global name shadows it.
// It does not follow the global into an object property or through the parameter of a
// function called elsewhere, and an unknown receiver indexed by a computed key is not
// treated as the global.

// globalBase are the names that hold a global object in Node and in browsers.
var globalBase = []string{"globalThis", "global", "window", "self", "frames", "parent", "top", "opener"}

// globalScope resolves a name at a position to the global object or to something else.
// A name resolves through the innermost enclosing scope that declares it: a function
// parameter, a function declaration, a var (scoped to its function), or a let/const
// (scoped to its block), or an import. It is the global when any value that declaration or
// an assignment gives it can yield the global, and otherwise is a local that shadows the
// global (`var self = this` in a constructor). A name no scope declares is the global
// only when it is one of globalBase. At the top level a var of a globalBase name stays the
// global until it is certainly replaced: in a script it binds the global object's own
// property.
type globalScope struct {
	tf       *thisFrames
	decls    []globalDecl
	byScope  map[int]map[string][]int // scope (a block index, or -1 for the top level) → name → decls
	sites    map[int]bool             // positions of declared names, which are not uses
	yields   []bool                   // decl initialises its name from a global-yielding expression
	flows    [][2]int                 // initialiser and bound-argument ranges whose value a decl holds
	thisArg  map[int][2]int           // function block → the this its in-place call binds, or {0, 0} for a plain call
	thisIs   map[int]bool             // function block whose this, bound by its in-place call, can be the global
	fnDecl   map[int]int              // decl → the block of the function it declares
	kwFrame  map[int]int              // position of a function keyword → the block of its body
	retThis  map[int]bool             // function block → whether it returns its own this (memo)
	keyed    bool                     // a pattern takes a computed, Function, eval or require key from the global
	patterns [][3]int                 // destructuring pattern bracket, source start and end
}

// globalDecl is one declared name; start == end when it has no initialiser.
type globalDecl struct {
	name       string
	start, end int
	topVar     bool // a var at the top level
	bare       bool // declared outside every block, so it runs before what follows it
	weak       bool // declared in a block that may not be the scope it is read as; never shadows
}

func newGlobalScope(clean []rune, tf *thisFrames) *globalScope {
	gs := &globalScope{tf: tf, byScope: map[int]map[string][]int{}, sites: map[int]bool{},
		thisArg: map[int][2]int{}, thisIs: map[int]bool{}, fnDecl: map[int]int{},
		kwFrame: map[int]int{}, retThis: map[int]bool{}}
	for k, kw := range tf.fnKw {
		if kw >= 0 {
			gs.kwFrame[kw] = k
		}
	}
	n := len(clean)
	add := func(scope, at int, name string, start, end int, topVar, bare bool) {
		if gs.byScope[scope] == nil {
			gs.byScope[scope] = map[string][]int{}
		}
		weak := scope >= 0 && tf.weak[scope]
		gs.byScope[scope][name] = append(gs.byScope[scope][name], len(gs.decls))
		gs.decls = append(gs.decls, globalDecl{name, start, end, topVar, bare, weak})
		if !weak {
			gs.sites[at] = true // a weak declaration's name may be a use, so it stays one
		}
	}
	// bind declares the names the binding at clean[at] introduces, each holding the value
	// of clean[start:end]. A destructured name holds a property of that value, which is
	// judged as the value itself; a rest name holds an array of it and is not followed.
	// withDefault declares name at site s holding clean[start:end], and also holding its
	// default value when one follows the name.
	withDefault := func(scope, s int, name string, start, end int, topVar, bare bool) {
		add(scope, s, name, start, end, topVar, bare)
		_, e := readWord(clean, s)
		q := skipSpace(clean, e)
		if q < n && clean[q] == ':' {
			q = typeEnd(clean, q+1)
		}
		if q < n && clean[q] == '=' && !(q+1 < n && (clean[q+1] == '=' || clean[q+1] == '>')) {
			d := [2]int{q + 1, initEnd(clean, q+1)}
			add(scope, s, name, d[0], d[1], topVar, bare)
			gs.flows = append(gs.flows, d)
		}
	}
	bind := func(scope, at, start, end int, topVar, bare bool) {
		switch {
		case clean[at] == '{' || clean[at] == '[':
			if start < end {
				gs.patterns = append(gs.patterns, [3]int{at, start, end})
			}
			sites, _ := patternSites(clean, at)
			for _, s := range sites {
				name, _ := readWord(clean, s)
				withDefault(scope, s, name, start, end, topVar, bare)
			}
		case at+3 <= n && string(clean[at:at+3]) == "...":
			if s := skipSpace(clean, at+3); s < n && isIdentStart(clean[s]) {
				name, _ := readWord(clean, s)
				add(scope, s, name, 0, 0, false, false)
			}
			return
		case isIdentStart(clean[at]):
			name, _ := readWord(clean, at)
			withDefault(scope, at, name, start, end, topVar, bare)
		default:
			return
		}
		if start < end {
			gs.flows = append(gs.flows, [2]int{start, end})
		}
	}
	inParams := make([]bool, n)
	for k, pr := range tf.params {
		if pr[0] < 0 {
			continue
		}
		for p := pr[0]; p < pr[1]; p++ {
			inParams[p] = true
		}
		args, thisArg, called := iifeArgs(clean, tf, k)
		if called {
			gs.thisArg[k] = thisArg
		}
		if thisArg[0] < thisArg[1] {
			gs.flows = append(gs.flows, thisArg) // the function's own this, judged as one
		}
		j := 0
		for _, at := range paramSites(clean, pr[0], pr[1]) {
			if w, _ := peekWord(clean, at); w == "this" {
				continue // a TypeScript this parameter takes no argument
			}
			var arg [2]int
			if j < len(args) {
				arg = args[j]
			}
			j++
			bind(k, at, arg[0], arg[1], false, false)
		}
	}
	type assign struct {
		name           string
		at, start, end int
	}
	var assigns []assign
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
			if ambient(clean, tf, tf.block(i)) {
				break // a TypeScript declaration binds no value; `declare function` is an expression below
			}
			if b >= 0 && clean[b] != ';' && clean[b] != '{' && clean[b] != '}' {
				break // a function expression's name is scoped to its own body
			}
			at := skipSpace(clean, next)
			if name, _ := peekWord(clean, at); name != "" {
				add(tf.varScope(tf.block(i)), at, name, 0, 0, false, false)
				if k, ok := gs.kwFrame[i]; ok {
					gs.fnDecl[len(gs.decls)-1] = k
				}
			}
		case "import":
			if ambient(clean, tf, tf.block(i)) {
				break
			}
			for _, at := range importSites(clean, next) {
				name, _ := readWord(clean, at)
				add(-1, at, name, 0, 0, false, false)
			}
		case "var", "let", "const":
			block := tf.block(i)
			if w, _ := wordBefore(clean, skipSpaceBack(clean, i-1)); w == "declare" || ambient(clean, tf, block) {
				break // a TypeScript declaration binds no value
			}
			scope := block
			if word == "var" {
				for scope >= 0 && !tf.scope[scope] && !namespaceBlock(clean, tf.opens[scope]) {
					scope = tf.parent[scope]
				}
			} else if body, ok := forBody(clean, tf, i); ok {
				// A for header's let or const is scoped to the loop; read it as the body's,
				// and leave it undeclared when the body is not a block.
				if body < 0 {
					break
				}
				block, scope = body, body
			}
			for p := next; ; {
				at := skipSpace(clean, p)
				var nx int
				if at < n && (clean[at] == '{' || clean[at] == '[') {
					_, e := patternSites(clean, at)
					nx = e + 1
				} else if name, e := peekWord(clean, at); name != "" {
					nx = e
				} else {
					break
				}
				q := skipSpace(clean, nx)
				if q < n && clean[q] == ':' {
					q = typeEnd(clean, q+1) // a TypeScript annotation
				}
				start, end := q, q
				if q < n && clean[q] == '=' && !(q+1 < n && (clean[q+1] == '=' || clean[q+1] == '>')) {
					start, end = q+1, initEnd(clean, q+1)
				}
				bind(scope, at, start, end, word == "var" && scope < 0, block < 0)
				if end >= n || clean[end] != ',' {
					break
				}
				p = end + 1
			}
		default:
			if gs.sites[i] || inParams[i] {
				break
			}
			if start := assignStart(clean, skipSpace(clean, next)); start > 0 {
				assigns = append(assigns, assign{word, i, start, initEnd(clean, start)})
			}
		}
		i = next
	}
	// An assignment is one more value its name can hold, in the scope that declares the
	// name, or at the top level for an undeclared one. A global name assigned without a
	// declaration stays the global.
	for _, a := range assigns {
		k := tf.block(a.at)
		for k >= 0 && len(gs.byScope[k][a.name]) == 0 {
			k = tf.parent[k]
		}
		if k < 0 && len(gs.byScope[-1][a.name]) == 0 && isGlobalBase(a.name) {
			continue
		}
		add(k, a.at, a.name, a.start, a.end, false, false)
		gs.flows = append(gs.flows, [2]int{a.start, a.end})
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
		// A sloppy function called in place plainly has the global for its this; one
		// called with .call has the this it is handed.
		for k, r := range gs.thisArg {
			if !gs.thisIs[k] && (r[0] == r[1] || gs.yieldsGlobal(clean, r[0], r[1])) {
				gs.thisIs[k] = true
				changed = true
			}
		}
	}
	for _, pt := range gs.patterns {
		if riskyPattern(clean, pt[0]) && gs.yieldsGlobal(clean, pt[1], pt[2]) {
			gs.keyed = true
		}
	}
	return gs
}

// riskyPattern reports whether the destructuring pattern opening at clean[open] takes a
// computed key, or a key named Function, eval or require, anywhere in it: from the global
// object, each reads code this lane cannot follow under a name it does not track.
func riskyPattern(clean []rune, open int) bool {
	_, end := patternSites(clean, open)
	for p := open + 1; p < end; p++ {
		switch {
		case clean[p] == '[':
			if b := skipSpaceBack(clean, p-1); b >= 0 && (clean[b] == '{' || clean[b] == ',') {
				return true
			}
		case isIdentStart(clean[p]):
			w, e := readWord(clean, p)
			if b := skipSpaceBack(clean, p-1); w == "Function" || w == "eval" || w == "require" {
				if !(b >= 0 && clean[b] == '.') {
					return true
				}
			}
			p = e - 1
		}
	}
	return false
}

// paramSites returns where each parameter in the list clean[start:end] begins: its name,
// the bracket of a destructuring pattern, or the dots of a rest parameter.
func paramSites(clean []rune, start, end int) []int {
	var out []int
	depth, slot := 0, -1
	for p := start; p < end; p++ {
		switch r := clean[p]; {
		case r == ',' && depth == 0:
			if slot >= 0 {
				out = append(out, slot)
			}
			slot = -1
		case r == '(' || r == '[' || r == '{':
			if depth == 0 && slot < 0 {
				slot = p
			}
			depth++
		case r == ')' || r == ']' || r == '}':
			depth--
		case unicode.IsSpace(r):
		default:
			if depth == 0 && slot < 0 {
				slot = p
			}
		}
	}
	if slot >= 0 {
		out = append(out, slot)
	}
	return out
}

// patternSites returns the positions of the names the destructuring pattern opening at
// clean[open] binds, and the index of its closing bracket.
func patternSites(clean []rune, open int) (sites []int, end int) {
	n := len(clean)
	obj := clean[open] == '{'
	for p := open + 1; p < n; {
		p = skipSpace(clean, p)
		if p >= n {
			break
		}
		switch clean[p] {
		case '}', ']', ')':
			return sites, p
		case ',':
			p++
			continue
		}
		from, target := p, p
		if p+3 <= n && string(clean[p:p+3]) == "..." {
			target = skipSpace(clean, p+3)
		} else if obj {
			key := p
			if clean[p] == '[' {
				key = closeBracket(clean, p)
			} else if isIdentStart(clean[p]) {
				_, e := readWord(clean, p)
				key = e - 1
			}
			if q := skipSpace(clean, key+1); q < n && clean[q] == ':' {
				target = skipSpace(clean, q+1)
			}
		}
		switch {
		case target < n && (clean[target] == '{' || clean[target] == '['):
			inner, e := patternSites(clean, target)
			sites = append(sites, inner...)
			p = e + 1
		case target < n && isIdentStart(clean[target]):
			sites = append(sites, target)
			_, p = readWord(clean, target)
		default:
			p = target + 1
		}
		if q := skipSpace(clean, p); q < n && clean[q] == '=' {
			p = initEnd(clean, q+1) // a default value
		}
		if p <= from {
			p = from + 1
		}
	}
	return sites, n
}

// forBody reports whether the let or const at i opens a for header, `for [await] (let ...`,
// and returns the block of the loop body, or -1 when the body is a single statement.
func forBody(clean []rune, tf *thisFrames, i int) (int, bool) {
	b := skipSpaceBack(clean, i-1)
	if b < 0 || clean[b] != '(' {
		return 0, false
	}
	w, s := wordBefore(clean, skipSpaceBack(clean, b-1))
	if w == "await" {
		w, _ = wordBefore(clean, skipSpaceBack(clean, s-1))
	}
	if w != "for" {
		return 0, false
	}
	q := skipSpace(clean, closeParen(clean, b)+1)
	if q >= len(clean) || clean[q] != '{' {
		return -1, true
	}
	return tf.block(q + 1), true
}

// ambient reports whether block k lies inside a TypeScript `declare` block (`declare global`,
// `declare module '...'`, `declare namespace N`), whose declarations bind no value.
func ambient(clean []rune, tf *thisFrames, k int) bool {
	for ; k >= 0; k = tf.parent[k] {
		if declareBlock(clean, tf.opens[k]) {
			return true
		}
	}
	return false
}

// namespaceBlock reports whether the '{' at open opens a TypeScript namespace or module body,
// which scopes a var like a function body: `namespace A.B {` or `module '_' {` on one line,
// starting a statement. Any other block, `x = module\n{` among them, does not.
func namespaceBlock(clean []rune, open int) bool {
	k := skipSpaceBack(clean, open-1)
	if k < 0 || !sameLine(clean, k, open) {
		return false
	}
	w, s := wordBefore(clean, k)
	for w != "" && s >= 2 && clean[s-1] == '.' { // a dotted name
		w, s = wordBefore(clean, s-2)
	}
	if w == "" {
		return false
	}
	kw, ks := wordBefore(clean, skipSpaceBack(clean, s-1))
	if kw != "namespace" && kw != "module" || !sameLine(clean, ks, s) {
		return false
	}
	q := skipSpaceBack(clean, ks-1)
	if q < 0 || clean[q] == ';' || clean[q] == '{' || clean[q] == '}' {
		return true
	}
	w, _ = wordBefore(clean, q)
	return w == "export" || w == "declare"
}

// sameLine reports whether no line break lies between positions a and b.
func sameLine(clean []rune, a, b int) bool {
	for p := a; p < b; p++ {
		if clean[p] == '\n' {
			return false
		}
	}
	return true
}

// declareBlock reports whether one of the words before the '{' at open (a dotted name, a
// blanked module string) is declare.
func declareBlock(clean []rune, open int) bool {
	k := skipSpaceBack(clean, open-1)
	for steps := 0; k >= 0 && steps < 8; steps++ {
		w, s := wordBefore(clean, k)
		switch w {
		case "":
			return false
		case "declare":
			return true
		}
		k = skipSpaceBack(clean, s-1)
		if k >= 0 && clean[k] == '.' {
			k = skipSpaceBack(clean, k-1)
		}
	}
	return false
}

// importSites returns the positions of the names an import statement whose keyword ends
// at p binds: `import a, { b as c, type d } from` binds a, c and d; `import * as e from`
// binds e; `import f = require(...)` binds f. A dynamic import() or import.meta binds none,
// and neither does a TypeScript type-only import (`import type ...`, `{ type g }`).
func importSites(clean []rune, p int) []int {
	n := len(clean)
	if q := skipSpace(clean, p); q >= n || clean[q] == '(' || clean[q] == '.' {
		return nil
	}
	if typeModifier(clean, skipSpace(clean, p)) {
		return nil
	}
	var sites []int
	typeOnly := false
	for q := p; q < n; {
		q = skipSpace(clean, q)
		if q >= n || clean[q] == ';' || clean[q] == '_' {
			break // the end, or the blanked module string
		}
		if !isIdentStart(clean[q]) {
			if clean[q] == '{' || clean[q] == ',' {
				typeOnly = typeModifier(clean, skipSpace(clean, q+1))
			}
			q++
			continue
		}
		w, e := readWord(clean, q)
		if w == "from" {
			break
		}
		r := skipSpace(clean, e)
		next, _ := peekWord(clean, r)
		if (r < n && (clean[r] == ',' || clean[r] == '}' || clean[r] == '=') || next == "from") && !typeOnly {
			sites = append(sites, q)
		}
		if r < n && clean[r] == '=' {
			break
		}
		q = e
	}
	return sites
}

// typeModifier reports whether the word at q is a TypeScript `type` modifier: `type` followed
// by a name, a brace or a star, rather than a binding named type (`type,`, `type from`, `type as`).
func typeModifier(clean []rune, q int) bool {
	w, e := peekWord(clean, q)
	if w != "type" {
		return false
	}
	r := skipSpace(clean, e)
	if r < len(clean) && (clean[r] == '{' || clean[r] == '*') {
		return true
	}
	next, e := peekWord(clean, r)
	if next == "as" {
		// `type as as x` and a lone `type as` import the name as, type-only; `type as x`
		// renames a binding named type.
		after, _ := peekWord(clean, skipSpace(clean, e))
		return after == "" || after == "as"
	}
	return next != "" && next != "from"
}

// typeEnd returns the index of the '=', ',' or ';' that ends a TypeScript type annotation
// starting at p at bracket depth zero, or of the bracket that closes the enclosing one.
func typeEnd(clean []rune, p int) int {
	depth := 0
	for ; p < len(clean); p++ {
		switch clean[p] {
		case '(', '[', '{', '<':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return p
			}
			depth--
		case '>':
			if !(p > 0 && clean[p-1] == '=') && depth > 0 {
				depth--
			}
		case '=':
			if depth == 0 && !(p+1 < len(clean) && clean[p+1] == '>') {
				return p
			}
		case ',', ';':
			if depth == 0 {
				return p
			}
		}
	}
	return p
}

// assignStart returns the start of the value assigned when the operator at p is `=`,
// `||=`, `&&=` or `??=`, or -1.
func assignStart(clean []rune, p int) int {
	n := len(clean)
	if p < n && clean[p] == '=' && !(p+1 < n && (clean[p+1] == '=' || clean[p+1] == '>')) {
		return p + 1
	}
	if p+2 < n && clean[p+2] == '=' && clean[p] == clean[p+1] && (clean[p] == '|' || clean[p] == '&' || clean[p] == '?') {
		return p + 3
	}
	return -1
}

func isGlobalBase(name string) bool {
	for _, b := range globalBase {
		if name == b {
			return true
		}
	}
	return false
}

// iifeArgs returns the argument ranges a function expression in block k is called with
// immediately: `(function (a) {...})(x)`, `function (a) {...}(x)` in expression position,
// or either followed by `.call(thisArg, x)`, whose thisArg range it returns too. called
// reports whether it is called in place at all. It returns no arguments when an argument
// is spread, or when the body reads `arguments`, which would see an argument no parameter
// names.
func iifeArgs(clean []rune, tf *thisFrames, k int) (args [][2]int, thisArg [2]int, called bool) {
	kw := tf.fnKw[k]
	if kw < 0 {
		return nil, thisArg, false
	}
	n := len(clean)
	open, close := tf.opens[k], tf.closes[k]
	if close >= n {
		return nil, thisArg, false
	}
	before := skipSpaceBack(clean, kw-1)
	p := skipSpace(clean, close+1)
	switch {
	case p < n && clean[p] == '(' && before >= 0 && strings.ContainsRune("(,=!+-~?:&|[", clean[before]):
	case p < n && clean[p] == ')' && before >= 0 && clean[before] == '(' && closeParen(clean, before) == p:
		p = skipSpace(clean, p+1)
	default:
		return nil, thisArg, false
	}
	call := false
	if p < n && clean[p] == '.' {
		if w, nx := peekWord(clean, skipSpace(clean, p+1)); w == "call" {
			p, call = skipSpace(clean, nx), true
		}
	}
	if p >= n || clean[p] != '(' {
		return nil, thisArg, false
	}
	if call {
		e := initEnd(clean, p+1)
		s := skipSpace(clean, p+1)
		if s >= e {
			return nil, thisArg, false // .call() binds undefined
		}
		thisArg = [2]int{s, e}
	}
	for i := open; i < close; {
		if !isIdentStart(clean[i]) {
			i++
			continue
		}
		w, nx := readWord(clean, i)
		if w == "arguments" {
			return nil, thisArg, true
		}
		i = nx
	}
	depth, from := 0, p+1
	for q := p + 1; q < n; q++ {
		switch clean[q] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				if s := skipSpace(clean, from); s < q {
					args = append(args, [2]int{s, q})
				}
				for _, a := range args {
					if a[1]-a[0] >= 3 && string(clean[a[0]:a[0]+3]) == "..." {
						return nil, thisArg, true
					}
				}
				if call && len(args) > 0 {
					args = args[1:]
				}
				return args, thisArg, true
			}
			depth--
		case ',':
			if depth == 0 {
				args = append(args, [2]int{skipSpace(clean, from), q})
				from = q + 1
			}
		}
	}
	return nil, thisArg, true
}

// closeParen returns the index of the ')' that closes the '(' at p, or len(clean).
func closeParen(clean []rune, p int) int {
	depth := 0
	for ; p < len(clean); p++ {
		switch clean[p] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return p
			}
		}
	}
	return p
}

// flowsTo reports whether the value at position i is the value of the expression in
// clean[start:i...]: no call, index, array, object or function bracket opened after start
// encloses i. A grouping parenthesis does not stop the value.
func flowsTo(clean []rune, start, i int) bool {
	var stack []bool // true for a bracket that stops the value
	for p := start; p < i; p++ {
		switch clean[p] {
		case '(':
			b := skipSpaceBack(clean, p-1)
			call := b >= start && (isIdentPart(clean[b]) || clean[b] == ')' || clean[b] == ']')
			stack = append(stack, call)
		case '[', '{':
			stack = append(stack, true)
		case ')', ']', '}':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case '=':
			// A store into a member or pattern on the way (`g = o.x = v`) hands the value
			// where this lane does not follow it.
			if assignStart(clean, p) == p+1 && memberStore(clean, p) {
				return false
			}
		}
	}
	for _, stops := range stack {
		if stops {
			return false
		}
	}
	return true
}

// held reports whether the global-valued token at i is the value a tracked declaration
// holds, so that handing it there is followed rather than an escape.
func (gs *globalScope) held(clean []rune, i int) bool {
	for _, r := range gs.flows {
		if r[0] <= i && i < r[1] && flowsTo(clean, r[0], i) {
			return true
		}
	}
	return false
}

// isGlobal reports whether the name at position i is the global object.
func (gs *globalScope) isGlobal(name string, i int) bool {
	if gs.sites[i] {
		return false
	}
	base := isGlobalBase(name)
	for k := gs.tf.block(i); ; k = gs.tf.parent[k] {
		if ds := gs.byScope[k][name]; len(ds) > 0 {
			shadows := false
			for _, d := range ds {
				if gs.yields[d] || (base && gs.decls[d].topVar && !gs.replaced(d, name, i)) {
					return true
				}
				shadows = shadows || !gs.decls[d].weak
			}
			if shadows {
				return false
			}
		}
		if k < 0 {
			return base
		}
	}
}

// replaced reports whether the top-level var d of a global name has certainly replaced the
// global by position i: it is assigned outside every block, and i is top-level code that
// runs after it. window and top cannot be replaced by a var.
func (gs *globalScope) replaced(d int, name string, i int) bool {
	decl := gs.decls[d]
	return decl.bare && decl.start < decl.end && i > decl.end && name != "window" && name != "top" && gs.tf.topLevel(i)
}

// thisGlobal reports whether this at position i is the global object as a value: at the top
// level, or in a function whose in-place call binds the global to it.
func (gs *globalScope) thisGlobal(i int) bool {
	k := gs.tf.block(i)
	for k >= 0 && !gs.tf.fn[k] {
		k = gs.tf.parent[k]
	}
	return k < 0 || gs.thisIs[k]
}

// returnsThis reports whether the function body block k returns its own this as a value.
func (gs *globalScope) returnsThis(clean []rune, k int) bool {
	if r, ok := gs.retThis[k]; ok {
		return r
	}
	r := false
	for i := gs.tf.opens[k]; i < gs.tf.closes[k] && !r; {
		if !isIdentStart(clean[i]) {
			i++
			continue
		}
		w, next := readWord(clean, i)
		if w == "this" {
			b := skipSpaceBack(clean, i-1)
			p := skipSpace(clean, next)
			f := gs.tf.block(i)
			for f >= 0 && !gs.tf.fn[f] {
				f = gs.tf.parent[f]
			}
			after, _ := peekWord(clean, p)
			if rw, _ := wordBefore(clean, b); rw == "return" && f == k && after != "instanceof" && after != "in" &&
				!(p < len(clean) && (clean[p] == '.' || clean[p] == '[' || clean[p] == '(')) &&
				!(p+1 < len(clean) && (clean[p] == '=' || clean[p] == '!') && clean[p+1] == '=') {
				r = true
			}
		}
		i = next
	}
	gs.retThis[k] = r
	return r
}

// lookup returns the declarations of name in the innermost scope enclosing i that has any.
func (gs *globalScope) lookup(name string, i int) []int {
	for k := gs.tf.block(i); ; k = gs.tf.parent[k] {
		if ds := gs.byScope[k][name]; len(ds) > 0 || k < 0 {
			return ds
		}
	}
}

// yieldsGlobal reports whether the expression in clean[start:end] can evaluate to the
// global: a global-valued name or `this` that is the global in value position (not a member
// read, call or index of it, and not under typeof), a call of a Function constructor call,
// or a plain call of a function that returns a this that is the global.
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
		case word == "function":
			if k, ok := gs.kwFrame[i]; ok && gs.thisIs[k] && gs.returnsThis(clean, k) && flowsTo(clean, start, i) {
				return true // (function () { return this; })()
			}
		case gs.callsReturnThis(clean, word, i, next) && flowsTo(clean, start, i):
			return true
		case (word == "this" && gs.thisGlobal(i)) || (word != "this" && gs.isGlobal(word, i)):
			if w, _ := wordBefore(clean, b); w == "typeof" || !flowsTo(clean, start, i) {
				break
			}
			p := skipSpace(clean, next)
			if andTest(clean, p) {
				break
			}
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

// callsReturnThis reports whether the name at [i, next) is called plainly and declares a
// function that returns its own this, which a plain sloppy call binds to the global.
func (gs *globalScope) callsReturnThis(clean []rune, word string, i, next int) bool {
	if p := skipSpace(clean, next); p >= len(clean) || clean[p] != '(' {
		return false
	}
	switch w, _ := wordBefore(clean, skipSpaceBack(clean, i-1)); w {
	case "new":
		return false // a construction yields the new object
	case "function":
		return false // the declaration itself
	}
	for _, d := range gs.lookup(word, i) {
		if k, ok := gs.fnDecl[d]; ok && gs.returnsThis(clean, k) {
			return true
		}
	}
	return false
}

// globalUse records a use of the global-valued name or global `this` at [i, next): a
// computed key on it, `.eval`, `.Function` or `.require` read from it, or the object
// handed on as a value. A literal key is judged by keyedUse. For a function's own `this`
// (callOnly), which is the global only when the function is called plainly, just a
// computed key that is called and `.eval`/`.Function` count: handing that `this` on
// (`fn.apply(this, args)`) and indexing it without a call are how methods written as
// functions use their receiver.
func (mb *moduleBindings) globalUse(clean []rune, i, next int, callOnly bool, gs *globalScope) {
	n := len(clean)
	b := skipSpaceBack(clean, i-1)
	if b >= 0 && clean[b] == '.' {
		return
	}
	p := skipSpace(clean, next)
	if p < n && clean[p] == ':' && !(p+1 < n && clean[p+1] == ':') && !(b >= 0 && clean[b] == '?') {
		return // an object key or a typed this parameter, not a use
	}
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
		switch w, e := peekWord(clean, skipSpace(clean, p+1)); {
		case w == "eval", w == "Function":
			mb.evaluated = true
		case w == "require" && !callOnly && !andTest(clean, skipSpace(clean, e)):
			// The global's require is not the module's: whatever a host put there loads
			// code this lane cannot follow. A test of it (`window.require && ...`) is not
			// a use.
			mb.evaluated = true
		}
	case !callOnly && escapesAsValue(clean, b, p) && !andTest(clean, p) && !gs.held(clean, i) && !indexKey(clean, b, p):
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
	fnKw   []int    // position of the `function` keyword for a function body, or -1
	global []bool   // this inside the block (not in a nested function) is the global
	// weak marks a block read as a method body outside any class body or object literal,
	// which may as well be a call followed by a plain block (`f(x)\n{`): it scopes what it
	// declares, but those declarations never shadow, and its this is the enclosing one.
	weak    []bool
	members []bool // the block is a class body or an object literal, which holds methods
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
		arrow  bool // an arrow's expression body, which no '}' closes
	}
	var stack []open
	var parens []int
	matchParen := map[int]int{} // ')' → '('
	push := func(o open, at int, fn, scope bool, params [2]int, kw int, weak, members bool) {
		parent := -1
		if len(stack) > 0 {
			parent = stack[len(stack)-1].k
		}
		stack = append(stack, o)
		tf.opens = append(tf.opens, at)
		tf.closes = append(tf.closes, n)
		tf.parent = append(tf.parent, parent)
		tf.fn = append(tf.fn, fn)
		tf.scope = append(tf.scope, scope)
		tf.params = append(tf.params, params)
		tf.fnKw = append(tf.fnKw, kw)
		tf.global = append(tf.global, o.global)
		tf.weak = append(tf.weak, weak)
		tf.members = append(tf.members, members)
	}
	for i := 0; i < n; i++ {
		for len(stack) > 0 && stack[len(stack)-1].arrow && i > tf.closes[stack[len(stack)-1].k] {
			stack = stack[:len(stack)-1]
		}
		switch clean[i] {
		case '=':
			// An arrow with an expression body scopes its parameters over that expression.
			if i+1 >= n || clean[i+1] != '>' {
				break
			}
			body := skipSpace(clean, i+2)
			if body >= n || clean[body] == '{' {
				break
			}
			params := [2]int{-1, -1}
			if q := skipSpaceBack(clean, i-1); q >= 0 && clean[q] == ')' {
				if o, ok := matchParen[q]; ok {
					params = [2]int{o + 1, q}
				}
			} else if w, s := wordBefore(clean, q); w != "" {
				params = [2]int{s, q + 1}
			}
			g := true
			if len(stack) > 0 {
				g = stack[len(stack)-1].global
			}
			push(open{len(tf.opens), g, true}, i+1, false, true, params, -1, false, false)
			tf.closes[len(tf.closes)-1] = arrowEnd(clean, body) - 1
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
			kw := -1
			method, members := false, false
			container := len(stack) > 0 && tf.members[stack[len(stack)-1].k]
			raw := skipSpaceBack(clean, i-1)
			b := raw
			if r := typedReturn(clean, b); r >= 0 {
				b = r
			}
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
					if q >= 0 && clean[q] == '>' { // a generic: name<T>(...)
						q = typeParamsStart(clean, q)
					}
					w, s := wordBefore(clean, q)
					d := skipSpaceBack(clean, s-1)
					if w != "" && (d >= 0 && clean[d] == '.' || w == "catch" && !(d >= 0 && clean[d] == '}')) {
						w = "." // a member call (`o.catch(x)`), read as a method name
					}
					if w2, _ := wordBefore(clean, d); w == "await" && w2 == "for" {
						w = "for"
					}
					switch w {
					case "catch":
						params = [2]int{o + 1, b}
					case "if", "for", "while", "switch", "with":
					case "function":
						g, fn, scope = true, true, true
						params = [2]int{o + 1, b}
						kw = s
					case "":
						if q >= 0 && clean[q] == '*' { // function* (...) or *method(...)
							if w2, s2 := wordBefore(clean, skipSpaceBack(clean, q-1)); w2 == "function" {
								g, kw = true, s2
								fn, scope = true, true
							} else {
								method = true
							}
							params = [2]int{o + 1, b}
						} else if q >= 0 && clean[q] == ']' { // a computed method name
							method = true
							params = [2]int{o + 1, b}
						}
					default:
						r := skipSpaceBack(clean, s-1)
						if r >= 0 && clean[r] == '*' { // function* name(...)
							r = skipSpaceBack(clean, r-1)
						}
						if w2, s2 := wordBefore(clean, r); w2 == "function" {
							g, kw = true, s2
							fn, scope = true, true
						} else {
							method = true // a method, getter or setter
						}
						params = [2]int{o + 1, b}
					}
				}
			default:
				if classBody(clean, b) {
					g, fn, members = false, true, true
				} else {
					members = objectLiteral(clean, raw, container)
				}
			}
			weak := false
			switch {
			case method && container:
				g, fn, scope = false, true, true
			case method:
				weak, scope = true, true // this stays outer
			}
			push(open{len(tf.opens), g, false}, i, fn, scope, params, kw, weak, members)
		case '}':
			if len(stack) > 0 {
				tf.closes[stack[len(stack)-1].k] = i
				stack = stack[:len(stack)-1]
			}
		}
	}
	return tf
}

// arrowEnd returns the index of the ',' or ';' that ends the arrow body expression
// starting at p at bracket depth zero, of a ':' that closes an enclosing ternary branch, of
// the bracket that closes the enclosing one, or of
// a line break where the expression cannot continue. A line break the expression may run
// on past ends it too unless an operator on either side joins the lines, so the body can
// be read shorter than it is, never longer: a name past it resolves outward.
//
// A bare '=' at depth zero ends the body as well: it is the initialiser after a TypeScript
// function type (`f: (a) => T = v`), or an assignment the body reads shorter for. Once a
// '<' that may open JSX appears, whose text the stripped source does not keep, a '?' no
// longer opens a ternary and any line break ends the body.
func arrowEnd(clean []rune, p int) int {
	depth, ternary := 0, 0
	jsx := false
	n := len(clean)
	for ; p < n; p++ {
		switch r := clean[p]; r {
		case '<':
			if p+1 < n && (isIdentStart(clean[p+1]) || clean[p+1] == '>') {
				jsx = true
			}
		case '=':
			if depth == 0 && assignStart(clean, p) == p+1 && !(p > 0 && strings.ContainsRune("=!<>+-*/%&|^?", clean[p-1])) {
				return p
			}
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
		case '?':
			if depth == 0 && !optionalDot(clean, p) && !jsx {
				if p+1 < n && clean[p+1] == '?' {
					p++ // ?? and ??=
				} else {
					ternary++
				}
			}
		case ':':
			// A ':' with no '?' of the body's own ends an enclosing ternary's branch.
			if depth == 0 {
				if ternary == 0 {
					return p
				}
				ternary--
			}
		case '\n':
			if jsx {
				return p
			}
			if depth > 0 {
				continue
			}
			b := skipSpaceBack(clean, p-1)
			a := skipSpace(clean, p+1)
			joined := b >= 0 && strings.ContainsRune("=+-*/%&|^<>?:!~(", clean[b]) ||
				a < n && strings.ContainsRune(".?:+-*/%&|^<>=([", clean[a])
			if !joined {
				return p
			}
		}
	}
	return p
}

// maxTypeScan bounds the backward scan over a TypeScript return type annotation.
const maxTypeScan = 256

// typedReturn returns the position of the ')' that ends a parameter list when the '{'
// after position b follows a TypeScript return type (`(...): Type {`), or -1.
func typedReturn(clean []rune, b int) int {
	if b < 0 || clean[b] == ')' {
		return -1
	}
	depth := 0
	for p := b; p >= 0 && b-p < maxTypeScan; p-- {
		switch clean[p] {
		case '>', ']', ')':
			depth++
		case '<', '[', '(':
			if depth == 0 {
				return -1
			}
			depth--
		case ';', '{', '}', '=':
			if depth == 0 && !(clean[p] == '=' && p+1 < len(clean) && clean[p+1] == '>') {
				return -1
			}
		case ':':
			if depth == 0 {
				if q := skipSpaceBack(clean, p-1); q >= 0 && clean[q] == ')' && !ternaryElse(clean, p) {
					return q
				}
				return -1
			}
		}
	}
	return -1
}

// typeParamsStart returns the last non-space index before the '<' that opens the type
// parameter list closing at q, or q when there is none within reach.
func typeParamsStart(clean []rune, q int) int {
	depth := 0
	for p := q; p >= 0 && q-p < maxTypeScan; p-- {
		switch clean[p] {
		case '>':
			depth++
		case '<':
			depth--
			if depth == 0 {
				return skipSpaceBack(clean, p-1)
			}
		}
	}
	return q
}

// objectLiteral reports whether the '{' after position b opens an object literal: it follows
// `=`, `(`, `[`, `,`, `?`, `return` or `export default`, or a ':' that is a ternary's or, in
// an object literal, a property's. A ':' after a case or a label opens a block.
func objectLiteral(clean []rune, b int, inObject bool) bool {
	if b < 0 {
		return false
	}
	switch clean[b] {
	case '=', '(', '[', ',', '?':
		return true
	case ':':
		return inObject || ternaryElse(clean, b)
	}
	w, _ := wordBefore(clean, b)
	return w == "return" || w == "default"
}

// classBody reports whether the '{' after position b opens a class body or a TypeScript
// interface body, whose this is a type: the keyword class (not a member named so) starts the
// statement's head at bracket depth zero, `class A<T> extends f().B<T> {`, or interface
// does, followed only by a name and type parameters or extends clauses.
func classBody(clean []rune, b int) bool {
	depth := 0
	for p := b; p >= 0 && b-p < maxTypeScan; p-- {
		switch r := clean[p]; {
		case r == ')' || r == ']' || r == '>':
			depth++
		case r == '(' || r == '[' || r == '<':
			if depth == 0 {
				return false
			}
			depth--
		case depth == 0 && (r == ';' || r == '{' || r == '}'):
			return false
		case depth == 0 && isIdentPart(r):
			w, s := wordBefore(clean, p)
			d := skipSpaceBack(clean, s-1)
			member := d >= 0 && clean[d] == '.'
			if w == "class" && !member {
				return true
			}
			if w == "interface" && !member {
				return interfaceHead(clean, s)
			}
			p = s
		}
	}
	return false
}

// interfaceHead reports whether the word interface at s begins a TypeScript interface
// declaration on its line: a statement start before it and a name after it on the same line.
func interfaceHead(clean []rune, s int) bool {
	q := skipSpaceBack(clean, s-1)
	if !(q < 0 || clean[q] == ';' || clean[q] == '{' || clean[q] == '}') {
		if w, _ := wordBefore(clean, q); w != "export" && w != "declare" && w != "default" {
			return false
		}
	}
	_, e := readWord(clean, s)
	name, ne := peekWord(clean, skipSpace(clean, e))
	return name != "" && sameLine(clean, s, ne)
}

// indexKey reports whether the value between the '[' at b and the ']' at p is the key of
// a member access, which reads only the property its string names.
func indexKey(clean []rune, b, p int) bool {
	if b < 1 || clean[b] != '[' || p >= len(clean) || clean[p] != ']' {
		return false
	}
	q := skipSpaceBack(clean, b-1)
	if q < 0 {
		return false
	}
	if w, _ := wordBefore(clean, q); w == "return" || w == "yield" || w == "await" || w == "typeof" || w == "in" || w == "of" {
		return false
	}
	return isIdentPart(clean[q]) || clean[q] == ')' || clean[q] == ']'
}

// andTest reports whether the operator at p is `&&` (not `&&=`): a value tested by it is
// handed on only when it is falsy, and the global object never is.
func andTest(clean []rune, p int) bool {
	return p+1 < len(clean) && clean[p] == '&' && clean[p+1] == '&' && !(p+2 < len(clean) && clean[p+2] == '=')
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
