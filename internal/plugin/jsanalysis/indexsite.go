package jsanalysis

import (
	"strings"
	"unicode"
)

type keyMemoKey struct {
	decl int
	word string
}

type keyMemoVal struct {
	safe  bool
	enums []int
}

// keyJudge decides whether a key expression can never evaluate to word ("constructor" or
// "__proto__"). It is sound in one direction only: safe means no run of the program gives
// the key that string; anything it cannot follow is unknown. A key ranging over the own
// keys of a receiver (for-in, Object.keys, Object.entries) is safe only for that receiver,
// so the judge returns the receivers it relied on for the site to check (enums).
type keyJudge struct {
	clean, src []rune
	gs         *globalScope
	word       string
	seen       map[int]bool
	enums      []int
	cycle      bool
}

func newKeyJudge(clean, src []rune, gs *globalScope, word string) *keyJudge {
	if gs.keyMemo == nil {
		gs.keyMemo = map[keyMemoKey]keyMemoVal{}
	}
	return &keyJudge{clean: clean, src: src, gs: gs, word: word, seen: map[int]bool{}}
}

// keySafe judges clean[from:to] and returns the enumerated receivers its safety rests on.
func (j *keyJudge) keySafe(from, to int) (bool, []int) {
	j.enums, j.cycle = nil, false
	ok := j.expr(from, to)
	return ok, j.enums
}

func trimRange(clean []rune, from, to int) (int, int) {
	for from < to && unicode.IsSpace(clean[from]) {
		from++
	}
	for to > from && unicode.IsSpace(clean[to-1]) {
		to--
	}
	return from, to
}

// stringLiteral reports whether a JS string or template literal opens at a.
func stringLiteral(clean, src []rune, a int) bool {
	return a < len(clean) && (clean[a] == '_' || clean[a] == '`') && (src[a] == '\'' || src[a] == '"' || src[a] == '`')
}

// templateScan reads the template literal opening at src[a] and returns the index past its
// closing backtick, its text pieces holding no escape, and how many substitutions it has.
// A substitution's code is visible in clean and its closing '}' is blanked, which is how its
// end is found; a nested template, comment or regex literal makes it give up (ok false).
func templateScan(clean, src []rune, a int) (end int, pieces []string, subs int, ok bool) {
	n := len(src)
	var piece []rune
	escaped := false
	flush := func() {
		if !escaped && len(piece) > 0 {
			pieces = append(pieces, string(piece))
		}
		piece, escaped = nil, false
	}
	for k := a + 1; k < n; k++ {
		switch c := src[k]; {
		case c == '\\':
			escaped = true
			k++
		case c == '`':
			flush()
			return k + 1, pieces, subs, true
		case c == '$' && k+1 < n && src[k+1] == '{':
			flush()
			subs++
			depth := 0
			k += 2
			for ; k < n; k++ {
				if src[k] == '}' && clean[k] == ' ' && depth == 0 {
					break
				}
				switch {
				case clean[k] == '_' && (src[k] == '\'' || src[k] == '"'):
					q := src[k]
					for k++; k < n && src[k] != q; k++ {
						if src[k] == '\\' {
							k++
						}
					}
				case src[k] == '`':
					return 0, nil, 0, false
				case clean[k] == '{':
					depth++
				case clean[k] == '}':
					depth--
				case clean[k] == ' ' && !unicode.IsSpace(src[k]):
					return 0, nil, 0, false
				}
			}
		default:
			piece = append(piece, c)
		}
	}
	return 0, nil, 0, false
}

// templateEnds reports whether a template closing at e ends the range ending at to. Its
// closing backtick and any text after its last substitution are blank in clean, so a range
// trimmed of blanks can stop short of e.
func templateEnds(clean []rune, e, to int) bool {
	if e < to {
		return false
	}
	for k := to; k < e; k++ {
		if !unicode.IsSpace(clean[k]) {
			return false
		}
	}
	return true
}

type topOp struct {
	at int
	op string
}

// binaryOps are the punctuators that follow an operand, longest first.
var binaryOps = []string{">>>=", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
	"=>", "==", "!=", "<=", ">=", "&&", "||", "??", "**", "<<", ">>", "+=", "-=", "*=", "/=", "%=",
	"&=", "|=", "^=", "+", "-", "*", "/", "%", "&", "|", "^", "<", ">", "=", "?", ":", ","}

// topOps lists the operators at bracket depth zero in clean[from:to]: binary operators by
// their text, prefix operators as "pre"+op, postfix updates as "post"+op, and the operator
// words in, instanceof, typeof, void, delete and new. Brackets and literals are skipped
// whole; false when the range cannot be read.
func (j *keyJudge) topOps(from, to int) ([]topOp, bool) {
	clean := j.clean
	var ops []topOp
	operand := false
	for k := from; k < to; {
		c := clean[k]
		switch {
		case unicode.IsSpace(c):
			k++
		case stringLiteral(clean, j.src, k) && j.src[k] == '`':
			e, _, _, ok := templateScan(clean, j.src, k)
			if !ok || !templateEnds(clean, e, to) {
				return nil, false
			}
			k, operand = min(e, to), true
		case stringLiteral(clean, j.src, k):
			k, operand = k+1, true
		case c == '(' || c == '[' || c == '{':
			e := closeOf(clean, k)
			if e >= to {
				return nil, false
			}
			k, operand = e+1, true
		case c == ')' || c == ']' || c == '}':
			return nil, false
		case isIdentPart(c):
			w, e := readWord(clean, k)
			switch w {
			case "in", "instanceof":
				if operand {
					ops = append(ops, topOp{k, w})
					operand = false
				}
			case "typeof", "void", "delete", "new", "await":
				ops = append(ops, topOp{k, w})
				operand = false
			default:
				operand = true
			}
			k = e
		case c == '.':
			if k+2 < to && clean[k+1] == '.' && clean[k+2] == '.' {
				return nil, false
			}
			k++
		case c == '?' && k+1 < to && clean[k+1] == '.' && !(k+2 < to && unicode.IsDigit(clean[k+2])):
			k += 2
		case strings.ContainsRune(operatorRunes+",:", c):
			if operand {
				if k+1 < to && (c == '+' || c == '-') && clean[k+1] == c {
					ops = append(ops, topOp{k, "post" + string([]rune{c, c})})
					k += 2
					continue
				}
				if c == '!' && !(k+1 < to && clean[k+1] == '=') {
					k++ // a TypeScript non-null assertion
					continue
				}
				op := ""
				for _, b := range binaryOps {
					if k+len(b) <= to && string(clean[k:k+len(b)]) == b {
						op = b
						break
					}
				}
				if op == "" {
					return nil, false
				}
				ops = append(ops, topOp{k, op})
				k += len(op)
				operand = false
				continue
			}
			switch {
			case k+1 < to && (c == '+' || c == '-') && clean[k+1] == c:
				ops = append(ops, topOp{k, "pre" + string([]rune{c, c})})
				k += 2
			case c == '+' || c == '-' || c == '!' || c == '~':
				ops = append(ops, topOp{k, "pre" + string(c)})
				k++
			default:
				return nil, false
			}
		default:
			return nil, false
		}
	}
	return ops, true
}

// expr reports whether the expression in clean[from:to] can never evaluate to j.word.
func (j *keyJudge) expr(from, to int) bool {
	clean, src := j.clean, j.src
	from, to = trimRange(clean, from, to)
	if from >= to {
		return false
	}
	if clean[from] == '(' && closeOf(clean, from) == to-1 {
		return j.expr(from+1, to-1)
	}
	ops, ok := j.topOps(from, to)
	if !ok {
		return false
	}
	split := func(match func(string) bool) []int {
		var at []int
		for _, o := range ops {
			if match(o.op) {
				at = append(at, o.at)
			}
		}
		return at
	}
	if cs := split(func(op string) bool { return op == "," }); len(cs) > 0 {
		return j.expr(cs[len(cs)-1]+1, to)
	}
	for _, o := range ops {
		if strings.HasSuffix(o.op, "=") && o.op != "==" && o.op != "===" && o.op != "!=" && o.op != "!==" && o.op != "<=" && o.op != ">=" || o.op == "=>" {
			if o.op == "=" {
				return j.expr(o.at+1, to)
			}
			return false
		}
	}
	for idx, o := range ops {
		if o.op != "?" {
			continue
		}
		depth := 0
		for _, c := range ops[idx+1:] {
			switch c.op {
			case "?":
				depth++
			case ":":
				if depth == 0 {
					return j.expr(o.at+1, c.at) && j.expr(c.at+1, to)
				}
				depth--
			}
		}
		return false
	}
	logical := func(op string) bool { return op == "||" || op == "??" || op == "&&" }
	if ls := split(logical); len(ls) > 0 {
		s := from
		for _, l := range ls {
			if !j.expr(s, l) {
				return false
			}
			s = l + 2
		}
		return j.expr(s, to)
	}
	lt, gt := false, false
	for _, o := range ops {
		switch o.op {
		case "|", "^", "&", "==", "!=", "===", "!==", "<=", ">=", "<<", ">>", ">>>", "*", "/", "%", "**", "-", "in", "instanceof":
			return true
		case "<":
			lt = true
		case ">":
			gt = true
		}
	}
	if lt != gt {
		return true
	}
	if ps := split(func(op string) bool { return op == "+" }); len(ps) > 0 {
		s := from
		for _, p := range ps {
			if j.piece(s, p) {
				return true
			}
			s = p + 1
		}
		return j.piece(s, to)
	}
	if len(ops) > 0 {
		switch first, last := ops[0], ops[len(ops)-1]; {
		case first.at == from && (strings.HasPrefix(first.op, "pre") || first.op == "typeof" || first.op == "void" || first.op == "delete"):
			return true
		case strings.HasPrefix(last.op, "post") && skipSpace(clean, last.at+2) >= to:
			return true
		}
		return false
	}
	if stringLiteral(clean, src, from) {
		if src[from] == '`' {
			e, _, subs, ok := templateScan(clean, src, from)
			if !ok || !templateEnds(clean, e, to) {
				return false
			}
			if subs > 0 {
				return j.piece(from, to)
			}
		} else if to != from+1 {
			return false
		}
		v := specifierAt(src, from)
		return v != "" && v != j.word
	}
	if unicode.IsDigit(clean[from]) {
		return true
	}
	w, e := readWord(clean, from)
	if w == "Symbol" && len(j.gs.lookup("Symbol", from)) == 0 {
		p := skipSpace(clean, e)
		if p < to && clean[p] == '(' && closeOf(clean, p) == to-1 {
			return true // a symbol names no string member
		}
		if p < to && clean[p] == '.' {
			if _, me := peekWord(clean, skipSpace(clean, p+1)); me == to {
				return true
			}
		}
	}
	if e != to {
		return false
	}
	switch w {
	case "undefined", "null", "true", "false", "NaN", "Infinity":
		if len(j.gs.lookup(w, from)) == 0 {
			return true
		}
	}
	if w == "" || !isIdentStart(clean[from]) {
		return false
	}
	return j.ident(w, from)
}

// piece reports whether the operand clean[from:to] of a + chain puts into the result text
// that word does not contain, so the result is never word: a string literal whose value is
// not a substring of word, a template with such a text piece, a number, or a unary
// arithmetic, bitwise, logical-not or update operation, which yields a number or boolean.
func (j *keyJudge) piece(from, to int) bool {
	clean, src := j.clean, j.src
	from, to = trimRange(clean, from, to)
	if from >= to {
		return false
	}
	if clean[from] == '(' && closeOf(clean, from) == to-1 {
		return j.piece(from+1, to-1)
	}
	if stringLiteral(clean, src, from) {
		if src[from] == '`' {
			e, pieces, _, ok := templateScan(clean, src, from)
			if !ok || !templateEnds(clean, e, to) {
				return false
			}
			for _, p := range pieces {
				if !strings.Contains(j.word, p) {
					return true
				}
			}
			return false
		}
		v := specifierAt(src, from)
		return to == from+1 && v != "" && !strings.Contains(j.word, v)
	}
	if unicode.IsDigit(clean[from]) {
		_, e := readWord(clean, from)
		return skipSpace(clean, e) >= to
	}
	switch c := clean[from]; c {
	case '+', '-', '~', '!':
		return true
	}
	if to-from >= 2 && (string(clean[to-2:to]) == "++" || string(clean[to-2:to]) == "--") {
		return true
	}
	return false
}

// ident judges the name at pos by every value it can hold: each declaration and
// assignment in the scope that binds it, each compound assignment and update, and any
// destructuring or for head that rebinds it.
func (j *keyJudge) ident(name string, pos int) bool {
	gs := j.gs
	ds := gs.lookup(name, pos)
	if len(ds) == 0 {
		return false
	}
	key := keyMemoKey{ds[0], j.word}
	if v, ok := gs.keyMemo[key]; ok {
		if v.safe {
			j.enums = append(j.enums, v.enums...)
		}
		return v.safe
	}
	if j.seen[ds[0]] {
		j.cycle = true // assume safe: every rule keeps a safe value safe
		return true
	}
	j.seen[ds[0]] = true
	outerCycle, outerEnums := j.cycle, j.enums
	j.cycle, j.enums = false, nil
	safe := j.identDecls(name, ds)
	delete(j.seen, ds[0])
	mine := j.enums
	if !safe || !j.cycle {
		gs.keyMemo[key] = keyMemoVal{safe, mine}
	}
	j.cycle = j.cycle || outerCycle
	j.enums = append(outerEnums, mine...)
	return safe
}

func (j *keyJudge) identDecls(name string, ds []int) bool {
	gs, clean := j.gs, j.clean
	for _, d := range ds {
		if !j.decl(d) {
			return false
		}
	}
	for _, o := range gs.occurrences(clean, name) {
		if gs.sites[o] || !gs.sameVariable(name, ds, o) {
			continue
		}
		next := o + len([]rune(name))
		if rebound(clean, o, next) {
			return false
		}
		p := skipSpace(clean, next)
		if p+1 < len(clean) && clean[p] == '+' && clean[p+1] == '=' {
			if !j.piece(p+2, initEnd(clean, p+2)) {
				return false
			}
		}
	}
	return true
}

// decl judges one binding of a key name.
func (j *keyJudge) decl(d int) bool {
	gs := j.gs
	dl := gs.decls[d]
	switch dl.kind {
	case 'p':
		return j.callbackParam(d)
	case 'f', 'i':
		return false
	}
	if dl.topVar {
		return false
	}
	if dl.start == dl.end {
		return j.forHead(dl)
	}
	if dl.pat >= 0 {
		return false
	}
	return j.expr(dl.start, dl.end)
}

// forHead judges a binding with no initializer: a for-of over an array literal of safe
// keys, a for-of over Object.keys(R) or a for-in over R (the own keys of R), the first
// element of a for-of pattern over Object.entries(R), or a plain declaration, which holds
// undefined until an assignment the scope also judges.
func (j *keyJudge) forHead(dl globalDecl) bool {
	clean := j.clean
	head := dl.at
	if dl.pat >= 0 {
		head = dl.pat
	}
	var after int
	if dl.pat >= 0 {
		after = closeOf(clean, dl.pat) + 1
	} else {
		_, after = readWord(clean, dl.at)
	}
	q := skipSpace(clean, after)
	w, we := peekWord(clean, q)
	if w != "of" && w != "in" {
		return dl.pat < 0
	}
	o := enclosingOpen(clean, head)
	if o < 0 || clean[o] != '(' {
		return false
	}
	from, to := trimRange(clean, we, closeOf(clean, o))
	if dl.pat >= 0 {
		if w != "of" || clean[dl.pat] != '[' {
			return false
		}
		if sites, _ := patternSites(clean, dl.pat); len(sites) == 0 || sites[0] != dl.at {
			return false
		}
		return j.objectCall(from, to, "entries")
	}
	if w == "in" {
		r, e := peekWord(clean, from)
		if r == "" || e != to {
			return false
		}
		j.enums = append(j.enums, from)
		return true
	}
	if clean[from] == '[' && closeOf(clean, from) == to-1 {
		return j.elements(from)
	}
	return j.objectCall(from, to, "keys")
}

// elements reports whether every element of the array literal opening at o is a safe key.
func (j *keyJudge) elements(o int) bool {
	clean := j.clean
	e := closeOf(clean, o)
	s := o + 1
	depth := 0
	for k := o + 1; k <= e; k++ {
		switch clean[k] {
		case '(', '[', '{':
			depth++
		case ')', '}':
			depth--
		case ']':
			if depth > 0 {
				depth--
				continue
			}
			fallthrough
		case ',':
			if depth > 0 {
				continue
			}
			if a, b := trimRange(clean, s, k); a < b && !j.expr(a, b) {
				return false
			}
			s = k + 1
		}
	}
	return true
}

// objectCall reports whether clean[from:to] is exactly Object.<method>(R) for a bare name
// R, recording R as an enumerated receiver.
func (j *keyJudge) objectCall(from, to int, method string) bool {
	clean := j.clean
	w, e := peekWord(clean, from)
	if w != "Object" || len(j.gs.lookup("Object", from)) > 0 {
		return false
	}
	p := skipSpace(clean, e)
	if p >= to || clean[p] != '.' {
		return false
	}
	m, e := peekWord(clean, skipSpace(clean, p+1))
	if m != method {
		return false
	}
	p = skipSpace(clean, e)
	if p >= to || clean[p] != '(' || closeOf(clean, p) != to-1 {
		return false
	}
	a, b := trimRange(clean, p+1, to-1)
	r, re := peekWord(clean, a)
	if r == "" || re != b {
		return false
	}
	j.enums = append(j.enums, a)
	return true
}

// callbackParam judges the first parameter of a function or arrow passed straight to
// forEach, map, filter, some, every, find, findIndex or flatMap on an array literal of
// safe keys or on Object.keys(R).
func (j *keyJudge) callbackParam(d int) bool {
	gs, clean := j.gs, j.clean
	dl := gs.decls[d]
	k := dl.scope
	if k < 0 || dl.pat >= 0 {
		return false
	}
	pr := gs.tf.params[k]
	if pr[0] < 0 {
		return false
	}
	if sites := paramSites(clean, pr[0], pr[1]); len(sites) == 0 || sites[0] != dl.at {
		return false
	}
	start := pr[0]
	switch {
	case gs.tf.fnKw[k] >= 0:
		start = gs.tf.fnKw[k]
	case pr[0] > 0 && clean[pr[0]-1] == '(' && closeOf(clean, pr[0]-1) == pr[1]:
		start = pr[0] - 1
	}
	b := skipSpaceBack(clean, start-1)
	if b < 0 || clean[b] != '(' {
		return false
	}
	m, ms := wordBefore(clean, skipSpaceBack(clean, b-1))
	switch m {
	case "forEach", "map", "filter", "some", "every", "find", "findIndex", "flatMap":
	default:
		return false
	}
	dot := skipSpaceBack(clean, ms-1)
	if dot < 0 || clean[dot] != '.' {
		return false
	}
	r := skipSpaceBack(clean, memberDot(clean, dot)-1)
	if r < 0 {
		return false
	}
	switch clean[r] {
	case ']':
		o := openBefore(clean, r)
		if o < 0 {
			return false
		}
		if op, ok := indexOperator(clean, o); ok && indexedValue(clean, gs.tf, op) {
			return false
		}
		return j.elements(o)
	case ')':
		o := openBefore(clean, r)
		if o < 0 {
			return false
		}
		s := receiverStart(clean, o)
		if s < 0 {
			return false
		}
		return j.objectCall(s, r+1, "keys")
	}
	return false
}

// occurrences returns the positions of name in clean other than as a member.
func (gs *globalScope) occurrences(clean []rune, name string) []int {
	if gs.occ == nil {
		gs.occ = map[string][]int{}
		for i := 0; i < len(clean); {
			if !isIdentStart(clean[i]) || i > 0 && isIdentPart(clean[i-1]) {
				i++
				continue
			}
			w, next := readWord(clean, i)
			b := skipSpaceBack(clean, i-1)
			if b >= 0 && clean[b] == '#' {
				i = next // a private name is never a variable
				continue
			}
			if !(b >= 0 && clean[b] == '.' && !(b >= 2 && clean[b-1] == '.' && clean[b-2] == '.')) {
				gs.occ[w] = append(gs.occ[w], i)
			}
			i = next
		}
	}
	return gs.occ[name]
}

// sameVariable reports whether name at o resolves to the binding ds was looked up as: they
// share a declaration other than an assignment.
func (gs *globalScope) sameVariable(name string, ds []int, o int) bool {
	other := gs.lookup(name, o)
	for _, a := range ds {
		if gs.decls[a].kind == 'a' {
			continue
		}
		for _, b := range other {
			if gs.decls[b].kind != 'a' && gs.decls[b].at == gs.decls[a].at {
				return true
			}
		}
	}
	return false
}

// literalValue returns the bracket of the object or array literal clean[start:end] holds,
// directly, in parentheses or as the last value of a chain of plain assignments, or -1.
func literalValue(clean []rune, start, end int) int {
	if start >= end {
		return -1
	}
	v, depth := start, 0
	for k := start; k < end; k++ {
		switch c := clean[k]; c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '=':
			if depth != 0 || k+1 < end && (clean[k+1] == '=' || clean[k+1] == '>') {
				continue
			}
			if k > start && strings.ContainsRune("=!<>", clean[k-1]) {
				continue
			}
			if k > start && strings.ContainsRune("+-*/%&|^?", clean[k-1]) {
				return -1
			}
			v = k + 1
		}
	}
	v, end = trimRange(clean, v, end)
	for v < end && clean[v] == '(' && closeOf(clean, v) == end-1 {
		v, end = trimRange(clean, v+1, end-1)
	}
	if v < end && (clean[v] == '{' || clean[v] == '[') && closeOf(clean, v) == end-1 {
		return v
	}
	return -1
}

// literalContent reports whether the literal opening at o can give no member read a
// constructor or prototype the lane does not see: an object literal with no __proto__ or
// constructor key in any spelling (plain, quoted, method, accessor or a computed key not
// known to be another name), and every spread, in it or in an array literal, of a literal
// so judged.
func (j *keyJudge) literalContent(o int) bool {
	clean, src := j.clean, j.src
	e := closeOf(clean, o)
	if e >= len(clean) {
		return false
	}
	s := o + 1
	depth := 0
	for k := o + 1; k <= e; k++ {
		switch clean[k] {
		case '(', '[', '{':
			depth++
			continue
		case ')', ']', '}':
			if k < e {
				depth--
				continue
			}
		case ',':
			if depth > 0 {
				continue
			}
		default:
			continue
		}
		a, b := trimRange(clean, s, k)
		s = k + 1
		if a >= b {
			continue
		}
		if b-a > 3 && string(clean[a:a+3]) == "..." {
			v := literalValue(clean, a+3, b)
			if v < 0 || !j.literalContent(v) {
				return false
			}
			continue
		}
		if clean[o] != '{' {
			continue
		}
		p := a
		if clean[p] == '*' {
			p = skipSpace(clean, p+1)
		}
		for {
			w, we := peekWord(clean, p)
			if w != "get" && w != "set" && w != "async" && w != "static" {
				break
			}
			q := skipSpace(clean, we)
			if q < b && (clean[q] == '(' || clean[q] == ':' || clean[q] == ',' || clean[q] == '=') || q >= b {
				break
			}
			p = q
			if clean[p] == '*' {
				p = skipSpace(clean, p+1)
			}
		}
		switch {
		case stringLiteral(clean, src, p):
			v := specifierAt(src, p)
			if v == "constructor" || v == "__proto__" || v == "" && !(p+1 < len(src) && src[p+1] == src[p]) {
				return false
			}
		case clean[p] == '[':
			ok, enums := j.keySafe(p+1, closeOf(clean, p))
			if !ok || len(enums) > 0 {
				return false
			}
		default:
			if w, _ := peekWord(clean, p); w == "constructor" || w == "__proto__" {
				return false
			}
		}
	}
	return true
}

// literalReceiver reports whether the name at i is a receiver whose every value is an
// object or array literal the lane sees in full (literalContent): a const or let at the
// top level (a top-level var may alias a CommonJS wrapper parameter or a global), or a
// const, let or function-scoped var in a function or block, never a parameter, import,
// function or destructured binding, never rebound by a pattern or for head, and never
// given a compound assignment or update.
func (gs *globalScope) literalReceiver(clean, src []rune, name string, i int) bool {
	ds := gs.lookup(name, i)
	if len(ds) == 0 {
		return false
	}
	j := newKeyJudge(clean, src, gs, "constructor")
	scope := gs.decls[ds[0]].scope
	named := false
	for _, d := range ds {
		dl := gs.decls[d]
		switch dl.kind {
		case 'c', 'l':
			named = true
		case 'v':
			if scope < 0 || gs.blockFunction(clean, name, dl.scope) {
				return false
			}
			named = true
		case 'a':
		default:
			return false
		}
		if dl.weak || dl.pat >= 0 || dl.topVar {
			return false
		}
		v := literalValue(clean, dl.start, dl.end)
		if v < 0 || !j.literalContent(v) {
			return false
		}
	}
	if !named {
		return false
	}
	if scope < 0 {
		switch name {
		case "module", "exports", "require", "__filename", "__dirname":
			return false
		}
	}
	for _, o := range gs.occurrences(clean, name) {
		if gs.sites[o] || !gs.sameVariable(name, ds, o) {
			continue
		}
		next := o + len([]rune(name))
		if rebound(clean, o, next) || compoundAfter(clean, skipSpace(clean, next)) || updateBefore(clean, o) {
			return false
		}
	}
	return true
}

// blockFunction reports whether a function declaration named name has scope as its nearest
// function scope. In sloppy code one declared in a nested block also assigns the function to
// that scope's var of the same name when the declaration runs.
func (gs *globalScope) blockFunction(clean []rune, name string, scope int) bool {
	tf := gs.tf
	for _, dl := range gs.decls {
		if dl.kind != 'f' || dl.name != name {
			continue
		}
		s := dl.scope
		for s >= 0 && !tf.scope[s] && !namespaceBlock(clean, tf.opens[s]) {
			s = tf.parent[s]
		}
		if s == scope {
			return true
		}
	}
	return false
}

// compoundAfter reports whether a compound assignment other than ||=, &&= and ??=, or a
// postfix update, starts at p.
func compoundAfter(clean []rune, p int) bool {
	n := len(clean)
	if p+1 < n && (clean[p] == '+' || clean[p] == '-') && clean[p+1] == clean[p] {
		return true
	}
	e := p
	for e < n && strings.ContainsRune(operatorRunes, clean[e]) {
		e++
	}
	op := string(clean[p:e])
	switch op {
	case "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "&=", "|=", "^=":
		return true
	}
	return false
}

// updateBefore reports whether a prefix update precedes the name at o.
func updateBefore(clean []rune, o int) bool {
	b := skipSpaceBack(clean, o-1)
	return b >= 1 && (clean[b] == '+' || clean[b] == '-') && clean[b-1] == clean[b]
}

// assignAfter reports whether an assignment of any kind or a postfix update starts at p.
func assignAfter(clean []rune, p int) bool {
	n := len(clean)
	if assignTarget(clean, p) || compoundAfter(clean, p) {
		return true
	}
	for _, op := range []string{"||=", "&&=", "??="} {
		if p+3 <= n && string(clean[p:p+3]) == op {
			return true
		}
	}
	return false
}

// enumReceiverOK reports whether the enumerated receivers a key relies on are the receiver
// named at recv and that receiver's own keys are only its literal's: it is a literal
// receiver with no constructor key, never written through a member or a computed member,
// never handed to a call other than Object.keys or Object.entries, and never aliased.
func (gs *globalScope) enumReceiverOK(clean, src []rune, recv int, enums []int) bool {
	name, _ := peekWord(clean, recv)
	if name == "" || !gs.literalReceiver(clean, src, name, recv) {
		return false
	}
	ds := gs.lookup(name, recv)
	for _, e := range enums {
		if w, _ := peekWord(clean, e); w != name || e > 0 && clean[e-1] == '#' || !gs.sameVariable(name, ds, e) {
			return false
		}
	}
	n := len(clean)
	for _, o := range gs.occurrences(clean, name) {
		if gs.sites[o] || !gs.sameVariable(name, ds, o) {
			continue
		}
		next := o + len([]rune(name))
		p := skipSpace(clean, next)
		switch {
		case p < n && clean[p] == '.' && !(p+1 < n && clean[p+1] == '.') || optionalDot(clean, p):
			q := p + 1
			if optionalDot(clean, p) {
				q = p + 2
			}
			if w, we := peekWord(clean, skipSpace(clean, q)); w != "" && assignAfter(clean, skipSpace(clean, we)) {
				return false
			}
		case p < n && clean[p] == '[':
			if assignAfter(clean, skipSpace(clean, closeBracket(clean, p)+1)) {
				return false
			}
		}
		b := skipSpaceBack(clean, o-1)
		if b >= 0 && (clean[b] == '(' || clean[b] == ',') {
			c := b
			if clean[b] == ',' {
				c = enclosingOpen(clean, b)
			}
			if c >= 0 && clean[c] == '(' {
				if _, ok := indexOperator(clean, c); ok {
					m, ms := wordBefore(clean, skipSpaceBack(clean, c-1))
					d := skipSpaceBack(clean, ms-1)
					r, _ := wordBefore(clean, skipSpaceBack(clean, d-1))
					if !(clean[b] == '(' && (m == "keys" || m == "entries") && d >= 0 && clean[d] == '.' && r == "Object") {
						return false
					}
				}
			}
		}
		if assignTarget(clean, b) && b >= 0 && (b == 0 || !strings.ContainsRune("=!<>+-*/%&|^?", clean[b-1])) && valueTail(clean, next) {
			return false
		}
	}
	return true
}

// indexScan judges every computed member read in clean, and the reflective and prototype
// forms that stand for one. A read whose key may be "constructor" and whose value is
// called or handed on reaches Function from any function receiver, so it marks the module
// evaluated unless its receiver is a literal receiver (exempt, which the caller voids when
// any module may rewrite a prototype: protoWrite).
func indexScan(clean, src []rune, gs *globalScope) (evaluated, exempt, protoWrite bool) {
	n := len(clean)
	j := newKeyJudge(clean, src, gs, "constructor")
	pj := newKeyJudge(clean, src, gs, "__proto__")
	hops := newHopJudges(clean, src, gs)
	var initOf map[int]int
	constFollow := func(start, next int, descriptor bool) bool {
		if initOf == nil {
			initOf = map[int]int{}
			for d, dl := range gs.decls {
				if dl.start < dl.end && dl.pat < 0 && !dl.topVar && (dl.kind == 'c' || dl.kind == 'l' || dl.kind == 'v') {
					a, _ := trimRange(clean, dl.start, dl.end)
					initOf[a] = d
				}
			}
		}
		d, ok := initOf[start]
		if !ok {
			return false
		}
		dl := gs.decls[d]
		if _, b := trimRange(clean, dl.start, dl.end); b != next {
			return false
		}
		kw, ks := wordBefore(clean, skipSpaceBack(clean, dl.at-1))
		if kw != "const" && kw != "let" && kw != "var" {
			return false
		}
		if w, _ := wordBefore(clean, skipSpaceBack(clean, ks-1)); w == "export" {
			return false
		}
		ds := gs.lookup(dl.name, dl.at)
		for _, o := range gs.occurrences(clean, dl.name) {
			if gs.sites[o] || !gs.sameVariable(dl.name, ds, o) {
				continue
			}
			if !readOnly(clean, src, hops, o, o+len([]rune(dl.name)), descriptor) {
				return false
			}
		}
		return true
	}
	// site judges one computed read: the receiver starts at recv (a bare name or not), the
	// key is clean[ka:kb], and the read's value spans [start, next).
	site := func(recv, ka, kb, start, next int, descriptor bool) {
		ok, enums := j.keySafe(ka, kb)
		if ok && (len(enums) == 0 || gs.enumReceiverOK(clean, src, recv, enums)) {
			return
		}
		if readOnly(clean, src, hops, start, next, descriptor) || constFollow(start, next, descriptor) {
			return
		}
		if w, _ := peekWord(clean, recv); w != "" && w != "this" && isIdentStart(clean[recv]) {
			if b := skipSpaceBack(clean, recv-1); !(b >= 0 && (clean[b] == '.' || clean[b] == '#')) && gs.literalReceiver(clean, src, w, recv) {
				exempt = true
				return
			}
		}
		evaluated = true
	}
	// memberUse judges a member named word, read through the operator at dot (a dot, or the
	// bracket of a whole-literal key) and ending before next, or a bare word when !member.
	memberUse := func(word string, member bool, dot, i, next int) {
		p := skipSpace(clean, next)
		called := p < n && clean[p] == '(' || optionalCall(clean, p)
		callOpen := p
		if optionalCall(clean, p) {
			callOpen = skipSpace(clean, p+2)
		}
		switch {
		case member && (word == "getOwnPropertyDescriptors" || word == "getOwnPropertyNames" || word == "ownKeys"):
			if !called || !ownKeysRead(clean, src, gs, dot, closeOf(clean, callOpen)+1) {
				evaluated = true
			}
		case member && (word == "get" || word == "getOwnPropertyDescriptor") && called:
			if r := receiverName(clean, src, dot); (r == "Reflect" || r == "Object" && word == "getOwnPropertyDescriptor") && len(gs.lookup(r, i)) == 0 {
				args := callArgs(clean, callOpen)
				if len(args) >= 2 && !(stringLiteral(clean, src, args[1][0]) && args[1][1] == args[1][0]+1) {
					start := receiverStart(clean, dot)
					recv := args[0][0]
					if w, e := peekWord(clean, recv); w == "" || e != args[0][1] {
						recv = args[0][1] - 1
					}
					site(recv, args[1][0], args[1][1], start, closeOf(clean, callOpen)+1, word == "getOwnPropertyDescriptor")
				}
			}
		case word == "setPrototypeOf":
			if !called {
				protoWrite = true
			} else if args := callArgs(clean, callOpen); len(args) < 2 || !protoValue(clean, args[1][0], args[1][1]) {
				protoWrite = true
			}
		case member && word == "create" && called:
			if r := receiverName(clean, src, dot); r == "Object" {
				args := callArgs(clean, callOpen)
				if len(args) == 0 || !protoValue(clean, args[0][0], args[0][1]) || len(args) > 1 && literalValue(clean, args[1][0], args[1][1]) < 0 {
					protoWrite = true
				}
			}
		case member && word == "defineProperties":
			if args := callArgs(clean, callOpen); !called || len(args) < 2 || literalValue(clean, args[1][0], args[1][1]) < 0 {
				protoWrite = true
			}
		case member && word == "set" && called:
			if r := receiverName(clean, src, dot); r == "Reflect" {
				args := callArgs(clean, callOpen)
				if len(args) < 2 {
					protoWrite = true
				} else if safe, enums := pj.keySafe(args[1][0], args[1][1]); !safe || len(enums) > 0 {
					protoWrite = true
				}
			}
		}
	}
	for p := 0; p < n; p++ {
		if clean[p] != '[' {
			continue
		}
		e := closeBracket(clean, p)
		if e >= n {
			continue
		}
		ka, kb := trimRange(clean, p+1, e)
		op, ok := indexOperator(clean, p)
		if !ok {
			if b := skipSpaceBack(clean, p-1); b >= 0 && (clean[b] == '{' || clean[b] == ',') && destructuredKey(clean, p, e+1) {
				if safe, enums := j.keySafe(ka, kb); !safe || len(enums) > 0 {
					evaluated = true
				}
			}
			continue
		}
		if !indexedValue(clean, gs.tf, op) || ka >= kb {
			continue
		}
		if w, _ := peekWord(clean, ka); w == "keyof" {
			continue
		}
		write := assignAfter(clean, skipSpace(clean, e+1)) && !compoundAfter(clean, skipSpace(clean, e+1))
		if write {
			q := skipSpace(clean, e+1)
			for q < n && clean[q] != '=' {
				q++
			}
			if safe, enums := pj.keySafe(ka, kb); (!safe || len(enums) > 0) && !plainValue(clean, src, q+1, initEnd(clean, q+1)) {
				protoWrite = true
			}
		}
		if stringLiteral(clean, src, ka) && wholeKey(clean, src, ka) {
			memberUse(specifierAt(src, ka), true, op, op, e+1)
			continue // keyedUse judges a literal key
		}
		start := receiverStart(clean, op)
		recv := skipSpaceBack(clean, op-1)
		if w, s := wordBefore(clean, recv); w != "" {
			recv = s
		}
		site(recv, ka, kb, start, e+1, false)
	}
	for i := 0; i < n; {
		if !isIdentStart(clean[i]) || i > 0 && isIdentPart(clean[i-1]) {
			i++
			continue
		}
		word, next := readWord(clean, i)
		if word == "_" && src[i] != '_' {
			if specifierAt(src, i) == "__proto__" {
				q := skipSpace(clean, next)
				b := skipSpaceBack(clean, i-1)
				switch {
				case q < n && clean[q] == ':' && !(q+1 < n && clean[q+1] == ':'):
					protoWrite = true
				case literalArgument(clean, i):
					protoWrite = true
				case b >= 0 && clean[b] == '[' && q < n && clean[q] == ']' && assignAfter(clean, skipSpace(clean, q+1)):
					protoWrite = true
				}
			}
			i = next
			continue
		}
		b := skipSpaceBack(clean, i-1)
		member := b >= 0 && clean[b] == '.' && !(b >= 2 && clean[b-1] == '.' && clean[b-2] == '.')
		switch {
		case !member && (word == "Reflect" || word == "Object") && len(gs.lookup(word, i)) == 0:
			if reflectiveUse(clean, src, gs, j, word, i, next) {
				evaluated = true
			}
		case !member && word == "getOwnPropertyDescriptor" && b >= 0 && (clean[b] == '{' || clean[b] == ',') && destructuredKey(clean, i, next):
			evaluated = true
		case word == "__proto__":
			q := skipSpace(clean, next)
			switch {
			case member && assignTarget(clean, q):
				protoWrite = protoWrite || !protoValue(clean, q+1, initEnd(clean, q+1))
			case !member && q < n && clean[q] == ':' && !(q+1 < n && clean[q+1] == ':'):
				protoWrite = protoWrite || !protoValue(clean, q+1, initEnd(clean, q+1))
			}
		default:
			memberUse(word, member, memberDot(clean, max(b, 0)), i, next)
		}
		i = next
	}
	return evaluated, exempt, protoWrite
}

// indexedValue reports whether the '[' whose member operator starts at op reads a member
// of the value before it. A '}' before it ends an object literal or a function expression
// only when that is what the block is; after any other block the bracket opens an array
// literal statement. A declaration keyword before it opens a destructuring pattern.
func indexedValue(clean []rune, tf *thisFrames, op int) bool {
	k := skipSpaceBack(clean, op-1)
	if w, _ := wordBefore(clean, k); w == "const" || w == "let" || w == "var" {
		return false
	}
	if clean[k] != '}' {
		return true
	}
	for f := range tf.opens {
		if tf.closes[f] != k {
			continue
		}
		if tf.members[f] && !tf.fn[f] && !classBody(clean, skipSpaceBack(clean, tf.opens[f]-1)) {
			return true
		}
		if kw := tf.fnKw[f]; kw >= 0 {
			b := skipSpaceBack(clean, kw-1)
			return b >= 0 && clean[b] != ';' && clean[b] != '{' && clean[b] != '}'
		}
		return false
	}
	return false
}

// hopJudges judge the key of a read indexed again, against each member that invokes or
// returns a function's constructor, and against a property descriptor's value, get and set.
type hopJudges struct {
	call, desc []*keyJudge
}

func newHopJudges(clean, src []rune, gs *globalScope) *hopJudges {
	h := &hopJudges{}
	for _, w := range []string{"call", "apply", "bind", "constructor", "valueOf"} {
		h.call = append(h.call, newKeyJudge(clean, src, gs, w))
	}
	for _, w := range []string{"value", "get", "set"} {
		h.desc = append(h.desc, newKeyJudge(clean, src, gs, w))
	}
	return h
}

// may reports whether the key clean[from:to] may name one of the judged members.
func (h *hopJudges) may(from, to int, descriptor bool) bool {
	js := h.call
	if descriptor {
		js = append(append([]*keyJudge{}, h.call...), h.desc...)
	}
	for _, j := range js {
		if ok, enums := j.keySafe(from, to); !ok || len(enums) > 0 {
			return true
		}
	}
	return false
}

// readOnly reports whether a computed read whose value spans [start, next) is used only
// where it is neither called nor handed on (indexPairRead). A read indexed again by a key
// that may name a member invoking or returning a function's constructor (or, for a
// property descriptor, its value, get or set) is read-only only when that second read is.
// A property descriptor (descriptor) is also not read for its value, get or set by member.
func readOnly(clean, src []rune, h *hopJudges, start, next int, descriptor bool) bool {
	n := len(clean)
	p := skipSpace(clean, next)
	q := p
	if optionalDot(clean, p) {
		q = skipSpace(clean, p+2)
	}
	if q < n && clean[q] == '[' {
		e := closeBracket(clean, q)
		if e < n && h.may(q+1, e, descriptor) {
			return readOnly(clean, src, h, start, e+1, false)
		}
	}
	if descriptor {
		if _, member := memberReadAt(clean, p); member {
			d := p + 1
			if optionalDot(clean, p) {
				d = p + 2
			}
			if w, _ := peekWord(clean, skipSpace(clean, d)); w == "value" || w == "get" || w == "set" {
				return false
			}
		}
	}
	return indexPairRead(clean, start, next)
}

// receiverName returns the name of the object a member operator at dot reads from: the
// word before it, or the value of a whole string-literal key when a bracket closes there.
func receiverName(clean, src []rune, dot int) string {
	k := skipSpaceBack(clean, dot-1)
	if k >= 0 && clean[k] == ']' {
		if o := openBefore(clean, k); o >= 0 {
			if a := skipSpace(clean, o+1); stringLiteral(clean, src, a) && wholeKey(clean, src, a) {
				return specifierAt(src, a)
			}
		}
		return ""
	}
	w, _ := wordBefore(clean, k)
	return w
}

// callArgs returns the trimmed argument ranges of the call whose '(' is at o.
func callArgs(clean []rune, o int) [][2]int {
	if o >= len(clean) || clean[o] != '(' {
		return nil
	}
	e := closeOf(clean, o)
	var args [][2]int
	s, depth := o+1, 0
	for k := o + 1; k <= e && k < len(clean); k++ {
		switch clean[k] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if k < e {
				depth--
				continue
			}
			fallthrough
		case ',':
			if depth > 0 {
				continue
			}
			if a, b := trimRange(clean, s, k); a < b {
				args = append(args, [2]int{a, b})
			}
			s = k + 1
		}
	}
	return args
}

// protoValue reports whether clean[from:to] is a prototype the lane sees: null, an object
// literal, or X.prototype or X && X.prototype for a name X.
func protoValue(clean []rune, from, to int) bool {
	from, to = trimRange(clean, from, to)
	if from >= to {
		return false
	}
	if w, e := peekWord(clean, from); w == "null" && e == to {
		return true
	}
	if clean[from] == '{' && closeOf(clean, from) == to-1 {
		return true
	}
	dotted := func(a, b int) bool {
		a, b = trimRange(clean, a, b)
		x, e := peekWord(clean, a)
		if x == "" {
			return false
		}
		d := skipSpace(clean, e)
		if d >= b || clean[d] != '.' {
			return false
		}
		w, e := peekWord(clean, skipSpace(clean, d+1))
		return w == "prototype" && e == b
	}
	for k := from; k+1 < to; k++ {
		if clean[k] == '&' && clean[k+1] == '&' {
			x, _ := peekWord(clean, from)
			y, _ := peekWord(clean, skipSpace(clean, k+2))
			return x != "" && x == y && dotted(k+2, to)
		}
	}
	return dotted(from, to)
}

// plainValue reports whether clean[from:to] is a literal value that is no function: an
// object, array, string or numeric literal, true, false, null or undefined.
func plainValue(clean, src []rune, from, to int) bool {
	from, to = trimRange(clean, from, to)
	if from >= to {
		return false
	}
	switch {
	case (clean[from] == '{' || clean[from] == '[') && closeOf(clean, from) == to-1:
		return true
	case stringLiteral(clean, src, from) && to == from+1:
		return true
	case unicode.IsDigit(clean[from]):
		_, e := readWord(clean, from)
		return e == to
	}
	w, e := peekWord(clean, from)
	switch w {
	case "true", "false", "null", "undefined":
		return e == to
	}
	return false
}

// reflectiveUse reports whether the unshadowed Reflect or Object at i is used in a way that
// can read a member under a key the lane does not see: Reflect.get or
// getOwnPropertyDescriptor (Object's getOwnPropertyDescriptor) taken without being called,
// either object indexed by a key that is not a literal, or Reflect handed on as a value
// (Object only as a whole initializer or destructuring source).
func reflectiveUse(clean, src []rune, gs *globalScope, j *keyJudge, word string, i, next int) bool {
	n := len(clean)
	reads := func(m string) bool {
		return m == "getOwnPropertyDescriptor" || word == "Reflect" && m == "get"
	}
	p := skipSpace(clean, next)
	q := p
	if optionalDot(clean, p) {
		q = p + 1
	}
	if q+1 < n && clean[q] == '.' && clean[q+1] == '[' {
		q++
	}
	switch {
	case q < n && clean[q] == '.' && !(q+1 < n && clean[q+1] == '.'):
		m, e := peekWord(clean, skipSpace(clean, q+1))
		c := skipSpace(clean, e)
		return reads(m) && !(c < n && clean[c] == '(' || optionalCall(clean, c))
	case q < n && clean[q] == '[':
		e := closeBracket(clean, q)
		a := skipSpace(clean, q+1)
		if stringLiteral(clean, src, a) && wholeKey(clean, src, a) {
			if !reads(specifierAt(src, a)) {
				return false
			}
			c := skipSpace(clean, e+1)
			return !(c < n && clean[c] == '(' || optionalCall(clean, c))
		}
		ok, enums := j.keySafe(q+1, e)
		return !ok || len(enums) > 0
	}
	b := skipSpaceBack(clean, i-1)
	if word == "Reflect" {
		w, _ := wordBefore(clean, b)
		return w != "typeof"
	}
	if b >= 1 && clean[b] == '=' && !strings.ContainsRune("=!<>+-*/%&|^?", clean[b-1]) && valueTail(clean, next) {
		return true
	}
	return false
}

// ownKeysRead reports whether the result of an own-keys or descriptors call, whose member
// operator is at op and which ends before next, is only read for a member other than
// constructor, call, apply, bind and valueOf, tested with in, !! or against undefined, or
// bound to a const used only so.
func ownKeysRead(clean, src []rune, gs *globalScope, op, next int) bool {
	start := receiverStart(clean, op)
	if start < 0 {
		return false
	}
	if keysResultRead(clean, start, next) {
		return true
	}
	b := skipSpaceBack(clean, start-1)
	if b < 1 || clean[b] != '=' || strings.ContainsRune("=!<>+-*/%&|^?", clean[b-1]) {
		return false
	}
	name, ns := wordBefore(clean, skipSpaceBack(clean, b-1))
	if kw, _ := wordBefore(clean, skipSpaceBack(clean, ns-1)); kw != "const" || name == "" {
		return false
	}
	if e := skipSpace(clean, next); e < len(clean) && clean[e] != ';' && clean[e] != ',' && clean[e] != '\n' && clean[e] != '}' {
		return false
	}
	ds := gs.lookup(name, ns)
	for _, o := range gs.occurrences(clean, name) {
		if gs.sites[o] || !gs.sameVariable(name, ds, o) {
			continue
		}
		if !keysResultRead(clean, o, o+len([]rune(name))) {
			return false
		}
	}
	return true
}

func keysResultRead(clean []rune, start, next int) bool {
	n := len(clean)
	p := skipSpace(clean, next)
	if ok, member := memberReadAt(clean, p); member {
		return ok
	}
	b := skipSpaceBack(clean, start-1)
	if w, _ := wordBefore(clean, b); w == "in" {
		return operandEnds(clean, p)
	}
	if b >= 1 && clean[b] == '!' && clean[b-1] == '!' {
		return operandEnds(clean, p)
	}
	isUndefined := func(k int) bool {
		w, _ := peekWord(clean, k)
		return w == "undefined"
	}
	for _, op := range []string{"===", "!==", "==", "!="} {
		if p+len(op) <= n && string(clean[p:p+len(op)]) == op {
			return isUndefined(skipSpace(clean, p+len(op)))
		}
		if l := len(op); b-l+1 >= 0 && string(clean[b-l+1:b+1]) == op {
			w, _ := wordBefore(clean, skipSpaceBack(clean, b-l))
			return w == "undefined" && operandEnds(clean, p)
		}
	}
	return false
}
