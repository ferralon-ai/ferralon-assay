package pythonanalysis

import (
	"maps"
	"slices"
	"strings"
	"unicode"
)

// declKind classifies a parsed Python declaration.
type declKind int

const (
	kindFunc  declKind = iota // a def: module-level function, nested function, or class method
	kindClass                 // a class declaration (carries methods)
)

// decl is one parsed Python declaration with the chain of enclosing class names that
// locate it inside the file's module.
type decl struct {
	kind      declKind
	name      string
	enclosing []string // outer→inner class names; empty for a module-level declaration
	arity     int      // parameter count (kindFunc only; includes self/cls)
	bases     []string // the positional base expressions of a class (kindClass only)
	params    paramShape
	inDef     bool // declared inside a def body, where enclosing omits the def
}

// parseResult holds the module-relative path and declarations parsed from one source
// file, plus a flag recording whether the scanner skipped a construct it does not model
// (surfaced as declared partiality).
type parseResult struct {
	module  string // source import path relative to the build root, '/'-joined, no extension
	decls   []decl
	skipped bool
}

// logicalLine is one Python logical line: the source text of a statement (physical
// lines joined across bracket-continuations and backslash-continuations) plus the
// indentation of its first physical line. Indentation is what defines Python block
// structure, so it is the scope key.
type logicalLine struct {
	indent int
	text   string
}

// parseFile parses one Python source file (already read into src, with module set to
// its import path) and returns the module-level, nested, and class-method declarations.
// It works on a comment/string-stripped copy so no literal can be mistaken for code.
func parseFile(module, src string) parseResult {
	clean := stripPython(src)
	lines := logicalLines(clean)
	res := parseResult{module: module}
	res.decls = parseDecls(lines)
	return res
}

// stripPython blanks comments and string literals (single/double, and triple-quoted,
// with escape handling) to whitespace, preserving newlines and indentation so byte
// offsets, line structure, and block indentation are intact but no comment/string
// content can be mistaken for code. A string literal collapses to a single '_' token
// (a valid identifier char) so a literal argument still counts toward call-site arity.
// This is the lexical pre-pass the scanner relies on.
func stripPython(src string) string {
	clean, _ := stripPythonLiterals(src)
	return clean
}

// strLiteral is one string literal blanked by stripPythonLiterals: the rune index just past
// it in the cleaned text, its raw body between the quotes (escapes left unprocessed), and the
// rune index the body starts at.
type strLiteral struct {
	end  int
	body string
	from int
}

// stripPythonLiterals is stripPython that also returns every blanked string literal keyed
// by the rune index of its '_' token in the cleaned text. Blanking is rune-length
// preserving, so that index is also the opening quote's index in src; callers that need a
// literal's value at a known code position (a dynamic import's module name) read it here.
func stripPythonLiterals(src string) (string, map[int]strLiteral) {
	var b strings.Builder
	b.Grow(len(src))
	r := []rune(src)
	n := len(r)
	lits := map[int]strLiteral{}
	for i := 0; i < n; {
		c := r[i]
		switch {
		case c == '#':
			// comment → blank to end of line (keep the newline)
			for i < n && r[i] != '\n' {
				b.WriteByte(' ')
				i++
			}
		case c == '"' || c == '\'':
			start := i
			i = stripStringLiteral(&b, r, i)
			body, from := literalBody(r, start, i)
			lits[start] = strLiteral{end: i, body: body, from: from}
		default:
			b.WriteRune(c)
			i++
		}
	}
	return b.String(), lits
}

// spliceFStrings returns clean with each f-string and t-string substitution written back at
// its own offset as a bracketed expression, so the call scanner reads a substitution's calls
// as sites and its names as uses. A substitution's own literals are blanked; its conversion,
// debug '=' and format spec stay blank, apart from the substitutions nested in the spec. A
// spliced literal's newlines become spaces, which keeps its substitutions on the logical line
// the literal opens. The returned literals add those blanked inside substitutions. unread
// holds the text of each substitution with no closing brace, which is not spliced.
func spliceFStrings(clean string, lits map[int]strLiteral) (spliced string, all map[int]strLiteral, unread []string) {
	r := []rune(clean)
	all = maps.Clone(lits)
	for start, lit := range lits {
		if !fStringPrefix(r, start) || !strings.ContainsRune(lit.body, '{') {
			continue
		}
		unread = append(unread, spliceSubstitutions(r, all, []rune(lit.body), lit.from, rawPrefix(r, start))...)
		for i := start; i < lit.end && i < len(r); i++ {
			if r[i] == '\n' {
				r[i] = ' '
			}
		}
	}
	return string(r), all, unread
}

// spliceSubstitutions writes the substitutions of an f-string body that starts at r[at] into
// r, adding the literals inside them to lits, and returns the text of those it can't splice.
// raw reports a raw prefix, under which \N{...} is text rather than a named escape.
func spliceSubstitutions(r []rune, lits map[int]strLiteral, body []rune, at int, raw bool) (unread []string) {
	for i := 0; i < len(body); i++ {
		if body[i] != '{' {
			continue
		}
		if i+1 < len(body) && body[i+1] == '{' {
			i++
			continue
		}
		if !raw && namedEscape(body, i) {
			for i < len(body) && body[i] != '}' {
				i++
			}
			continue
		}
		end := scanField(body, i+1, true, nil)
		if end >= len(body) {
			return append(unread, string(body[i+1:]))
		}
		exprEnd := scanField(body, i+1, false, nil)
		code := exprEnd
		if k := trimRightSpace(body, i+1, code); k > i+1 && body[k-1] == '=' {
			code = k - 1
		}
		c, clits := stripPythonLiterals(string(body[i+1 : code]))
		c, clits, cunread := spliceFStrings(c, clits)
		unread = append(unread, cunread...)
		off := at + i + 1
		copy(r[off:], []rune(c))
		for k, l := range clits {
			l.end += off
			l.from += off
			lits[k+off] = l
		}
		r[at+i] = '['
		r[at+end] = ']'
		// A conversion holds no brace, so the spec's substitutions are those after exprEnd.
		if exprEnd < end {
			unread = append(unread, spliceSubstitutions(r, lits, body[exprEnd+1:end], at+exprEnd+1, raw)...)
		}
		i = end
	}
	return unread
}

// scanField returns the index in body, from i, of the brace that closes a substitution, or
// with whole false of the first conversion '!' or format-spec ':' before it, skipping nested
// brackets, string literals and comments; len(body) when there is none. A format spec is text
// apart from its nested substitutions, so its quotes and brackets open nothing; a non-nil
// stop reports the spec runes that end the enclosing literal instead, and scanField returns
// the first one's index.
func scanField(body []rune, i int, whole bool, stop func(int) bool) int {
	depth := 0
	var sink strings.Builder
	for i < len(body) {
		switch c := body[i]; {
		case c == '"' || c == '\'':
			i = stripStringLiteral(&sink, body, i)
			continue
		case c == '#':
			for i < len(body) && body[i] != '\n' {
				i++
			}
			continue
		case c == '(' || c == '[' || c == '{':
			depth++
		case (c == ')' || c == ']') && depth > 0:
			depth--
		case c == '}':
			if depth == 0 {
				return i
			}
			depth--
		case depth == 0 && whole && c == ':':
			for i++; i < len(body); i++ {
				if stop != nil && stop(i) {
					return i
				}
				switch body[i] {
				case '{':
					if i = scanField(body, i+1, true, stop); i < len(body) && body[i] != '}' {
						return i
					}
				case '}':
					return i
				}
			}
			return len(body)
		case depth == 0 && !whole && (c == ':' || c == '!' && !(i+1 < len(body) && body[i+1] == '=')):
			return i
		}
		i++
	}
	return len(body)
}

// namedEscape reports whether the brace at body[i] opens a \N{...} named escape: an N
// after an odd run of backslashes.
func namedEscape(body []rune, i int) bool {
	if i < 2 || body[i-1] != 'N' {
		return false
	}
	n := 0
	for k := i - 2; k >= 0 && body[k] == '\\'; k-- {
		n++
	}
	return n%2 == 1
}

// rawPrefix reports whether the literal opening at r[start] carries an r or R prefix.
func rawPrefix(r []rune, start int) bool {
	for j := start - 1; j >= 0 && j >= start-2 && unicode.IsLetter(r[j]); j-- {
		if r[j] == 'r' || r[j] == 'R' {
			return true
		}
	}
	return false
}

// trimRightSpace returns the index just past the last non-space rune of body[from:to].
func trimRightSpace(body []rune, from, to int) int {
	for to > from && unicode.IsSpace(body[to-1]) {
		to--
	}
	return to
}

// literalBody returns the runes between a literal's opening and closing quotes and the index
// they start at, given the opening quote index and the index just past the literal. An
// unterminated literal yields everything after the opening quote(s).
func literalBody(r []rune, start, end int) (string, int) {
	q := 1
	if start+2 < len(r) && r[start+1] == r[start] && r[start+2] == r[start] {
		q = 3
	}
	from := start + q
	to := end
	if to-q >= from && to <= len(r) && to-1 >= 0 && r[to-1] == r[start] {
		to -= q
	}
	if from > to {
		return "", from
	}
	return string(r[from:to]), from
}

// stripStringLiteral blanks a Python string literal starting at the quote rune r[i]
// (single- or triple-quoted) and returns the index just past the closing quote. The
// literal is replaced by a single '_' token; interior runes become spaces and interior
// newlines are preserved so the line structure of a multi-line (triple-quoted) string
// is kept intact. An f-string or t-string's substitutions are skipped whole, so a quote
// inside one opens a nested literal (PEP 701) rather than closing this one.
func stripStringLiteral(b *strings.Builder, r []rune, i int) int {
	n := len(r)
	quote := r[i]
	triple := i+2 < n && r[i+1] == quote && r[i+2] == quote
	field := fieldSkipper(r, i, triple)
	b.WriteByte('_')
	if triple {
		b.WriteString("  ")
		i += 3
		for i < n {
			if j := field(i); j > i {
				blankRunes(b, r[i:j])
				i = j
				continue
			}
			if r[i] == '\\' && i+1 < n {
				b.WriteString("  ")
				i += 2
				continue
			}
			if r[i] == quote && i+2 < n && r[i+1] == quote && r[i+2] == quote {
				b.WriteString("   ")
				return i + 3
			}
			if r[i] == quote && i+2 >= n {
				// closing triple at EOF
				break
			}
			if r[i] == '\n' {
				b.WriteByte('\n')
			} else {
				b.WriteByte(' ')
			}
			i++
		}
		return i
	}
	i++
	for i < n && r[i] != quote {
		if j := field(i); j > i {
			blankRunes(b, r[i:j])
			i = j
			continue
		}
		if r[i] == '\\' && i+1 < n {
			b.WriteString("  ")
			i += 2
			continue
		}
		if r[i] == '\n' {
			// unterminated single-line string — stop at the newline
			return i
		}
		b.WriteByte(' ')
		i++
	}
	if i < n {
		b.WriteByte(' ')
		i++
	}
	return i
}

// fieldSkipper returns, for the literal whose opening quote is r[start], a function giving
// the index just past the f-string or t-string construct that starts at r[i] and holds a
// brace: a whole substitution, a {{ escape, a \N{...} named escape, or the backslash before a
// brace, which escapes nothing. It returns i when none starts there, which is always so
// outside f-strings and for a substitution that never closes; that brace is then text, as
// before PEP 701.
func fieldSkipper(r []rune, start int, triple bool) func(i int) int {
	if !fStringPrefix(r, start) {
		return func(i int) int { return i }
	}
	quote, raw := r[start], rawPrefix(r, start)
	// A single-quoted literal's format spec ends at its quote or a newline, a triple-quoted
	// one's at three quotes.
	stop := func(j int) bool {
		if !triple {
			return r[j] == quote || r[j] == '\n'
		}
		return r[j] == quote && j+2 < len(r) && r[j+1] == quote && r[j+2] == quote
	}
	return func(i int) int {
		switch {
		case r[i] == '\\' && i+1 < len(r) && r[i+1] == '{':
			return i + 1
		case r[i] == '\\' && !raw && i+2 < len(r) && r[i+1] == 'N' && r[i+2] == '{':
			for j := i + 3; j < len(r) && r[j] != quote && r[j] != '\n'; j++ {
				if r[j] == '}' {
					return j + 1
				}
			}
		case r[i] != '{':
		case i+1 < len(r) && r[i+1] == '{':
			return i + 2
		default:
			if end := scanField(r, i+1, true, stop); end < len(r) && r[end] == '}' {
				return end + 1
			}
		}
		return i
	}
}

// blankRunes writes a space for each rune of s, keeping its newlines.
func blankRunes(b *strings.Builder, s []rune) {
	for _, c := range s {
		if c == '\n' {
			b.WriteByte('\n')
		} else {
			b.WriteByte(' ')
		}
	}
}

// logicalLines splits cleaned source into logical lines, joining physical lines across
// unbalanced brackets ((),[],{}) and trailing backslash continuations so a multi-line
// def/class signature is one logical line. The indent recorded is that of the first
// physical line of the logical line. Blank/whitespace-only lines are dropped.
func logicalLines(clean string) []logicalLine {
	var out []logicalLine
	physical := strings.Split(clean, "\n")

	var cur strings.Builder
	curIndent := 0
	open := false
	bracketDepth := 0

	flush := func() {
		if open {
			text := strings.TrimSpace(cur.String())
			if text != "" {
				out = append(out, logicalLine{indent: curIndent, text: text})
			}
		}
		cur.Reset()
		open = false
		bracketDepth = 0
	}

	for _, line := range physical {
		trimmedRight := strings.TrimRight(line, "\r")
		if !open {
			if strings.TrimSpace(trimmedRight) == "" {
				continue
			}
			curIndent = indentWidth(trimmedRight)
			open = true
		}
		cur.WriteByte(' ')
		cur.WriteString(strings.TrimSpace(trimmedRight))

		bracketDepth += bracketDelta(trimmedRight)
		cont := strings.HasSuffix(strings.TrimRight(trimmedRight, " \t"), "\\")
		if bracketDepth <= 0 && !cont {
			flush()
		}
	}
	flush()
	return out
}

// bracketDelta returns the net bracket depth change contributed by a physical line
// (already string/comment-stripped): +1 per opening (,[,{ and -1 per closing.
func bracketDelta(line string) int {
	depth := 0
	for _, c := range line {
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		}
	}
	return depth
}

// scope is one entry on the indentation scope stack. A scope with className != "" is a
// class body (its direct defs are methods); a scope with className == "" is a def body
// or the module.
type scope struct {
	indent    int
	className string
}

// parseDecls scans the logical lines for class and def declarations, tracking block
// structure by indentation. A def's enclosing class chain is every class scope on the
// stack, so a method resolves under its class(es). Decorators ("@...") and async are
// tolerated. Recognized shapes:
//   - "class Name(bases):"          — a class declaration
//   - "def name(params):"           — a function/method
//   - "async def name(params):"     — an async function/method
func parseDecls(lines []logicalLine) []decl {
	var stack []scope
	var decls []decl

	inDef := func() bool {
		return slices.ContainsFunc(stack, func(s scope) bool { return s.className == "" })
	}
	classChain := func() []string {
		var out []string
		for _, s := range stack {
			if s.className != "" {
				out = append(out, s.className)
			}
		}
		return out
	}

	for _, ll := range lines {
		// Pop scopes we have dedented out of: a new statement at indent I closes every
		// scope whose body-indent is >= I.
		for len(stack) > 0 && ll.indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}

		text := ll.text
		if strings.HasPrefix(text, "@") {
			continue // decorator line — attaches to the following def (ingress: follow-on)
		}
		kw, rest := firstWord(text)
		if kw == "async" {
			kw, rest = firstWord(strings.TrimSpace(rest))
		}
		switch kw {
		case "class":
			name, ok := parseClassName(rest)
			if !ok {
				continue
			}
			decls = append(decls, decl{kind: kindClass, name: name, enclosing: classChain(), bases: classBases(rest), inDef: inDef()})
			stack = append(stack, scope{indent: ll.indent, className: name})
		case "def":
			name, arity, ok := parseDefSignature(rest)
			if !ok {
				continue
			}
			_, after := readIdent(strings.TrimSpace(rest))
			decls = append(decls, decl{kind: kindFunc, name: name, enclosing: classChain(), arity: arity, params: paramShapeOf(strings.TrimSpace(after)), inDef: inDef()})
			stack = append(stack, scope{indent: ll.indent, className: ""})
		}
	}
	return decls
}

// parseClassName reads the class name from the text following the "class" keyword:
// "Name(bases):" or "Name:". ok is false when no identifier follows.
func parseClassName(rest string) (string, bool) {
	rest = strings.TrimSpace(rest)
	name, _ := readIdent(rest)
	if name == "" {
		return "", false
	}
	return name, true
}

// classBases reads the positional base expressions of a class header's "Name(bases):",
// leaving out keyword arguments (metaclass=...).
func classBases(rest string) []string {
	r := []rune(strings.TrimSpace(rest))
	_, end := readWordRunes(r, 0)
	open := skipSpaceRunes(r, end)
	if open >= len(r) || r[open] != '(' {
		return nil
	}
	args, _ := callArgs(r, open)
	var out []string
	for _, a := range args {
		s := strings.TrimSpace(string(r[a[0]:a[1]]))
		if _, _, kw := keywordArg(s); kw || strings.HasPrefix(s, "**") {
			continue
		}
		out = append(out, s)
	}
	return out
}

// parseDefSignature reads the def's name and parameter arity from the text following
// the "def" keyword: "name(params):". Arity counts top-level comma-separated parameters
// (including self/cls, and *args/**kw as one each). ok is false when the shape is not a
// def signature.
func parseDefSignature(rest string) (name string, arity int, ok bool) {
	rest = strings.TrimSpace(rest)
	name, after := readIdent(rest)
	if name == "" {
		return "", 0, false
	}
	after = strings.TrimSpace(after)
	if !strings.HasPrefix(after, "(") {
		return "", 0, false
	}
	arity = paramArity(after)
	return name, arity, true
}

// paramShape is the range of argument counts a parameter list accepts: required counts
// the parameters with no default (keyword-only ones too, since a call passes them as
// keyword arguments), max every parameter but the bare "*" and "/" markers, and variadic is
// set by *args or **kwargs, which take any number more.
type paramShape struct {
	required, max int
	variadic      bool
}

// accepts reports whether a call with n arguments fits the parameter list.
func (s paramShape) accepts(n int) bool {
	return n >= s.required && (s.variadic || n <= s.max)
}

// paramShapeOf reads the paramShape of a "(...)" list, given a string that begins with '('.
func paramShapeOf(s string) paramShape {
	r := []rune(s)
	var out paramShape
	depth, start := 0, 1
	param := func(end int) {
		p := strings.TrimSpace(string(r[start:end]))
		switch {
		case p == "", p == "*", p == "/":
		case strings.HasPrefix(p, "*"):
			out.variadic = true
		default:
			out.max++
			if !hasDefault(p) {
				out.required++
			}
		}
	}
	// A lambda default's own parameters run to its ':' and are no parameters of the def; a
	// lambda parameter's default may itself be a lambda, so open lambdas are counted.
	lambdas := 0
	for i := 0; i < len(r); i++ {
		switch r[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				param(i)
				return out
			}
		case ':':
			if depth == 1 && lambdas > 0 {
				lambdas--
			}
		case ',':
			if depth == 1 && lambdas == 0 {
				param(i)
				start = i + 1
			}
		default:
			if depth == 1 && isIdentStartRune(r[i]) && (i == 0 || !isIdentPart(r[i-1])) {
				w, end := readWordRunes(r, i)
				if w == "lambda" {
					lambdas++
				}
				i = end - 1
			}
		}
	}
	return out
}

// hasDefault reports whether one parameter's text ("x", "x: int", "x=1", "x: int = 1")
// carries a default: an "=" outside its annotation's brackets.
func hasDefault(p string) bool {
	depth := 0
	for _, c := range p {
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '=':
			if depth == 0 {
				return true
			}
		}
	}
	return false
}

// paramArity counts the top-level comma-separated parameters of a "(...)" list, given a
// string that begins with '('. An empty "()" is arity 0.
func paramArity(s string) int { return paramArityAt([]rune(s), 0) }

// paramArityAt is paramArity over r starting at the opening bracket r[start], so a caller
// already holding runes doesn't copy the rest of the line once per call site.
func paramArityAt(r []rune, start int) int {
	n := len(r)
	depth := 0
	count := 0
	seenToken := false
	for i := start; i < n; i++ {
		switch r[i] {
		case '(', '[', '{':
			if depth == 1 {
				seenToken = true // an argument that is only a bracketed literal: "f([x])"
			}
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				if seenToken {
					count++
				}
				return count
			}
		case ',':
			if depth == 1 {
				count++
				seenToken = false // reset so a trailing comma "(a, b,)" is arity 2, not 3
			}
		default:
			if depth == 1 && !unicode.IsSpace(r[i]) {
				seenToken = true
			}
		}
	}
	return count
}

// firstWord splits off the leading identifier/keyword of text and returns it with the
// remainder (leading space preserved-trimmed by the caller).
func firstWord(text string) (word, rest string) {
	word, after := readIdent(text)
	return word, after
}

// readIdent reads a Python identifier at the start of s and returns it with the
// remainder of s after it. It returns "" when s does not start with an identifier.
func readIdent(s string) (string, string) {
	r := []rune(s)
	i := 0
	for i < len(r) && unicode.IsSpace(r[i]) {
		i++
	}
	start := i
	for i < len(r) && isIdentPart(r[i]) {
		i++
	}
	if i == start {
		return "", s
	}
	return string(r[start:i]), string(r[i:])
}

func isIdentPart(c rune) bool {
	return c == '_' || unicode.IsLetter(c) || unicode.IsDigit(c)
}

// indentWidth counts the leading whitespace columns of a line (a tab counts as one).
func indentWidth(line string) int {
	w := 0
	for _, c := range line {
		if c == ' ' || c == '\t' {
			w++
			continue
		}
		break
	}
	return w
}
