package javaanalysis

import (
	"strings"
	"unicode"
)

// declKind classifies a parsed Java declaration.
type declKind int

const (
	kindType declKind = iota
	kindMethod
	kindField
)

// decl is one parsed Java declaration: a type, method, or field, with the chain
// of enclosing type names that locate it inside the file's package.
type decl struct {
	kind      declKind
	name      string
	enclosing []string // outer→inner type names; empty for a top-level type
	arity     int      // method parameter count (kindMethod only)
}

// callSite is one method-call expression observed inside a method body: the
// enclosing method (caller) and the simple name + argument arity of the callee
// invocation. The callee is named lexically (no type resolution), so it is
// resolved to a concrete declaration later by name+arity (calls.go). When the
// caller is a constructor/initializer or static block the caller fields locate
// the enclosing method; a call not inside a method body is not recorded.
type callSite struct {
	callerEnclosing []string // enclosing type chain of the method the call appears in
	callerName      string   // simple name of the enclosing method
	callerArity     int      // arity of the enclosing method (overload disambiguation)
	calleeName      string   // simple name being invoked
	calleeArity     int      // argument count at the call site
}

// ingressMarker is one entry-point signal found lexically around a method
// declaration: a route annotation (@GetMapping etc.) or the servlet
// doGet/doPost override on a class that extends HttpServlet.
type ingressMarker struct {
	enclosing []string // enclosing type chain of the ingress method
	name      string   // simple method name
	arity     int      // method arity
	kind      string   // plugin.Ingress Kind: "http_route" | "servlet"
	selector  string   // route selector when an annotation carries a path
}

// parseResult holds the package name and declarations parsed from one Java source
// file, plus a flag recording whether the parser skipped any construct it does
// not model (which the caller surfaces as declared partiality).
type parseResult struct {
	pkg       string
	decls     []decl
	calls     []callSite      // method-call expressions inside method bodies
	ingresses []ingressMarker // annotation/servlet entry-point markers
	skipped   bool            // a construct was not fully modeled (e.g. annotation type body)
}

// stripJava removes comments, string literals, char literals, and text-block
// contents from Java source, replacing each with equivalent whitespace so byte
// offsets and newlines are preserved but no comment/string content can be
// mistaken for a declaration. This is the lexical pre-pass the brace/keyword
// scanner relies on.
func stripJava(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	r := []rune(src)
	n := len(r)
	for i := 0; i < n; {
		c := r[i]
		switch {
		case c == '/' && i+1 < n && r[i+1] == '/':
			// line comment
			for i < n && r[i] != '\n' {
				b.WriteByte(' ')
				i++
			}
		case c == '/' && i+1 < n && r[i+1] == '*':
			// block comment
			b.WriteString("  ")
			i += 2
			for i < n && !(r[i] == '*' && i+1 < n && r[i+1] == '/') {
				if r[i] == '\n' {
					b.WriteByte('\n')
				} else {
					b.WriteByte(' ')
				}
				i++
			}
			if i < n {
				b.WriteString("  ")
				i += 2
			}
		case c == '"' && i+2 < n && r[i+1] == '"' && r[i+2] == '"':
			// text block (""" ... """). The leading '_' is a placeholder TOKEN (a
			// valid identifier char) so an argument that is only a literal still
			// counts toward call-site arity; the remaining width is blanked.
			b.WriteString("_  ")
			i += 3
			for i < n && !(r[i] == '"' && i+2 < n && r[i+1] == '"' && r[i+2] == '"') {
				if r[i] == '\n' {
					b.WriteByte('\n')
				} else {
					b.WriteByte(' ')
				}
				i++
			}
			if i < n {
				b.WriteString("   ")
				i += 3
			}
		case c == '"':
			// string literal. The opening '_' is a placeholder TOKEN (valid ident
			// char) so a string-only argument still counts toward call-site arity.
			b.WriteByte('_')
			i++
			for i < n && r[i] != '"' {
				if r[i] == '\\' && i+1 < n {
					b.WriteString("  ")
					i += 2
					continue
				}
				b.WriteByte(' ')
				i++
			}
			if i < n {
				b.WriteByte(' ')
				i++
			}
		case c == '\'':
			// char literal. The opening '_' is a placeholder TOKEN so a char-only
			// argument still counts toward call-site arity.
			b.WriteByte('_')
			i++
			for i < n && r[i] != '\'' {
				if r[i] == '\\' && i+1 < n {
					b.WriteString("  ")
					i += 2
					continue
				}
				b.WriteByte(' ')
				i++
			}
			if i < n {
				b.WriteByte(' ')
				i++
			}
		default:
			b.WriteRune(c)
			i++
		}
	}
	return b.String()
}

// typeKeywords are the declaration keywords that introduce a named Java type.
var typeKeywords = map[string]bool{
	"class":     true,
	"interface": true,
	"enum":      true,
	"record":    true,
}

// parseFile parses one Java source file (already read into src) and returns the
// package and the type/method/field declarations it contains. It works on a
// comment/string-stripped copy so no literal can be mistaken for code. It is a
// structural parser: it tracks brace depth and the enclosing type stack, and
// recognizes type declarations, methods (by the "name(...) {" or "name(...);"
// shape at type-body depth), and fields (by the "name ... ;" shape). Constructs
// it does not model set skipped=true so the caller can declare partiality.
func parseFile(src string) parseResult {
	clean := stripJava(src)
	res := parseResult{pkg: parsePackage(clean)}

	r := []rune(clean)
	n := len(r)

	// typeStack holds the enclosing block frames at the current brace depth. A
	// frame with name=="" marks a non-type block (method body, initializer,
	// lambda) so declarations inside it are not mistaken for type members. The
	// enum flag drives leading enum-constant parsing.
	var typeStack []frame

	i := 0
	for i < n {
		c := r[i]

		switch {
		case c == '{':
			// A brace not consumed by a type declaration opens a non-type block.
			typeStack = append(typeStack, frame{})
			i++
		case c == '}':
			if len(typeStack) > 0 {
				typeStack = typeStack[:len(typeStack)-1]
			}
			i++
		case isIdentStart(c):
			word, next := readWord(r, i)
			// An annotation type "@interface" is not modeled: it uses a distinct
			// member grammar. Detect the '@' immediately before "interface" and
			// declare partiality, skipping its body rather than misparsing it.
			if word == "interface" && precededByAt(r, i) {
				res.skipped = true
				if open, ok := findBrace(r, next); ok {
					i = skipGroup(r, open)
				} else {
					i = next
				}
				continue
			}
			if typeKeywords[word] {
				name, openIdx, ok := parseTypeHeader(r, next)
				if !ok {
					res.skipped = true
					i = next
					continue
				}
				enclosing := enclosingTypes(typeStack)
				res.decls = append(res.decls, decl{kind: kindType, name: name, enclosing: enclosing})
				fr := frame{name: name, isEnum: word == "enum"}
				if fr.isEnum {
					// The enum constant section runs from just after '{' to the
					// first ';' (or the body's end). Capture the simple constant
					// identifiers and declare partiality, since constants with
					// constructor args or bodies are not fully modeled.
					constants, consumed, partial := parseEnumConstants(r, openIdx+1)
					selfEnclosing := append(append([]string(nil), enclosing...), name)
					for _, cn := range constants {
						res.decls = append(res.decls, decl{kind: kindField, name: cn, enclosing: selfEnclosing})
					}
					if partial {
						res.skipped = true
					}
					typeStack = append(typeStack, fr)
					i = consumed
					continue
				}
				typeStack = append(typeStack, fr)
				i = openIdx + 1 // consume the '{' as the type body open
				continue
			}
			if word == "package" || word == "import" {
				// skip to the terminating ';'
				i = skipTo(r, next, ';')
				continue
			}
			// Member-level: only consider declarations when the immediate
			// enclosing block is a type body (top of stack is a named type).
			if inTypeBody(typeStack) {
				if d, adv, ok := parseMember(r, i, enclosingTypes(typeStack)); ok {
					res.decls = append(res.decls, d)
					i = adv
					continue
				}
			}
			i = next
		default:
			i++
		}
	}

	// Second pass (body-aware): collect call sites and annotation/servlet ingress
	// markers from the same cleaned source. Declarations and call/ingress data are
	// gathered separately so the working declaration scanner above is untouched.
	res.calls, res.ingresses = parseCallsAndIngresses(r)
	return res
}

// frame is one entry on the enclosing-block stack.
type frame struct {
	name   string // "" for a non-type block
	isEnum bool
}

// parseEnumConstants reads the leading constant section of an enum body, given
// the index just past the body-opening '{'. It returns the simple constant names,
// the index to resume scanning from (just past the '{' so members after the
// optional ';' are still parsed normally), and partial=true when a constant
// carries constructor args or a class body (forms this engine does not fully
// model). Constants are recognized as identifiers at brace-depth 0 separated by
// commas up to the first ';' or the closing '}'.
func parseEnumConstants(r []rune, pos int) (names []string, resume int, partial bool) {
	n := len(r)
	depth := 0
	expectName := true
	for pos < n {
		c := r[pos]
		switch {
		case c == '{' || c == '(' || c == '[' || c == '<':
			depth++
			partial = true // a constant body / constructor args present
			pos = skipGroup(r, pos)
			continue
		case c == '}':
			if depth == 0 {
				return names, pos, partial // enum had no member section
			}
			depth--
		case c == ';':
			if depth == 0 {
				// resume just past '{'-equivalent: leave the rest of the body to
				// the normal member scanner, starting after this ';'.
				return names, pos + 1, partial
			}
		case c == ',':
			if depth == 0 {
				expectName = true
			}
		case isIdentStart(c):
			word, nx := readWord(r, pos)
			if depth == 0 && expectName {
				names = append(names, word)
				expectName = false
			}
			pos = nx
			continue
		}
		pos++
	}
	return names, n, partial
}

// parsePackage extracts the package name from a "package a.b.c;" statement, or
// "" for the default package.
func parsePackage(clean string) string {
	idx := indexWord(clean, "package")
	if idx < 0 {
		return ""
	}
	rest := clean[idx+len("package"):]
	end := strings.IndexByte(rest, ';')
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(strings.Join(strings.Fields(rest[:end]), ""))
}

// parseTypeHeader, given the rune slice positioned just AFTER a type keyword,
// reads the type name and scans forward to the body-opening '{', skipping the
// extends/implements/permits clause and any generic/record-parameter lists. It
// returns the name, the index of the opening '{', and ok=false if no body brace
// is found before a ';' (e.g. an annotation-less forward decl) or EOF.
func parseTypeHeader(r []rune, pos int) (name string, openIdx int, ok bool) {
	n := len(r)
	pos = skipSpace(r, pos)
	if pos >= n || !isIdentStart(r[pos]) {
		return "", 0, false
	}
	name, pos = readWord(r, pos)
	// Scan to the next top-level '{' or ';', skipping nested () <> [] groups so a
	// record header "record P(int x)" or a generic "class C<T>" is handled.
	for pos < n {
		switch r[pos] {
		case '{':
			return name, pos, true
		case ';':
			return name, 0, false
		case '(', '<', '[':
			pos = skipGroup(r, pos)
		default:
			pos++
		}
	}
	return "", 0, false
}

// parseTypeHeaderServlet is parseTypeHeader plus a lexical check of the header's
// extends clause for HttpServlet. It returns the type name, whether the header
// extends a HttpServlet type, the body-opening '{' index, and ok. The servlet
// check is name-only (no type resolution): "extends HttpServlet" or any
// "extends <X>Servlet" / fully-qualified "javax.servlet.http.HttpServlet" is
// treated as a servlet base, the same lexical idiom the Go plugin uses for its
// handler-shape detection. A false positive (a non-servlet *Servlet base) only
// adds a candidate ingress that yields no pair unless a sink is reachable.
func parseTypeHeaderServlet(r []rune, pos int) (name string, isServlet bool, openIdx int, ok bool) {
	n := len(r)
	pos = skipSpace(r, pos)
	if pos >= n || !isIdentStart(r[pos]) {
		return "", false, 0, false
	}
	name, pos = readWord(r, pos)
	sawExtends := false
	for pos < n {
		switch {
		case r[pos] == '{':
			return name, isServlet, pos, true
		case r[pos] == ';':
			return name, false, 0, false
		case r[pos] == '(' || r[pos] == '<' || r[pos] == '[':
			pos = skipGroup(r, pos)
		case isIdentStart(r[pos]):
			w, nx := readWord(r, pos)
			switch {
			case w == "extends":
				sawExtends = true
			case w == "implements" || w == "permits":
				sawExtends = false
			case sawExtends && isServletBase(w):
				isServlet = true
			}
			pos = nx
		default:
			pos++
		}
	}
	return "", false, 0, false
}

// isServletBase reports whether a base-type token in an extends clause names the
// servlet base class. It accepts the bare "HttpServlet", the dotted
// "javax.servlet.http.HttpServlet" / "jakarta.servlet.http.HttpServlet" leaf, and
// (conservatively) any identifier ending in "HttpServlet".
func isServletBase(tok string) bool {
	if dot := strings.LastIndexByte(tok, '.'); dot >= 0 {
		tok = tok[dot+1:]
	}
	return tok == "HttpServlet" || strings.HasSuffix(tok, "HttpServlet")
}

// parseMember tries to parse a method or field declaration starting at the first
// identifier of a member at type-body depth. It returns the decl, the index just
// past the declaration, and ok=false if the shape is not a recognizable member
// (in which case the caller advances by one word and continues).
//
// Strategy: a member declaration is a run of tokens ending in either:
//   - "ident ( params ) {"  or  "ident ( params ) ;"  → method (incl. ctor)
//   - "ident ;"  or  "ident = ... ;"                  → field
//
// We scan forward over the modifier/type tokens to the first '(' , '=', ';', or
// '{'. The identifier immediately before '(' is the method name; before '=' or
// ';' (with no '(') it is the field name.
func parseMember(r []rune, start int, enclosing []string) (decl, int, bool) {
	n := len(r)
	pos := start
	lastIdent := ""
	for pos < n {
		c := r[pos]
		switch {
		case c == '(':
			if lastIdent == "" {
				return decl{}, start, false
			}
			arity, after := parseParamArity(r, pos)
			// After the param list, a method has '{' (body) or ';' (abstract);
			// otherwise it is not a method (e.g. a field initialized from a call).
			q := skipSpace(r, after)
			// skip a throws clause
			if q < n && isIdentStart(r[q]) {
				if w, nx := readWord(r, q); w == "throws" {
					q = nx
					for q < n && r[q] != '{' && r[q] != ';' {
						q++
					}
				}
			}
			if q < n && (r[q] == '{' || r[q] == ';') {
				d := decl{kind: kindMethod, name: lastIdent, enclosing: enclosing, arity: arity}
				if r[q] == '{' {
					return d, q, true // leave '{' so the body opens a non-type block
				}
				return d, q + 1, true
			}
			return decl{}, start, false
		case c == '=' || c == ';':
			if lastIdent == "" {
				return decl{}, start, false
			}
			return decl{kind: kindField, name: lastIdent, enclosing: enclosing}, skipTo(r, pos, ';'), true
		case c == '{' || c == '}':
			return decl{}, start, false
		case c == '<' || c == '[':
			pos = skipGroup(r, pos)
		case isIdentStart(c):
			lastIdent, pos = readWord(r, pos)
		default:
			pos++
		}
	}
	return decl{}, start, false
}

// parseParamArity counts the comma-separated parameters of a method, given the
// position of the opening '('. An empty "()" is arity 0. It returns the arity and
// the index just past the matching ')'.
func parseParamArity(r []rune, open int) (int, int) {
	n := len(r)
	depth := 0
	count := 0
	seenToken := false
	pos := open
	for pos < n {
		switch r[pos] {
		case '(', '[', '<':
			depth++
		case ')', ']', '>':
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

// --- enclosing-type helpers ---

// enclosingTypes returns the chain of named enclosing types from the block stack,
// dropping the non-type-block markers.
func enclosingTypes(stack []frame) []string {
	var out []string
	for _, f := range stack {
		if f.name != "" {
			out = append(out, f.name)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// inTypeBody reports whether the innermost open block is a named type body.
func inTypeBody(stack []frame) bool {
	return len(stack) > 0 && stack[len(stack)-1].name != ""
}

// --- low-level scanners over the cleaned rune slice ---

func isIdentStart(c rune) bool {
	return c == '_' || c == '$' || unicode.IsLetter(c)
}

func isIdentPart(c rune) bool {
	return c == '_' || c == '$' || unicode.IsLetter(c) || unicode.IsDigit(c)
}

// readWord reads a Java identifier/keyword starting at i and returns it with the
// index just past it.
func readWord(r []rune, i int) (string, int) {
	start := i
	for i < len(r) && isIdentPart(r[i]) {
		i++
	}
	return string(r[start:i]), i
}

// precededByAt reports whether the first non-space rune before index i is '@'
// (the marker that turns "interface" into the "@interface" annotation type).
func precededByAt(r []rune, i int) bool {
	j := i - 1
	for j >= 0 && (r[j] == ' ' || r[j] == '\t') {
		j--
	}
	return j >= 0 && r[j] == '@'
}

// findBrace returns the index of the next '{' at or after i (and ok), or ok=false
// if a ';' or EOF is reached first.
func findBrace(r []rune, i int) (int, bool) {
	for ; i < len(r); i++ {
		switch r[i] {
		case '{':
			return i, true
		case ';':
			return 0, false
		}
	}
	return 0, false
}

func skipSpace(r []rune, i int) int {
	for i < len(r) && unicode.IsSpace(r[i]) {
		i++
	}
	return i
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

// skipGroup skips a balanced (), <>, or [] group starting at the opening rune at
// i and returns the index just past the matching close. Mismatched/unterminated
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

// indexWord returns the byte index of the first occurrence of word as a whole
// token in s, or -1.
func indexWord(s, word string) int {
	from := 0
	for {
		idx := strings.Index(s[from:], word)
		if idx < 0 {
			return -1
		}
		abs := from + idx
		beforeOK := abs == 0 || !isIdentPart(rune(s[abs-1]))
		afterIdx := abs + len(word)
		afterOK := afterIdx >= len(s) || !isIdentPart(rune(s[afterIdx]))
		if beforeOK && afterOK {
			return abs
		}
		from = abs + len(word)
	}
}
