package dotnetanalysis

import (
	"strings"
	"unicode"
)

// declKind classifies a parsed C# declaration.
type declKind int

const (
	kindFunc declKind = iota // a method or constructor
	kindType                 // a class / struct / interface / record / enum declaration
)

// decl is one parsed C# declaration with the namespace and enclosing-type chain that
// locate it inside the compilation.
type decl struct {
	kind      declKind
	name      string
	namespace string   // dotted namespace, e.g. "Ionic.Zip"; "" for the global namespace
	enclosing []string // outer→inner enclosing TYPE names; empty for a namespace-level type
	arity     int      // parameter count (kindFunc only)
}

// parseResult holds the module-relative path and declarations parsed from one source file,
// plus a flag recording whether the scanner skipped a construct it does not model (surfaced
// as declared partiality).
type parseResult struct {
	module  string // source path relative to the build root, '/'-joined, no extension
	decls   []decl
	skipped bool
}

// parseFile parses one C# source file (already read into src, with module set to its
// build-root-relative path) and returns the declared types and methods. It works on a
// comment/string-stripped copy so no literal can be mistaken for code.
func parseFile(module, src string) parseResult {
	clean := stripCSharp(src)
	res := parseResult{module: module}
	res.decls = parseDecls([]rune(clean), &res.skipped)
	return res
}

// stripCSharp removes comments, string/char literals (regular, verbatim @"...",
// interpolated $"...", verbatim-interpolated $@"..."/@$"...") and preprocessor directives,
// replacing each with equivalent whitespace so byte offsets and newlines are preserved but
// no literal content can be mistaken for code. A string literal collapses to a single '_'
// token (a valid identifier char) so a literal-only argument still counts toward call-site
// arity. Interpolated strings are flattened (including {..} interpolations) to a single '_'
// — interpolated calls are not modeled (a declared-partial, conservative limitation: it
// never fabricates an edge and never mis-balances braces).
func stripCSharp(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	r := []rune(src)
	n := len(r)
	atLineStart := true // tracks whether only whitespace precedes on the current line
	for i := 0; i < n; {
		c := r[i]
		switch {
		case c == '/' && i+1 < n && r[i+1] == '/':
			for i < n && r[i] != '\n' {
				b.WriteByte(' ')
				i++
			}
		case c == '/' && i+1 < n && r[i+1] == '*':
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
		case c == '#' && atLineStart:
			// preprocessor directive (#region, #if, #nullable, ...) → blank to EOL
			for i < n && r[i] != '\n' {
				b.WriteByte(' ')
				i++
			}
		case c == '@' && i+1 < n && r[i+1] == '"',
			c == '$' && i+1 < n && r[i+1] == '@' && i+2 < n && r[i+2] == '"',
			c == '@' && i+1 < n && r[i+1] == '$' && i+2 < n && r[i+2] == '"':
			i = stripVerbatimString(&b, r, i)
			atLineStart = false
		case c == '$' && i+1 < n && r[i+1] == '"':
			i = stripInterpolatedString(&b, r, i)
			atLineStart = false
		case c == '"':
			i = stripRegularString(&b, r, i)
			atLineStart = false
		case c == '\'':
			i = stripCharLiteral(&b, r, i)
			atLineStart = false
		default:
			if c == '\n' {
				atLineStart = true
			} else if !unicode.IsSpace(c) {
				atLineStart = false
			}
			b.WriteRune(c)
			i++
		}
	}
	return b.String()
}

// stripRegularString blanks a regular "..." string (with backslash escapes) to a single
// '_' token and returns the index just past the closing quote.
func stripRegularString(b *strings.Builder, r []rune, i int) int {
	n := len(r)
	b.WriteByte('_')
	i++ // opening quote
	for i < n && r[i] != '"' {
		if r[i] == '\\' && i+1 < n {
			b.WriteString("  ")
			i += 2
			continue
		}
		if r[i] == '\n' {
			return i // unterminated
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

// stripCharLiteral blanks a '...' char literal (with backslash escapes) to a single '_'
// token and returns the index just past the closing quote.
func stripCharLiteral(b *strings.Builder, r []rune, i int) int {
	n := len(r)
	b.WriteByte('_')
	i++ // opening quote
	for i < n && r[i] != '\'' {
		if r[i] == '\\' && i+1 < n {
			b.WriteString("  ")
			i += 2
			continue
		}
		if r[i] == '\n' {
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

// stripVerbatimString blanks a verbatim @"..." (or interpolated-verbatim $@"..." / @$"...")
// string. In a verbatim string a doubled quote "" is a literal quote (not a terminator) and
// backslashes are not escapes. Interpolations {..} (when the $ form) are flattened along
// with the rest. Returns the index just past the closing quote.
func stripVerbatimString(b *strings.Builder, r []rune, i int) int {
	n := len(r)
	b.WriteByte('_')
	// consume the @ / $@ / @$ prefix then the opening quote
	for i < n && r[i] != '"' {
		b.WriteByte(' ')
		i++
	}
	i++ // opening quote
	for i < n {
		if r[i] == '"' {
			if i+1 < n && r[i+1] == '"' { // doubled quote → literal quote, stay inside
				b.WriteString("  ")
				i += 2
				continue
			}
			b.WriteByte(' ')
			i++
			return i
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

// stripInterpolatedString blanks a regular interpolated $"..." string to a single '_'
// token, consuming balanced {..} interpolations (and {{ }} literal-brace escapes) so no
// interpolation brace can perturb the declaration scanner's brace balance. Returns the
// index just past the closing quote.
func stripInterpolatedString(b *strings.Builder, r []rune, i int) int {
	n := len(r)
	b.WriteByte('_')
	b.WriteByte(' ') // the '$'
	i++              // '$'
	i++              // opening quote
	depth := 0
	for i < n {
		c := r[i]
		if depth == 0 {
			if c == '\\' && i+1 < n {
				b.WriteString("  ")
				i += 2
				continue
			}
			if c == '{' && i+1 < n && r[i+1] == '{' {
				b.WriteString("  ")
				i += 2
				continue
			}
			if c == '}' && i+1 < n && r[i+1] == '}' {
				b.WriteString("  ")
				i += 2
				continue
			}
			if c == '{' {
				depth++
				b.WriteByte(' ')
				i++
				continue
			}
			if c == '"' {
				b.WriteByte(' ')
				i++
				return i
			}
			if c == '\n' {
				b.WriteByte('\n')
			} else {
				b.WriteByte(' ')
			}
			i++
			continue
		}
		// inside an interpolation hole — flatten until it closes
		if c == '{' {
			depth++
		} else if c == '}' {
			depth--
		}
		if c == '\n' {
			b.WriteByte('\n')
		} else {
			b.WriteByte(' ')
		}
		i++
	}
	return i
}

// typeKeywords introduce a C# type declaration.
var typeKeywords = map[string]bool{
	"class": true, "struct": true, "interface": true, "record": true, "enum": true,
}

// frame is one entry on the brace-block stack. A frame is either a namespace (nsName set),
// a type (typeName set), or a plain block (both empty — a method body, accessor block, or
// control block whose contents are not declarations at this level).
type frame struct {
	nsName   string
	typeName string
}

// parseDecls scans the cleaned source for namespace, type, and method declarations,
// tracking scope with a brace stack. It records:
//   - namespaces: block "namespace A.B { }" and file-scoped "namespace A.B;"
//   - types: class / struct / interface / record / enum, arbitrarily nested
//   - methods/constructors at type-body depth (identified by a "Name(params)" run followed
//     by a '{' block body, a '=>' expression body, or a ';' abstract/interface signature)
//
// A method's namespace and enclosing-type chain are the namespace/type frames on the stack.
func parseDecls(r []rune, skipped *bool) []decl {
	n := len(r)
	var stack []frame
	var decls []decl
	fileNamespace := "" // set by a file-scoped "namespace A.B;"

	currentNamespace := func() string {
		parts := make([]string, 0, len(stack)+1)
		if fileNamespace != "" {
			parts = append(parts, fileNamespace)
		}
		for _, f := range stack {
			if f.nsName != "" {
				parts = append(parts, f.nsName)
			}
		}
		return strings.Join(parts, ".")
	}
	typeChain := func() []string {
		var out []string
		for _, f := range stack {
			if f.typeName != "" {
				out = append(out, f.typeName)
			}
		}
		return out
	}
	inTypeBody := func() bool {
		return len(stack) > 0 && stack[len(stack)-1].typeName != ""
	}

	i := 0
	for i < n {
		c := r[i]
		switch {
		case c == '{':
			stack = append(stack, frame{})
			i++
		case c == '}':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			i++
		case isIdentStart(c):
			word, next := readWord(r, i)
			switch {
			case word == "namespace":
				name, openIdx, fileScoped, ok := parseNamespaceHeader(r, next)
				if !ok {
					i = next
					continue
				}
				if fileScoped {
					if fileNamespace == "" {
						fileNamespace = name
					} else {
						fileNamespace += "." + name
					}
					i = openIdx + 1 // past the ';'
					continue
				}
				stack = append(stack, frame{nsName: name})
				i = openIdx + 1 // past the '{'
				continue

			case typeKeywords[word]:
				name, openIdx, hasBody, ok := parseTypeHeader(r, next)
				if !ok {
					i = next
					continue
				}
				decls = append(decls, decl{
					kind:      kindType,
					name:      name,
					namespace: currentNamespace(),
					enclosing: typeChain(),
				})
				if hasBody {
					stack = append(stack, frame{typeName: name})
					i = openIdx + 1 // past the '{'
				} else {
					i = openIdx + 1 // positional record with no body: past the ';'
				}
				continue

			default:
				if inTypeBody() {
					if name, arity, contIdx, hasBlock, ok := methodDeclAt(r, i); ok {
						decls = append(decls, decl{
							kind:      kindFunc,
							name:      name,
							namespace: currentNamespace(),
							enclosing: typeChain(),
							arity:     arity,
						})
						if hasBlock {
							stack = append(stack, frame{})
							i = contIdx + 1 // past the body-opening '{'
						} else {
							i = contIdx // at/after the terminating ';'
						}
						continue
					}
				}
				i = next
			}
		default:
			i++
		}
	}
	return decls
}

// parseNamespaceHeader reads a namespace name (dotted, possibly "global::") from just after
// the "namespace" keyword and scans to its opening '{' (block form) or ';' (file-scoped
// form). It returns the dotted name, the index of the '{' or ';', whether it was
// file-scoped, and ok.
func parseNamespaceHeader(r []rune, pos int) (name string, openIdx int, fileScoped, ok bool) {
	n := len(r)
	pos = skipSpace(r, pos)
	var sb strings.Builder
	for pos < n {
		c := r[pos]
		switch {
		case isIdentPart(c):
			w, np := readWord(r, pos)
			sb.WriteString(w)
			pos = np
		case c == '.':
			sb.WriteByte('.')
			pos++
		case c == ':': // "global::" qualifier — skip the "::"
			pos++
		case c == '{':
			if sb.Len() == 0 {
				return "", 0, false, false
			}
			return sb.String(), pos, false, true
		case c == ';':
			if sb.Len() == 0 {
				return "", 0, false, false
			}
			return sb.String(), pos, true, true
		case unicode.IsSpace(c):
			pos++
		default:
			return "", 0, false, false
		}
	}
	return "", 0, false, false
}

// parseTypeHeader reads a type name from just after a type keyword and scans to the body's
// opening '{' (skipping generics "<...>", a primary-constructor "(...)", a base list
// ": Base, IFoo", and generic constraints "where ..."). A positional record ending in ';'
// with no body returns hasBody=false with openIdx at the ';'. ok is false when no type name
// follows or no body/';' terminator is found.
func parseTypeHeader(r []rune, pos int) (name string, openIdx int, hasBody, ok bool) {
	n := len(r)
	pos = skipSpace(r, pos)
	// "record class"/"record struct" — skip the optional class/struct after record.
	if w, np := peekWord(r, pos); w == "class" || w == "struct" {
		pos = skipSpace(r, np)
	}
	if pos >= n || !isIdentStart(r[pos]) {
		return "", 0, false, false
	}
	name, pos = readWord(r, pos)
	for pos < n {
		switch r[pos] {
		case '{':
			return name, pos, true, true
		case ';':
			return name, pos, false, true
		case '<', '(', '[':
			pos = skipGroup(r, pos)
		default:
			pos++
		}
	}
	return "", 0, false, false
}

// methodDeclAt attempts to parse a method or constructor at type-body depth starting at the
// first token of the member (a modifier, return type, or the name itself). It scans the
// signature to the parameter-list '(': if a '{', ';', or '=' (a field/property/expression-
// bodied-property initializer) is reached BEFORE a top-level '(', it is NOT a method. The
// method name is the identifier immediately before '(' (skipping a generic "<...>"). After
// the matching ')' it skips generic constraints and finds the body: '{' (block, hasBlock
// true, contIdx at the '{'), '=>' (expression body, hasBlock false, contIdx past the ';'),
// or ';' (abstract/interface/partial, hasBlock false, contIdx past the ';').
func methodDeclAt(r []rune, start int) (name string, arity, contIdx int, hasBlock, ok bool) {
	n := len(r)
	pos := start
	lastIdent := ""
	lastIdentEnd := -1
	for pos < n {
		c := r[pos]
		switch {
		case c == '<' || c == '[':
			pos = skipGroup(r, pos) // generic arg list or attribute/array — skip
		case c == '(':
			// A method/ctor iff we have an identifier immediately preceding this '('.
			if lastIdent == "" || !typeNameGuard(lastIdent) {
				return "", 0, 0, false, false
			}
			arity, after := parseParamArity(r, pos)
			return finishMethodSignature(r, lastIdent, arity, after)
		case c == '{' || c == ';' || c == '=':
			return "", 0, 0, false, false // field / property / auto-accessor — not a method
		case c == '}':
			return "", 0, 0, false, false
		case isIdentStart(c):
			w, np := readWord(r, pos)
			if typeKeywords[w] || w == "namespace" {
				return "", 0, 0, false, false // a nested type/namespace — let the caller handle it
			}
			lastIdent = w
			lastIdentEnd = np
			pos = np
		default:
			pos++
		}
	}
	_ = lastIdentEnd
	return "", 0, 0, false, false
}

// typeNameGuard rejects a few identifiers that, when immediately before '(', denote a
// control-flow statement rather than a method name (defensive — control statements only
// appear inside method bodies, i.e. below type-body depth, but this guards a mis-push).
func typeNameGuard(name string) bool {
	switch name {
	case "if", "for", "foreach", "while", "switch", "catch", "using", "lock", "fixed", "return":
		return false
	}
	return true
}

// finishMethodSignature, given the parameter list already consumed (after = index just past
// the matching ')'), scans past generic "where" constraints to the member body and reports
// how to continue. '{' → block body; '=>' → expression body (skip to ';'); ';' → no body.
func finishMethodSignature(r []rune, name string, arity, after int) (string, int, int, bool, bool) {
	n := len(r)
	pos := skipSpace(r, after)
	for pos < n {
		switch {
		case r[pos] == '{':
			return name, arity, pos, true, true
		case r[pos] == ';':
			return name, arity, pos + 1, false, true
		case r[pos] == '=' && pos+1 < n && r[pos+1] == '>':
			end := skipToStatementEnd(r, pos+2)
			return name, arity, end, false, true
		case r[pos] == '<' || r[pos] == '(' || r[pos] == '[':
			pos = skipGroup(r, pos) // a "where T : IFoo<X>" constraint's group
		default:
			pos++
		}
	}
	return "", 0, 0, false, false
}

// skipToStatementEnd returns the index just past the next ';' at or after pos (skipping
// balanced groups), or len(r). Used to consume an expression-bodied member's body.
func skipToStatementEnd(r []rune, pos int) int {
	n := len(r)
	for pos < n {
		switch r[pos] {
		case ';':
			return pos + 1
		case '(', '[', '{':
			pos = skipGroup(r, pos)
		default:
			pos++
		}
	}
	return n
}

// --- low-level scanners over the cleaned rune slice ---

func isIdentStart(c rune) bool {
	return c == '_' || c == '@' || unicode.IsLetter(c)
}

func isIdentPart(c rune) bool {
	return c == '_' || unicode.IsLetter(c) || unicode.IsDigit(c)
}

// readWord reads a C# identifier/keyword starting at i and returns it with the index just
// past it. A leading '@' verbatim-identifier marker is dropped from the returned word.
func readWord(r []rune, i int) (string, int) {
	start := i
	if i < len(r) && r[i] == '@' {
		start = i + 1
		i++
	}
	for i < len(r) && isIdentPart(r[i]) {
		i++
	}
	return string(r[start:i]), i
}

// peekWord reads the identifier at the (already space-skipped) position pos without
// committing; it returns "" when pos is not at an identifier.
func peekWord(r []rune, pos int) (string, int) {
	if pos >= len(r) || !isIdentStart(r[pos]) {
		return "", pos
	}
	return readWord(r, pos)
}

func skipSpace(r []rune, i int) int {
	for i < len(r) && unicode.IsSpace(r[i]) {
		i++
	}
	return i
}

// parseParamArity counts the comma-separated parameters of a parameter list, given the
// position of the opening '('. An empty "()" is arity 0. It returns the arity and the index
// just past the matching ')'.
func parseParamArity(r []rune, open int) (int, int) {
	n := len(r)
	depth := 0
	count := 0
	seenToken := false
	pos := open
	for pos < n {
		switch r[pos] {
		case '(', '[', '{', '<':
			depth++
		case ')', ']', '}', '>':
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
				seenToken = false
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

// skipGroup skips a balanced (), <>, [], or {} group starting at the opening rune at i and
// returns the index just past the matching close. Mismatched/unterminated groups advance to
// EOF.
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
	case '{':
		close = '}'
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
