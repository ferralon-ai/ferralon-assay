package jsanalysis

import (
	"strings"
	"unicode"
	"unicode/utf16"
)

// bindingKind classifies how a local name was bound to a module specifier.
type bindingKind int

const (
	bindImport   bindingKind = iota + 1 // ESM:  import { x } from 'spec' / import d from 'spec' / import * as ns from 'spec'
	bindRequire                         // CJS:  const x = require('spec')  / const { x } = require('spec')
	bindReExport                        // ESM:  export { x } from 'spec'   / export * from 'spec'
)

// binding is what one local name in a module binds to. A binding names its target
// module by a SPECIFIER LITERAL only — the resolver (resolve.go) turns the specifier
// into a module/instance. The parser performs NO resolution; it records exactly the
// syntax it saw (§3.8 evidence-only).
type binding struct {
	Local     string // local name introduced in this module ("fetch", "d", "ns")
	Specifier string // the module specifier LITERAL as written ("./util", "lodash", "#internal", "@scope/pkg/sub")
	Kind      bindingKind
	Imported  string // name taken from the target module: the member ("fetch"); "default" for a
	// default import; "*" for a namespace import / whole-module require.
}

// bindingTable is per-module: local name → binding. A local name binds to exactly ONE
// target by construction; a redeclaration/shadow of the same local name is recorded as
// ambiguous (the resolver returns resolveUnresolved for it).
type bindingTable map[string]binding

// moduleBindings is the whole per-module binding view the parser extracts and the
// resolver consumes: the import/require bindings usable in this module, local class
// instantiations (for receiver-based method resolution), re-exports this module
// forwards to importers, ambiguous local names, and the runtime-computed-specifier
// flags that drive the C5 partiality codes.
type moduleBindings struct {
	imports       bindingTable       // local name → import/require binding (names usable IN this module)
	instances     map[string]string  // local var → class name, from `const x = new Class()` ("ns.Class" for `new ns.Class()`)
	derived       map[string]string  // local var → callee chain, from `const x = callee.chain(...)` (whole initializer)
	reExports     map[string]binding // exported name → re-export binding (for `export { x } from 'spec'`)
	reExportStars []string           // specifiers from `export * from 'spec'`
	ambiguous     map[string]bool    // local names bound more than once → resolve as unresolved
	specifiers    []loadSpec         // every literal specifier the module loads (import, export-from, require, import()), at any scope
	prefixLoads   []prefixLoad       // require/import() whose specifier is a literal prefix plus a runtime value
	dynImport     bool               // saw a runtime-computed ESM target `import(expr)` with no static prefix
	computedReq   bool               // saw a runtime-computed CJS target `require(var)` with no static prefix
	nativeLoad    bool               // saw dlopen, getBuiltinModule or _linkedBinding, which load code this lane never reads
	evaluated     bool               // saw eval or the Function constructor, which run code built at run time
}

// loadSpec is one literal specifier a module loads. viaRequire marks a require() load,
// which Node resolves under the "require" condition; any other form may resolve under
// either, because a transpiler can emit ESM syntax as require().
type loadSpec struct {
	spec       string
	viaRequire bool
	dynImport  bool // a literal import()
}

// prefixLoad is a require(...) or import(...) whose specifier starts with a literal and
// continues with a runtime value: './locales/' + lang, or a template literal such as
// `./plugins/${name}`.
type prefixLoad struct {
	prefix string   // the literal text before the runtime part
	dyn    bool     // import(...) rather than require(...)
	pos    int      // rune index of the require/import keyword
	caller frameRef // the frame the load runs in (set by parseFile from the call scan)
}

func newModuleBindings() moduleBindings {
	return moduleBindings{
		imports:   bindingTable{},
		instances: map[string]string{},
		derived:   map[string]string{},
		reExports: map[string]binding{},
		ambiguous: map[string]bool{},
	}
}

// extractModuleBindings scans one module for its import/require/export-from bindings,
// class instantiations, the literal specifiers it loads, and runtime-computed specifiers. It walks the COMMENT/STRING-
// STRIPPED runes (clean) for structure — so no keyword inside a comment or string
// literal can be mistaken for a binding — and reads the actual specifier text from the
// position-identical RAW source (src) wherever clean marks a former string literal with
// '_'. stripJS is length-preserving rune-for-rune, so clean[i] and src[i] name the same
// source position. §3.8 evidence-only: a non-literal specifier yields NO binding.
func extractModuleBindings(clean, src []rune) moduleBindings {
	mb := newModuleBindings()
	n := len(clean)
	add := func(b binding) {
		if b.Local == "" {
			return
		}
		if _, exists := mb.imports[b.Local]; exists {
			mb.ambiguous[b.Local] = true
			return
		}
		mb.imports[b.Local] = b
	}
	frames := newThisFrames(clean)
	globals := newGlobalScope(clean, frames)
	ls := newLoaderScope(clean, globals)
	reqNames, crNames := ls.req, ls.cr
	if globals.keyed || computedIndexPair(clean, src) || identifierEscape(clean) {
		mb.evaluated = true
	}
	mb.patternKeys(clean, src, globals)
	i := 0
	for i < n {
		if !isIdentStart(clean[i]) {
			i++
			continue
		}
		word, next := readWord(clean, i)
		switch {
		case word == "import" && !memberName(clean, i):
			i = parseImportForm(clean, src, next, &mb, add)
		case word == "export" && !memberName(clean, i):
			i = parseExportForm(clean, src, next, &mb)
		case word == "const", word == "let", word == "var":
			i = parseDeclForm(clean, src, next, &mb, add)
		case reqNames[word]:
			// A loader use NOT consumed as a const/let/var binding: `return require(f)`,
			// `const r = require`, a createRequire result called inline.
			mb.requireUse(clean, src, i, next, ls)
			i = next
		case crNames[word]:
			mb.createRequireUse(clean, src, i, next)
			i = next
		case word == "_load", word == "dlopen", word == "getBuiltinModule", word == "_linkedBinding", word == "eval":
			mb.memberUse(clean, i, word)
			i = next
		case word == "arguments":
			mb.argumentsUse(clean, i, next, frames)
			i = next
		case word == "constructor":
			mb.constructorUse(clean, src, i)
			i = next
		case word == "Function":
			mb.functionUse(clean, src, i, next)
			i = next
		case ls.module.names[word]:
			mb.objectUse(clean, src, i, next, &ls.module, globals)
			i = next
		case ls.process.names[word]:
			mb.objectUse(clean, src, i, next, &ls.process, globals)
			i = next
		case globals.isGlobal(word, i):
			mb.globalUse(clean, i, next, false, globals)
			i = next
		case word == "this" && frames.globalAt(i):
			mb.globalUse(clean, i, next, !globals.thisGlobal(i), globals)
			i = next
		case word == "_" && src[i] != '_': // a string literal; see keyedUse
			mb.keyedUse(clean, src, i)
			i = next
		case globals.callsReturnThis(clean, word, i, next):
			// `G()` for `function G() { return this; }` is the global, used where it is called
			mb.globalUse(clean, i, closeParen(clean, skipSpace(clean, next))+1, false, globals)
			i = next
		default:
			i = next
		}
	}
	return mb
}

// memberName reports whether the word at i is read as a property (`x.import`, `x?.export`),
// not a keyword, so what follows it is still scanned. A spread (`...import(x)`) is not one,
// nor a dot that may end a number (`1.` then a line break, where ASI makes import a keyword).
func memberName(clean []rune, i int) bool {
	b := skipSpaceBack(clean, i-1)
	if b < 0 || clean[b] != '.' || b > 0 && clean[b-1] == '.' {
		return false
	}
	t := b
	for t > 0 && isIdentPart(clean[t-1]) {
		t--
	}
	return t == b || clean[t] < '0' || clean[t] > '9'
}

// importPair is one (local, imported) name pair collected while parsing an import clause
// before its specifier is known.
type importPair struct {
	local    string
	imported string
}

// parseImportForm parses an ESM import STARTING just after the "import" keyword and
// returns the index to resume at. It handles dynamic import() (records dynImport, no
// binding), import.meta (ignored), side-effect `import 'x'` (no binding), and the
// default / `* as ns` / `{ named }` clauses followed by `from '<spec>'`. A `type`-only
// import (or inline `type` specifier) yields no runtime binding.
func parseImportForm(clean, src []rune, pos int, mb *moduleBindings, add func(binding)) int {
	n := len(clean)
	p := skipSpace(clean, pos)
	if p >= n {
		return pos
	}
	if clean[p] == '(' { // dynamic import(expr)
		mb.loaderCall(clean, src, pos-len("import"), p, true)
		return pos
	}
	if clean[p] == '.' { // import.meta
		return pos
	}
	if clean[p] == '_' { // side-effect import 'x'
		mb.specifiers = append(mb.specifiers, loadSpec{spec: specifierAt(src, p)})
		return p + 1
	}
	typeOnly := false
	if w, nx := peekWord(clean, p); w == "type" {
		// `import type ...` — the whole statement is type-only unless it's `import type from ...`
		// (a value named "type"); the latter is vanishingly rare, so treat as type-only.
		typeOnly = true
		p = skipSpace(clean, nx)
	}

	var pairs []importPair
	for p < n {
		ch := clean[p]
		switch {
		case ch == '{':
			var np int
			pairs, np = collectBraceList(clean, p, pairs, false)
			p = skipSpace(clean, np)
		case ch == '*':
			p = skipSpace(clean, p+1)
			if w, nx := peekWord(clean, p); w == "as" {
				p = skipSpace(clean, nx)
				lw, lq := readWord(clean, p)
				pairs = append(pairs, importPair{local: lw, imported: "*"})
				p = skipSpace(clean, lq)
			}
		case ch == ',':
			p = skipSpace(clean, p+1)
		case isIdentStart(ch):
			w, nx := readWord(clean, p)
			if w == "from" {
				p = skipSpace(clean, nx)
				goto spec
			}
			pairs = append(pairs, importPair{local: w, imported: "default"})
			p = skipSpace(clean, nx)
		default:
			goto spec
		}
	}
spec:
	if p < n && clean[p] == '_' {
		specifier := specifierAt(src, p)
		if !typeOnly {
			mb.specifiers = append(mb.specifiers, loadSpec{spec: specifier})
			for _, pr := range pairs {
				add(binding{Local: pr.local, Specifier: specifier, Kind: bindImport, Imported: pr.imported})
			}
		}
		return p + 1
	}
	return p
}

// parseExportForm parses `export * from '<spec>'` and `export { a, b as c } from
// '<spec>'` re-exports STARTING just after the "export" keyword. A local `export { ... }`
// with no `from` (a re-export of local names) is not a module binding and is ignored.
func parseExportForm(clean, src []rune, pos int, mb *moduleBindings) int {
	n := len(clean)
	p := skipSpace(clean, pos)
	if p >= n {
		return pos
	}
	if clean[p] == '*' {
		p = skipSpace(clean, p+1)
		if w, nx := peekWord(clean, p); w == "as" { // export * as ns from
			p = skipSpace(clean, nx)
			_, lq := readWord(clean, p)
			p = skipSpace(clean, lq)
		}
		if w, nx := peekWord(clean, p); w == "from" {
			p = skipSpace(clean, nx)
			if p < n && clean[p] == '_' {
				mb.reExportStars = append(mb.reExportStars, specifierAt(src, p))
				mb.specifiers = append(mb.specifiers, loadSpec{spec: specifierAt(src, p)})
				return p + 1
			}
		}
		return p
	}
	if clean[p] == '{' {
		var pairs []importPair
		var np int
		// For re-exports the "imported" name is the source member and the "local" is the
		// EXPORTED name (`export { a as c }` re-exports source a under the name c).
		pairs, np = collectBraceList(clean, p, pairs, false)
		p = skipSpace(clean, np)
		if w, nx := peekWord(clean, p); w == "from" {
			p = skipSpace(clean, nx)
			if p < n && clean[p] == '_' {
				specifier := specifierAt(src, p)
				mb.specifiers = append(mb.specifiers, loadSpec{spec: specifier})
				for _, pr := range pairs {
					mb.reExports[pr.local] = binding{Local: pr.local, Specifier: specifier, Kind: bindReExport, Imported: pr.imported}
				}
				return p + 1
			}
		}
		// A local `export { a as b }` hands its local names on to importers, so the names are
		// left for the caller to judge as uses (`export { require as r }`).
		return pos
	}
	return pos
}

// parseDeclForm parses a const/let/var declarator STARTING just after the keyword,
// recognizing CJS require bindings (`const x = require('spec')`, `const { a, b: c } =
// require('spec')`), class instantiations (`const x = new Class()`), and runtime-
// computed specifiers (`= require(var)` / `= import(expr)`).
func parseDeclForm(clean, src []rune, pos int, mb *moduleBindings, add func(binding)) int {
	n := len(clean)
	p := skipSpace(clean, pos)
	if p >= n {
		return pos
	}
	if clean[p] == '{' {
		var pairs []importPair
		var np int
		pairs, np = collectBraceList(clean, p, pairs, true)
		p = skipSpace(clean, np)
		if p >= n || clean[p] != '=' {
			return pos
		}
		p = skipSpace(clean, p+1)
		if w, nx := peekWord(clean, p); w == "require" {
			p = skipSpace(clean, nx)
			if p < n && clean[p] == '(' {
				a := skipSpace(clean, p+1)
				if specifier, ok := literalLoadArg(clean, src, a); ok {
					mb.specifiers = append(mb.specifiers, loadSpec{spec: specifier, viaRequire: true})
					for _, pr := range pairs {
						add(binding{Local: pr.local, Specifier: specifier, Kind: bindRequire, Imported: pr.imported})
					}
					return a + 1
				}
			}
		}
		return pos
	}
	if !isIdentStart(clean[p]) {
		return pos
	}
	name, nx := readWord(clean, p)
	p = skipSpace(clean, nx)
	if p < n && clean[p] == ':' { // TS type annotation
		for p < n && clean[p] != '=' && clean[p] != ';' && clean[p] != '\n' {
			p++
		}
	}
	if p >= n || clean[p] != '=' {
		return pos
	}
	p = skipSpace(clean, p+1)
	if w, nx := peekWord(clean, p); w == "await" {
		p = skipSpace(clean, nx)
	}
	w, wq := peekWord(clean, p)
	switch w {
	case "require":
		p = skipSpace(clean, wq)
		if p < n && clean[p] == '(' {
			a := skipSpace(clean, p+1)
			if specifier, ok := literalLoadArg(clean, src, a); ok {
				mb.specifiers = append(mb.specifiers, loadSpec{spec: specifier, viaRequire: true})
				add(binding{Local: name, Specifier: specifier, Kind: bindRequire, Imported: "*"})
				return a + 1
			}
		}
	case "new":
		p = skipSpace(clean, wq)
		if chain, _ := readChain(clean, p); chain != "" {
			mb.instances[name] = chain
		}
	case "":
	default:
		if chain, q := readChain(clean, p); q < n && clean[q] == '(' && wholeInitializer(clean, skipGroup(clean, q)) {
			mb.derived[name] = chain
		}
	}
	return pos
}

// readChain reads a dotted identifier chain ("express.Router") starting at p and returns it
// with the index just past it. It returns "" when p does not start an identifier.
func readChain(clean []rune, p int) (string, int) {
	n := len(clean)
	var b strings.Builder
	for p < n && isIdentStart(clean[p]) {
		w, nx := readWord(clean, p)
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.WriteString(w)
		p = nx
		if p+1 < n && clean[p] == '.' && isIdentStart(clean[p+1]) {
			p++
			continue
		}
		break
	}
	return b.String(), p
}

// wholeInitializer reports whether the declarator's initializer ends at p: nothing but
// blanks before a statement or declarator boundary, so `x = f()` binds the call's result
// and `x = f().g` does not.
func wholeInitializer(clean []rune, p int) bool {
	n := len(clean)
	for p < n && (clean[p] == ' ' || clean[p] == '\t' || clean[p] == '\r') {
		p++
	}
	return p >= n || clean[p] == ';' || clean[p] == '\n' || clean[p] == ',' || clean[p] == '}'
}

// collectBraceList parses a `{ a, b as c }` (import) or `{ a, b: c }` (destructure)
// list STARTING at the opening '{' and returns the appended pairs and the index just
// past '}'. destructure selects the `b: c` rename syntax; otherwise the `b as c`
// syntax. An inline `type X` entry (TS) is skipped.
func collectBraceList(clean []rune, open int, pairs []importPair, destructure bool) ([]importPair, int) {
	n := len(clean)
	q := open + 1
	for q < n && clean[q] != '}' {
		q = skipSpace(clean, q)
		if q < n && clean[q] == '}' {
			break
		}
		w, nq := readWord(clean, q)
		if w == "" {
			q++
			continue
		}
		if !destructure && w == "type" {
			q = skipSpace(clean, nq)
			_, nq2 := readWord(clean, q)
			q = skipSpace(clean, nq2)
			if q < n && clean[q] == ',' {
				q++
			}
			continue
		}
		imported := w
		local := w
		q = skipSpace(clean, nq)
		if destructure {
			if q < n && clean[q] == ':' { // { imported: local }
				q = skipSpace(clean, q+1)
				lw, lq := readWord(clean, q)
				local = lw
				q = lq
			}
		} else {
			if aw, aq := peekWord(clean, q); aw == "as" { // { imported as local }
				q = skipSpace(clean, aq)
				lw, lq := readWord(clean, q)
				local = lw
				q = lq
			}
		}
		pairs = append(pairs, importPair{local: local, imported: imported})
		q = skipSpace(clean, q)
		if q < n && clean[q] == ',' {
			q++
		}
	}
	if q < n {
		q++ // past '}'
	}
	return pairs, q
}

// identifierEscape reports whether the code outside literals and comments holds a \u
// escape, which can only spell part of a name (`g.\u0063onstructor`, `\u0065val`). The
// scan reads names as written, so such a name could be any loader or evaluator under a
// spelling it does not recognise.
func identifierEscape(clean []rune) bool {
	for k := 0; k+1 < len(clean); k++ {
		if clean[k] == '\\' && clean[k+1] == 'u' {
			return true
		}
	}
	return false
}

// specifierAt returns the value of the string or template literal whose opening quote is at
// src[pos] (clean marks that position with '_'), decoded as the engine reads it: single-
// character, \xHH, \uHHHH and \u{H…} escapes (two \u escapes forming a surrogate pair make
// one code point), legacy octal escapes in a string (valid in sloppy code; in strict code
// the literal is a syntax error and nothing runs), and line continuations, which add
// nothing. A template is read up to its first interpolation, which is returned as "${", so
// a caller sees it is computed. A malformed escape, a line break in a string or an
// unterminated literal returns "", as for a position holding no literal, so no misspelling
// reads as another key.
func specifierAt(src []rune, pos int) string {
	n := len(src)
	if pos >= n {
		return ""
	}
	quote := src[pos]
	if quote != '\'' && quote != '"' && quote != '`' {
		return ""
	}
	tmpl := quote == '`'
	var units []uint16
	put := func(r rune) { units = utf16.AppendRune(units, r) }
	for i := pos + 1; i < n; i++ {
		c := src[i]
		switch {
		case c == quote:
			return string(utf16.Decode(units))
		case tmpl && c == '$' && i+1 < n && src[i+1] == '{':
			return string(utf16.Decode(units)) + "${"
		case tmpl && c == '\r':
			if i+1 < n && src[i+1] == '\n' {
				i++
			}
			put('\n')
		case !tmpl && (c == '\n' || c == '\r'):
			return ""
		case c != '\\':
			put(c)
		default:
			k, ok := escapeAt(src, i+1, tmpl, &units)
			if !ok {
				return ""
			}
			i = k - 1
		}
	}
	return ""
}

// escapeAt decodes the escape whose character after the backslash is at src[i], appending
// its UTF-16 code units, and returns the index past it; false when it is malformed.
func escapeAt(src []rune, i int, tmpl bool, units *[]uint16) (int, bool) {
	n := len(src)
	if i >= n {
		return i, false
	}
	put := func(r rune) { *units = utf16.AppendRune(*units, r) }
	switch c := src[i]; c {
	case '\n', '\u2028', '\u2029':
		return i + 1, true
	case '\r':
		if i+1 < n && src[i+1] == '\n' {
			return i + 2, true
		}
		return i + 1, true
	case 'b':
		put('\b')
	case 'f':
		put('\f')
	case 'n':
		put('\n')
	case 'r':
		put('\r')
	case 't':
		put('\t')
	case 'v':
		put('\v')
	case 'x':
		v, ok := hexValue(src, i+1, i+3)
		if !ok {
			return i, false
		}
		put(v)
		return i + 3, true
	case 'u':
		if i+1 < n && src[i+1] == '{' {
			e := i + 2
			for e < n && src[e] != '}' {
				e++
			}
			if e >= n || e == i+2 {
				return i, false
			}
			v, ok := hexValue(src, i+2, e)
			if !ok {
				return i, false
			}
			*units = append(*units, codeUnits(v)...)
			return e + 1, true
		}
		v, ok := hexValue(src, i+1, i+5)
		if !ok {
			return i, false
		}
		*units = append(*units, uint16(v))
		return i + 5, true
	case '0', '1', '2', '3', '4', '5', '6', '7':
		if tmpl {
			if c != '0' || i+1 < n && src[i+1] >= '0' && src[i+1] <= '9' {
				return i, false
			}
			put(0)
			break
		}
		width := 3
		if c > '3' {
			width = 2
		}
		v, e := rune(0), i
		for e < n && e-i < width && src[e] >= '0' && src[e] <= '7' {
			v = v*8 + src[e] - '0'
			e++
		}
		put(v)
		return e, true
	case '8', '9':
		if tmpl {
			return i, false
		}
		put(c)
	default:
		put(c)
	}
	return i + 1, true
}

// hexValue reads src[from:to] as hexadecimal digits: false when the range runs past src,
// holds anything else, or exceeds the last code point.
func hexValue(src []rune, from, to int) (rune, bool) {
	if to > len(src) {
		return 0, false
	}
	v := rune(0)
	for _, c := range src[from:to] {
		var d rune
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, false
		}
		if v = v*16 + d; v > unicode.MaxRune {
			return 0, false
		}
	}
	return v, true
}

// codeUnits returns the UTF-16 code units of a code point escape, which in a JS string may
// be a lone surrogate that pairs with an adjacent escape.
func codeUnits(v rune) []uint16 {
	if v >= 0xD800 && v <= 0xDFFF {
		return []uint16{uint16(v)}
	}
	return utf16.AppendRune(nil, v)
}

// loadArgKind classifies the argument of a require(...) or import(...) call.
type loadArgKind int

const (
	loadArgNone     loadArgKind = iota // no argument: `require()`
	loadArgLiteral                     // a whole literal: `'json5'`, `` `./util` ``
	loadArgPrefix                      // a literal prefix then a runtime value: `'./x/' + n`, `` `./x/${n}` ``
	loadArgComputed                    // anything else: `n`, `cond ? 'a' : 'b'`, `'a'.concat(n)`
)

// classifyLoadArg reads the argument starting at clean index a (the first rune after the
// call's '('). A literal counts as whole only when the argument ends right after it; a
// literal followed by `+`, or a template with an interpolation, is a prefix, and its text
// up to the runtime part is returned.
func classifyLoadArg(clean, src []rune, a int) (loadArgKind, string) {
	n := len(clean)
	if a >= n || clean[a] == ')' {
		return loadArgNone, ""
	}
	if clean[a] != '_' || a >= len(src) || (src[a] != '\'' && src[a] != '"' && src[a] != '`') {
		return loadArgComputed, ""
	}
	text := specifierAt(src, a)
	if interpolated(src, a) {
		if k := strings.Index(text, "${"); k > 0 {
			return loadArgPrefix, text[:k]
		}
		return loadArgComputed, ""
	}
	after := skipSpace(clean, a+1)
	switch {
	case after < n && (clean[after] == ')' || clean[after] == ','):
		return loadArgLiteral, text
	case after < n && clean[after] == '+' && text != "":
		return loadArgPrefix, text
	}
	return loadArgComputed, ""
}

// literalLoadArg returns the specifier when the argument at a is a whole literal.
func literalLoadArg(clean, src []rune, a int) (string, bool) {
	kind, text := classifyLoadArg(clean, src, a)
	return text, kind == loadArgLiteral
}

// recordLoad files one require(...) / import(...) argument under the module's literal
// specifiers, its static-prefix loads, or its runtime-computed flags. at is the rune
// index of the keyword, kept so the call graph can find the frame the load runs in.
func recordLoad(clean, src []rune, at, a int, dyn bool, mb *moduleBindings) {
	kind, text := classifyLoadArg(clean, src, a)
	switch kind {
	case loadArgLiteral:
		mb.specifiers = append(mb.specifiers, loadSpec{spec: text, viaRequire: !dyn, dynImport: dyn})
	case loadArgPrefix:
		mb.prefixLoads = append(mb.prefixLoads, prefixLoad{prefix: text, dyn: dyn, pos: at})
	case loadArgComputed:
		if dyn {
			mb.dynImport = true
		} else {
			mb.computedReq = true
		}
	}
}
