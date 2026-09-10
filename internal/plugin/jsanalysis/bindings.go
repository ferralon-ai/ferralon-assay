package jsanalysis

import "strings"

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
	instances     map[string]string  // local var → class name, from `const x = new Class()`
	reExports     map[string]binding // exported name → re-export binding (for `export { x } from 'spec'`)
	reExportStars []string           // specifiers from `export * from 'spec'`
	ambiguous     map[string]bool    // local names bound more than once → resolve as unresolved
	dynImport     bool               // saw a runtime-computed ESM target `import(expr)`
	computedReq   bool               // saw a runtime-computed CJS target `require(var)`
}

func newModuleBindings() moduleBindings {
	return moduleBindings{
		imports:   bindingTable{},
		instances: map[string]string{},
		reExports: map[string]binding{},
		ambiguous: map[string]bool{},
	}
}

// extractModuleBindings scans one module for its import/require/export-from bindings,
// class instantiations, and runtime-computed specifiers. It walks the COMMENT/STRING-
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
	i := 0
	for i < n {
		if !isIdentStart(clean[i]) {
			i++
			continue
		}
		word, next := readWord(clean, i)
		switch word {
		case "import":
			i = parseImportForm(clean, src, next, &mb, add)
		case "export":
			i = parseExportForm(clean, src, next, &mb)
		case "require":
			// A require() NOT anchored to a const/let/var binding (e.g. `return require(f)`):
			// flag a computed specifier when the sole argument is non-literal.
			p := skipSpace(clean, next)
			if p < n && clean[p] == '(' {
				a := skipSpace(clean, p+1)
				if a < n && clean[a] != '_' && clean[a] != ')' {
					mb.computedReq = true
				}
			}
			i = next
		case "const", "let", "var":
			i = parseDeclForm(clean, src, next, &mb, add)
		default:
			i = next
		}
	}
	return mb
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
		mb.dynImport = true
		return pos
	}
	if clean[p] == '.' { // import.meta
		return pos
	}
	if clean[p] == '_' { // side-effect import 'x'
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
				for _, pr := range pairs {
					mb.reExports[pr.local] = binding{Local: pr.local, Specifier: specifier, Kind: bindReExport, Imported: pr.imported}
				}
				return p + 1
			}
		}
		return p
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
				if a < n && clean[a] == '_' {
					specifier := specifierAt(src, a)
					for _, pr := range pairs {
						add(binding{Local: pr.local, Specifier: specifier, Kind: bindRequire, Imported: pr.imported})
					}
					return a + 1
				}
				if a < n && clean[a] != ')' {
					mb.computedReq = true
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
			if a < n && clean[a] == '_' {
				add(binding{Local: name, Specifier: specifierAt(src, a), Kind: bindRequire, Imported: "*"})
				return a + 1
			}
			if a < n && clean[a] != ')' {
				mb.computedReq = true
			}
		}
	case "import":
		p = skipSpace(clean, wq)
		if p < n && clean[p] == '(' {
			mb.dynImport = true
		}
	case "new":
		p = skipSpace(clean, wq)
		if cw, _ := peekWord(clean, p); cw != "" {
			mb.instances[name] = cw
		}
	}
	return pos
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

// specifierAt reads a string/template specifier from the RAW source at pos, where the
// opening quote/backtick lives (clean marks that position with '_'). Escapes are
// unescaped by one level; interpolations are not expected in a specifier.
func specifierAt(src []rune, pos int) string {
	n := len(src)
	if pos >= n {
		return ""
	}
	quote := src[pos]
	if quote != '\'' && quote != '"' && quote != '`' {
		return ""
	}
	var b strings.Builder
	for i := pos + 1; i < n && src[i] != quote; i++ {
		if src[i] == '\\' && i+1 < n {
			b.WriteRune(src[i+1])
			i++
			continue
		}
		b.WriteRune(src[i])
	}
	return b.String()
}
