package jsanalysis

// Escape roots.
//
// Package code this lane does not open can call back into first-party code: a function
// passed to it, a method of an object handed to it, a module it loads by name. Such an
// edge is hidden, and a sink behind it would look unreached. The lane closes that gap by
// making every function the hidden edge could land on a call-graph root, so it is searched
// whether or not any visible edge reaches it, and a package's scoped limit need not list
// first-party code among its Targets.
//
// The rule over-approximates escape rather than tracking it. A declared function is a
// root when:
//   - it is a class member (methods, accessors, constructors, and functions nested in a
//     class body): an instance can escape through any value, so all of them are roots;
//   - its name appears anywhere in its module other than as the callee of a direct call or
//     its own declaration: passed, assigned, returned, stored, exported, spread, wrapped
//     with call/apply/bind, constructed with new, used as a JSX tag, or used inside a
//     template-literal substitution (which the call scanner does not see);
//   - it is declared with export, or is a named function expression in expression position;
//   - its module can reach functions by computed name: a .vue component (its template
//     names functions), a module that evaluates code (eval, Function), or a script-mode
//     file whose top-level functions are globals.
//
// A function whose name never escapes its module and that is not a class member can only
// run through a visible direct call in that module. Object-literal methods and anonymous
// functions are not frames of their own: the call scanner attributes their calls to the
// enclosing frame, which is a root or reached whenever the object or closure can exist.

// fileEscapes is the escape scan's result for one file.
type fileEscapes struct {
	names    map[string]bool // declared function names used as values
	all      bool            // every declared function is a root
	topLevel bool            // every function outside a class is a root (script-mode file)
}

// root reports whether a declared function is an escape root.
func (fe fileEscapes) root(d decl) bool {
	switch {
	case d.kind != kindFunc:
		return false
	case fe.all, len(d.enclosing) > 0:
		return true
	case fe.topLevel:
		return true
	}
	return fe.names[d.name]
}

// scanEscapes runs the escape scan over a file's cleaned runes (clean) and its
// position-identical raw source (src).
func scanEscapes(clean, src []rune, decls []decl) fileEscapes {
	declared := map[string]bool{}
	for _, d := range decls {
		if d.kind == kindFunc {
			declared[d.name] = true
		}
	}
	fe := fileEscapes{names: map[string]bool{}}
	moduleSyntax := false
	n := len(clean)
	for i := 0; i < n; {
		c := clean[i]
		if !isIdentStart(c) || (i > 0 && isIdentPart(clean[i-1])) {
			i++
			continue
		}
		word, next := readWord(clean, i)
		switch word {
		case "import", "export", "require", "module", "exports":
			moduleSyntax = true
		case "eval":
			fe.all = true
		case "Function":
			if p := skipSpace(clean, next); p < n && clean[p] == '(' || escPrevWord(clean, i) == "new" {
				fe.all = true
			}
		}
		if declared[word] && escapesAt(clean, i, next) {
			fe.names[word] = true
		}
		i = next
	}
	fe.topLevel = !moduleSyntax
	for name := range templateSubstitutionWords(clean, src) {
		if declared[name] {
			fe.names[name] = true
		}
	}
	return fe
}

// escapesAt classifies one occurrence of a declared function's name spanning [at, next).
func escapesAt(clean []rune, at, next int) bool {
	if p := escPrevSignificant(clean, at); p >= 0 && clean[p] == '.' {
		// A property access x.name names a property, not the binding, unless it is a
		// spread (...name).
		if !(p >= 2 && clean[p-1] == '.' && clean[p-2] == '.') {
			return false
		}
		return true
	}
	switch prev := escPrevWord(clean, at); prev {
	case "function":
		return funcKeywordEscapes(clean, escWordStart(clean, at))
	case "const", "let", "var":
		return escPrevWord(clean, escWordStart(clean, at)) == "export"
	case "class":
		return false
	case "new":
		return true
	}
	if p := escPrevSignificant(clean, at); p >= 0 && clean[p] == '*' {
		// function* name(
		if fs := escPrevSignificant(clean, p); fs >= 0 && escWordEndingAt(clean, fs) == "function" {
			return funcKeywordEscapes(clean, fs-len("function")+1)
		}
	}
	p := skipSpace(clean, next)
	if p < len(clean) && clean[p] == '(' {
		return false
	}
	if p+2 < len(clean) && clean[p] == '?' && clean[p+1] == '.' && clean[p+2] == '(' {
		return false
	}
	return true
}

// funcKeywordEscapes reports whether the function introduced by the `function` keyword at
// kw is exported or is a function expression (its value is used), rather than a plain
// declaration statement.
func funcKeywordEscapes(clean []rune, kw int) bool {
	start := kw
	if escPrevWord(clean, start) == "async" {
		start = escWordStart(clean, start)
	}
	switch escPrevWord(clean, start) {
	case "export":
		return true
	case "default":
		return true
	}
	p := escPrevSignificant(clean, start)
	if p < 0 {
		return false
	}
	switch clean[p] {
	case '{', '}', ';', ')':
		return false
	}
	return true
}

// escPrevSignificant returns the index of the last non-space rune before pos, or -1.
func escPrevSignificant(r []rune, pos int) int {
	for p := pos - 1; p >= 0; p-- {
		switch r[p] {
		case ' ', '\t', '\n', '\r':
			continue
		}
		return p
	}
	return -1
}

// escPrevWord returns the identifier that immediately precedes pos (separated only by
// space), or "".
func escPrevWord(r []rune, pos int) string {
	p := escPrevSignificant(r, pos)
	if p < 0 || !isIdentPart(r[p]) {
		return ""
	}
	return escWordEndingAt(r, p)
}

// escWordStart returns the start index of the identifier that immediately precedes pos.
func escWordStart(r []rune, pos int) int {
	p := escPrevSignificant(r, pos)
	for p >= 0 && isIdentPart(r[p]) {
		p--
	}
	return p + 1
}

// escWordEndingAt returns the identifier whose last rune is at end.
func escWordEndingAt(r []rune, end int) string {
	s := end
	for s > 0 && isIdentPart(r[s-1]) {
		s--
	}
	return string(r[s : end+1])
}

// templateSubstitutionWords returns every identifier inside a template literal's ${…}
// substitutions. stripJS blanks whole template literals, so the call and escape scans
// never see these expressions; a function named in one is treated as escaping. The walk
// mirrors stripJS's template handling, starting from each template's '_' token in clean.
func templateSubstitutionWords(clean, src []rune) map[string]bool {
	words := map[string]bool{}
	n := len(src)
	for i := 0; i < n && i < len(clean); i++ {
		if src[i] != '`' || clean[i] != '_' {
			continue
		}
		depth := 0
		for j := i + 1; j < n; j++ {
			switch {
			case src[j] == '\\' && j+1 < n:
				j++
			case depth == 0 && src[j] == '`':
				i = j
				j = n
			case src[j] == '$' && j+1 < n && src[j+1] == '{':
				depth++
				j++
			case depth > 0 && src[j] == '}':
				depth--
			case depth > 0 && isIdentStart(src[j]) && !isIdentPart(src[j-1]):
				w, next := readWord(src, j)
				words[w] = true
				j = next - 1
			}
		}
	}
	return words
}
