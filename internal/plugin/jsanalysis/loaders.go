package jsanalysis

import (
	"strings"
	"unicode"
)

// Node's module loader can be reached under other names than a direct require('x') call:
// require itself passed around or aliased (`const r = require`), module.require, and the
// function createRequire(...) returns. A load through any of them runs code this lane may
// not open, so every use is either a static specifier the module loads or a computed one.

// loaderNames returns the local names that are require-like (require and every binding
// initialised from a createRequire(...) call) and createRequire-like (createRequire and its
// import/destructure renames). Bindings may be declared after their first use, so the
// names are collected before the module is scanned for uses.
func loaderNames(clean []rune) (req, cr map[string]bool) {
	req = map[string]bool{"require": true}
	cr = map[string]bool{"createRequire": true}
	n := len(clean)
	for i := 0; i < n; {
		if !isIdentStart(clean[i]) {
			i++
			continue
		}
		word, next := readWord(clean, i)
		if word == "createRequire" {
			p := skipSpace(clean, next)
			if w, nx := peekWord(clean, p); w == "as" { // import { createRequire as cr }
				if local, _ := peekWord(clean, skipSpace(clean, nx)); local != "" {
					cr[local] = true
				}
			} else if p < n && clean[p] == ':' { // const { createRequire: cr } = ...
				if local, _ := peekWord(clean, skipSpace(clean, p+1)); local != "" {
					cr[local] = true
				}
			}
		}
		i = next
	}
	for i := 0; i < n; {
		if !isIdentStart(clean[i]) {
			i++
			continue
		}
		word, next := readWord(clean, i)
		if cr[word] {
			if p := skipSpace(clean, next); p < n && clean[p] == '(' {
				if name, ok := declBoundName(clean, i); ok {
					req[name] = true
				}
			}
		}
		i = next
	}
	return req, cr
}

// requireUse records one occurrence of a require-like name whose identifier ends at next.
// A call loads its argument; `.resolve` only computes a path. Any other use hands the
// loader on, so the module can load targets this lane never sees.
func (mb *moduleBindings) requireUse(clean, src []rune, i, next int) {
	p := skipSpace(clean, next)
	call := p < len(clean) && clean[p] == '('
	switch w, _ := wordBefore(clean, skipSpaceBack(clean, i-1)); {
	case w == "typeof" && !call: // a type test of the loader; `typeof require('x')` still loads x
		return
	case w == "const", w == "let", w == "var": // the declaration of a createRequire result
		return
	}
	switch {
	case call:
		mb.loaderCall(clean, src, i, p, false)
	case p < len(clean) && clean[p] == '.':
		if w, _ := peekWord(clean, skipSpace(clean, p+1)); w != "resolve" {
			mb.computedReq = true
		}
	default:
		mb.computedReq = true
	}
}

// createRequireUse records one occurrence of a createRequire-like name. Calling the result
// immediately loads its argument, and binding the result to a declared name makes that name
// require-like (loaderNames). Anything else lets a require function escape where this lane
// cannot follow its calls.
func (mb *moduleBindings) createRequireUse(clean, src []rune, i, next int) {
	p := skipSpace(clean, next)
	call := p < len(clean) && clean[p] == '('
	if w, _ := wordBefore(clean, skipSpaceBack(clean, i-1)); w == "typeof" && !call {
		return
	}
	if !call {
		mb.computedReq = true
		return
	}
	_, end := parseParamArity(clean, p)
	if q := skipSpace(clean, end); q < len(clean) && clean[q] == '(' {
		mb.loaderCall(clean, src, i, q, false)
		return
	}
	if _, ok := declBoundName(clean, i); !ok {
		mb.computedReq = true
	}
}

// Code also runs unread through entry points that never spell require: Module._load, which
// require wraps; process.dlopen, which loads a native addon; eval and the Function
// constructor, which run source built at run time; and any of these reached by a string
// key (`module['require']`). Each sets a flag rather than a specifier, because what it
// loads is never statically known.

// memberUse records an identifier at i that is a loader entry point when reached as a
// member: `._load` loads a module as require does, `.dlopen` loads a native addon, and
// `.eval` on the global object is eval.
func (mb *moduleBindings) memberUse(clean []rune, i int, word string) {
	p := skipSpaceBack(clean, i-1)
	if p < 0 || clean[p] != '.' {
		if word == "eval" {
			mb.evaluated = true
		}
		return
	}
	switch word {
	case "_load":
		mb.computedReq = true
	case "dlopen":
		mb.nativeLoad = true
	case "eval":
		switch recv, _ := wordBefore(clean, skipSpaceBack(clean, p-1)); recv {
		case "globalThis", "global", "window", "self":
			mb.evaluated = true
		}
	}
}

// functionUse records a use of the Function constructor at i: a call, `new Function`, a
// `.call`/`.apply`/`.bind` on it, or an assignment that aliases it. A TypeScript type
// annotation (`cb: Function`) and `Function.prototype` are not uses.
func (mb *moduleBindings) functionUse(clean []rune, i, next int) {
	b := skipSpaceBack(clean, i-1)
	if b >= 0 && clean[b] == '.' {
		return
	}
	p := skipSpace(clean, next)
	switch {
	case p < len(clean) && clean[p] == '(':
	case p < len(clean) && clean[p] == '.':
		switch w, _ := peekWord(clean, skipSpace(clean, p+1)); w {
		case "call", "apply", "bind":
		default:
			return
		}
	default:
		w, _ := wordBefore(clean, b)
		assigned := b >= 1 && clean[b] == '=' && !strings.ContainsRune("=!<>", clean[b-1])
		if w != "new" && !assigned {
			return
		}
	}
	mb.evaluated = true
}

// keyedUse records the string literal at a (clean marks it '_') when it is the whole key of
// a bracket access, `x['require']`, naming a loader entry point; module itself indexed by a
// computed key is treated the same way, since the key can name any of them.
func (mb *moduleBindings) keyedUse(clean, src []rune, a int) {
	if b := skipSpaceBack(clean, a-1); b < 0 || clean[b] != '[' {
		return
	}
	if e := skipSpace(clean, a+1); e >= len(clean) || clean[e] != ']' {
		return
	}
	switch specifierAt(src, a) {
	case "require", "createRequire", "_load":
		mb.computedReq = true
	case "dlopen":
		mb.nativeLoad = true
	case "eval", "Function":
		mb.evaluated = true
	}
}

// moduleIndexUse records `module[expr]` with a key that is not a literal: the key can name
// require or the Module constructor's loaders.
func (mb *moduleBindings) moduleIndexUse(clean []rune, i, next int) {
	if b := skipSpaceBack(clean, i-1); b >= 0 && clean[b] == '.' {
		return
	}
	p := skipSpace(clean, next)
	if p >= len(clean) || clean[p] != '[' {
		return
	}
	if a := skipSpace(clean, p+1); a < len(clean) && clean[a] == '_' {
		return // a literal key; keyedUse judges it
	}
	mb.computedReq = true
}

// loaderCall records the argument of a loader call whose '(' is at open; at is the index
// of the loader name, kept to find the frame the load runs in. A whole string literal is a
// specifier the module loads, a literal prefix followed by a runtime value is a static-prefix
// load, and anything else is a target computed at run time (recordLoad).
func (mb *moduleBindings) loaderCall(clean, src []rune, at, open int, dyn bool) {
	recordLoad(clean, src, at, skipSpace(clean, open+1), dyn, mb)
}

// declBoundName returns NAME when the call starting at the identifier at i is the
// initialiser of `const|let|var NAME [: Type] = [await] [a.b.]ident(...)`.
func declBoundName(clean []rune, i int) (string, bool) {
	p := skipSpaceBack(clean, i-1)
	for p >= 0 && clean[p] == '.' { // member chain: module.constructor.createRequire
		w, s := wordBefore(clean, skipSpaceBack(clean, p-1))
		if w == "" {
			return "", false
		}
		p = skipSpaceBack(clean, s-1)
	}
	if w, s := wordBefore(clean, p); w == "await" {
		p = skipSpaceBack(clean, s-1)
	}
	if p < 1 || clean[p] != '=' || strings.ContainsRune("=!<>+-*/%&|^?", clean[p-1]) {
		return "", false
	}
	name, s := wordBefore(clean, skipSpaceBack(clean, p-1))
	if name == "" {
		return "", false
	}
	q := skipSpaceBack(clean, s-1)
	if q >= 0 && clean[q] == ':' { // TS annotation: the word read was the type
		name, s = wordBefore(clean, skipSpaceBack(clean, q-1))
		if name == "" {
			return "", false
		}
		q = skipSpaceBack(clean, s-1)
	}
	switch kw, _ := wordBefore(clean, q); kw {
	case "const", "let", "var":
		return name, true
	}
	return "", false
}

// wordBefore returns the identifier ending at p (inclusive) and its start index, or "" when
// p is not inside an identifier.
func wordBefore(r []rune, p int) (string, int) {
	if p < 0 || p >= len(r) || !isIdentPart(r[p]) {
		return "", p
	}
	s := p
	for s > 0 && isIdentPart(r[s-1]) {
		s--
	}
	return string(r[s : p+1]), s
}

// skipSpaceBack returns the last non-space index at or before i, or -1.
func skipSpaceBack(r []rune, i int) int {
	for i >= 0 && unicode.IsSpace(r[i]) {
		i--
	}
	return i
}
