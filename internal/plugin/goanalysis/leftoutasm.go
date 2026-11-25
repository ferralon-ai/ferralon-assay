package goanalysis

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/scanner"
	"unicode"
)

// lofForeignExt holds the extensions of the source files other than Go and Plan 9 assembly that
// go/build may compile into a package.
var lofForeignExt = map[string]bool{
	".c": true, ".cc": true, ".cpp": true, ".cxx": true, ".m": true,
	".f": true, ".F": true, ".for": true, ".f90": true,
	".S": true, ".sx": true, ".swig": true, ".swigcxx": true, ".syso": true,
}

// lofCFamily holds the foreign extensions gc compiles only into a package that uses cgo.
var lofCFamily = map[string]bool{
	".c": true, ".cc": true, ".cpp": true, ".cxx": true, ".m": true,
	".f": true, ".F": true, ".for": true, ".f90": true,
}

// lofAsm is what a package's Plan 9 assembly defines and names, read from its assembly files some
// build the refutation describes compiles (lofPkg.asmFiles) and the headers they include.
type lofAsm struct {
	// text holds the package's functions the assembly gives a body (TEXT); defs every symbol of
	// the package it defines (TEXT, GLOBL, DATA). A file-local symbol is keyed "name<>".
	text, defs map[string]bool
	// refs holds the Go symbols it names outside a definition, as package path ("" for the
	// package itself) and name.
	refs [][2]string
	// opaque is set when the assembly may run code the walk cannot follow to a declaration: a
	// symbol it names that is not a Go symbol of the package, a definition, or a symbol of a
	// package it names; a header it cannot find; text it cannot read or tokenize; or other source
	// that may give the package's functions their bodies (lofWorld.foreignBody).
	opaque bool
}

// asmOf returns p's assembly, read on first use.
func (w *lofWorld) asmOf(p *lofPkg) *lofAsm {
	if p.asmRead == nil {
		p.asmRead = w.readAsm(p)
	}
	return p.asmRead
}

func (w *lofWorld) readAsm(p *lofPkg) *lofAsm {
	a := &lofAsm{text: map[string]bool{}, defs: map[string]bool{}}
	if w.foreignBody(p) {
		a.opaque = true
		return a
	}
	r := &lofAsmReader{w: w, p: p, a: a, read: map[string]bool{}, local: map[string]bool{}, ext: map[string]bool{}, alias: map[string]bool{}, macros: map[string]int{}}
	for _, f := range p.asmFiles {
		r.file(f)
	}
	for name := range r.ext {
		if !r.local[name] && !(r.alias[name] && r.macros[name] == 1) {
			a.opaque = true
		}
	}
	slices.SortFunc(a.refs, func(x, y [2]string) int { return strings.Compare(x[0]+"\x00"+x[1], y[0]+"\x00"+y[1]) })
	a.refs = slices.Compact(a.refs)
	return a
}

// foreignBody reports whether p holds source other than Go and Plan 9 assembly that some build
// the refutation describes may compile into it, and so give one of its bodyless functions its
// body: a .syso object, which go/build links whatever its content; a .S or .sx file, assembled by
// the C compiler when the package uses cgo; a SWIG interface; or, in a package that uses cgo, a C,
// C++, Objective-C or Fortran file. A file whose build constraint cannot be read counts.
func (w *lofWorld) foreignBody(p *lofPkg) bool {
	cgo := func() bool {
		return slices.ContainsFunc(p.files, func(f *lofFile) bool { return f.cgo }) ||
			p.loaded != nil && slices.ContainsFunc(p.loaded.GoFiles, importsC)
	}
	for _, full := range p.foreign {
		ext := filepath.Ext(full)
		if lofCFamily[ext] && !cgo() {
			continue
		}
		if ext == ".syso" {
			return true
		}
		src, err := os.ReadFile(full)
		if err != nil {
			return true
		}
		x, err := fileConstraint(src)
		if err != nil || !w.excluded(x) {
			return true
		}
	}
	return false
}

// lofAsmIdentRune is the assembler's identifier rune (cmd/asm/internal/lex): a letter, '_', the
// middle dot '·' that separates a symbol's package from its name, the division slash '∕' that
// stands for '/' in a package path, and a digit after the first rune. '.' is not one, so an import
// path with a dot cannot be named.
func lofAsmIdentRune(ch rune, i int) bool {
	switch {
	case unicode.IsLetter(ch), ch == '_', ch == '·', ch == '∕':
		return true
	}
	return i > 0 && unicode.IsDigit(ch)
}

type lofAsmTok struct {
	tok            rune
	text           string
	line, off, end int
}

type lofAsmReader struct {
	w    *lofWorld
	p    *lofPkg
	a    *lofAsm
	read map[string]bool
	// local holds the names without a package the assembly defines; ext those it names as a
	// symbol (name(SB)) outside a definition; alias the macros defined to one Go symbol, and
	// macros how many times each macro is defined or undefined.
	local, ext, alias map[string]bool
	macros            map[string]int
}

// file reads one assembly file or header, and every header it includes.
func (r *lofAsmReader) file(path string) {
	if r.read[path] {
		return
	}
	r.read[path] = true
	src, err := os.ReadFile(path)
	if err != nil {
		r.a.opaque = true
		return
	}
	var s scanner.Scanner
	s.Init(bytes.NewReader(src))
	s.Filename = path
	s.Mode = scanner.ScanChars | scanner.ScanFloats | scanner.ScanIdents | scanner.ScanInts | scanner.ScanStrings | scanner.ScanComments | scanner.SkipComments
	s.IsIdentRune = lofAsmIdentRune
	s.Error = func(*scanner.Scanner, string) {}
	var toks []lofAsmTok
	for t := s.Scan(); t != scanner.EOF; t = s.Scan() {
		text := s.TokenText()
		toks = append(toks, lofAsmTok{tok: t, text: text, line: s.Position.Line, off: s.Position.Offset, end: s.Position.Offset + len(text)})
	}
	if s.ErrorCount > 0 {
		r.a.opaque = true
		return
	}
	at := func(i int, tok rune, text string) bool {
		return i >= 0 && i < len(toks) && toks[i].tok == tok && (text == "" || toks[i].text == text)
	}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.tok == '#' && at(i+1, scanner.Ident, "include") {
			if !at(i+2, scanner.String, "") {
				r.a.opaque = true
				return
			}
			r.include(toks[i+2].text)
			i += 2
			continue
		}
		// A macro defined once, to one Go symbol the walk follows from its definition, names
		// that symbol when used as name(SB). Any other macro used so stays an unknown symbol.
		if t.tok == '#' && (at(i+1, scanner.Ident, "define") || at(i+1, scanner.Ident, "undef")) && at(i+2, scanner.Ident, "") {
			name := toks[i+2].text
			r.macros[name]++
			if toks[i+1].text == "define" && at(i+3, scanner.Ident, "") && strings.Contains(toks[i+3].text, "·") && toks[i+3].line == toks[i+2].line &&
				(i+4 == len(toks) || toks[i+4].line > toks[i+3].line) {
				r.alias[name] = true
			}
		}
		// The assembler takes a symbol only against the static base, (SB); SB anywhere else, as
		// a macro's name or body, may make one of what the walk reads as something else.
		if t.tok == scanner.Ident && t.text == "SB" && !(at(i-1, '(', "") && at(i+1, ')', "")) {
			r.a.opaque = true
		}
		if t.tok != scanner.Ident {
			continue
		}
		// What follows the name: <> marks a file-local symbol, <ABI…> an ABI, then an offset,
		// then (SB) marks a symbol.
		j, static := i+1, false
		if at(j, '<', "") {
			switch {
			case at(j+1, '>', ""):
				static, j = true, j+2
			case at(j+1, scanner.Ident, "") && at(j+2, '>', ""):
				j += 3
			}
		}
		for at(j, '+', "") || at(j, '-', "") || at(j, scanner.Int, "") {
			j++
		}
		sym := at(j, '(', "") && at(j+1, scanner.Ident, "SB") && at(j+2, ')', "")
		def := i > 0 && toks[i-1].tok == scanner.Ident && (toks[i-1].text == "TEXT" || toks[i-1].text == "GLOBL" || toks[i-1].text == "DATA")
		dot := strings.LastIndex(t.text, "·")
		if dot < 0 {
			name := t.text
			if static {
				name += "<>"
			}
			switch {
			case sym && def:
				r.local[name] = true
			case sym:
				r.ext[name] = true
			}
			continue
		}
		// A dot or slash against the token is a path or a name the assembler does not take as one
		// symbol: an import path with a dot, or a compiler-made name such as f.func1 or f.abi0.
		if i > 0 && toks[i-1].end == t.off && (toks[i-1].tok == '.' || toks[i-1].tok == '/') ||
			i+1 < len(toks) && toks[i+1].off == t.end && strings.HasPrefix(toks[i+1].text, ".") {
			r.a.opaque = true
			continue
		}
		pkg, name := t.text[:dot], t.text[dot+len("·"):]
		if name == "" || strings.Contains(pkg, "·") || strings.Contains(name, "∕") {
			r.a.opaque = true
			continue
		}
		pkg = strings.ReplaceAll(pkg, "∕", "/")
		if pkg == r.p.path {
			pkg = ""
		}
		if static {
			name += "<>"
		}
		switch {
		case def && pkg == "":
			r.a.defs[name] = true
			if toks[i-1].text == "TEXT" && !static {
				r.a.text[name] = true
			}
		case def:
			// A definition of another package's symbol gives that package a body; its own
			// bodyless function finds none in its own assembly and stays opaque.
		default:
			r.a.refs = append(r.a.refs, [2]string{pkg, name})
		}
	}
}

// include reads the header a #include names, found as the assembler finds it: the path itself
// (relative to the package's directory, where the go command runs the assembler), then the
// build's object directory, then the toolchain's pkg/include. The object directory holds only
// go_asm.h, which the compiler generates from the package's Go declarations: constants and
// offsets, no symbols.
func (r *lofAsmReader) include(quoted string) {
	name, err := strconv.Unquote(quoted)
	if err != nil || name == "" {
		r.a.opaque = true
		return
	}
	if filepath.IsAbs(name) {
		r.file(name)
		return
	}
	if local := filepath.Join(r.p.dir, name); lofIsFile(local) {
		r.file(local)
		return
	}
	if name == "go_asm.h" {
		return
	}
	if r.w.goroot != "" {
		if std := filepath.Join(r.w.goroot, "pkg", "include", name); lofIsFile(std) {
			r.file(std)
			return
		}
	}
	r.a.opaque = true
}

func lofIsFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}
