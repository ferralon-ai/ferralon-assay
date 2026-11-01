package goanalysis

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// lofDefSrc records whose code a definer, or a gap in the index, sits in: the standard library's,
// a module's, or both.
type lofDefSrc uint8

const (
	lofDefStd lofDefSrc = 1 << iota
	lofDefMod
)

// lofLinkDeps are the packages cmd/go adds to a link without an import naming them
// (load.LinkerDeps): external linking, GOARM=5, -race, -msan, -asan and -cover, and cgo's own
// translation.
var lofLinkDeps = []string{"math", "runtime", "runtime/asan", "runtime/cgo", "runtime/coverage", "runtime/msan", "runtime/race", "syscall"}

// lofLinkIndex holds, by bare link symbol name, what may define that name in some link the
// refutation describes, over U: every package the loaded program, cmd/go's implicit link
// dependencies, or any build variant of a package on the way imports. cmd/link binds a bare name an
// assembly body references to such a definer before any dynamic import of it.
type lofLinkIndex struct {
	// gap is set when U holds a package the index cannot resolve or read whole, or a file that may
	// define any name (an object file of unknown format, an #include that does not resolve).
	gap lofDefSrc
	// goDefs holds the Go declarations a //go:linkname pushes to the name, each a function with a
	// body or a variable, and the //export functions of that name.
	goDefs map[string][]lofGoDef
	// asmText and asmData hold the packages whose Go assembly defines the name, by TEXT and by
	// DATA or GLOBL.
	asmText map[string][]string
	asmData map[string][]string
	// opaque holds the names a definer the walk cannot follow may define: a .syso object's global
	// symbols, and names a macro or an included header mentions.
	opaque map[string]lofDefSrc
}

// lofGoDef is a Go declaration defining a bare link symbol: the local name in the package at path
// whose files carry the package clause.
type lofGoDef struct {
	path, clause, local string
}

// linkIndex returns the world's link index, built on first use from U alone, so that no closure's
// walk, nor the order closures run in, changes it.
func (w *lofWorld) linkIndex() *lofLinkIndex {
	if w.linkIdx != nil {
		return w.linkIdx
	}
	ix := &lofLinkIndex{goDefs: map[string][]lofGoDef{}, asmText: map[string][]string{}, asmData: map[string][]string{}, opaque: map[string]lofDefSrc{}}
	w.linkIdx = ix
	seen := map[string]bool{}
	var all []string
	frontier := slices.Concat(slices.Sorted(maps.Keys(w.loaded)), lofLinkDeps)
	for len(frontier) > 0 {
		if w.ctx.Err() != nil || (!w.deadline.IsZero() && time.Now().After(w.deadline)) {
			ix.gap |= lofDefStd | lofDefMod
			break
		}
		var todo []string
		for _, ip := range frontier {
			if !seen[ip] && ip != "unsafe" && ip != "C" {
				seen[ip] = true
				todo = append(todo, ip)
			}
		}
		slices.Sort(todo)
		w.resolve(todo)
		frontier = nil
		for _, ip := range todo {
			d := w.dirs[ip]
			if d == "" {
				ix.gap |= w.defSrc(ip)
				continue
			}
			imps, item := w.dirImports(d, w.std[ip])
			if item != "" {
				ix.gap |= w.defSrc(ip)
			}
			frontier = append(frontier, imps...)
			all = append(all, ip)
		}
	}
	slices.Sort(all)
	w.asmSession().prefetch(w.asmItems(all))
	for _, ip := range all {
		w.scanDefiners(ix, ip)
	}
	return ix
}

// asmItems returns the assembly files of the packages ips that some described build compiles.
func (w *lofWorld) asmItems(ips []string) []lofAsmItem {
	var items []lofAsmItem
	for _, ip := range ips {
		dir := w.dirs[ip]
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".s") {
				continue
			}
			full := filepath.Join(dir, e.Name())
			text, err := os.ReadFile(full)
			if err != nil {
				continue
			}
			if x, err := fileConstraint(text); err == nil && !w.excluded(x) {
				items = append(items, lofAsmItem{pkg: ip, dir: dir, file: full, std: w.std[ip]})
			}
		}
	}
	return items
}

func (w *lofWorld) defSrc(ip string) lofDefSrc {
	if w.std[ip] {
		return lofDefStd
	}
	return lofDefMod
}

// scanDefiners indexes the definers of bare link symbols among the files of the package ip that
// some described build compiles: Go files' //go:linkname pushes and //export functions, Go
// assembly, and .syso objects.
func (w *lofWorld) scanDefiners(ix *lofLinkIndex, ip string) {
	dir, src := w.dirs[ip], w.defSrc(ip)
	ents, err := os.ReadDir(dir)
	if err != nil {
		ix.gap |= src
		return
	}
	type goFile struct {
		path string
		text []byte
	}
	var goFiles []goFile
	directives := false
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() {
			continue
		}
		full := filepath.Join(dir, n)
		switch {
		case strings.HasSuffix(n, ".syso"):
			syms, err := lofObjSymbols(full)
			if err != nil {
				ix.gap |= src
				continue
			}
			for _, s := range syms {
				ix.opaque[s] |= src
				if t, ok := strings.CutPrefix(s, "_"); ok && t != "" {
					ix.opaque[t] |= src
				}
			}
			continue
		case strings.HasSuffix(n, ".s"), strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go"):
		default:
			continue
		}
		text, err := os.ReadFile(full)
		if err != nil {
			ix.gap |= src
			continue
		}
		x, err := fileConstraint(text)
		if err != nil {
			ix.gap |= src
			continue
		}
		if w.excluded(x) {
			continue
		}
		if strings.HasSuffix(n, ".s") {
			// A cgo package's assembly goes to the C compiler in a cgo build, but is Go assembly
			// in a build with cgo disabled, which the refutation describes too.
			o := w.asmSession().object(lofAsmItem{pkg: ip, dir: dir, file: full, std: w.std[ip]})
			if !o.ok {
				ix.gap |= src
				continue
			}
			for sym := range o.text {
				if name, ok := lofBareAsm(sym); ok {
					ix.asmText[name] = lofAppendPath(ix.asmText[name], ip)
				}
			}
			for sym := range o.data {
				if name, ok := lofBareAsm(sym); ok {
					ix.asmData[name] = lofAppendPath(ix.asmData[name], ip)
				}
			}
			continue
		}
		goFiles = append(goFiles, goFile{full, text})
		directives = directives || bytes.Contains(text, []byte("//go:linkname")) || bytes.Contains(text, []byte("//export"))
	}
	if !directives {
		return
	}
	// A //go:linkname push defines its remote only from a function with a body or a variable,
	// either of which may sit in any file of the package's clause.
	type pushed struct{ clause, local, remote string }
	var pushes []pushed
	defined := map[[2]string]bool{}
	for _, f := range goFiles {
		af, err := parser.ParseFile(token.NewFileSet(), f.path, f.text, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			ix.gap |= src
			continue
		}
		clause := af.Name.Name
		if clause == "documentation" {
			continue
		}
		cgo := slices.ContainsFunc(af.Imports, func(im *ast.ImportSpec) bool { return im.Path.Value == `"C"` })
		for _, cg := range af.Comments {
			for _, c := range cg.List {
				// A remote naming a package, or none, never matches a bare name.
				if local, remote, ok := parseLinkname(c.Text); ok {
					pushes = append(pushes, pushed{clause, local, remote})
				}
				if name, ok := strings.CutPrefix(c.Text, "//export "); ok && cgo {
					name = strings.TrimSpace(name)
					ix.goDefs[name] = append(ix.goDefs[name], lofGoDef{ip, clause, name})
				}
			}
		}
		for _, decl := range af.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				if decl.Recv == nil && decl.Body != nil {
					defined[[2]string{clause, decl.Name.Name}] = true
				}
			case *ast.GenDecl:
				if decl.Tok != token.VAR {
					continue
				}
				for _, spec := range decl.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok {
						for _, n := range vs.Names {
							defined[[2]string{clause, n.Name}] = true
						}
					}
				}
			}
		}
	}
	for _, p := range pushes {
		if defined[[2]string{p.clause, p.local}] {
			ix.goDefs[p.remote] = append(ix.goDefs[p.remote], lofGoDef{ip, p.clause, p.local})
		}
	}
}

func lofAppendPath(paths []string, ip string) []string {
	if len(paths) > 0 && paths[len(paths)-1] == ip {
		return paths
	}
	return append(paths, ip)
}

// lofBareAsm returns the bare link symbol an assembly symbol names, without its ABI selector: not
// a Go symbol ("·name", "pkg·name", "pkg.name") nor a file-local one ("name<>").
func lofBareAsm(sym string) (string, bool) {
	if strings.HasSuffix(sym, "<>") {
		return "", false
	}
	if i := strings.IndexByte(sym, '<'); i >= 0 {
		sym = sym[:i]
	}
	if sym == "" || strings.ContainsAny(sym, ".·") {
		return "", false
	}
	return sym, true
}

var errLofObjFormat = errors.New("unknown object format")

// lofObjSymbols returns the global symbols an object file defines: ELF, Mach-O (thin or fat) or
// PE/COFF. Any other format is an error.
func lofObjSymbols(path string) ([]string, error) {
	var out []string
	if f, err := elf.Open(path); err == nil {
		defer f.Close()
		syms, err := f.Symbols()
		if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
			return nil, err
		}
		for _, s := range syms {
			if b := elf.ST_BIND(s.Info); s.Section != elf.SHN_UNDEF && (b == elf.STB_GLOBAL || b == elf.STB_WEAK) {
				out = append(out, s.Name)
			}
		}
		return out, nil
	}
	machoSyms := func(f *macho.File) {
		if f.Symtab == nil {
			return
		}
		for _, s := range f.Symtab.Syms {
			// N_EXT, in a section.
			if s.Type&0x01 != 0 && s.Sect != 0 {
				out = append(out, s.Name)
			}
		}
	}
	if f, err := macho.Open(path); err == nil {
		defer f.Close()
		machoSyms(f)
		return out, nil
	}
	if f, err := macho.OpenFat(path); err == nil {
		defer f.Close()
		for _, a := range f.Arches {
			machoSyms(a.File)
		}
		return out, nil
	}
	if f, err := pe.Open(path); err == nil {
		defer f.Close()
		switch f.Machine {
		case pe.IMAGE_FILE_MACHINE_I386, pe.IMAGE_FILE_MACHINE_AMD64, pe.IMAGE_FILE_MACHINE_ARM, pe.IMAGE_FILE_MACHINE_ARMNT,
			pe.IMAGE_FILE_MACHINE_ARM64, pe.IMAGE_FILE_MACHINE_RISCV64, pe.IMAGE_FILE_MACHINE_LOONGARCH64:
		default:
			return nil, errLofObjFormat
		}
		for _, s := range f.Symbols {
			// IMAGE_SYM_CLASS_EXTERNAL, in a section.
			if s.SectionNumber > 0 && s.StorageClass == 2 {
				out = append(out, s.Name)
			}
		}
		return out, nil
	}
	return nil, errLofObjFormat
}

// linkDefiner follows what some described link may bind the bare symbol name to, a name package
// from references and does not define itself: a Go declaration a //go:linkname pushes to it or an
// //export function of it, walked; a Go assembly definition, whose body is walked. A definer the
// walk cannot follow (a .syso object's symbol, a name a macro or header may produce), or a gap in
// the index, fails closed. It reports whether there is any definer; when there is none, the name
// binds only to foreign code.
func (k *lofWalk) linkDefiner(from *lofPkg, name string) bool {
	ix := k.w.linkIndex()
	found := false
	for _, d := range ix.goDefs[name] {
		found = true
		q := k.w.pkg(d.path)
		if q.name != d.clause && q.missing == "" {
			q = k.w.pkgVariant(d.path, d.clause)
		}
		k.enter(q)
		if q.missing != "" || !k.resolveIn(q, d.local) {
			k.fail(q, lofAsmSymbol)
		}
	}
	for _, path := range ix.asmText[name] {
		found = true
		q := k.w.pkg(path)
		k.enter(q)
		bodies := q.asmText[name]
		if q.missing != "" || len(bodies) == 0 {
			k.fail(q, lofAsmSymbol)
		}
		for _, b := range bodies {
			k.walkAsm(q, b)
		}
	}
	for _, path := range ix.asmData[name] {
		found = true
		q := k.w.pkg(path)
		k.enter(q)
		if q.missing != "" || !q.asmData[name] {
			k.fail(q, lofAsmSymbol)
		}
	}
	if src := ix.opaque[name] | ix.gap; src != 0 {
		found = true
		if src&lofDefMod != 0 {
			k.out.fail(lofAsmSymbol)
		} else {
			k.fail(from, lofAsmSymbol)
		}
	}
	return found
}
