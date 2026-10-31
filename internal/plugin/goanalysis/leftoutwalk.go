package goanalysis

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/tools/go/packages"
)

// The items a left-out file's declaration closure fails closed on: each marks something the walk
// cannot follow, load or bound, and a file whose closure raises one counts.
const (
	lofParseError       = "parse_error"
	lofMissingSource    = "missing_source"
	lofUnresolvedImport = "unresolved_import"
	lofUnknownToolchain = "unknown_toolchain"
	lofGorootMismatch   = "goroot_mismatch"
	lofLinkname         = "linkname"
	lofBodyless         = "bodyless"
	lofAsmSymbol        = "asm_symbol"
	lofBudget           = "budget"
	lofUnresolvedName   = "unresolved_name"
	lofGraphError       = "graph_error"
	lofVariantTypecheck = "variant_typecheck"
)

// The walk's budget. A closure that walks more than lofBudgetDecls declarations fails closed
// (lofBudget), and so does every closure still unfinished lofBudgetTime after the engine started.
var (
	lofBudgetDecls = 2_000_000
	lofBudgetTime  = 10 * time.Minute
)

// lofUniverse holds the names the universe block declares.
var lofUniverse = func() map[string]bool {
	m := map[string]bool{}
	for _, n := range types.Universe.Names() {
		m[n] = true
	}
	return m
}()

// lofWorld is the source the left-out closures walk, shared between them: each package's
// declarations parsed once, from the union of its build variants.
type lofWorld struct {
	ctx      context.Context
	buildDir string
	env      []string
	// epoch numbers the walks; closures run one at a time.
	epoch int
	// excluded reports whether a file with this build constraint compiles in no build the
	// refutation describes (toolchainExcluded).
	excluded func(constraint.Expr) bool
	// goroot is the toolchain's root the compiler's intrinsic table is read from; "" reads none.
	goroot string
	// modcache is the module cache's root, whose module source the build compiles as it was
	// downloaded; "" when not known.
	modcache string
	deadline time.Time
	loaded   map[string]*packages.Package
	modules  map[string]bool
	dirs     map[string]string
	names    map[string]string
	// std records whether each resolved import path is a standard-library package, as go list
	// reports it, so an unloaded module whose path has no dot is not taken for one.
	std  map[string]bool
	pkgs map[string]*lofPkg
	// pushes maps a //go:linkname remote ("path.name") to the (file, local) declarations that
	// push their bodies to it.
	pushes     map[string][][2]string
	pushesRead bool
	intrinsics map[string]bool
	// dropped holds the files proved never to compile; no package is parsed with them.
	dropped    map[string]bool
	linkMemo   map[string]lofLinks
	importMemo map[string]lofDirImports
	// stdNames holds, by directory, the names a standard-library package declares in any build
	// variant; nil when the directory cannot be read whole.
	stdNames map[string]map[string]bool
	// base is the walk of the roots of the package whose files closure last walked; a walk of
	// another package's files, or a dropped file, replaces it.
	base *lofWalk
	// carriers holds the method names some loaded type declares a method of that carries a value
	// in (lofCarriesIn); nil until first asked.
	carriers map[string]bool
	// holders holds the method names some loaded type declares a method of whose results hold an
	// interface or a func.
	holders map[string]bool
}

func newLofWorld(ctx context.Context, pkgs []*packages.Package, buildDir string, env []string, excluded func(constraint.Expr) bool, goroot string, deadline time.Time) *lofWorld {
	w := &lofWorld{
		ctx: ctx, buildDir: buildDir, env: env, excluded: excluded, goroot: goroot, deadline: deadline,
		loaded: map[string]*packages.Package{}, modules: map[string]bool{},
		dirs: map[string]string{}, names: map[string]string{}, std: map[string]bool{}, pkgs: map[string]*lofPkg{},
		pushes: map[string][][2]string{}, dropped: map[string]bool{},
		linkMemo: map[string]lofLinks{}, importMemo: map[string]lofDirImports{}, stdNames: map[string]map[string]bool{},
	}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.Types != nil {
			w.loaded[p.PkgPath] = p
		}
		if p.Module != nil {
			w.modules[p.Module.Path] = true
		}
	})
	return w
}

// lofPkg is one package's source: for a package the build loaded, only the files it left out;
// for any other, every non-test Go file some build compiles. Declarations of every variant are
// indexed together.
type lofPkg struct {
	path   string
	dir    string
	name   string
	std    bool
	loaded *packages.Package
	// missing is set when no directory holds the package (lofUnresolvedImport) or it cannot be
	// read (lofMissingSource).
	missing string
	errs    []string
	files   []*lofFile
	decls   map[string][]*lofDecl
	methods map[string][]*lofDecl
	byRecv  map[string][]*lofDecl
	inits   []*lofDecl
	exports []*lofDecl
	imports []string
	asmText map[string][]*lofAsm
	asmData map[string]bool
	// asmNames holds the names under this package's path among asmText's and asmData's symbols.
	asmNames map[string]bool
}

// lofFile is one parsed Go file of a lofPkg.
type lofFile struct {
	pkg   *lofPkg
	path  string
	ast   *ast.File
	named map[string]string
	plain []string
	dots  []string
	all   []string
	// links maps a //go:linkname local name to its remote; badLink is set for a malformed one.
	links   map[string]string
	badLink bool
	cgo     bool
	decls   []*lofDecl
}

// lofDecl is one package-level declaration: a function or method, a type, or a var or const spec.
type lofDecl struct {
	file *lofFile
	node ast.Node
	name string
	recv string
	done bool
	// seen is the epoch of the last walk that queued it; src is its key in lofClosure.src.
	seen int
	src  string
	refs []lofRef
	// called holds the names it selects on a value: methods, or fields it may call.
	called  []string
	dyn     bool
	reflect bool
	// asserts is set when it asserts or switches on an interface value's dynamic type to a type
	// other than an interface literal, whose methods it can only call by name.
	asserts bool
}

// lofRef is a reference a declaration makes. A bare identifier resolves in its own package (in),
// then through its file's dot imports (alts), then the universe; a qualified one names pkg.
type lofRef struct {
	pkg  string
	name string
	in   *lofPkg
	file *lofFile
	alts []string
	bare bool
	// soft marks a composite-literal key, which is a field name unless a declaration has it.
	soft bool
	link bool
}

// lofAsm is one assembly TEXT body: the symbols it references, and whether it calls through a
// register.
type lofAsm struct {
	file    string
	refs    []string
	dynamic bool
}

// lofClosure is what one left-out file's declaration closure touches: the loaded declarations it
// reaches (terminals), the source declarations it walks, the method names it selects, and what it
// fails closed on.
type lofClosure struct {
	funcs map[*types.Func]bool
	// inits holds the loaded packages the closure links, whose initializers run once it does.
	inits map[*types.Package]bool
	types map[*types.TypeName]bool
	vars  bool
	// sink is set when a loaded declaration it reaches can carry a value into loaded code that
	// calls through it: a function's parameter or result, a type, or a variable whose type holds
	// an interface or a func; or a method of a loaded type it may call by name whose parameter
	// or result does.
	sink bool
	// held is set when a loaded function's result holds an interface or a func, and asserts
	// when the closure asserts a dynamic type: together, a value of any type loaded code made.
	held    bool
	asserts bool
	methods map[string]bool
	dyn     bool
	reflect bool
	// src holds each source function walked, as its package path and "F" or "T.M".
	src map[[2]string]bool
	// newMeth holds the loaded types the file declares methods on.
	newMeth []*types.TypeName
	fc      []string
	// fcStd holds what fails closed only for a standard-library refutation: a target inside the
	// toolchain's own packages, which call no module code.
	fcStd []string
	// unres holds the bare identifiers no declaration has, and unresQ the qualified references to a
	// standard-library package that no declaration of it has.
	unres  []lofRef
	unresQ []lofRef
	decls  int
	// excluded is set when the file compiles in no build the refutation describes; dropped when
	// that is because it never compiles at all (uncompilable).
	excluded bool
	dropped  bool
}

func newLofClosure() *lofClosure {
	return &lofClosure{funcs: map[*types.Func]bool{}, inits: map[*types.Package]bool{}, types: map[*types.TypeName]bool{}, methods: map[string]bool{}, src: map[[2]string]bool{}}
}

func (c *lofClosure) clone() *lofClosure {
	cp := *c
	cp.funcs, cp.inits, cp.types, cp.methods, cp.src = maps.Clone(c.funcs), maps.Clone(c.inits), maps.Clone(c.types), maps.Clone(c.methods), maps.Clone(c.src)
	cp.newMeth, cp.fc, cp.fcStd, cp.unres, cp.unresQ = slices.Clone(c.newMeth), slices.Clone(c.fc), slices.Clone(c.fcStd), slices.Clone(c.unres), slices.Clone(c.unresQ)
	return &cp
}

func (c *lofClosure) fail(item string) {
	if !slices.Contains(c.fc, item) {
		c.fc = append(c.fc, item)
	}
}

func (c *lofClosure) failStd(item string) {
	if !slices.Contains(c.fcStd, item) {
		c.fcStd = append(c.fcStd, item)
	}
}

// resolve finds the directory and package name of each import path not yet known, with one
// `go list` per batch. The name is the package clause of a file some build compiles when go list
// reports none (every file excluded by the scan's own configuration).
func (w *lofWorld) resolve(paths []string) {
	var need []string
	for _, p := range paths {
		if _, ok := w.dirs[p]; ok || p == "C" {
			continue
		}
		if lp, ok := w.loaded[p]; ok {
			if dir := lofLoadedDir(lp); dir != "" {
				w.dirs[p], w.names[p] = dir, lp.Name
				w.std[p] = lp.Module == nil && isStdlibPath(p, w.modules)
				continue
			}
		}
		need = append(need, p)
	}
	slices.Sort(need)
	need = slices.Compact(need)
	for i := 0; i < len(need); i += 400 {
		batch := need[i:min(i+400, len(need))]
		cmd := exec.CommandContext(w.ctx, "go", append([]string{"list", "-e", "-f", "{{.ImportPath}}\t{{.Dir}}\t{{.Name}}\t{{.Standard}}"}, batch...)...)
		cmd.Dir = w.buildDir
		cmd.Env = w.env
		out, _ := cmd.Output()
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Split(line, "\t")
			if len(f) != 4 || f[1] == "" {
				continue
			}
			w.dirs[f[0]] = f[1]
			w.std[f[0]] = f[3] == "true"
			if f[2] != "" {
				w.names[f[0]] = f[2]
			}
		}
	}
	for _, p := range need {
		if _, ok := w.dirs[p]; !ok {
			w.dirs[p] = ""
			w.std[p] = isStdlibPath(p, w.modules)
		}
		if _, ok := w.names[p]; !ok && w.dirs[p] != "" {
			w.names[p] = w.clauseName(w.dirs[p])
		}
	}
}

func lofLoadedDir(lp *packages.Package) string {
	for _, files := range [][]string{lp.GoFiles, lp.IgnoredFiles, lp.OtherFiles} {
		if len(files) > 0 {
			return filepath.Dir(files[0])
		}
	}
	return ""
}

// clauseName returns the package clause of the first non-test Go file in dir that some build
// compiles, or "" when there is none.
func (w *lofWorld) clauseName(dir string) string {
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		if x, err := fileConstraint(src); err != nil || w.excluded(x) {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), "", src, parser.PackageClauseOnly)
		if err != nil || f.Name.Name == "documentation" {
			continue
		}
		return f.Name.Name
	}
	return ""
}

// pkg returns the package at path, parsed on first use.
func (w *lofWorld) pkg(path string) *lofPkg {
	return w.pkgVariant(path, "")
}

// pkgVariant returns the package at path whose files carry the package clause name, or the
// package's own name when name is "". A clause other than the package's own is a package the
// build did not load, whatever path's is.
func (w *lofWorld) pkgVariant(path, name string) *lofPkg {
	key := path
	if name != "" {
		key = path + "\x00" + name
	}
	if p, ok := w.pkgs[key]; ok {
		return p
	}
	w.resolve([]string{path})
	p := &lofPkg{
		path: path, dir: w.dirs[path], name: w.names[path], std: w.std[path],
		decls: map[string][]*lofDecl{}, methods: map[string][]*lofDecl{}, byRecv: map[string][]*lofDecl{},
		asmText: map[string][]*lofAsm{}, asmData: map[string]bool{},
	}
	if lp := w.loaded[path]; lp != nil && (name == "" || name == lp.Name) {
		p.loaded, p.name = lp, lp.Name
	} else if name != "" {
		p.name = name
	}
	w.pkgs[key] = p
	if p.dir == "" {
		p.missing = lofUnresolvedImport
		return p
	}
	w.parse(p)
	return p
}

// parse reads p's directory: its Go files (for a loaded package, only those the build left out),
// excluding test files, files another package clause names, files excluded from every build the
// refutation describes, and files proved never to compile; and its assembly.
func (w *lofWorld) parse(p *lofPkg) {
	ents, err := os.ReadDir(p.dir)
	if err != nil {
		p.missing = lofMissingSource
		return
	}
	compiled := map[string]bool{}
	if p.loaded != nil {
		for _, f := range p.loaded.GoFiles {
			compiled[f] = true
		}
	}
	fset := token.NewFileSet()
	var asmFiles, headers []string
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() {
			continue
		}
		full := filepath.Join(p.dir, n)
		switch {
		case strings.HasSuffix(n, ".s"):
			asmFiles = append(asmFiles, full)
			continue
		case strings.HasSuffix(n, ".h"):
			headers = append(headers, full)
			continue
		case !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") || compiled[full] || w.dropped[full]:
			continue
		}
		src, err := os.ReadFile(full)
		if err != nil {
			p.errs = append(p.errs, lofMissingSource)
			continue
		}
		x, err := fileConstraint(src)
		if err != nil {
			p.errs = append(p.errs, lofParseError)
			continue
		}
		if w.excluded(x) {
			continue
		}
		af, err := parser.ParseFile(fset, full, src, parser.ParseComments)
		if err != nil {
			p.errs = append(p.errs, lofParseError)
			continue
		}
		clause := af.Name.Name
		if clause == "documentation" {
			continue
		}
		if p.name == "" {
			p.name = clause
		}
		if clause != p.name {
			continue
		}
		w.index(p, full, af)
	}
	for _, full := range asmFiles {
		src, err := os.ReadFile(full)
		if err != nil {
			p.errs = append(p.errs, lofMissingSource)
			continue
		}
		x, err := fileConstraint(src)
		if err != nil {
			p.errs = append(p.errs, lofParseError)
			continue
		}
		if w.excluded(x) {
			continue
		}
		parseAsm(p, full, src, headers)
	}
	slices.Sort(p.imports)
	p.imports = slices.Compact(p.imports)
	w.resolve(p.imports)
}

// index records one parsed file's imports, directives and package-level declarations in p.
func (w *lofWorld) index(p *lofPkg, path string, af *ast.File) {
	f := &lofFile{pkg: p, path: path, ast: af, named: map[string]string{}, links: map[string]string{}}
	for _, im := range af.Imports {
		ip, err := strconv.Unquote(im.Path.Value)
		if err != nil {
			p.errs = append(p.errs, lofParseError)
			continue
		}
		if ip == "C" {
			f.cgo = true
			continue
		}
		if p.std && !isStdlibPath(ip, nil) {
			// The standard library resolves the golang.org/x packages it imports to its own vendor copies.
			ip = "vendor/" + ip
		}
		f.all = append(f.all, ip)
		p.imports = append(p.imports, ip)
		switch {
		case im.Name == nil:
			f.plain = append(f.plain, ip)
		case im.Name.Name == ".":
			f.dots = append(f.dots, ip)
		case im.Name.Name == "_":
		default:
			f.named[im.Name.Name] = ip
		}
	}
	var exports []string
	for _, cg := range af.Comments {
		for _, c := range cg.List {
			if local, remote, ok := parseLinkname(c.Text); ok {
				switch {
				case local == "" || remote == "\x00":
					f.badLink = true
				case remote != "":
					f.links[local] = remote
					w.pushes[remote] = append(w.pushes[remote], [2]string{path, local})
				}
			}
			if name, ok := strings.CutPrefix(c.Text, "//export "); ok && f.cgo {
				exports = append(exports, strings.TrimSpace(name))
			}
		}
	}
	add := func(d *lofDecl) { f.decls = append(f.decls, d) }
	for _, decl := range af.Decls {
		switch decl := decl.(type) {
		case *ast.FuncDecl:
			d := &lofDecl{file: f, node: decl, name: decl.Name.Name}
			add(d)
			switch {
			case decl.Recv != nil && len(decl.Recv.List) > 0:
				d.recv = recvName(decl.Recv.List[0].Type)
				p.methods[d.name] = append(p.methods[d.name], d)
				p.byRecv[d.recv] = append(p.byRecv[d.recv], d)
			case d.name == "init":
				p.inits = append(p.inits, d)
			default:
				p.decls[d.name] = append(p.decls[d.name], d)
				if slices.Contains(exports, d.name) {
					p.exports = append(p.exports, d)
				}
			}
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				switch spec := spec.(type) {
				case *ast.ValueSpec:
					d := &lofDecl{file: f, node: spec}
					add(d)
					for _, n := range spec.Names {
						p.decls[n.Name] = append(p.decls[n.Name], d)
					}
					if decl.Tok == token.VAR && len(spec.Values) > 0 {
						p.inits = append(p.inits, d)
					}
				case *ast.TypeSpec:
					d := &lofDecl{file: f, node: spec, name: spec.Name.Name}
					add(d)
					p.decls[d.name] = append(p.decls[d.name], d)
				}
			}
		}
	}
	p.files = append(p.files, f)
}

// parseLinkname reads a //go:linkname directive: local and remote ("" when it names none; "\x00"
// when malformed). ok is false for any other comment.
func parseLinkname(text string) (local, remote string, ok bool) {
	rest, ok := strings.CutPrefix(text, "//go:linkname")
	if !ok || (rest != "" && rest[0] != ' ' && rest[0] != '\t') {
		return "", "", false
	}
	f := strings.Fields(rest)
	switch len(f) {
	case 1:
		return f[0], "", true
	case 2:
		return f[0], f[1], true
	case 0:
		return "", "", true
	}
	return f[0], "\x00", true
}

// recvName names a receiver's type with any pointer and type parameters dropped.
func recvName(x ast.Expr) string {
	for {
		switch t := x.(type) {
		case *ast.StarExpr:
			x = t.X
		case *ast.ParenExpr:
			x = t.X
		case *ast.IndexExpr:
			x = t.X
		case *ast.IndexListExpr:
			x = t.X
		case *ast.Ident:
			return t.Name
		default:
			return ""
		}
	}
}

// importFor returns the import path the qualifier x names in f, or "".
func (w *lofWorld) importFor(f *lofFile, x string) string {
	if ip, ok := f.named[x]; ok {
		return ip
	}
	for _, ip := range f.plain {
		if w.names[ip] == x {
			return ip
		}
	}
	return ""
}

// refsOf computes d's references once. An identifier the parser resolved to a declaration inside
// the function is a local; one resolved to a package-level declaration of the file, or not
// resolved at all, is a reference by name. Calling a local, the result of a call, a selected field
// or anything else that is not a declaration named in source is a dynamic call.
func (w *lofWorld) refsOf(d *lofDecl) {
	if d.done {
		return
	}
	d.done = true
	f := d.file
	// The parser leaves a method's receiver type parameters unresolved; they are locals of the
	// method all the same.
	recvParams := map[string]bool{}
	if fd, ok := d.node.(*ast.FuncDecl); ok && fd.Recv != nil && len(fd.Recv.List) > 0 {
		t := ast.Unparen(fd.Recv.List[0].Type)
		if st, ok := t.(*ast.StarExpr); ok {
			t = ast.Unparen(st.X)
		}
		var params []ast.Expr
		switch t := t.(type) {
		case *ast.IndexExpr:
			params = []ast.Expr{t.Index}
		case *ast.IndexListExpr:
			params = t.Indices
		}
		for _, x := range params {
			if id, ok := x.(*ast.Ident); ok && id.Name != "_" {
				recvParams[id.Name] = true
			}
		}
	}
	local := func(id *ast.Ident) bool {
		if id.Obj == nil {
			return recvParams[id.Name]
		}
		return f.ast.Scope.Lookup(id.Name) != id.Obj
	}
	bare := func(id *ast.Ident, soft bool) {
		if id.Name == "_" {
			return
		}
		d.refs = append(d.refs, lofRef{name: id.Name, in: f.pkg, file: f, alts: f.dots, bare: true, soft: soft && id.Obj == nil})
	}
	var visit func(n ast.Node)
	var callee func(fun ast.Expr)
	ident := func(id *ast.Ident, call bool) {
		if local(id) {
			d.dyn = d.dyn || call
			return
		}
		bare(id, false)
	}
	selector := func(x *ast.SelectorExpr, call bool) {
		if id, ok := x.X.(*ast.Ident); ok && id.Obj == nil {
			if id.Name == "C" && f.cgo {
				// C code reaches Go only through //export functions, which are roots.
				return
			}
			if ip := w.importFor(f, id.Name); ip != "" {
				d.refs = append(d.refs, lofRef{pkg: ip, name: x.Sel.Name, file: f})
				return
			}
		}
		d.called = append(d.called, x.Sel.Name)
		d.dyn = d.dyn || call
		switch x.Sel.Name {
		case "Call", "CallSlice", "Method", "MethodByName":
			// Keyed on the name alone: a reflect.Value can come from a package the file does not
			// import.
			d.reflect = true
		}
		visit(x.X)
	}
	callee = func(fun ast.Expr) {
		switch fun := ast.Unparen(fun).(type) {
		case *ast.Ident:
			ident(fun, true)
		case *ast.SelectorExpr:
			selector(fun, true)
		case *ast.IndexExpr:
			callee(fun.X)
			visit(fun.Index)
		case *ast.IndexListExpr:
			callee(fun.X)
			for _, ix := range fun.Indices {
				visit(ix)
			}
		case *ast.FuncLit, *ast.ArrayType, *ast.ChanType, *ast.FuncType, *ast.MapType,
			*ast.InterfaceType, *ast.StructType, *ast.StarExpr:
			visit(fun)
		default:
			d.dyn = true
			visit(fun)
		}
	}
	visit = func(n ast.Node) {
		if n == nil {
			return
		}
		ast.Inspect(n, func(x ast.Node) bool {
			switch x := x.(type) {
			case *ast.CallExpr:
				callee(x.Fun)
				for _, a := range x.Args {
					visit(a)
				}
				return false
			case *ast.SelectorExpr:
				selector(x, false)
				return false
			case *ast.Ident:
				ident(x, false)
				return false
			case *ast.KeyValueExpr:
				if id, ok := x.Key.(*ast.Ident); ok {
					if id.Obj == nil || !local(id) {
						bare(id, true)
					}
					visit(x.Value)
					return false
				}
			case *ast.TypeAssertExpr:
				if _, ok := ast.Unparen(x.Type).(*ast.InterfaceType); !ok && x.Type != nil {
					d.asserts = true
				}
			case *ast.TypeSwitchStmt:
				d.asserts = true
			case *ast.BranchStmt:
				return false
			case *ast.LabeledStmt:
				visit(x.Stmt)
				return false
			case *ast.Field:
				visit(x.Type)
				return false
			case *ast.FuncDecl:
				if x.Recv != nil {
					visit(x.Recv)
				}
				visit(x.Type)
				if x.Body != nil {
					visit(x.Body)
				}
				return false
			case *ast.TypeSpec:
				if x.TypeParams != nil {
					visit(x.TypeParams)
				}
				visit(x.Type)
				return false
			case *ast.ValueSpec:
				if x.Type != nil {
					visit(x.Type)
				}
				for _, v := range x.Values {
					visit(v)
				}
				return false
			}
			return true
		})
	}
	visit(d.node)
}

// lofWalk is one left-out file's closure in progress.
type lofWalk struct {
	w     *lofWorld
	out   *lofClosure
	epoch int
	// base is the epoch of the walk this one continues: what it queued counts as queued.
	base    int
	own     *lofPkg
	touched map[*lofFile]bool
	entered map[*lofPkg]bool
	called  map[string]bool
	asmDone map[*lofAsm]bool
	queue   []*lofDecl
	stopped bool
}

// closure walks the declaration closure of the left-out file at path, a file of the package at
// pkgPath (loaded, or not). Every declaration of the file is a root; so are the initializers of
// every package the closure enters and the //export functions of its cgo files. Loaded
// declarations are terminals, not walked.
func (w *lofWorld) closure(path, pkgPath string) *lofClosure {
	out := newLofClosure()
	src, err := os.ReadFile(path)
	if err != nil {
		out.fail(lofMissingSource)
		return out
	}
	x, err := fileConstraint(src)
	if err != nil {
		out.fail(lofParseError)
		return out
	}
	if w.excluded(x) {
		out.excluded = true
		return out
	}
	af, err := parser.ParseFile(token.NewFileSet(), path, src, parser.PackageClauseOnly)
	if err != nil {
		out.fail(lofParseError)
		return out
	}
	// go/build never compiles a documentation clause into the package. A _test clause in a file not
	// named _test.go is an ordinary package name to it, so such a file is walked (and fails closed).
	if af.Name.Name == "documentation" {
		out.excluded = true
		return out
	}
	own := w.pkg(pkgPath)
	if own.name != af.Name.Name {
		own = w.pkgVariant(pkgPath, af.Name.Name)
	}
	// The package's files are named by the directory go list reports; path may reach the same
	// directory by another name (a symbolic link).
	if own.dir != "" && sameDir(filepath.Dir(path), own.dir) {
		path = filepath.Join(own.dir, filepath.Base(path))
	}
	if w.dropped[path] {
		return &lofClosure{excluded: true, dropped: true}
	}
	var file *lofFile
	for _, f := range own.files {
		if f.path == path {
			file = f
		}
	}
	if file == nil {
		switch {
		case own.missing != "":
			out.fail(own.missing)
		case len(own.errs) > 0:
			out.fail(own.errs[0])
		default:
			out.fail(lofMissingSource)
		}
		return out
	}
	for _, d := range file.decls {
		if d.recv != "" && own.loaded != nil {
			if tn, ok := own.loaded.Types.Scope().Lookup(d.recv).(*types.TypeName); ok && !slices.Contains(out.newMeth, tn) {
				out.newMeth = append(out.newMeth, tn)
			}
		}
	}
	k := w.continued(own)
	k.out.newMeth = out.newMeth
	out = k.out
	for _, d := range file.decls {
		k.push(d)
	}
	k.touch(file)
	k.drain()
	if len(out.unres)+len(out.unresQ) == 0 || k.stopped {
		return out
	}
	// A name no declaration has leaves the closure open unless the file that names it never
	// compiles (uncompilable); then the walk restarts without that file.
	var files []*lofFile
	bare := map[*lofFile][]string{}
	qual := map[*lofFile][]lofRef{}
	for _, r := range out.unres {
		if !slices.Contains(files, r.file) {
			files = append(files, r.file)
		}
		bare[r.file] = append(bare[r.file], r.name)
	}
	for _, r := range out.unresQ {
		if !slices.Contains(files, r.file) {
			files = append(files, r.file)
		}
		qual[r.file] = append(qual[r.file], r)
	}
	var drop []string
	for _, f := range files {
		if item := w.uncompilable(f, bare[f], qual[f]); item != "" {
			out.fail(item)
			return out
		}
		drop = append(drop, f.path)
	}
	for _, d := range drop {
		w.dropped[d] = true
	}
	w.base = nil
	for key, p := range w.pkgs {
		if slices.ContainsFunc(p.files, func(f *lofFile) bool { return w.dropped[f.path] }) {
			delete(w.pkgs, key)
		}
	}
	if w.dropped[path] {
		return &lofClosure{excluded: true, dropped: true}
	}
	return w.closure(path, pkgPath)
}

// continued returns a walk of own's closure, continued from a copy of the walk of own's roots
// alone (its initializers, exports and files), which the files of own that follow in turn share.
// The closure is the least fixed point of its roots, so the continued walk reaches what one rooted
// at the file and own together does.
func (w *lofWorld) continued(own *lofPkg) *lofWalk {
	if w.base == nil || w.base.own != own {
		w.epoch++
		w.base = &lofWalk{w: w, out: newLofClosure(), epoch: w.epoch, own: own, touched: map[*lofFile]bool{}, entered: map[*lofPkg]bool{}, called: map[string]bool{}, asmDone: map[*lofAsm]bool{}}
		w.base.enter(own)
		w.base.drain()
	}
	b := w.base
	w.epoch++
	return &lofWalk{w: w, out: b.out.clone(), epoch: w.epoch, base: b.epoch, own: own, touched: maps.Clone(b.touched), entered: maps.Clone(b.entered), called: maps.Clone(b.called), asmDone: maps.Clone(b.asmDone), stopped: b.stopped}
}

// sameDir reports whether a and b name the same directory.
func sameDir(a, b string) bool {
	if a == b {
		return true
	}
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	return err == nil && os.SameFile(ai, bi)
}

// uncompilable proves that the Go file f, which names identifiers no declaration has, compiles in
// no build. It returns "" when proved, and otherwise what the closure fails closed on.
//
// A qualified reference qual names a standard-library package, which the toolchain's own source
// holds whole: when no Go file of that package, under any build constraint, declares the name
// (stdAbsent), every build of f fails on it. go/types, checking f alone, must report each of them
// undefined. Any one unproved is lofUnresolvedName.
//
// With no qualified reference, the bare identifiers carry the proof: go/types, checking f alone,
// must report each undefined (as "undefined: name", or as an undefined array length), and the file
// is lofUnresolvedName when a name could come from a file the check does not see:
//
//   - f dot-imports a package;
//   - the package's source set is incomplete: its directory, or a Go file in it, cannot be read or
//     parsed;
//   - a name begins with "_" and a file of the package uses cgo (import "C"), whose generated Go
//     declares such names;
//   - the directory holds a SWIG interface, whose generated Go may declare any name;
//   - the package lies outside the module cache and the toolchain's source (fixedSource): any
//     other source may gain a file before the build compiles it, from a generator no file of the
//     package names;
//   - another file of the package, in any build variant (excluded ones and the ignore tag
//     included), declares the name.
//
// Either way the check is given the build's type information for every import of f the build
// loaded, so that a use of one does not cascade into an error, and fails every other import. It
// may report nothing else but failed imports, other identifiers that f's sibling files declare,
// and other names selected from a package it was given; otherwise the file is
// lofVariantTypecheck.
func (w *lofWorld) uncompilable(f *lofFile, bare []string, qual []lofRef) string {
	byQual := len(qual) > 0
	imports := map[string]*types.Package{}
	for _, r := range qual {
		lp := w.loaded[r.pkg]
		if lp == nil || !w.stdAbsent(w.pkg(r.pkg), r.name) {
			return lofUnresolvedName
		}
		imports[r.pkg] = lp.Types
	}
	dir := filepath.Dir(f.path)
	if f.pkg.missing != "" || len(f.pkg.errs) > 0 || !byQual && (len(f.dots) > 0 || !w.fixedSource(dir)) {
		return lofUnresolvedName
	}
	clause := f.ast.Name.Name
	ents, err := os.ReadDir(dir)
	if err != nil {
		return lofUnresolvedName
	}
	underscore := slices.ContainsFunc(bare, func(n string) bool { return strings.HasPrefix(n, "_") })
	siblings := map[string]bool{}
	for _, e := range ents {
		n := e.Name()
		if !byQual && (strings.HasSuffix(n, ".swig") || strings.HasSuffix(n, ".swigcxx")) {
			return lofUnresolvedName
		}
		if e.IsDir() || !strings.HasSuffix(n, ".go") {
			continue
		}
		full := filepath.Join(dir, n)
		src, err := os.ReadFile(full)
		if err != nil {
			return lofUnresolvedName
		}
		if strings.HasSuffix(n, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), full, src, parser.SkipObjectResolution)
		if err != nil {
			return lofUnresolvedName
		}
		if af.Name.Name != clause {
			continue
		}
		if !byQual && underscore {
			for _, im := range af.Imports {
				if im.Path.Value == `"C"` {
					return lofUnresolvedName
				}
			}
		}
		if full == f.path {
			continue
		}
		for _, n := range lofPackageNames(af) {
			// A dropped file compiles in no build, so no build that compiles f has its names.
			if !byQual && slices.Contains(bare, n) && !w.dropped[full] {
				return lofUnresolvedName
			}
			siblings[n] = true
		}
	}
	fset := token.NewFileSet()
	af, err := parser.ParseFile(fset, f.path, nil, parser.SkipObjectResolution)
	if err != nil {
		return lofUnresolvedName
	}
	// The checker also gets every other import the build loaded, so that a use of one does not
	// cascade into an error. Only imports confirms a name; any error left still withholds.
	given := lofGivenImporter{"unsafe": types.Unsafe}
	for _, im := range af.Imports {
		ip, _ := strconv.Unquote(im.Path.Value)
		if lp := w.loaded[ip]; lp != nil && lp.Types != nil {
			given[ip] = lp.Types
		}
	}
	maps.Copy(given, imports)
	confirmed := map[string]bool{}
	other := false
	conf := types.Config{
		Importer: given,
		Error: func(err error) {
			te, ok := err.(types.Error)
			if !ok {
				other = true
				return
			}
			undef, isUndef := strings.CutPrefix(te.Msg, "undefined: ")
			if n, ok := strings.CutPrefix(te.Msg, "undefined array length "); ok {
				undef, isUndef = strings.TrimSuffix(n, " or missing type constraint"), true
			}
			x, sel, isSel := strings.Cut(undef, ".")
			switch {
			case isUndef && isSel && imports[w.importFor(f, x)] != nil:
				confirmed[w.importFor(f, x)+"."+sel] = true
			case isUndef && slices.Contains(bare, undef):
				confirmed[undef] = true
			case isUndef && siblings[undef]:
			case strings.HasPrefix(te.Msg, "could not import "):
			default:
				other = true
			}
		},
	}
	_, _ = conf.Check(f.pkg.path, fset, []*ast.File{af}, nil)
	if other {
		return lofVariantTypecheck
	}
	if byQual {
		for _, r := range qual {
			if !confirmed[r.pkg+"."+r.name] {
				return lofVariantTypecheck
			}
		}
		return ""
	}
	for _, n := range bare {
		if !confirmed[n] {
			return lofVariantTypecheck
		}
	}
	return ""
}

// stdAbsent reports whether no Go file of the standard-library package p declares name, under any
// build constraint: p is read from the build toolchain's own source, every non-test Go file in its
// directory. A name beginning with "_" may be one cgo generates, and is never proved absent.
func (w *lofWorld) stdAbsent(p *lofPkg, name string) bool {
	if !p.std || w.goroot == "" || strings.HasPrefix(name, "_") || !lofUnder(p.dir, filepath.Join(w.goroot, "src")) {
		return false
	}
	names, ok := w.stdNames[p.dir]
	if !ok {
		names = lofDirNames(p.dir)
		w.stdNames[p.dir] = names
	}
	return names != nil && !names[name]
}

// lofDirNames returns the names every non-test Go file in dir declares at package level, or nil
// when the directory or one of them cannot be read or parsed.
func lofDirNames(dir string) map[string]bool {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	names := map[string]bool{}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, n), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil
		}
		for _, name := range lofPackageNames(af) {
			names[name] = true
		}
	}
	return names
}

// fixedSource reports whether dir lies in a module the go command extracted into the module cache
// (below a "path@version" directory) or in the toolchain's source, which the build compiles as they
// are: nothing is generated there before it. A directory in the tree being built never is, wherever
// that tree lies.
func (w *lofWorld) fixedSource(dir string) bool {
	if w.buildDir == "" || filepath.Clean(dir) == filepath.Clean(w.buildDir) || lofUnder(dir, w.buildDir) {
		return false
	}
	if w.goroot != "" && lofUnder(dir, filepath.Join(w.goroot, "src")) {
		return true
	}
	if w.modcache == "" || !lofUnder(dir, w.modcache) {
		return false
	}
	rel, _ := filepath.Rel(w.modcache, dir)
	parts := strings.Split(filepath.ToSlash(rel), "/")
	return parts[0] != "cache" && slices.ContainsFunc(parts, func(p string) bool { return strings.Contains(p, "@") })
}

// lofUnder reports whether path lies below root.
func lofUnder(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// lofPackageNames returns the names a file declares at package level.
func lofPackageNames(af *ast.File) []string {
	var out []string
	for _, d := range af.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				out = append(out, d.Name.Name)
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch spec := spec.(type) {
				case *ast.ValueSpec:
					for _, n := range spec.Names {
						out = append(out, n.Name)
					}
				case *ast.TypeSpec:
					out = append(out, spec.Name.Name)
				}
			}
		}
	}
	return out
}

// lofGivenImporter imports only the packages it holds, by import path, and fails every other
// import, so go/types checks a file against its own declarations and those packages only.
type lofGivenImporter map[string]*types.Package

func (g lofGivenImporter) Import(path string) (*types.Package, error) {
	if p := g[path]; p != nil {
		return p, nil
	}
	return nil, fmt.Errorf("not loaded: %s", path)
}

// push queues d for walking.
func (k *lofWalk) push(d *lofDecl) {
	if d.seen == k.epoch || k.base != 0 && d.seen == k.base {
		return
	}
	d.seen = k.epoch
	k.queue = append(k.queue, d)
}

func (k *lofWalk) drain() {
	for len(k.queue) > 0 && !k.stopped {
		d := k.queue[0]
		k.queue = k.queue[1:]
		k.out.decls++
		if k.out.decls > lofBudgetDecls || time.Now().After(k.w.deadline) || k.w.ctx.Err() != nil {
			k.out.fail(lofBudget)
			k.stopped = true
			return
		}
		k.walk(d)
	}
}

// fail records a fail-closed item raised in package p: inside the toolchain's own packages, a
// linkname, assembly or bodyless item fails closed for a standard-library refutation only, since
// that code calls module code only through the values and method names the walk follows.
func (k *lofWalk) fail(p *lofPkg, item string) {
	if p != nil && p.std && (item == lofLinkname || item == lofAsmSymbol || item == lofBodyless) {
		k.out.failStd(item)
		return
	}
	k.out.fail(item)
}

// touch links what compiling f links: the packages it imports, whose initializers run, and the
// targets of its //go:linkname directives.
func (k *lofWalk) touch(f *lofFile) {
	if k.touched[f] {
		return
	}
	k.touched[f] = true
	if f.badLink {
		k.fail(f.pkg, lofLinkname)
	}
	for _, ip := range f.all {
		k.ref(lofRef{pkg: ip, file: f})
	}
	locals := make([]string, 0, len(f.links))
	for l := range f.links {
		locals = append(locals, l)
	}
	sort.Strings(locals)
	for _, l := range locals {
		k.remote(f.pkg, f.links[l])
	}
}

// enter links package p. A package the build did not load contributes its initializers, the
// //export functions of its cgo files, the methods of the names the closure has called, and its
// files' imports and directives; a loaded package contributes its initializer as a terminal, the
// rest being in the loaded program already.
func (k *lofWalk) enter(p *lofPkg) {
	if k.entered[p] {
		return
	}
	k.entered[p] = true
	if p.missing != "" {
		k.out.fail(p.missing)
		return
	}
	for _, e := range p.errs {
		k.out.fail(e)
	}
	if p.loaded != nil {
		k.out.inits[p.loaded.Types] = true
		return
	}
	for _, d := range p.inits {
		k.push(d)
	}
	for _, d := range p.exports {
		k.push(d)
	}
	for m := range k.called {
		for _, d := range p.methods[m] {
			k.push(d)
		}
	}
	for _, f := range p.files {
		k.touch(f)
	}
}

// walk follows d's references.
func (k *lofWalk) walk(d *lofDecl) {
	f := d.file
	p := f.pkg
	k.touch(f)
	k.w.refsOf(d)
	switch n := d.node.(type) {
	case *ast.FuncDecl:
		if d.src == "" {
			d.src = d.name
			if d.recv != "" {
				d.src = d.recv + "." + d.name
			}
		}
		k.out.src[[2]string{p.path, d.src}] = true
		if n.Body == nil && d.recv == "" {
			k.bodyless(d, n)
		}
	case *ast.TypeSpec:
		// A value of the type may reach code that calls any of its methods by interface.
		for _, m := range p.byRecv[d.name] {
			k.push(m)
		}
	}
	for _, r := range d.refs {
		k.ref(r)
	}
	k.out.dyn = k.out.dyn || d.dyn
	k.out.reflect = k.out.reflect || d.reflect
	k.out.asserts = k.out.asserts || d.asserts
	for _, m := range d.called {
		k.out.methods[m] = true
		k.out.sink = k.out.sink || k.w.carrier(m)
		k.out.held = k.out.held || k.w.holder(m)
		if k.called[m] {
			continue
		}
		k.called[m] = true
		for q := range k.entered {
			if q.loaded == nil {
				for _, md := range q.methods[m] {
					k.push(md)
				}
			}
		}
	}
}

// ref follows one reference.
func (k *lofWalk) ref(r lofRef) {
	if r.bare {
		if k.resolveIn(r.in, r.name) {
			return
		}
		for _, ip := range r.alts {
			q := k.w.pkg(ip)
			k.enter(q)
			if k.resolveIn(q, r.name) {
				return
			}
		}
		if lofUniverse[r.name] || r.soft {
			return
		}
		k.out.unres = append(k.out.unres, r)
		return
	}
	if r.pkg == "unsafe" {
		return
	}
	p := k.w.pkg(r.pkg)
	k.enter(p)
	if r.name == "" || p.missing != "" {
		return
	}
	if !k.resolveIn(p, r.name) {
		if p.std {
			k.out.unresQ = append(k.out.unresQ, r)
			return
		}
		k.out.fail(lofUnresolvedName)
	}
}

// resolveIn follows the declarations named name in p: a loaded one as a terminal, and every source
// one; reporting whether there is one, or an assembly symbol of that name.
func (k *lofWalk) resolveIn(p *lofPkg, name string) bool {
	found := false
	if p.loaded != nil {
		if obj := p.loaded.Types.Scope().Lookup(name); obj != nil {
			k.terminal(obj)
			found = true
		}
	}
	for _, d := range p.decls[name] {
		k.push(d)
		found = true
	}
	if !p.asmNames[name] {
		return found
	}
	sym := p.path + "." + name
	for _, b := range p.asmText[sym] {
		k.walkAsm(p, b)
		found = true
	}
	return found || p.asmData[sym]
}

// terminal records a loaded declaration the closure reaches.
func (k *lofWalk) terminal(obj types.Object) {
	switch o := obj.(type) {
	case *types.Func:
		k.out.funcs[o.Origin()] = true
		sig := o.Signature()
		k.out.sink = k.out.sink || lofHoldsDispatch(sig.Params(), nil) || lofCarriesIn(sig.Results(), nil)
		k.out.held = k.out.held || lofHoldsDispatch(sig.Results(), nil)
		if r := sig.Recv(); r != nil {
			k.out.sink = k.out.sink || lofCarriesIn(r.Type(), nil)
		}
	case *types.TypeName:
		k.out.types[o] = true
		k.out.sink = k.out.sink || lofHoldsDispatch(o.Type(), nil)
	case *types.Var:
		k.out.vars = true
		k.out.sink = k.out.sink || lofHoldsDispatch(o.Type(), nil)
	}
}

// lofCarriesIn reports whether loaded code that hands out a value of type t can receive through it
// a value holding an interface or a func: an interface or a func carries one in only through its
// methods' or its own parameters, or what its methods or it return; anything else through any
// part that can hold one. Methods called on the value by name are lofWorld.carrier's, and a
// dynamic type asserted out of an interface lofClosure.held's.
func lofCarriesIn(t types.Type, seen map[types.Type]bool) bool {
	if tu, ok := t.(*types.Tuple); ok {
		for i := 0; i < tu.Len(); i++ {
			if lofCarriesIn(tu.At(i).Type(), seen) {
				return true
			}
		}
		return false
	}
	t = types.Unalias(t)
	if _, ok := t.(*types.Named); ok {
		if seen[t] {
			return false
		}
		if seen == nil {
			seen = map[types.Type]bool{}
		}
		seen[t] = true
	}
	switch u := t.Underlying().(type) {
	case *types.Interface:
		for i := 0; i < u.NumMethods(); i++ {
			if sig := u.Method(i).Signature(); lofHoldsDispatch(sig.Params(), nil) || lofCarriesIn(sig.Results(), seen) {
				return true
			}
		}
		return false
	case *types.Signature:
		return lofHoldsDispatch(u.Params(), nil) || lofCarriesIn(u.Results(), seen)
	}
	return lofHoldsDispatch(t, nil)
}

// lofHoldsDispatch reports whether a value of type t can hold an interface or a func: either is,
// or contains one through a pointer, slice, array, map, channel, struct field or tuple element. A
// type parameter may be instantiated with either.
func lofHoldsDispatch(t types.Type, seen map[types.Type]bool) bool {
	switch t := t.(type) {
	case nil:
		return false
	case *types.Named:
		if seen[t] {
			return false
		}
		if seen == nil {
			seen = map[types.Type]bool{}
		}
		seen[t] = true
		return lofHoldsDispatch(t.Underlying(), seen)
	case *types.Alias:
		return lofHoldsDispatch(types.Unalias(t), seen)
	case *types.Interface, *types.Signature, *types.TypeParam:
		return true
	case *types.Basic:
		return t.Kind() == types.UnsafePointer
	case *types.Pointer:
		return lofHoldsDispatch(t.Elem(), seen)
	case *types.Slice:
		return lofHoldsDispatch(t.Elem(), seen)
	case *types.Array:
		return lofHoldsDispatch(t.Elem(), seen)
	case *types.Chan:
		return lofHoldsDispatch(t.Elem(), seen)
	case *types.Map:
		return lofHoldsDispatch(t.Key(), seen) || lofHoldsDispatch(t.Elem(), seen)
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if lofHoldsDispatch(t.Field(i).Type(), seen) {
				return true
			}
		}
	case *types.Tuple:
		for i := 0; i < t.Len(); i++ {
			if lofHoldsDispatch(t.At(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}

// carrier reports whether a method named name of some loaded type can carry a value into loaded
// code: a loaded value's dynamic type is a loaded one, and every method a call by name can
// dispatch to is declared on a package-level type of a loaded package, or promoted from one.
func (w *lofWorld) carrier(name string) bool {
	w.methodIndex()
	return w.carriers[name]
}

// holder reports whether a method named name of some loaded type returns a value that holds an
// interface or a func, whose dynamic type the closure may assert.
func (w *lofWorld) holder(name string) bool {
	w.methodIndex()
	return w.holders[name]
}

func (w *lofWorld) methodIndex() {
	if w.carriers == nil {
		w.carriers, w.holders = map[string]bool{}, map[string]bool{}
		for _, lp := range w.loaded {
			sc := lp.Types.Scope()
			for _, n := range sc.Names() {
				tn, ok := sc.Lookup(n).(*types.TypeName)
				if !ok {
					continue
				}
				nt, ok := types.Unalias(tn.Type()).(*types.Named)
				if !ok {
					continue
				}
				for i := 0; i < nt.NumMethods(); i++ {
					m := nt.Method(i)
					sig := m.Signature()
					if lofHoldsDispatch(sig.Params(), nil) || lofCarriesIn(sig.Results(), nil) {
						w.carriers[m.Name()] = true
					}
					if lofHoldsDispatch(sig.Results(), nil) {
						w.holders[m.Name()] = true
					}
				}
			}
		}
	}
}

// remote follows a //go:linkname remote ("path.name", "path.T.m", "path.(*T).m") named in package
// from. One the walk cannot find fails closed; inside the toolchain's own packages, for a
// standard-library refutation only.
func (k *lofWalk) remote(from *lofPkg, remote string) {
	slash := strings.LastIndexByte(remote, '/')
	dot := strings.IndexByte(remote[slash+1:], '.')
	if dot < 0 {
		k.fail(from, lofLinkname)
		return
	}
	path, sym := remote[:slash+1+dot], remote[slash+1+dot+1:]
	if path == "unsafe" {
		return
	}
	p := k.w.pkg(path)
	k.enter(p)
	recv, name, isMethod := strings.Cut(sym, ".")
	found := false
	if !isMethod {
		found = p.missing == "" && k.resolveIn(p, sym)
	} else {
		recv = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(recv, "("), "*"), ")")
		if p.loaded != nil {
			if tn, ok := p.loaded.Types.Scope().Lookup(recv).(*types.TypeName); ok {
				if obj, _, _ := types.LookupFieldOrMethod(types.NewPointer(tn.Type()), true, tn.Pkg(), name); obj != nil {
					k.terminal(obj)
					found = true
				}
			}
		}
		for _, d := range p.byRecv[recv] {
			if d.name == name {
				k.push(d)
				found = true
			}
		}
	}
	if !found {
		if p.std {
			k.out.failStd(lofLinkname)
		} else {
			k.fail(from, lofLinkname)
		}
	}
}

// bodyless resolves a function declared without a body: a //go:linkname pull names its body (an
// edge touch follows), a push from another package or an assembly TEXT symbol of its own package
// provides it, the host provides it (//go:wasmimport: foreign code, a dynamic call), or the
// compiler expands it inline. Anything else fails closed.
func (k *lofWalk) bodyless(d *lofDecl, fn *ast.FuncDecl) {
	p := d.file.pkg
	if d.file.links[d.name] != "" {
		return
	}
	if wasmImport(fn) {
		k.out.dyn = true
		return
	}
	sym := p.path + "." + d.name
	found := false
	for _, b := range p.asmText[sym] {
		k.walkAsm(p, b)
		found = true
	}
	k.w.readPushes()
	for _, push := range k.w.pushes[sym] {
		if k.pushBody(push[0], push[1]) {
			found = true
		}
	}
	if !found && !k.w.intrinsic(sym) {
		k.fail(p, lofBodyless)
	}
}

// pushBody follows the function local of the Go file at path, which pushes its body to a
// bodyless declaration, reporting whether it found it.
func (k *lofWalk) pushBody(path, local string) bool {
	for _, lp := range k.w.loaded {
		if slices.Contains(lp.GoFiles, path) {
			if obj := lp.Types.Scope().Lookup(local); obj != nil {
				k.terminal(obj)
				return true
			}
			return false
		}
	}
	for _, p := range k.w.pkgs {
		for _, f := range p.files {
			if f.path != path {
				continue
			}
			for _, d := range p.decls[local] {
				k.push(d)
				return true
			}
		}
	}
	return false
}

// readPushes records the //go:linkname directives of every loaded package's files, compiled or
// left out. A package parsed later records its own as it is indexed.
func (w *lofWorld) readPushes() {
	if w.pushesRead {
		return
	}
	w.pushesRead = true
	for _, lp := range w.loaded {
		for _, path := range lp.GoFiles {
			src, err := os.ReadFile(path)
			if err != nil || !bytes.Contains(src, []byte("//go:linkname")) {
				continue
			}
			sc := bufio.NewScanner(bytes.NewReader(src))
			sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
			for sc.Scan() {
				local, remote, ok := parseLinkname(strings.TrimSpace(sc.Text()))
				if ok && local != "" && remote != "" && remote != "\x00" {
					w.pushes[remote] = append(w.pushes[remote], [2]string{path, local})
				}
			}
		}
	}
}

// intrinsicCall matches an entry of the compiler's intrinsic table: add, addF or alias, then the
// package path and function name.
var intrinsicCall = regexp.MustCompile(`\b(?:add|addF|alias)\(\s*"([^"]+)",\s*"([^"]+)"`)

// intrinsic reports whether the toolchain's compiler lists the function path.Name as an intrinsic
// for some architecture: a bodyless function it expands inline, calling no Go code. An unreadable
// table lists nothing.
func (w *lofWorld) intrinsic(name string) bool {
	if w.intrinsics == nil {
		w.intrinsics = map[string]bool{}
		if w.goroot != "" {
			src, err := os.ReadFile(filepath.Join(w.goroot, "src", "cmd", "compile", "internal", "ssagen", "intrinsics.go"))
			if err == nil {
				for _, m := range intrinsicCall.FindAllSubmatch(src, -1) {
					w.intrinsics[string(m[1])+"."+string(m[2])] = true
				}
			}
		}
	}
	return w.intrinsics[name]
}

// wasmImport reports whether fn is declared //go:wasmimport.
func wasmImport(fn *ast.FuncDecl) bool {
	if fn.Doc == nil {
		return false
	}
	for _, c := range fn.Doc.List {
		if strings.HasPrefix(c.Text, "//go:wasmimport ") {
			return true
		}
	}
	return false
}

// walkAsm follows an assembly body's symbol references: "path.name" to a Go declaration or an
// assembly symbol of that package, a file-local "name<>" to its file's, and a bare symbol to p's
// own, else to foreign code, a dynamic call. A qualified or file-local symbol the walk cannot find
// fails closed.
func (k *lofWalk) walkAsm(p *lofPkg, body *lofAsm) {
	if k.asmDone[body] {
		return
	}
	k.asmDone[body] = true
	k.out.dyn = k.out.dyn || body.dynamic
	for _, ref := range body.refs {
		switch {
		case strings.HasSuffix(ref, "<>"):
			bodies, ok := p.asmText[ref]
			for _, b := range bodies {
				k.walkAsm(p, b)
			}
			if !ok && !p.asmData[ref] {
				k.fail(p, lofAsmSymbol)
			}
		case strings.Contains(ref, "."):
			dot := strings.LastIndexByte(ref, '.')
			path, name := ref[:dot], ref[dot+1:]
			if path != p.path && path == p.path[strings.LastIndexByte(p.path, '/')+1:] {
				// Some assembly qualifies its own package's symbols by the package name alone.
				path = p.path
			}
			t := p
			if path != p.path {
				t = k.w.pkg(path)
				k.enter(t)
			}
			if t.missing != "" || !k.resolveIn(t, name) {
				if t.std {
					k.out.failStd(lofAsmSymbol)
				} else {
					k.fail(p, lofAsmSymbol)
				}
			}
		default:
			bodies, ok := p.asmText[ref]
			for _, b := range bodies {
				k.walkAsm(p, b)
			}
			if !ok && !p.asmData[ref] {
				k.out.dyn = true
			}
		}
	}
}

// asmName indexes sym under asmNames when it names a symbol of p.
func (p *lofPkg) asmName(sym string) {
	if name, ok := strings.CutPrefix(sym, p.path+"."); ok {
		if p.asmNames == nil {
			p.asmNames = map[string]bool{}
		}
		p.asmNames[name] = true
	}
}

// parseAsm records an assembly file's TEXT bodies, with the symbols each references, and its data
// symbols. A symbol is "pkgpath.name" for the Go-visible form ("·name", "pkg∕path·name"),
// "file:name<>" for a file-local one, and the bare name otherwise. A reference made by a macro the
// file defines or includes from its own directory counts for every body of the file. A call or
// jump through a register is a dynamic call.
func parseAsm(p *lofPkg, path string, src []byte, headers []string) {
	norm := func(sym string) string {
		if i := strings.IndexByte(sym, '<'); i >= 0 && !strings.HasSuffix(sym, "<>") {
			sym = sym[:i]
		}
		if strings.HasSuffix(sym, "<>") {
			return path + ":" + strings.TrimPrefix(sym, "·")
		}
		pkg, name, ok := strings.Cut(sym, "·")
		if !ok {
			return sym
		}
		if pkg == "" {
			pkg = p.path
		}
		return strings.ReplaceAll(pkg, "∕", "/") + "." + name
	}
	var shared []string
	var bodies []*lofAsm
	var cur *lofAsm
	for _, h := range headers {
		if bytes.Contains(src, []byte(filepath.Base(h))) {
			if hs, err := os.ReadFile(h); err == nil {
				for _, l := range strings.Split(string(hs), "\n") {
					for _, ref := range asmRefs(l) {
						shared = append(shared, norm(ref))
					}
				}
			}
		}
	}
	for _, line := range strings.Split(string(src), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#define") || strings.HasSuffix(t, "\\") {
			for _, ref := range asmRefs(t) {
				shared = append(shared, norm(ref))
			}
			continue
		}
		fields := strings.Fields(t)
		if len(fields) == 0 {
			continue
		}
		op := fields[0]
		if strings.HasSuffix(op, ":") && len(fields) > 1 {
			op = fields[1]
		}
		switch op {
		case "TEXT":
			refs := asmRefs(t)
			if len(refs) == 0 {
				cur = nil
				continue
			}
			cur = &lofAsm{file: path}
			sym := norm(refs[0])
			p.asmText[sym] = append(p.asmText[sym], cur)
			p.asmName(sym)
			bodies = append(bodies, cur)
			continue
		case "GLOBL", "DATA":
			for _, ref := range asmRefs(t) {
				p.asmData[norm(ref)] = true
				p.asmName(norm(ref))
			}
			continue
		}
		if cur == nil {
			continue
		}
		for _, ref := range asmRefs(t) {
			cur.refs = append(cur.refs, norm(ref))
		}
		if asmIndirect(fields) {
			cur.dynamic = true
		}
	}
	for _, b := range bodies {
		b.refs = append(b.refs, shared...)
	}
}

// asmRefs returns the symbols a line of assembly references as name(SB).
func asmRefs(line string) []string {
	var out []string
	for rest := line; ; {
		i := strings.Index(rest, "(SB)")
		if i < 0 {
			return out
		}
		j := i
		for j > 0 && !strings.ContainsRune(" \t,$*()", rune(rest[j-1])) {
			j--
		}
		sym := rest[j:i]
		// An offset, numeric or a constant's name, follows the symbol.
		if k := strings.IndexAny(sym, "+-"); k > 0 {
			sym = sym[:k]
		}
		if sym != "" {
			out = append(out, sym)
		}
		rest = rest[i+4:]
	}
}

// asmIndirect reports whether an instruction is a call or jump to an address held in a register.
func asmIndirect(fields []string) bool {
	if strings.HasSuffix(fields[0], ":") {
		fields = fields[1:]
	}
	if len(fields) < 2 {
		return false
	}
	switch strings.ToUpper(fields[0]) {
	case "CALL", "JMP", "BL", "B", "BR", "BLR", "JAL", "JALR", "BCTRL", "BCTR":
	default:
		return false
	}
	target := strings.Join(fields[1:], " ")
	if strings.Contains(target, "(SB)") || strings.Contains(target, "(PC)") {
		return false
	}
	for _, r := range target {
		if r >= 'a' && r <= 'z' {
			// A label: registers are spelled in upper case.
			return strings.ContainsAny(target, "()*")
		}
	}
	return true
}

// lofToolchain finds the standard library source the release's go command builds from, which must
// be the release's own and read without an overlay; it returns that GOROOT, or the fail-closed
// item when it cannot.
func lofToolchain(ctx context.Context, buildDir string, env []string, release *goRelease) (string, string) {
	if release == nil {
		return "", lofUnknownToolchain
	}
	if strings.Contains(envOr(env, "GOFLAGS", ""), "-overlay") {
		return "", lofGorootMismatch
	}
	cmd := exec.CommandContext(ctx, "go", "env", "GOROOT")
	cmd.Dir = buildDir
	cmd.Env = append(slices.Clone(env), "GOTOOLCHAIN="+release.toolchain())
	out, err := cmd.Output()
	root := strings.TrimSpace(string(out))
	if err != nil || root == "" {
		return "", lofUnknownToolchain
	}
	version, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		return "", lofUnknownToolchain
	}
	first, _, _ := strings.Cut(string(version), "\n")
	if r, ok := parseGoRelease(first); !ok || r != *release {
		return "", lofGorootMismatch
	}
	return root, ""
}

// lofModCache returns the module cache's root the build's go command reads modules from, or "".
func lofModCache(ctx context.Context, buildDir string, env []string) string {
	cmd := exec.CommandContext(ctx, "go", "env", "GOMODCACHE")
	cmd.Dir = buildDir
	cmd.Env = env
	out, err := cmd.Output()
	root := strings.TrimSpace(string(out))
	if err != nil || !filepath.IsAbs(root) {
		return ""
	}
	return root
}

// links returns the packages the build did not load that a file in dir can link, over every build
// variant of every package on the way: the imports of dir's non-test Go files, unioned, followed
// through each unloaded package's own files the same way. A loaded package is not followed: the
// build already links its imports. std marks dir as the standard library's, whose golang.org/x
// imports resolve to its vendored copies. What the walk cannot read or resolve fails closed.
func (w *lofWorld) links(dir string, std bool) (map[string]bool, []string) {
	key := dir
	if std {
		key = "std\x00" + dir
	}
	if l, ok := w.linkMemo[key]; ok {
		return l.pkgs, l.fc
	}
	var fc []string
	fail := func(item string) {
		if !slices.Contains(fc, item) {
			fc = append(fc, item)
		}
	}
	out := map[string]bool{}
	start, item := w.dirImports(dir, std)
	if item != "" {
		fail(item)
	}
	for frontier := start; len(frontier) > 0; {
		var todo []string
		for _, ip := range frontier {
			if out[ip] || ip == "unsafe" {
				continue
			}
			if _, ok := w.loaded[ip]; ok {
				continue
			}
			out[ip] = true
			todo = append(todo, ip)
		}
		w.resolve(todo)
		frontier = nil
		for _, ip := range todo {
			d := w.dirs[ip]
			if d == "" {
				fail(lofUnresolvedImport)
				continue
			}
			imps, item := w.dirImports(d, w.std[ip])
			if item != "" {
				fail(item)
			}
			frontier = append(frontier, imps...)
		}
	}
	w.linkMemo[key] = lofLinks{out, fc}
	return out, fc
}

// lofLinks is one directory's links result.
type lofLinks struct {
	pkgs map[string]bool
	fc   []string
}

// dirImports returns the imports of dir's non-test Go files that some described build compiles,
// unioned over every variant, with the fail-closed item for a directory or file it cannot read or
// parse.
func (w *lofWorld) dirImports(dir string, std bool) ([]string, string) {
	key := dir
	if std {
		key = "std\x00" + dir
	}
	if l, ok := w.importMemo[key]; ok {
		return l.imports, l.fc
	}
	imports, item := readDirImports(dir, std, w.excluded)
	w.importMemo[key] = lofDirImports{imports, item}
	return imports, item
}

type lofDirImports struct {
	imports []string
	fc      string
}

func readDirImports(dir string, std bool, excluded func(constraint.Expr) bool) ([]string, string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, lofMissingSource
	}
	seen := map[string]bool{}
	var out []string
	item := ""
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		full := filepath.Join(dir, n)
		src, err := os.ReadFile(full)
		if err != nil {
			item = lofMissingSource
			continue
		}
		x, err := fileConstraint(src)
		if err != nil {
			item = lofParseError
			continue
		}
		if excluded(x) {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), full, src, parser.ImportsOnly)
		if err != nil {
			item = lofParseError
			continue
		}
		if af.Name.Name == "documentation" {
			continue
		}
		for _, im := range af.Imports {
			ip, err := strconv.Unquote(im.Path.Value)
			if err != nil {
				item = lofParseError
				continue
			}
			if ip == "C" || ip == "unsafe" {
				continue
			}
			if std && !isStdlibPath(ip, nil) {
				ip = "vendor/" + ip
			}
			if !seen[ip] {
				seen[ip] = true
				out = append(out, ip)
			}
		}
	}
	return out, item
}
