package goanalysis

import (
	"bufio"
	"bytes"
	"context"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/tools/go/packages"
)

// escapeMode decides which values the scanned build creates Escape counts as reaching a dispatch site
// the build traced once left-out code has handled them.
type escapeMode int

const (
	// escapeAllBase counts every one, once the closure holds any left-out body.
	escapeAllBase escapeMode = iota
	// escapeImporters counts those whose type or function belongs to a package holding a left-out
	// body the closure reaches, or imported by the file of one: code that can name them.
	escapeImporters
)

// escapeBaseTypes is the escapeMode leftOutReachesSymbols applies.
var escapeBaseTypes = escapeAllBase

// The reasons leftOutReachesSymbols withholds for other than reaching a vulnerable symbol: each
// marks something the closure cannot follow or bound.
const (
	lofParseError       = "parse_error"
	lofMissingSource    = "missing_source"
	lofUnresolvedImport = "unresolved_import"
	lofUnknownToolchain = "unknown_toolchain"
	lofGorootMismatch   = "goroot_mismatch"
	lofCgo              = "cgo"
	lofLinkname         = "linkname"
	lofBodyless         = "bodyless"
	lofAsmSymbol        = "asm_symbol"
	lofReflectCall      = "reflect_call"
	lofBudget           = "budget"
	// lofReachesSymbol is the reason for reaching a vulnerable symbol, or any declaration of a
	// vulnerable package that lists none.
	lofReachesSymbol = "reaches_symbol"
)

// The closure's budget: past either bound it withholds (lofBudget).
var (
	lofBudgetDecls = 400000
	lofBudgetTime  = 10 * time.Minute
)

// lofReflectKeys are the declarations through which reached code calls what reflection hands it
// (reflectCallCallees, reflectMethodCallees).
var lofReflectKeys = map[string]bool{
	declKey("reflect", "Value", "Call"):                     true,
	declKey("reflect", "Value", "CallSlice"):                true,
	declKey("reflect", "Value", "Method"):                   true,
	declKey("reflect", "Value", "MethodByName"):             true,
	declKey("text/template", "Template", "Execute"):         true,
	declKey("text/template", "Template", "ExecuteTemplate"): true,
	declKey("html/template", "Template", "Execute"):         true,
	declKey("html/template", "Template", "ExecuteTemplate"): true,
}

// lofVerdict is what leftOutReachesSymbols found: whether to withhold, why (a lof reason), how many
// declarations the closure walked, the first vulnerable symbol it reached, and the chain of
// declarations, seed first, it was walking when it decided.
type lofVerdict struct {
	Withhold bool
	Reason   string
	Closure  int
	Hit      string
	Via      []string
}

// leftOutReachesSymbols reports whether code the build left out may reach one of the standard
// library's vulnerable symbols (vulnerable, by package path, "F" and "T.M"; a package listing none
// counts whole). Left-out code is every non-test Go file of a loaded package's directory that the
// build excluded and some build under release compiles, every file of a package only such code
// imports, and every main-module package the load never listed.
//
// The closure starts from what of that code can run in another build: a left-out declaration that
// replaces one the scanned build reaches (reached), or a method of a type it uses that an interface
// call it makes dispatches to; left-out init functions and package variables; those of each package
// left-out code links; left-out //go:linkname pushes; and the main, init and variables of an unlisted
// main-module package. It follows, by name over parsed source, never type-checked, every declaration
// a walked body names (each build's same-named declarations alike), every method of a type walked
// code mentions whose name a walked body selects with a compatible arity, linkname and assembly
// symbols, and the function values reached code creates once walked code makes a dynamic call. What
// the scanned build reaches is not walked again, except for the methods and function values of its
// own that a dispatch site it traced can call once left-out code hands them back (Escape, under
// escapeBaseTypes). Anything the closure cannot follow or bound withholds.
func leftOutReachesSymbols(ctx context.Context, pkgs []*packages.Package, vulnerable map[string][]string, reached *reachedBase, release goRelease, buildDir string, env []string) lofVerdict {
	a := newLofAnalysis(ctx, pkgs, vulnerable, reached, release, buildDir, env)
	a.run()
	v := lofVerdict{Closure: len(a.walked), Hit: a.hit, Reason: a.fail, Via: a.via}
	if a.hit != "" {
		v.Reason = lofReachesSymbol
	}
	v.Withhold = v.Reason != ""
	return v
}

type lofArity struct {
	n int
	// spread is a call whose single argument is a call (its results may be several); ellipsis
	// passes a slice as the variadic parameter. A selection that is not called has no arity: any.
	spread, ellipsis, any bool
}

// compatible reports whether a call of arity a can be one of a function with params parameters.
func (a lofArity) compatible(params int, variadic bool) bool {
	switch {
	case a.any || a.spread:
		return true
	case a.ellipsis:
		return variadic && a.n == params
	case variadic:
		return a.n >= params-1
	}
	return a.n == params
}

type lofDeclKind int

const (
	lofFunc lofDeclKind = iota
	lofVar
	lofConst
	lofType
)

type lofPkg struct {
	path, dir, name string
	loaded          bool
	files           []*lofFile
	decls           map[string][]*lofDecl // package-level name → declarations, every build's
	methods         map[string][]*lofDecl // receiver type name + "\x00" + method name → declarations
	asmText         map[string][]*lofAsm  // TEXT symbol → bodies
	asmData         map[string]bool       // GLOBL and DATA symbols
}

type lofFile struct {
	pkg      *lofPkg
	path     string
	fset     *token.FileSet
	ast      *ast.File
	included bool
	cgo      bool
	imports  map[string]string // local name ("" when unnamed) → import paths, keyed by spelling
	unnamed  []string
	dots     []string
	blank    []string
	// linknames maps a local name to its //go:linkname remote ("" when the directive names none);
	// badLinkname holds the local names of malformed directives.
	linknames   map[string]string
	badLinkname map[string]bool
}

type lofDecl struct {
	file     *lofFile
	kind     lofDeclKind
	recv     string
	name     string
	fn       *ast.FuncDecl
	spec     ast.Spec
	params   int
	results  int
	variadic bool
}

func (d *lofDecl) key() string     { return declKey(d.file.pkg.path, d.recv, d.name) }
func (d *lofDecl) recvKey() string { return d.file.pkg.path + "\x00" + d.recv }

type lofAsm struct {
	file    string
	refs    []string
	dynamic bool
}

type lofAnalysis struct {
	ctx      context.Context
	buildDir string
	env      []string
	release  goRelease
	built    func(constraint.Expr) bool
	goroot   string
	start    time.Time

	loaded  map[string]*packages.Package
	modules map[string]bool
	opened  map[string]*lofPkg
	failed  map[string]string
	dirs    map[string]string

	base          *reachedBase
	baseDecls     map[string]bool
	baseTypes     map[string]bool
	baseMethods   map[string][]baseFunc // by method name
	invokes       map[string][]baseFunc // by method name
	valuedKeys    map[string]bool
	symbols       map[string]bool
	wholePackages map[string]bool

	walked     map[*lofDecl]bool
	walkedSpec map[ast.Spec]bool
	walkedLit  map[*ast.FuncLit]bool
	walkedAsm  map[*lofAsm]bool
	queue      []*lofDecl
	inst       map[string]bool
	selectors  map[string][]lofArity
	byName     map[string][]*lofDecl // method name → declarations of every opened package
	dynamic    []lofArity
	linked     map[string]bool
	added      map[string]bool // Valued and Escape entries already added
	leftOut    bool
	outPkgs    map[string]bool
	pushes     map[string][][2]string // remote → (package, local) of each //go:linkname push
	pushesRead bool
	intrinsics map[string]bool // "path.Name" of each function the compiler replaces with inline code

	fail, hit string
	// cur is the declaration being walked; from maps each declaration to the one whose walk added
	// it; via is the chain to cur when the analysis decided.
	cur  *lofDecl
	from map[*lofDecl]*lofDecl
	via  []string
}

func newLofAnalysis(ctx context.Context, pkgs []*packages.Package, vulnerable map[string][]string, reached *reachedBase, release goRelease, buildDir string, env []string) *lofAnalysis {
	a := &lofAnalysis{
		ctx: ctx, buildDir: buildDir, env: env, release: release, start: time.Now(),
		built:         func(x constraint.Expr) bool { return !ignored(x) && !releaseExcluded(x, release) },
		loaded:        map[string]*packages.Package{},
		modules:       map[string]bool{},
		opened:        map[string]*lofPkg{},
		failed:        map[string]string{},
		dirs:          map[string]string{},
		base:          reached,
		baseDecls:     map[string]bool{},
		baseTypes:     map[string]bool{},
		baseMethods:   map[string][]baseFunc{},
		invokes:       map[string][]baseFunc{},
		valuedKeys:    map[string]bool{},
		symbols:       map[string]bool{},
		wholePackages: map[string]bool{},
		walked:        map[*lofDecl]bool{},
		walkedSpec:    map[ast.Spec]bool{},
		walkedLit:     map[*ast.FuncLit]bool{},
		walkedAsm:     map[*lofAsm]bool{},
		inst:          map[string]bool{},
		selectors:     map[string][]lofArity{},
		byName:        map[string][]*lofDecl{},
		linked:        map[string]bool{},
		added:         map[string]bool{},
		outPkgs:       map[string]bool{},
		pushes:        map[string][][2]string{},
		from:          map[*lofDecl]*lofDecl{},
	}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		a.loaded[p.PkgPath] = p
		if p.Module != nil {
			a.modules[p.Module.Path] = true
		}
	})
	for _, k := range reached.Decls {
		a.baseDecls[k] = true
	}
	for _, k := range reached.Types {
		a.baseTypes[k] = true
	}
	for _, m := range reached.Methods {
		a.baseMethods[keyName(m.Key)] = append(a.baseMethods[keyName(m.Key)], m)
	}
	for _, m := range reached.Invokes {
		a.invokes[keyName(m.Key)] = append(a.invokes[keyName(m.Key)], m)
	}
	for _, v := range reached.Valued {
		if v.Key != "" {
			a.valuedKeys[v.Key] = true
		}
	}
	for pkg, syms := range vulnerable {
		if len(syms) == 0 {
			a.wholePackages[pkg] = true
		}
		for _, s := range syms {
			recv, name, ok := strings.Cut(s, ".")
			if !ok {
				recv, name = "", s
			}
			a.symbols[declKey(pkg, recv, name)] = true
		}
	}
	return a
}

// keyName is the declaration name a declKey ends in.
func keyName(key string) string { return key[strings.LastIndexByte(key, 0)+1:] }

func (a *lofAnalysis) done() bool { return a.fail != "" || a.hit != "" }

// failWith fails the analysis for reason; what names the thing it could not follow.
func (a *lofAnalysis) failWith(reason string, what ...string) {
	if a.fail == "" && a.hit == "" {
		a.fail = reason
		a.trace()
		a.via = append(a.via, what...)
	}
}

// trace records the chain of declarations that led to cur.
func (a *lofAnalysis) trace() {
	for d, n := a.cur, 0; d != nil && n < 64; d, n = a.from[d], n+1 {
		pos := d.file.fset.Position(d.pos())
		a.via = append(a.via, strings.ReplaceAll(d.key(), "\x00", ".")+" "+filepath.Base(pos.Filename)+":"+strconv.Itoa(pos.Line))
	}
	slices.Reverse(a.via)
}

func (d *lofDecl) pos() token.Pos {
	if d.fn != nil {
		return d.fn.Pos()
	}
	return d.spec.Pos()
}

func (a *lofAnalysis) run() {
	if !a.toolchain() {
		return
	}
	a.seedLoaded()
	a.seedFirstParty()
	for !a.done() {
		a.drain()
		if a.done() || !a.escape() {
			break
		}
	}
}

// toolchain finds the standard library source the release's go command builds from, which must be
// the release's own and read without an overlay.
func (a *lofAnalysis) toolchain() bool {
	if strings.Contains(envOr(a.env, "GOFLAGS", ""), "-overlay") {
		a.failWith(lofGorootMismatch)
		return false
	}
	cmd := exec.CommandContext(a.ctx, "go", "env", "GOROOT")
	cmd.Dir = a.buildDir
	cmd.Env = append(slices.Clone(a.env), "GOTOOLCHAIN="+a.release.toolchain())
	out, err := cmd.Output()
	root := strings.TrimSpace(string(out))
	if err != nil || root == "" {
		a.failWith(lofUnknownToolchain)
		return false
	}
	version, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		a.failWith(lofUnknownToolchain)
		return false
	}
	first, _, _ := strings.Cut(string(version), "\n")
	if r, ok := parseGoRelease(first); !ok || r != a.release {
		a.failWith(lofGorootMismatch)
		return false
	}
	a.goroot = root
	return true
}

// seedLoaded opens every loaded package with a left-out file and seeds what of those files can run.
func (a *lofAnalysis) seedLoaded() {
	paths := make([]string, 0, len(a.loaded))
	for path, p := range a.loaded {
		if len(a.leftOutFiles(p)) > 0 {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	for _, path := range paths {
		p := a.open(path)
		if p == nil {
			return
		}
		for _, f := range p.files {
			if f.included {
				continue
			}
			a.linkFile(f)
			for _, d := range a.fileDecls(f) {
				switch {
				case d.kind == lofFunc && d.recv == "" && d.name == "init",
					d.kind == lofVar,
					d.kind == lofFunc && (a.baseDecls[d.key()] || a.valuedKeys[d.key()]),
					d.kind == lofType && a.baseTypes[d.recvKeyType()],
					d.kind == lofFunc && d.recv == "" && d.fn.Body != nil && f.linknames[d.name] != "":
					a.addDecl(d)
				}
			}
		}
	}
}

func (d *lofDecl) recvKeyType() string { return d.file.pkg.path + "\x00" + d.name }

// fileDecls returns f's declarations in source order.
func (a *lofAnalysis) fileDecls(f *lofFile) []*lofDecl {
	var out []*lofDecl
	for _, ds := range f.pkg.decls {
		for _, d := range ds {
			if d.file == f {
				out = append(out, d)
			}
		}
	}
	for _, ds := range f.pkg.methods {
		for _, d := range ds {
			if d.file == f {
				out = append(out, d)
			}
		}
	}
	return out
}

// leftOutFiles returns the non-test Go files of p's directory the build left out that some build
// under the release compiles into p.
func (a *lofAnalysis) leftOutFiles(p *packages.Package) []string {
	var out []string
	for _, f := range p.IgnoredFiles {
		if !strings.HasSuffix(f, ".go") || strings.HasSuffix(f, "_test.go") {
			continue
		}
		name, _, expr, err := fileImports(f)
		if err != nil || (a.built(expr) && name == p.Name) {
			out = append(out, f)
		}
	}
	return out
}

// seedFirstParty seeds the main, init functions and variables of every main-module package
// directory the load never listed.
func (a *lofAnalysis) seedFirstParty() {
	loadedDirs := map[string]bool{}
	mainDir := ""
	for _, p := range a.loaded {
		if p.Module == nil {
			continue
		}
		if p.Module.Main && mainDir == "" {
			mainDir = p.Module.Dir
		}
		for _, files := range [][]string{p.GoFiles, p.OtherFiles, p.IgnoredFiles} {
			for _, f := range files {
				loadedDirs[filepath.Dir(f)] = true
			}
		}
	}
	if mainDir == "" {
		mainDir = a.buildDir
	}
	dirs := map[string]bool{}
	firstPartyLeftOut(mainDir, loadedDirs, func(path string) bool {
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			dirs[filepath.Dir(path)] = true
		}
		return false
	})
	if _, err := os.ReadDir(mainDir); err != nil {
		a.failWith(lofMissingSource)
		return
	}
	for _, dir := range sortedKeys(dirs) {
		p := a.openDir("dir:"+dir, dir, false)
		if p == nil {
			return
		}
		for _, f := range p.files {
			for _, d := range a.fileDecls(f) {
				if d.kind == lofVar || (d.kind == lofFunc && d.recv == "" && (d.name == "init" || d.name == "main")) {
					a.addDecl(d)
				}
			}
		}
	}
}

// open returns the package at import path, parsed, or nil after failing the analysis.
func (a *lofAnalysis) open(path string) *lofPkg {
	if p, ok := a.opened[path]; ok {
		return p
	}
	if reason, ok := a.failed[path]; ok {
		a.failWith(reason, path)
		return nil
	}
	if lp, ok := a.loaded[path]; ok {
		dir := ""
		for _, files := range [][]string{lp.GoFiles, lp.IgnoredFiles, lp.OtherFiles} {
			if len(files) > 0 {
				dir = filepath.Dir(files[0])
				break
			}
		}
		if dir == "" {
			// A loaded package with no files has no declarations to follow.
			return a.openDir(path, "", true)
		}
		return a.openDir(path, dir, true)
	}
	dir, ok := a.dirOf(path)
	if !ok {
		a.failed[path] = lofUnresolvedImport
		a.failWith(lofUnresolvedImport, path)
		return nil
	}
	return a.openDir(path, dir, false)
}

// dirOf finds the directory of an unloaded package: the release's source for the standard library,
// else the one `go list` resolves the way the build would.
func (a *lofAnalysis) dirOf(path string) (string, bool) {
	if strings.HasPrefix(path, "vendor/") || isStdlibPath(path, a.modules) {
		return filepath.Join(a.goroot, "src", filepath.FromSlash(path)), true
	}
	if dir, ok := a.dirs[path]; ok {
		return dir, dir != ""
	}
	cmd := exec.CommandContext(a.ctx, "go", "list", "-e", "-f", "{{.Dir}}", "--", path)
	cmd.Dir = a.buildDir
	cmd.Env = a.env
	out, err := cmd.Output()
	dir := ""
	if err == nil {
		dir = strings.TrimSpace(string(out))
	}
	a.dirs[path] = dir
	return dir, dir != ""
}

// openDir parses the package at path from dir: for a loaded package its included files and the
// ones left out of it, else every non-test Go file a build under the release compiles; and every
// assembly file.
func (a *lofAnalysis) openDir(path, dir string, loaded bool) *lofPkg {
	p := &lofPkg{path: path, dir: dir, loaded: loaded, decls: map[string][]*lofDecl{}, methods: map[string][]*lofDecl{}, asmText: map[string][]*lofAsm{}, asmData: map[string]bool{}}
	a.opened[path] = p
	fail := func(reason string) *lofPkg {
		delete(a.opened, path)
		a.failed[path] = reason
		a.failWith(reason, path)
		return nil
	}
	if dir == "" {
		return p
	}
	var goFiles []string
	included := map[string]bool{}
	if loaded {
		lp := a.loaded[path]
		p.name = lp.Name
		for _, f := range lp.GoFiles {
			included[f] = true
			goFiles = append(goFiles, f)
		}
		goFiles = append(goFiles, a.leftOutFiles(lp)...)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fail(lofMissingSource)
	}
	std := strings.HasPrefix(dir, filepath.Join(a.goroot, "src")+string(filepath.Separator))
	var asmFiles, headers []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			continue
		}
		full := filepath.Join(dir, name)
		switch {
		case strings.HasSuffix(name, ".s"):
			asmFiles = append(asmFiles, full)
		case strings.HasSuffix(name, ".h"):
			headers = append(headers, full)
		case !loaded && strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go"):
			goFiles = append(goFiles, full)
		}
	}
	fset := token.NewFileSet()
	for _, path := range goFiles {
		src, err := os.ReadFile(path)
		if err != nil {
			return fail(lofMissingSource)
		}
		expr, err := fileConstraint(src)
		if err != nil {
			return fail(lofParseError)
		}
		if !included[path] && !a.built(expr) {
			continue
		}
		f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
		if err != nil {
			return fail(lofParseError)
		}
		if p.name == "" && f.Name.Name != "main" {
			p.name = f.Name.Name
		}
		lf := &lofFile{pkg: p, path: path, fset: fset, ast: f, included: included[path], imports: map[string]string{}, linknames: map[string]string{}, badLinkname: map[string]bool{}}
		for _, imp := range f.Imports {
			ip, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return fail(lofParseError)
			}
			if ip == "C" {
				lf.cgo = true
				continue
			}
			if std && !isStdlibPath(ip, nil) {
				ip = "vendor/" + ip
			}
			switch {
			case imp.Name == nil:
				lf.unnamed = append(lf.unnamed, ip)
			case imp.Name.Name == ".":
				lf.dots = append(lf.dots, ip)
			case imp.Name.Name == "_":
				lf.blank = append(lf.blank, ip)
			default:
				lf.imports[imp.Name.Name] = ip
			}
		}
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				local, remote, ok := parseLinkname(c.Text)
				switch {
				case !ok:
				case local == "":
					lf.badLinkname[""] = true
				case remote == "\x00":
					lf.badLinkname[local] = true
				default:
					lf.linknames[local] = remote
					if remote != "" {
						a.pushes[remote] = append(a.pushes[remote], [2]string{path, local})
					}
				}
			}
		}
		p.files = append(p.files, lf)
		a.index(lf)
	}
	for _, path := range asmFiles {
		src, err := os.ReadFile(path)
		if err != nil {
			return fail(lofMissingSource)
		}
		expr, err := fileConstraint(src)
		if err != nil {
			return fail(lofParseError)
		}
		if !a.built(expr) {
			continue
		}
		parseAsm(p, path, src, headers)
	}
	// A method this package declares on a type the scanned build or the closure already uses joins
	// the closure when a selection or an interface call calls for it.
	for _, ds := range p.methods {
		for _, d := range ds {
			a.checkMethod(d)
		}
	}
	return p
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

// index records f's package-level declarations.
func (a *lofAnalysis) index(f *lofFile) {
	p := f.pkg
	for _, decl := range f.ast.Decls {
		switch decl := decl.(type) {
		case *ast.FuncDecl:
			d := &lofDecl{file: f, kind: lofFunc, name: decl.Name.Name, fn: decl}
			d.params, d.results, d.variadic = fieldArity(decl.Type)
			if decl.Recv != nil && len(decl.Recv.List) > 0 {
				d.recv = recvName(decl.Recv.List[0].Type)
				p.methods[d.recv+"\x00"+d.name] = append(p.methods[d.recv+"\x00"+d.name], d)
				a.byName[d.name] = append(a.byName[d.name], d)
				continue
			}
			p.decls[d.name] = append(p.decls[d.name], d)
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				switch spec := spec.(type) {
				case *ast.ValueSpec:
					kind := lofVar
					if decl.Tok == token.CONST {
						kind = lofConst
					}
					for _, n := range spec.Names {
						p.decls[n.Name] = append(p.decls[n.Name], &lofDecl{file: f, kind: kind, name: n.Name, spec: spec})
					}
				case *ast.TypeSpec:
					p.decls[spec.Name.Name] = append(p.decls[spec.Name.Name], &lofDecl{file: f, kind: lofType, name: spec.Name.Name, spec: spec})
				}
			}
		}
	}
}

// fieldArity counts a function type's parameters and results and reports whether it is variadic.
func fieldArity(ft *ast.FuncType) (params, results int, variadic bool) {
	count := func(fl *ast.FieldList) int {
		n := 0
		if fl != nil {
			for _, f := range fl.List {
				n += max(1, len(f.Names))
			}
		}
		return n
	}
	params, results = count(ft.Params), count(ft.Results)
	if ft.Params != nil && len(ft.Params.List) > 0 {
		_, variadic = ft.Params.List[len(ft.Params.List)-1].Type.(*ast.Ellipsis)
	}
	return params, results, variadic
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

// touch records that the closure reaches the declaration key.
func (a *lofAnalysis) touch(key string, kind lofDeclKind) {
	pkg, _, _ := strings.Cut(key, "\x00")
	if a.done() {
		return
	}
	if a.symbols[key] || (a.wholePackages[pkg] && (kind == lofFunc || kind == lofVar)) {
		a.hit = strings.ReplaceAll(strings.Replace(key, "\x00\x00", ".", 1), "\x00", ".")
		a.trace()
		return
	}
	if lofReflectKeys[key] {
		a.failWith(lofReflectCall)
	}
}

// addDecl puts d in the closure. Code the scanned build reaches is not walked again: a function it
// reaches, or a variable of a package it loads, whose initializer its package initializer runs.
func (a *lofAnalysis) addDecl(d *lofDecl) {
	if a.done() {
		return
	}
	a.touch(d.key(), d.kind)
	if a.walked[d] {
		return
	}
	a.walked[d] = true
	a.from[d] = a.cur
	if d.file.included && ((d.kind == lofFunc && a.baseDecls[d.key()]) || (d.kind == lofVar && d.file.pkg.loaded)) {
		return
	}
	a.queue = append(a.queue, d)
}

func (a *lofAnalysis) drain() {
	for len(a.queue) > 0 && !a.done() {
		d := a.queue[0]
		a.queue = a.queue[1:]
		if len(a.walked) > lofBudgetDecls || time.Since(a.start) > lofBudgetTime || a.ctx.Err() != nil {
			a.failWith(lofBudget)
			return
		}
		a.cur = d
		a.walk(d)
		a.cur = nil
	}
}

// walk follows d's body, initializer or type.
func (a *lofAnalysis) walk(d *lofDecl) {
	f := d.file
	if !f.included {
		a.leftOut = true
		a.outPkgs[f.pkg.path] = true
		for _, ip := range f.importPaths() {
			a.outPkgs[ip] = true
		}
		a.link(f.pkg.path)
	}
	if f.cgo && d.kind != lofType && d.kind != lofConst {
		a.failWith(lofCgo, f.path)
		return
	}
	if f.badLinkname[d.name] || f.badLinkname[""] {
		a.failWith(lofLinkname)
		return
	}
	// A bodyless function pulls the body its //go:linkname names; one with a body pushes its own,
	// which the declarations calling it reach as they are walked.
	if remote := f.linknames[d.name]; d.kind == lofFunc && d.recv == "" && remote != "" && d.fn.Body == nil {
		if !a.addRemote(remote) {
			a.failWith(lofLinkname, remote)
			return
		}
	}
	switch d.kind {
	case lofFunc:
		a.walkNode(f, d.fn.Type)
		if d.fn.Body != nil {
			a.walkNode(f, d.fn.Body)
		} else {
			a.bodyless(d)
		}
	case lofVar, lofConst, lofType:
		if a.walkedSpec[d.spec] {
			return
		}
		a.walkedSpec[d.spec] = true
		switch s := d.spec.(type) {
		case *ast.ValueSpec:
			if s.Type != nil {
				a.walkNode(f, s.Type)
			}
			for _, v := range s.Values {
				a.walkNode(f, v)
			}
		case *ast.TypeSpec:
			if s.TypeParams != nil {
				a.walkNode(f, s.TypeParams)
			}
			a.walkNode(f, s.Type)
		}
	}
}

func (f *lofFile) importPaths() []string {
	out := slices.Concat(f.unnamed, f.dots, f.blank)
	for _, ip := range f.imports {
		out = append(out, ip)
	}
	slices.Sort(out)
	return out
}

// linkFile links every package f imports, which a build compiling f links whether or not code it
// runs calls into them.
func (a *lofAnalysis) linkFile(f *lofFile) {
	for _, ip := range f.importPaths() {
		if !f.included {
			a.outPkgs[ip] = true
		}
		a.link(ip)
	}
}

// link seeds what runs once the build links the package at path: its init functions, variables and
// //go:linkname pushes, and those of every package it imports. A package the build loaded is linked
// already, its initializer traced.
func (a *lofAnalysis) link(path string) {
	if path == "unsafe" || a.linked[path] || a.done() {
		return
	}
	a.linked[path] = true
	if _, ok := a.loaded[path]; ok {
		return
	}
	p := a.open(path)
	if p == nil {
		return
	}
	for _, f := range p.files {
		a.linkFile(f)
		for _, d := range a.fileDecls(f) {
			if d.kind == lofVar || (d.kind == lofFunc && d.recv == "" && (d.name == "init" || (d.fn.Body != nil && f.linknames[d.name] != ""))) {
				a.addDecl(d)
			}
		}
	}
}

// addRemote puts the declaration a //go:linkname remote ("importpath.name", "importpath.T.m",
// "importpath.(*T).m") names in the closure, reporting whether it found one.
func (a *lofAnalysis) addRemote(remote string) bool {
	slash := strings.LastIndexByte(remote, '/')
	dot := strings.IndexByte(remote[slash+1:], '.')
	if dot < 0 {
		return false
	}
	path, sym := remote[:slash+1+dot], remote[slash+1+dot+1:]
	recv, name, isMethod := strings.Cut(sym, ".")
	if !isMethod {
		recv, name = "", sym
	}
	recv = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(recv, "("), "*"), ")")
	return a.addKey(declKey(path, recv, name), false)
}

// addKey puts every declaration keyed key in the closure, from each build's files, reporting
// whether it found one. A key it cannot find source for fails the analysis when must is set.
func (a *lofAnalysis) addKey(key string, must bool) bool {
	pkg, rest, _ := strings.Cut(key, "\x00")
	recv, name, _ := strings.Cut(rest, "\x00")
	if pkg == "unsafe" {
		return true
	}
	p := a.open(pkg)
	if p == nil {
		return false
	}
	var ds []*lofDecl
	if recv == "" {
		ds = p.decls[name]
	} else {
		ds = p.methods[recv+"\x00"+name]
	}
	if len(ds) == 0 {
		if must {
			a.failWith(lofMissingSource, key)
		}
		return false
	}
	for _, d := range ds {
		a.addDecl(d)
	}
	return true
}

// bodyless resolves a Go function declared without a body: a //go:linkname pull names its body (the
// edge walk added), else a push from another package or an assembly TEXT symbol of its own provides
// it.
func (a *lofAnalysis) bodyless(d *lofDecl) {
	p := d.file.pkg
	if remote := d.file.linknames[d.name]; remote != "" && d.recv == "" {
		return
	}
	if wasmImport(d.fn) {
		// The host provides the body: foreign code, which counts as a dynamic call.
		a.dynamic = append(a.dynamic, lofArity{any: true})
		return
	}
	found := false
	if d.recv == "" {
		a.readPushes()
		for _, push := range a.pushes[p.path+"."+d.name] {
			if pp := a.pkgOfFile(push[0]); pp != nil {
				for _, pd := range pp.decls[push[1]] {
					if pd.kind == lofFunc && pd.fn.Body != nil {
						a.addDecl(pd)
						found = true
					}
				}
			}
		}
		for _, body := range p.asmText[p.path+"."+d.name] {
			a.walkAsm(p, body)
			found = true
		}
	}
	if !found && d.recv == "" && a.intrinsic(p.path+"."+d.name) {
		// The compiler expands the call inline; it calls no Go code.
		found = true
	}
	if !found {
		a.failWith(lofBodyless, d.key())
	}
}

// intrinsicCall matches an entry of the compiler's intrinsic table: add, addF or alias, then the
// package path and function name.
var intrinsicCall = regexp.MustCompile(`\b(?:add|addF|alias)\(\s*"([^"]+)",\s*"([^"]+)"`)

// intrinsic reports whether the toolchain's compiler lists the function path.Name as an intrinsic
// for some architecture. A bodyless function the build compiles without assembly or a linkname is
// one the compiler expands inline on the target. An unreadable table lists nothing.
func (a *lofAnalysis) intrinsic(name string) bool {
	if a.intrinsics == nil {
		a.intrinsics = map[string]bool{}
		src, err := os.ReadFile(filepath.Join(a.goroot, "src", "cmd", "compile", "internal", "ssagen", "intrinsics.go"))
		if err == nil {
			for _, m := range intrinsicCall.FindAllSubmatch(src, -1) {
				a.intrinsics[string(m[1])+"."+string(m[2])] = true
			}
		}
	}
	return a.intrinsics[name]
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

// readPushes records the //go:linkname directives of every loaded package's files, included or not.
// A package opened later records its own as it is parsed.
func (a *lofAnalysis) readPushes() {
	if a.pushesRead {
		return
	}
	a.pushesRead = true
	for _, lp := range a.loaded {
		if _, ok := a.opened[lp.PkgPath]; ok {
			continue
		}
		for _, files := range [][]string{lp.GoFiles, lp.IgnoredFiles} {
			for _, path := range files {
				if !strings.HasSuffix(path, ".go") {
					continue
				}
				src, err := os.ReadFile(path)
				if err != nil || !bytes.Contains(src, []byte("//go:linkname")) {
					continue
				}
				sc := bufio.NewScanner(bytes.NewReader(src))
				sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
				for sc.Scan() {
					local, remote, ok := parseLinkname(strings.TrimSpace(sc.Text()))
					if ok && local != "" && remote != "" && remote != "\x00" {
						a.pushes[remote] = append(a.pushes[remote], [2]string{path, local})
					}
				}
			}
		}
	}
}

// pkgOfFile opens the package holding the Go file at path.
func (a *lofAnalysis) pkgOfFile(path string) *lofPkg {
	for _, p := range a.opened {
		for _, f := range p.files {
			if f.path == path {
				return p
			}
		}
	}
	for _, lp := range a.loaded {
		if slices.Contains(lp.GoFiles, path) || slices.Contains(lp.IgnoredFiles, path) {
			return a.open(lp.PkgPath)
		}
	}
	return nil
}

// walkAsm follows an assembly body's symbol references.
func (a *lofAnalysis) walkAsm(p *lofPkg, body *lofAsm) {
	if a.walkedAsm[body] || a.done() {
		return
	}
	a.walkedAsm[body] = true
	if body.dynamic {
		a.dynamic = append(a.dynamic, lofArity{any: true})
	}
	for _, ref := range body.refs {
		a.asmRef(p, body.file, ref)
		if a.done() {
			return
		}
	}
}

// asmRef resolves one assembly symbol reference made in file of package p: "pkgpath.name" to a Go
// declaration or a TEXT or data symbol of that package, a file-local "name<>" to its file's, and a
// bare symbol to p's own, else to foreign code, which counts as a dynamic call.
func (a *lofAnalysis) asmRef(p *lofPkg, file, ref string) {
	switch {
	case strings.HasSuffix(ref, "<>"):
		if bodies, ok := p.asmText[ref]; ok {
			for _, b := range bodies {
				a.walkAsm(p, b)
			}
			return
		}
		if !p.asmData[ref] {
			a.failWith(lofAsmSymbol, ref)
		}
	case strings.Contains(ref, "."):
		dot := strings.LastIndexByte(ref, '.')
		path, name := ref[:dot], ref[dot+1:]
		if path != p.path && path == p.path[strings.LastIndexByte(p.path, '/')+1:] {
			// Some assembly qualifies its own package's symbols by the package name alone.
			path, ref = p.path, p.path+"."+name
		}
		target := a.open(path)
		if target == nil {
			return
		}
		found := false
		for _, d := range target.decls[name] {
			a.addDecl(d)
			found = true
		}
		for _, b := range target.asmText[ref] {
			a.walkAsm(target, b)
			found = true
		}
		if !found && !target.asmData[ref] {
			a.failWith(lofAsmSymbol, ref)
		}
	default:
		if bodies, ok := p.asmText[ref]; ok {
			for _, b := range bodies {
				a.walkAsm(p, b)
			}
			return
		}
		if !p.asmData[ref] {
			a.dynamic = append(a.dynamic, lofArity{any: true})
		}
	}
}

// parseAsm records an assembly file's TEXT bodies, with the symbols each references, and its data
// symbols. A symbol is "pkgpath.name" for the Go-visible form ("·name", "pkg∕path·name"), "file:name<>"
// for a file-local one, and the bare name otherwise. A reference made by a macro the file defines or
// includes from its own directory counts for every body of the file. A call or jump through a
// register is a dynamic call.
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
	lines := strings.Split(string(src), "\n")
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
	for _, line := range lines {
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
			bodies = append(bodies, cur)
			continue
		case "GLOBL", "DATA":
			for _, ref := range asmRefs(t) {
				p.asmData[norm(ref)] = true
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

// walkNode follows the references in n, a node of file f.
func (a *lofAnalysis) walkNode(f *lofFile, n ast.Node) {
	calls := map[ast.Expr]lofArity{}
	ast.Inspect(n, func(n ast.Node) bool {
		if a.done() {
			return false
		}
		switch n := n.(type) {
		case *ast.CallExpr:
			ar := lofArity{n: len(n.Args), ellipsis: n.Ellipsis.IsValid()}
			if len(n.Args) == 1 && !ar.ellipsis {
				_, ar.spread = ast.Unparen(n.Args[0]).(*ast.CallExpr)
			}
			fun := ast.Unparen(n.Fun)
			switch x := fun.(type) {
			case *ast.IndexExpr:
				calls[x.X] = ar
				a.dynamic = append(a.dynamic, ar)
			case *ast.IndexListExpr:
				calls[x.X] = ar
			case *ast.Ident, *ast.SelectorExpr:
				calls[fun] = ar
			case *ast.StarExpr, *ast.ArrayType, *ast.FuncType, *ast.InterfaceType, *ast.MapType, *ast.ChanType, *ast.StructType:
			default:
				a.dynamic = append(a.dynamic, ar)
			}
		case *ast.SelectorExpr:
			ar, called := calls[n]
			if !called {
				ar = lofArity{any: true}
			}
			if x, ok := n.X.(*ast.Ident); ok && !f.local(x) {
				if path, ok := a.importFor(f, x.Name); ok {
					a.ref(path, n.Sel.Name)
					return false
				}
			}
			if called {
				a.dynamic = append(a.dynamic, ar)
			}
			a.selector(n.Sel.Name, ar)
			a.walkNode(f, n.X)
			return false
		case *ast.Ident:
			if n.Name == "_" {
				return false
			}
			if f.local(n) {
				if ar, called := calls[n]; called {
					a.dynamic = append(a.dynamic, ar)
				}
				return false
			}
			a.refLocal(f, n.Name)
		}
		return true
	})
}

// local reports whether id names something declared inside a function rather than at package level.
func (f *lofFile) local(id *ast.Ident) bool {
	return id.Obj != nil && f.ast.Scope.Lookup(id.Name) != id.Obj
}

// importFor resolves name, used as a package qualifier in f, to the import path it names.
func (a *lofAnalysis) importFor(f *lofFile, name string) (string, bool) {
	if ip, ok := f.imports[name]; ok {
		return ip, true
	}
	if decls := f.pkg.decls[name]; len(decls) > 0 {
		return "", false
	}
	var unsure []string
	for _, ip := range f.unnamed {
		switch guessPackageName(ip) {
		case name:
			return ip, true
		case "":
			unsure = append(unsure, ip)
		default:
			unsure = append(unsure, ip)
		}
	}
	for _, ip := range unsure {
		if ip == "unsafe" {
			continue
		}
		if p := a.open(ip); p != nil && p.name == name {
			return ip, true
		}
		if a.done() {
			return "", false
		}
	}
	return "", false
}

// guessPackageName is the package name an import path conventionally declares.
func guessPackageName(path string) string {
	elems := strings.Split(strings.TrimPrefix(path, "vendor/"), "/")
	last := elems[len(elems)-1]
	if len(elems) > 1 && len(last) > 1 && last[0] == 'v' {
		if _, err := strconv.Atoi(last[1:]); err == nil {
			last = elems[len(elems)-2]
		}
	}
	last = strings.TrimPrefix(last, "go-")
	if i := strings.IndexAny(last, ".-"); i >= 0 {
		last = last[:i]
	}
	return last
}

// refLocal follows an unqualified package-level name used in f: every declaration of that name in
// f's package, from each build's files, and in the packages f dot-imports.
func (a *lofAnalysis) refLocal(f *lofFile, name string) {
	a.refIn(f.pkg, name)
	for _, ip := range f.dots {
		if p := a.open(ip); p != nil {
			a.refIn(p, name)
		}
	}
}

// ref follows a qualified reference path.name.
func (a *lofAnalysis) ref(path, name string) {
	if path == "unsafe" || path == "" {
		return
	}
	if p := a.open(path); p != nil {
		a.refIn(p, name)
	}
}

func (a *lofAnalysis) refIn(p *lofPkg, name string) {
	for _, d := range p.decls[name] {
		if d.kind == lofType {
			a.instantiate(p, name)
			continue
		}
		a.addDecl(d)
	}
}

// instantiate records that the closure mentions the type p.name: its declarations join the closure,
// which instantiates the types they are built from, and each of its methods joins once a selection
// or an interface call calls for it.
func (a *lofAnalysis) instantiate(p *lofPkg, name string) {
	key := p.path + "\x00" + name
	if a.inst[key] {
		return
	}
	a.inst[key] = true
	for _, d := range p.decls[name] {
		a.addDecl(d)
	}
	for k, ds := range p.methods {
		if recv, _, _ := strings.Cut(k, "\x00"); recv == name {
			for _, d := range ds {
				a.checkMethod(d)
			}
		}
	}
}

// checkMethod puts the method d in the closure when its type is one the closure mentions or the
// scanned build uses, and a selection the closure makes calls for it; or when its type is one the
// closure mentions, or it is a method the scanned build left out, and an interface call the scanned
// build makes dispatches to it.
func (a *lofAnalysis) checkMethod(d *lofDecl) {
	rk := d.recvKey()
	inst, baseType := a.inst[rk], a.baseTypes[rk]
	if !inst && !baseType {
		return
	}
	for _, ar := range a.selectors[d.name] {
		if ar.compatible(d.params, d.variadic) {
			a.addDecl(d)
			return
		}
	}
	if inst || !d.file.included {
		for _, m := range a.invokes[d.name] {
			if m.Params == d.params && m.Results == d.results && m.Variadic == d.variadic {
				a.addDecl(d)
				return
			}
		}
	}
}

// selector records that the closure selects .name with arity ar: every method of that name, of a
// type the closure mentions or the scanned build uses, with a compatible arity joins the closure.
func (a *lofAnalysis) selector(name string, ar lofArity) {
	if slices.Contains(a.selectors[name], ar) {
		return
	}
	a.selectors[name] = append(a.selectors[name], ar)
	for _, d := range a.byName[name] {
		if (a.inst[d.recvKey()] || a.baseTypes[d.recvKey()]) && ar.compatible(d.params, d.variadic) {
			a.addDecl(d)
		}
	}
	for _, m := range a.baseMethods[name] {
		if ar.compatible(m.Params, m.Variadic) {
			a.addKey(m.Key, true)
		}
	}
}

// escape adds the function values and methods of the scanned build's own that left-out code can
// route back to a call it traced: those it uses as values, once the closure makes a dynamic call of
// a compatible arity, and its Escape entries once the closure holds a left-out body (all of them, or
// under escapeImporters those of a package code that walked can name). It reports whether it added
// any.
func (a *lofAnalysis) escape() bool {
	before := len(a.queue)
	add := func(v baseFunc) {
		id := v.Key + "\x00" + v.Pos
		if a.added[id] {
			return
		}
		a.added[id] = true
		if v.Key != "" {
			a.addKey(v.Key, true)
		} else {
			a.addLit(v)
		}
	}
	if len(a.dynamic) > 0 {
		for _, v := range a.base.Valued {
			if slices.ContainsFunc(a.dynamic, func(ar lofArity) bool { return ar.compatible(v.Params, v.Variadic) }) {
				add(v)
			}
		}
	}
	if a.leftOut {
		for _, e := range a.base.Escape {
			if escapeBaseTypes == escapeAllBase || a.outPkgs[e.Owner] {
				add(e)
			}
		}
	}
	return len(a.queue) > before
}

// addLit walks the function literal at v.Pos ("file:line:column"), in package v.Owner.
func (a *lofAnalysis) addLit(v baseFunc) {
	rest, colStr, _ := cutLast(v.Pos, ":")
	file, lineStr, _ := cutLast(rest, ":")
	line, _ := strconv.Atoi(lineStr)
	col, _ := strconv.Atoi(colStr)
	p := a.open(v.Owner)
	if p == nil {
		return
	}
	for _, f := range p.files {
		if f.path != file {
			continue
		}
		var match []*ast.FuncLit
		ast.Inspect(f.ast, func(n ast.Node) bool {
			if lit, ok := n.(*ast.FuncLit); ok {
				if pos := f.fset.Position(lit.Pos()); pos.Line == line && pos.Column == col {
					match = append(match, lit)
				}
			}
			return true
		})
		if len(match) == 0 {
			break
		}
		if f.cgo {
			a.failWith(lofCgo)
			return
		}
		for _, lit := range match {
			if !a.walkedLit[lit] {
				a.walkedLit[lit] = true
				a.walkNode(f, lit)
			}
		}
		return
	}
	a.failWith(lofMissingSource, v.Pos)
}

// cutLast slices s around the last instance of sep.
func cutLast(s, sep string) (before, after string, found bool) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}
