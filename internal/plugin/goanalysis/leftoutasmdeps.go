package goanalysis

import (
	"errors"
	"go/ast"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// The build configuration a generated go_asm.h may vary with beyond the package's own Go file set:
// a constant or type of the package can take its value from a dependency's file that an
// architecture level or an experiment selects. These read what the Go files show about that, over
// every file any build may compile.

// lofDepFacts is what the files a query reaches show: whether one is constrained on or named for an
// architecture level, the experiments they are constrained on, and whether some package or file
// could not be read.
type lofDepFacts struct {
	level, bad bool
	exps       []string
	// tags holds every other build tag the files are constrained on, and cgo where one imports "C".
	tags []string
}

func (f *lofDepFacts) add(o lofDepFacts) {
	f.level = f.level || o.level
	f.bad = f.bad || o.bad
	for _, x := range o.exps {
		if !slices.Contains(f.exps, x) {
			f.exps = append(f.exps, x)
		}
	}
	for _, x := range o.tags {
		if !slices.Contains(f.tags, x) {
			f.tags = append(f.tags, x)
		}
	}
}

// lofDepPkg is what one package directory's Go files show.
type lofDepPkg struct {
	bad bool
	// names holds the package clauses the files carry.
	names []string
	files []lofDepFile
	// decls holds every package-level name a file declares.
	decls map[string]bool
}

// lofDepFile is one Go file of a package.
type lofDepFile struct {
	lofDepFacts
	imports []lofDepImport
	// refs maps each package-level declaration of the file to the names it mentions: a local name
	// bare, a qualified one as "q.X".
	refs map[string][]string
	// ints holds the constants of the file whose value is integer arithmetic on literals and names
	// (lofDepIntExpr).
	ints map[string]bool
	// name is the file's base name, expr its build constraint (nil for none), and cgo whether it
	// imports "C".
	name string
	expr constraint.Expr
	cgo  bool
}

// lofDepImport is one import of a file; name is "" when the import gives none.
type lofDepImport struct{ name, path string }

// lofDepRead reads the Go files of dir that some build may compile: every file go/build lists as
// compiled, ignored or invalid under one configuration, which together hold each non-test Go file
// of the directory whatever the configuration. arches holds the GOARCH values, whose "<goarch>.<x>"
// build tags name architecture levels (internal/buildcfg, gogoarchTags).
func lofDepRead(dir string, arches map[string]bool) *lofDepPkg {
	out := &lofDepPkg{decls: map[string]bool{}}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		out.bad = true
		return out
	}
	c := build.Context{GOOS: "linux", GOARCH: "amd64", Compiler: "gc", ReleaseTags: build.Default.ReleaseTags}
	bp, err := c.ImportDir(dir, 0)
	if bp == nil {
		out.bad = true
		return out
	}
	if err != nil {
		// Files go/build sets aside for the package clause or a constraint it cannot parse are listed
		// as invalid; any other error may have cut the listing short.
		var ng *build.NoGoError
		var mp *build.MultiplePackageError
		if !errors.As(err, &ng) && !errors.As(err, &mp) && len(bp.InvalidGoFiles) == 0 {
			out.bad = true
		}
	}
	for _, list := range [][]string{bp.GoFiles, bp.CgoFiles, bp.IgnoredGoFiles, bp.InvalidGoFiles} {
		for _, n := range list {
			if strings.HasSuffix(n, "_test.go") {
				continue
			}
			f, name, ok := lofDepReadFile(filepath.Join(dir, n), arches)
			if !ok {
				out.bad = true
				continue
			}
			if !slices.Contains(out.names, name) {
				out.names = append(out.names, name)
			}
			for d := range f.refs {
				out.decls[d] = true
			}
			out.files = append(out.files, f)
		}
	}
	return out
}

func lofDepReadFile(path string, arches map[string]bool) (lofDepFile, string, bool) {
	f := lofDepFile{refs: map[string][]string{}, ints: map[string]bool{}, name: filepath.Base(path)}
	src, err := os.ReadFile(path)
	if err != nil {
		return f, "", false
	}
	x, err := fileConstraint(src)
	if err != nil {
		return f, "", false
	}
	f.expr = x
	for _, tag := range lofExprTags(x, nil) {
		if e, ok := strings.CutPrefix(tag, "goexperiment."); ok {
			if !slices.Contains(f.exps, e) {
				f.exps = append(f.exps, e)
			}
		} else if arch, _, ok := strings.Cut(tag, "."); ok && arches[arch] {
			f.level = true
		} else if !slices.Contains(f.tags, tag) {
			f.tags = append(f.tags, tag)
		}
	}
	f.level = f.level || lofDepLevelName(filepath.Base(path), arches)
	af, err := parser.ParseFile(token.NewFileSet(), path, src, parser.SkipObjectResolution)
	if err != nil {
		return f, "", false
	}
	for _, im := range af.Imports {
		p, err := strconv.Unquote(im.Path.Value)
		if err != nil {
			return f, "", false
		}
		var name string
		if im.Name != nil {
			name = im.Name.Name
		}
		f.imports = append(f.imports, lofDepImport{name, p})
		if p == "C" {
			f.cgo = true
			if !slices.Contains(f.tags, "cgo") {
				f.tags = append(f.tags, "cgo")
			}
		}
	}
	for _, d := range af.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				f.refs[d.Name.Name] = lofDepIdents(d.Type)
			}
		case *ast.GenDecl:
			var last []string
			lastInt := false
			for _, spec := range d.Specs {
				switch sp := spec.(type) {
				case *ast.TypeSpec:
					f.ints[sp.Name.Name] = false
					var refs []string
					if _, ok := sp.Type.(*ast.StructType); !ok || sp.Assign.IsValid() || sp.TypeParams != nil {
						// As in goSrc: a struct literal is a struct whatever its field types are.
						refs = lofDepIdents(sp.Type)
					}
					f.refs[sp.Name.Name] = append(f.refs[sp.Name.Name], refs...)
				case *ast.ValueSpec:
					refs := lofDepIdents(sp.Type)
					for _, v := range sp.Values {
						refs = append(refs, lofDepIdents(v)...)
					}
					isInt := false
					if d.Tok == token.CONST {
						isInt = sp.Type == nil && len(sp.Values) == len(sp.Names) && !slices.ContainsFunc(sp.Values, func(v ast.Expr) bool { return !lofDepIntExpr(v) })
						if len(sp.Values) == 0 && sp.Type == nil {
							refs, isInt = last, lastInt
						}
						last, lastInt = refs, isInt
					}
					for _, nm := range sp.Names {
						f.refs[nm.Name] = append(f.refs[nm.Name], refs...)
						if v, ok := f.ints[nm.Name]; !ok || v {
							f.ints[nm.Name] = isInt
						}
					}
				}
			}
		}
	}
	return f, af.Name.Name, true
}

// lofDepIntExpr reports whether e is integer arithmetic: integer and rune literals, names, and the
// arithmetic and bitwise operators. Its value is an integer whenever every name it mentions is one;
// a comparison, conversion, call, or any other literal may yield another kind.
func lofDepIntExpr(e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.BasicLit:
		return e.Kind == token.INT || e.Kind == token.CHAR
	case *ast.Ident:
		return e.Name != "true" && e.Name != "false" && e.Name != "nil"
	case *ast.SelectorExpr:
		_, ok := e.X.(*ast.Ident)
		return ok
	case *ast.ParenExpr:
		return lofDepIntExpr(e.X)
	case *ast.UnaryExpr:
		return (e.Op == token.ADD || e.Op == token.SUB || e.Op == token.XOR) && lofDepIntExpr(e.X)
	case *ast.BinaryExpr:
		switch e.Op {
		case token.ADD, token.SUB, token.MUL, token.QUO, token.REM, token.AND, token.OR, token.XOR, token.AND_NOT, token.SHL, token.SHR:
			return lofDepIntExpr(e.X) && lofDepIntExpr(e.Y)
		}
	}
	return false
}

// lofDepLevelName reports whether a file name carries an architecture-level element, as
// race_v3_amd64.go does: go/build does not select by one, but a file so named is level-specific.
func lofDepLevelName(name string, arches map[string]bool) bool {
	base := strings.TrimSuffix(strings.TrimSuffix(name, ".go"), "_test")
	elems := strings.Split(base, "_")
	for _, e := range elems[min(1, len(elems)):] {
		for arch, l := range lofAsmLevels {
			for _, v := range l.values {
				if e == arch+v || e == arch+"."+v || (e == v && strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' }) >= 0) {
					return true
				}
			}
		}
		if a, _, ok := strings.Cut(e, "."); ok && arches[a] {
			return true
		}
	}
	return false
}

// lofDepIdents returns the names n mentions: identifiers bare, and each qualified identifier also as
// "q.X".
func lofDepIdents(n ast.Node) []string {
	if n == nil {
		return nil
	}
	var out []string
	ast.Inspect(n, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := n.X.(*ast.Ident); ok {
				out = append(out, id.Name, id.Name+"."+n.Sel.Name)
				return false
			}
			ast.Inspect(n.X, func(m ast.Node) bool {
				if id, ok := m.(*ast.Ident); ok {
					out = append(out, id.Name)
				}
				return true
			})
			return false
		case *ast.Ident:
			out = append(out, n.Name)
		}
		return true
	})
	return out
}

// depPkg reads the package in dir once: per tool for the standard library, per session otherwise.
func (s *lofAsmSession) depPkg(dir string) *lofDepPkg {
	t := s.tool
	read := func() *lofDepPkg { return lofDepRead(dir, t.arches) }
	if dir != "" && strings.HasPrefix(dir, filepath.Join(t.root, "src")+string(filepath.Separator)) {
		return lofMemo(&t.mu, t.deps, dir, read)
	}
	return lofMemo(&s.mu, s.deps, dir, read)
}

// depDirs resolves import paths, as a package of the standard library (std) or not imports them, to
// their directories: "" for one that cannot be found. A standard-library import resolves in
// $GOROOT/src, its vendor directory for a path with a dot; any other through `go list`, which finds
// it as the build would without fetching.
func (s *lofAsmSession) depDirs(std bool, paths []string) map[string]string {
	t := s.tool
	out := map[string]string{}
	var need []string
	for _, p := range paths {
		if p == "C" || out[p] != "" {
			continue
		}
		dotted := strings.Contains(strings.SplitN(p, "/", 2)[0], ".")
		rel := p
		if std && dotted {
			rel = "vendor/" + p
		}
		if std || !dotted {
			if d := filepath.Join(t.root, "src", filepath.FromSlash(rel)); lofDir(d) {
				out[p] = d
				continue
			}
		}
		if std {
			out[p] = ""
			continue
		}
		s.mu.Lock()
		d, ok := s.depPaths[p]
		s.mu.Unlock()
		if ok {
			out[p] = d
			continue
		}
		need = append(need, p)
	}
	if len(need) > 0 {
		found := map[string]string{}
		cmd := exec.CommandContext(s.ctx, filepath.Join(t.root, "bin", "go"), append([]string{"list", "-e", "-find", "-f", "{{.ImportPath}}\t{{.Dir}}"}, need...)...)
		cmd.Dir = s.buildDir
		env := append(lofAsmBaseEnv(s.env), "GOPROXY=off", "GONOPROXY=none.invalid", "GOVCS=*:off", "GOTOOLCHAIN=local")
		cmd.Env = append(env, s.modGoflags())
		if lofAsmExecHook != nil {
			lofAsmExecHook(cmd)
		}
		if b, err := cmd.Output(); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if p, d, ok := strings.Cut(line, "\t"); ok && d != "" {
					found[p] = d
				}
			}
		}
		s.mu.Lock()
		for _, p := range need {
			s.depPaths[p] = found[p]
			out[p] = found[p]
		}
		s.mu.Unlock()
	}
	return out
}

func lofDir(d string) bool {
	fi, err := os.Stat(d)
	return err == nil && fi.IsDir()
}

// depStd reports whether dir holds a standard-library package.
func (s *lofAsmSession) depStd(dir string) bool {
	return strings.HasPrefix(dir, filepath.Join(s.tool.root, "src")+string(filepath.Separator))
}

// closure returns the facts of every Go file of the package in dir and of each package any of them
// may import, transitively.
func (s *lofAsmSession) closure(dir string) lofDepFacts {
	return lofMemo(&s.mu, s.closures, dir, func() lofDepFacts {
		var out lofDepFacts
		seen := map[string]bool{dir: true}
		queue := []string{dir}
		for len(queue) > 0 {
			d := queue[0]
			queue = queue[1:]
			pkg := s.depPkg(d)
			out.bad = out.bad || pkg.bad
			var imps []string
			for _, f := range pkg.files {
				out.add(f.lofDepFacts)
				for _, im := range f.imports {
					imps = append(imps, im.path)
				}
			}
			for _, c := range s.depDirs(s.depStd(d), imps) {
				if c == "" {
					out.bad = true
					continue
				}
				if !seen[c] {
					seen[c] = true
					queue = append(queue, c)
				}
			}
		}
		slices.Sort(out.exps)
		slices.Sort(out.tags)
		return out
	})
}

// levelDep reports whether a go_asm.h of the package may vary with the architecture level beyond
// its own Go file set: some file of the package or of its import closure is level-specific, or
// some could not be read.
func (s *lofAsmSession) levelDep(it lofAsmItem) bool {
	c := s.closure(it.dir)
	return c.level || c.bad
}

// slice returns the facts of the files declaring names in the package in dir and, transitively, of
// those declaring what their declarations mention, here and in the packages they qualify a name
// with. A name a file cannot place (a qualifier no import of it gives, or a dot import) brings in
// the whole closure of the file's imports.
func (s *lofAsmSession) slice(dir string, names []string) lofDepFacts {
	var out lofDepFacts
	type node struct{ dir, name string }
	seen := map[node]bool{}
	var queue []node
	push := func(d, n string) {
		if k := (node{d, n}); !seen[k] {
			seen[k] = true
			queue = append(queue, k)
		}
	}
	for _, n := range names {
		push(dir, n)
	}
	// allInt reports whether every declaration of name in d is integer arithmetic on names that are
	// all so in turn: which files declare them can change the constant's value, never its kind. No
	// value changes the symbols a listing references: a go_asm.h name's presence and kind do not
	// depend on one, a bool reads as either (lofAsmObj refs), and a string fails closed
	// (lofAsmHdrString). Only a kind does.
	memo := map[node]bool{}
	var allInt func(d, name string) bool
	allInt = func(d, name string) bool {
		k := node{d, name}
		if v, ok := memo[k]; ok {
			return v
		}
		memo[k] = false
		pkg := s.depPkg(d)
		ok := !pkg.bad
		for _, f := range pkg.files {
			refs, declared := f.refs[name]
			if !ok || !declared {
				continue
			}
			ok = f.ints[name]
			for _, r := range refs {
				if !ok {
					break
				}
				q, x, qualified := strings.Cut(r, ".")
				if !qualified {
					// A name no file of d declares is predeclared (iota) or a package's.
					ok = !pkg.decls[r] || allInt(d, r)
					if ok && !pkg.decls[r] {
						ok = !slices.ContainsFunc(f.imports, func(im lofDepImport) bool { return im.name == "." })
					}
					continue
				}
				if pkg.decls[q] {
					ok = false
					continue
				}
				found := false
				for _, im := range f.imports {
					if im.name == q || (im.name == "" && slices.Contains(s.depPkg(s.depDirs(s.depStd(d), []string{im.path})[im.path]).names, q)) {
						c := s.depDirs(s.depStd(d), []string{im.path})[im.path]
						found = c != "" && allInt(c, x)
						break
					}
				}
				ok = found
			}
		}
		memo[k] = ok
		return ok
	}
	whole := func(d string, imps []lofDepImport) {
		var paths []string
		for _, im := range imps {
			paths = append(paths, im.path)
		}
		for _, c := range s.depDirs(s.depStd(d), paths) {
			if c == "" {
				out.bad = true
				continue
			}
			out.add(s.closure(c))
		}
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		pkg := s.depPkg(n.dir)
		out.bad = out.bad || pkg.bad
		std := s.depStd(n.dir)
		for _, f := range pkg.files {
			refs, ok := f.refs[n.name]
			if !ok {
				continue
			}
			facts := f.lofDepFacts
			if n.dir == dir || (allInt(n.dir, n.name) && s.declaredAlways(pkg, n.name)) {
				// The package's own files are enumerated as its own, and lofAsmHdrStable judges them.
				// A file that can change only an integer's value changes no symbol, so long as some
				// file declares the name whatever the tags: where none does, the build that compiles
				// is not the one a single variant would make.
				facts.tags = nil
			}
			out.add(facts)
			var dots []lofDepImport
			for _, im := range f.imports {
				if im.name == "." {
					dots = append(dots, im)
				}
			}
			for _, r := range refs {
				q, x, qualified := strings.Cut(r, ".")
				if !qualified {
					if pkg.decls[r] {
						push(n.dir, r)
					} else if len(dots) > 0 {
						whole(n.dir, dots)
					}
					continue
				}
				placed := false
				for _, im := range f.imports {
					if im.name == "_" || im.name == "." || (im.name != "" && im.name != q) {
						continue
					}
					c := s.depDirs(std, []string{im.path})[im.path]
					if c == "" {
						if im.name == q {
							out.bad = true
							placed = true
						}
						continue
					}
					if im.name == "" && !slices.Contains(s.depPkg(c).names, q) {
						continue
					}
					push(c, x)
					placed = true
				}
				if pkg.decls[q] {
					// A selector on a local name: a field or method of it.
					push(n.dir, q)
					placed = true
				}
				if !placed {
					whole(n.dir, f.imports)
				}
			}
		}
	}
	slices.Sort(out.exps)
	slices.Sort(out.tags)
	return out
}

// lofAsmABIPkgs returns the packages the toolchain at root lets assembly use ABI selectors in, for
// which cmd/asm defines a GOEXPERIMENT_ macro per enabled experiment (cmd/asm/main.go): the
// allowAsmABIPkgs of cmd/internal/objabi/pkgspecial.go. nil when they cannot be read.
func lofAsmABIPkgs(root string) []string {
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, "src", "cmd", "internal", "objabi", "pkgspecial.go"), nil, parser.SkipObjectResolution)
	if err != nil {
		return nil
	}
	var out []string
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			if len(vs.Names) != 1 || vs.Names[0].Name != "allowAsmABIPkgs" || len(vs.Values) != 1 {
				continue
			}
			cl, ok := vs.Values[0].(*ast.CompositeLit)
			if !ok {
				return nil
			}
			for _, e := range cl.Elts {
				bl, ok := e.(*ast.BasicLit)
				if !ok || bl.Kind != token.STRING {
					return nil
				}
				p, err := strconv.Unquote(bl.Value)
				if err != nil {
					return nil
				}
				out = append(out, p)
			}
		}
	}
	return out
}

// effective returns the experiments a build of the tuple runs with, as the toolchain resolves its
// GOEXPERIMENT over the port's defaults (go list's context.ToolTags, internal/buildcfg): two
// tuples that resolve alike build alike. The GOEXPERIMENT itself, marked apart, when the toolchain
// cannot resolve it.
func (t *lofAsmTool) effective(tu lofAsmTuple) string {
	x := tu.goexperiment(t.experiment)
	vars := append(tu.envVars(), "GOEXPERIMENT="+x)
	return lofMemo(&t.mu, t.effs, strings.Join(vars, "\x00"), func() string {
		cmd := exec.Command(filepath.Join(t.root, "bin", "go"), "list", "-find", "-f", "{{join context.ToolTags \" \"}}", "unsafe")
		cmd.Dir = t.root
		cmd.Env = append(append(lofAsmBaseEnv(t.env), vars...), "GOTOOLCHAIN=local", "GOFLAGS=", "GOWORK=off")
		if lofAsmExecHook != nil {
			lofAsmExecHook(cmd)
		}
		b, err := cmd.Output()
		if err != nil {
			return "raw:" + x
		}
		var on []string
		for _, tag := range strings.Fields(string(b)) {
			if e, ok := strings.CutPrefix(tag, "goexperiment."); ok {
				on = append(on, e)
			}
		}
		slices.Sort(on)
		return "on:" + strings.Join(on, ",")
	})
}

// declaredAlways reports whether every assignment of the build tags the files of pkg declaring name
// are constrained on, and of cgo where one imports "C", selects one of them. A file go/build's name
// rules exclude on some port is taken to be selected by none.
func (s *lofAsmSession) declaredAlways(pkg *lofDepPkg, name string) bool {
	var files []lofDepFile
	var tags []string
	for _, f := range pkg.files {
		if _, ok := f.refs[name]; !ok {
			continue
		}
		if slices.ContainsFunc(s.tool.ports, func(p lofPort) bool { return !lofMatchName(p, f.name) }) {
			continue
		}
		files = append(files, f)
		if f.expr != nil {
			tags = lofExprTags(f.expr, tags)
		}
		if f.cgo && !slices.Contains(tags, "cgo") {
			tags = append(tags, "cgo")
		}
	}
	if len(files) == 0 || len(tags) > 16 {
		return false
	}
	for mask := uint32(0); mask < 1<<len(tags); mask++ {
		on := func(tag string) bool {
			i := slices.Index(tags, tag)
			return i >= 0 && mask&(1<<i) != 0
		}
		if !slices.ContainsFunc(files, func(f lofDepFile) bool {
			return (f.expr == nil || f.expr.Eval(on)) && (!f.cgo || on("cgo"))
		}) {
			return false
		}
	}
	return true
}
