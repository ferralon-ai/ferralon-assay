package goanalysis

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"go/build/constraint"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// lofEngine is what the left-out reach test needs from one scan, advisory-independent: every file
// the build left out, with its declaration closure (lofFacts), and two call graphs over the whole
// program (dependencies' bodies included), each built as govulncheck builds its own (lofGraph). G0
// is rooted at govulncheck's entries; G_T at those plus every loaded function the closures touch,
// and every method of every loaded type they touch. Each graph is kept as its callers per node, for
// the per-advisory reverse walk from the vulnerable symbols.
type lofEngine struct {
	Strs  []string
	Nodes []lofNode
	In0   [][]int32
	InT   [][]int32
	// Decls holds every function and declared method of every loaded package, in or out of either
	// graph, as {Pkg, Name, Sym, method name} string ids (method name -1 for a function): S is
	// every one of them the advisory names, whether loaded code calls it or not.
	Decls [][4]int32
	// Fail is set when the engine could not be built (lofGraphError): every left-out file counts.
	Fail string
	// FailStd is set when the toolchain's standard library source cannot be established
	// (lofUnknownToolchain, lofGorootMismatch): every left-out file counts for a standard-library
	// refutation.
	FailStd string
	// Facts holds each left-out file's lofFacts, gob-encoded on its own: a scan's check reads a few
	// files' facts, so it decodes only those (file).
	Facts map[string][]byte
	files map[string]*lofFacts
}

// seal encodes every file's facts into Facts.
func (e *lofEngine) seal() error {
	e.Facts = make(map[string][]byte, len(e.files))
	for path, f := range e.files {
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(f); err != nil {
			return err
		}
		e.Facts[path] = buf.Bytes()
	}
	return nil
}

// file returns the facts of the left-out file at path, decoding them on first use; ok is false
// when the engine holds no such file or its facts cannot be decoded.
func (e *lofEngine) file(path string) (f *lofFacts, ok bool) {
	if f, ok := e.files[path]; ok {
		return f, true
	}
	b, ok := e.Facts[path]
	if !ok {
		return nil, false
	}
	f = &lofFacts{}
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(f); err != nil {
		return nil, false
	}
	if e.files == nil {
		e.files = map[string]*lofFacts{}
	}
	e.files[path] = f
	return f, true
}

// lofNode is one function of the program: its symbol as the vulnerability database names it
// (dbSymbol: Pkg, Name, and Sym, the id of symKey(Pkg, Name)), the method names it answers to (M1 its own, M2 its enclosing function's;
// -1 for none), whether its address is taken in G_T's slice (Addr), and the slices it lies in: G0's
// final (F0) and G_T's final (FT).
type lofNode struct {
	Pkg, Name, Sym, M1, M2 int32
	Addr, F0, FT           bool
	// Synth marks a package's synthesized initializer: never a vulnerable symbol itself, only a
	// caller of the declared init functions and the calls in variable initializers it runs.
	Synth bool
}

// lofFacts is one left-out file's closure. Funcs, TypeMeth and NewMeth hold symbols (string ids of
// "pkg\x00name", as dbSymbol names them): the loaded functions the closure reaches, every method in
// the method set (T and *T) of a loaded type it names, and every method in the method set of a
// loaded type the file declares methods on. Methods holds the method names the closure selects
// (string ids); Src the source functions it walks (package path, "F" or "T.M"). Novel is set when
// one of the file's loaded roots lies outside G0's CHA-round or final slice. Links holds the
// packages the build did not load that the file can link (string ids), with LinkFC what that walk
// fails closed on.
type lofFacts struct {
	FC, FCStd                []string
	Funcs, TypeMeth, NewMeth []int32
	Methods                  []int32
	Src                      [][2]int32
	Dyn, Vars, Reflect, Sink bool
	Novel, Dropped           bool
	Excluded                 bool
	Links                    []int32
	LinkFC                   []string
}

// lofCandidate is a left-out file and the package it belongs to.
type lofCandidate struct {
	path, pkg string
	std       bool
}

// lofCandidates lists the non-test Go files the build left out: those of every loaded package, and
// those of the main module's directories the build did not load (firstPartyLeftOut), whose package
// is the module path joined with the directory.
func lofCandidates(pkgs []*packages.Package) []lofCandidate {
	var out []lofCandidate
	loadedDirs := map[string]bool{}
	mainDir, mainPath := "", ""
	goFile := func(f string) bool { return strings.HasSuffix(f, ".go") && !strings.HasSuffix(f, "_test.go") }
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, files := range [][]string{p.GoFiles, p.OtherFiles, p.IgnoredFiles} {
			for _, f := range files {
				loadedDirs[filepath.Dir(f)] = true
			}
		}
		if p.Module != nil && p.Module.Main && mainDir == "" {
			mainDir, mainPath = p.Module.Dir, p.Module.Path
		}
		for _, f := range p.IgnoredFiles {
			if goFile(f) {
				out = append(out, lofCandidate{path: f, pkg: p.PkgPath, std: p.Module == nil})
			}
		}
	})
	if mainDir != "" {
		firstPartyLeftOut(mainDir, loadedDirs, func(f string) bool {
			if goFile(f) {
				rel, err := filepath.Rel(mainDir, filepath.Dir(f))
				if err == nil {
					pkg := mainPath
					if rel != "." {
						pkg += "/" + filepath.ToSlash(rel)
					}
					out = append(out, lofCandidate{path: f, pkg: pkg})
				}
			}
			return false
		})
	}
	slices.SortFunc(out, func(a, b lofCandidate) int { return strings.Compare(a.path, b.path) })
	return slices.CompactFunc(out, func(a, b lofCandidate) bool { return a.path == b.path })
}

// loadLofEngine returns the scan's engine, built once per tree per scan through the run cache. A
// build that fails or panics yields an engine whose Fail is lofGraphError, so every left-out file
// counts.
func loadLofEngine(ctx context.Context, pkgs []*packages.Package, release *goRelease, buildDir string, env []string) *lofEngine {
	key := append([]string{buildDir, fmt.Sprint(release)}, env...)
	key = append(key, os.Environ()...)
	b, err := runCached(ctx, "leftout", key, func() (b []byte, err error) {
		defer func() {
			if r := recover(); r != nil {
				b, err = nil, fmt.Errorf("left-out engine: %v", r)
			}
		}()
		e, err := buildLofEngine(ctx, pkgs, release, buildDir, env)
		if err != nil {
			return nil, err
		}
		if err := e.seal(); err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(e); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	})
	if err != nil {
		return &lofEngine{Fail: lofGraphError}
	}
	var e lofEngine
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&e); err != nil {
		return &lofEngine{Fail: lofGraphError}
	}
	return &e
}

// lofInterner assigns string ids.
type lofInterner struct {
	ids  map[string]int32
	strs []string
}

func (in *lofInterner) id(s string) int32 {
	if id, ok := in.ids[s]; ok {
		return id
	}
	id := int32(len(in.strs))
	in.ids[s] = id
	in.strs = append(in.strs, s)
	return id
}

// symKey names a function as dbSymbol does: its package path and its name, "T.M" for a method.
func symKey(pkg, name string) string { return pkg + "\x00" + name }

func funcKey(f *types.Func) string {
	f = f.Origin()
	if f.Pkg() == nil {
		return ""
	}
	name := f.Name()
	if recv := f.Signature().Recv(); recv != nil {
		t := types.Unalias(recv.Type())
		if p, ok := t.(*types.Pointer); ok {
			t = types.Unalias(p.Elem())
		}
		if n, ok := t.(*types.Named); ok {
			name = n.Obj().Name() + "." + name
		}
	}
	return symKey(f.Pkg().Path(), name)
}

// buildLofEngine builds the engine: every candidate's closure under the walk's budget, then G0 and
// G_T.
func buildLofEngine(ctx context.Context, pkgs []*packages.Package, release *goRelease, buildDir string, env []string) (*lofEngine, error) {
	floor := goDirectiveFloor(pkgs)
	excluded := func(x constraint.Expr) bool { return ignored(x) || toolchainExcluded(x, release, floor) }
	goroot, failStd := lofToolchain(ctx, buildDir, env, release)
	w := newLofWorld(ctx, pkgs, buildDir, env, excluded, goroot, time.Now().Add(lofBudgetTime))
	w.modcache = lofModCache(ctx, buildDir, env)
	in := &lofInterner{ids: map[string]int32{}}
	e := &lofEngine{FailStd: failStd, files: map[string]*lofFacts{}}

	cands := lofCandidates(pkgs)
	closures := map[string]*lofClosure{}
	for _, c := range cands {
		cl := w.closure(c.path, c.pkg)
		closures[c.path] = cl
		f := &lofFacts{FC: cl.fc, FCStd: cl.fcStd, Dyn: cl.dyn, Vars: cl.vars, Reflect: cl.reflect, Sink: cl.sink,
			Excluded: cl.excluded, Dropped: cl.dropped}
		links, linkFC := w.links(filepath.Dir(c.path), c.std)
		for ip := range links {
			f.Links = append(f.Links, in.id(ip))
		}
		slices.Sort(f.Links)
		f.LinkFC = linkFC
		for m := range cl.methods {
			f.Methods = append(f.Methods, in.id(m))
		}
		for s := range cl.src {
			f.Src = append(f.Src, [2]int32{in.id(s[0]), in.id(s[1])})
		}
		for fn := range cl.funcs {
			f.Funcs = append(f.Funcs, in.id(funcKey(fn)))
		}
		for tp := range cl.inits {
			f.Funcs = append(f.Funcs, in.id(symKey(tp.Path(), "init")))
		}
		for tn := range cl.types {
			f.TypeMeth = append(f.TypeMeth, methodKeys(in, tn)...)
		}
		for _, tn := range cl.newMeth {
			f.NewMeth = append(f.NewMeth, methodKeys(in, tn)...)
		}
		e.files[c.path] = f
	}

	sp, err := buildSSAWith(&LoadResult{Packages: pkgs}, ssautil.AllPackages)
	if err != nil {
		return nil, err
	}
	chaG := cha.CallGraph(sp.prog)
	entries := sp.govulncheckEntries()
	g0, sl0, cs0 := lofGraph(chaG, entries)

	// The loaded roots each closure adds: the functions it reaches and the methods of the named
	// types it names.
	extra := map[*ssa.Function]bool{}
	for path, cl := range closures {
		roots := map[*ssa.Function]bool{}
		for fn := range cl.funcs {
			if v := sp.prog.FuncValue(fn); v != nil {
				roots[v] = true
			}
		}
		for tp := range cl.inits {
			if sp := sp.prog.Package(tp); sp != nil {
				if v := sp.Func("init"); v != nil {
					roots[v] = true
				}
			}
		}
		for tn := range cl.types {
			named, ok := tn.Type().(*types.Named)
			if !ok || named.TypeParams().Len() > 0 {
				continue
			}
			for _, t := range []types.Type{named, types.NewPointer(named)} {
				ms := sp.prog.MethodSets.MethodSet(t)
				for i := 0; i < ms.Len(); i++ {
					if v := sp.prog.MethodValue(ms.At(i)); v != nil {
						roots[v] = true
					}
				}
			}
		}
		for fn := range roots {
			extra[fn] = true
			if !sl0[fn] || !cs0[fn] {
				e.files[path].Novel = true
			}
		}
	}
	rootsT := slices.Clone(entries)
	for fn := range extra {
		rootsT = append(rootsT, fn)
	}
	gT, slT, _ := lofGraph(chaG, rootsT)

	addr := map[*ssa.Function]bool{}
	for fn := range slT {
		for _, b := range fn.Blocks {
			for _, ins := range b.Instrs {
				var buf [10]*ssa.Value
				ops := ins.Operands(buf[:0])
				if c, ok := ins.(ssa.CallInstruction); ok && c.Common().StaticCallee() != nil {
					ops = ops[1:]
				}
				for _, op := range ops {
					if f, ok := (*op).(*ssa.Function); ok {
						addr[f] = true
					}
				}
				if mc, ok := ins.(*ssa.MakeClosure); ok {
					addr[mc.Fn.(*ssa.Function)] = true
				}
			}
		}
	}

	ids := map[*ssa.Function]int32{}
	node := func(fn *ssa.Function) int32 {
		if id, ok := ids[fn]; ok {
			return id
		}
		id := int32(len(e.Nodes))
		ids[fn] = id
		pkg, name := lofSymbol(fn)
		n := lofNode{Pkg: in.id(pkg), Name: in.id(name), Sym: in.id(symKey(pkg, name)), M1: -1, M2: -1, Addr: addr[fn], F0: sl0[fn], FT: slT[fn],
			Synth: fn.Object() == nil && fn.Parent() == nil && fn.Name() == "init"}
		if fn.Signature.Recv() != nil {
			n.M1 = in.id(fn.Name())
		}
		if _, m, ok := strings.Cut(name, "."); ok {
			n.M2 = in.id(m)
		}
		e.Nodes = append(e.Nodes, n)
		return id
	}
	for _, set := range []map[*ssa.Function]bool{sl0, slT} {
		for fn := range set {
			node(fn)
		}
	}
	callers := func(g *callgraph.Graph) [][]int32 {
		for fn := range g.Nodes {
			if fn != nil {
				node(fn)
			}
		}
		of := make([][]int32, len(e.Nodes))
		for fn, n := range g.Nodes {
			if fn == nil {
				continue
			}
			id := ids[fn]
			for _, edge := range n.In {
				if edge.Caller.Func != nil {
					of[id] = append(of[id], ids[edge.Caller.Func])
				}
			}
		}
		return of
	}
	e.In0 = callers(g0)
	e.InT = callers(gT)
	seenPkg := map[*types.Package]bool{}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.Types == nil || seenPkg[p.Types] {
			return
		}
		seenPkg[p.Types] = true
		path := p.Types.Path()
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			switch o := scope.Lookup(name).(type) {
			case *types.Func:
				e.Decls = append(e.Decls, [4]int32{in.id(path), in.id(name), in.id(symKey(path, name)), -1})
			case *types.TypeName:
				named, ok := o.Type().(*types.Named)
				if !ok || o.IsAlias() {
					continue
				}
				for i := 0; i < named.NumMethods(); i++ {
					m := named.Method(i).Name()
					sym := name + "." + m
					e.Decls = append(e.Decls, [4]int32{in.id(path), in.id(sym), in.id(symKey(path, sym)), in.id(m)})
				}
			}
		}
	})
	for len(e.In0) < len(e.Nodes) {
		e.In0 = append(e.In0, nil)
	}
	e.Strs = in.strs
	return e, nil
}

// methodKeys returns the symbols of the methods in the method sets of tn's type and its pointer.
func methodKeys(in *lofInterner, tn *types.TypeName) []int32 {
	var out []int32
	for _, t := range []types.Type{tn.Type(), types.NewPointer(tn.Type())} {
		ms := types.NewMethodSet(t)
		for i := 0; i < ms.Len(); i++ {
			if f, ok := ms.At(i).Obj().(*types.Func); ok {
				if k := funcKey(f); k != "" {
					out = append(out, in.id(k))
				}
			}
		}
	}
	return out
}

// lofSymbol names fn as dbSymbol does, and a package's synthesized initializer, or a function
// nested in it, as the package's "init", the name its declared init functions take.
func lofSymbol(fn *ssa.Function) (pkg, name string) {
	root := fn
	for root.Parent() != nil {
		root = root.Parent()
	}
	if root.Object() == nil && root.Pkg != nil && root.Name() == "init" {
		return root.Pkg.Pkg.Path(), "init"
	}
	return dbSymbol(fn)
}

// lofGraph builds the call graph govulncheck (v1.3.0, internal/vulncheck callGraph) builds, rooted
// at roots: the functions roots reach through initial's call edges and function references (the
// CHA-round slice), refined by VTA, sliced again from the refined graph (the final slice), and
// refined by VTA once more. It returns the graph, its final slice and its CHA-round slice.
func lofGraph(initial *callgraph.Graph, roots []*ssa.Function) (*callgraph.Graph, map[*ssa.Function]bool, map[*ssa.Function]bool) {
	slice := func(cg *callgraph.Graph) map[*ssa.Function]bool {
		seen := map[*ssa.Function]bool{}
		stack := slices.Clone(roots)
		for len(stack) > 0 {
			f := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if seen[f] {
				continue
			}
			seen[f] = true
			if n := cg.Nodes[f]; n != nil {
				for _, e := range n.Out {
					if e.Site != nil {
						stack = append(stack, e.Callee.Func)
					}
				}
			}
			var buf [10]*ssa.Value
			for _, b := range f.Blocks {
				for _, instr := range b.Instrs {
					for _, op := range instr.Operands(buf[:0]) {
						if fn, ok := (*op).(*ssa.Function); ok {
							stack = append(stack, fn)
						}
					}
				}
			}
		}
		return seen
	}
	cs := slice(initial)
	v1 := vta.CallGraph(cs, initial)
	fs := slice(v1)
	return vta.CallGraph(fs, v1), fs, cs
}

// lofRow evaluates the left-out reach test for one refutation: the refuted module and its symbols
// that count, S (inS). sLoaded is set when one of S's packages is loaded in the build.
type lofRow struct {
	e       *lofEngine
	stdlib  bool
	inS     func(pkg, name string) bool
	inPkg   func(pkg string) bool
	sLoaded bool
	r0, rT  *lofReach
}

// lofReach is what reaches S in one graph: R, as symbols, is every function of S, whether the
// graph holds it or not, and every function of the graph's slice that calls into one; names, the
// method names R's functions answer to; addr, whether R holds a function whose address the slice
// takes.
type lofReach struct {
	syms  map[int32]bool
	names map[int32]bool
	addr  bool
}

func (row *lofRow) reach(callers [][]int32, inSlice func(lofNode) bool) *lofReach {
	r := &lofReach{syms: map[int32]bool{}, names: map[int32]bool{}}
	// inPkg by package string id, computed once per id: most declarations lie outside S's packages.
	pkgIn := map[int32]bool{}
	inS := func(pkg, name int32) bool {
		in, ok := pkgIn[pkg]
		if !ok {
			in = row.inPkg(row.e.Strs[pkg])
			pkgIn[pkg] = in
		}
		return in && row.inS(row.e.Strs[pkg], row.e.Strs[name])
	}
	for _, d := range row.e.Decls {
		if inS(d[0], d[1]) {
			r.syms[d[2]] = true
			if d[3] >= 0 {
				r.names[d[3]] = true
			}
		}
	}
	seen := make([]bool, len(row.e.Nodes))
	var queue []int32
	for i, n := range row.e.Nodes {
		if inSlice(n) && !n.Synth && inS(n.Pkg, n.Name) {
			seen[i] = true
			queue = append(queue, int32(i))
		}
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		n := row.e.Nodes[id]
		r.syms[n.Sym] = true
		for _, m := range []int32{n.M1, n.M2} {
			if m >= 0 {
				r.names[m] = true
			}
		}
		r.addr = r.addr || n.Addr
		if int(id) < len(callers) {
			for _, c := range callers[id] {
				if !seen[c] {
					seen[c] = true
					queue = append(queue, c)
				}
			}
		}
	}
	return r
}

// counts reports whether the left-out file at path may reach S. A file the engine does not hold, or
// any file when the engine could not be built, counts.
//
// Stage 0: when none of S's packages is loaded, the file counts only when it can link one of them
// (lofWorld.links), or that walk fails closed: S executes only once linked.
//
// Stage 1: the file counts when its closure fails closed, or when one of these holds against R,
// what reaches S in the graph the file is tested against:
//
//   - func-in-R: it reaches a loaded function in R;
//   - type-with-R-method: it names a loaded type whose method set (T or *T) holds an R method;
//   - method-set-change: it declares methods on a loaded type whose method set holds an R method;
//   - method-name-in-R: it selects a method name some R function answers to;
//   - dynamic-call-and-R-address-taken: it calls a function value, or reads a loaded variable,
//     while R holds a function whose address is taken;
//   - reflect-call: it calls reflect's Call, CallSlice, Method or MethodByName while R holds a
//     method or an address-taken function;
//   - reaches-S-in-source: it walks the source of a function in S;
//   - routed: it passes a value to a loaded function with a func- or interface-typed parameter
//     while R holds a method or an address-taken function.
//
// A file none of whose loaded roots is new to G0 (not Novel) is tested against G0's R, otherwise
// against G_T's. A non-novel file's roots already lie in both of G0's slices, so G0 already holds
// every call they make on the values the loaded program builds. What G0 lacks is only the values
// the file itself builds: a type it constructs is a loaded one it names (type-with-R-method), one
// it declares methods on (method-set-change), or its own source, walked whole; such a value reaches
// loaded code only as an argument to a loaded function, and loaded code calls into it only through
// a func- or interface-typed parameter (routed), a method name (method-name-in-R) or a dynamic
// call (dynamic-call-and-R-address-taken). Each of those is tested against R directly.
func (row *lofRow) counts(path string) bool {
	e := row.e
	if e.Fail != "" {
		return true
	}
	f, ok := e.file(path)
	if !ok {
		return true
	}
	if f.Dropped || f.Excluded {
		return false
	}
	if !row.sLoaded {
		linked := slices.ContainsFunc(f.Links, func(id int32) bool { return row.inPkg(e.Strs[id]) })
		if !linked {
			return len(f.LinkFC) > 0
		}
	}
	if len(f.FC) > 0 || (row.stdlib && (e.FailStd != "" || len(f.FCStd) > 0)) {
		return true
	}
	var r *lofReach
	if f.Novel {
		if row.rT == nil {
			row.rT = row.reach(e.InT, func(n lofNode) bool { return n.FT })
		}
		r = row.rT
	} else {
		if row.r0 == nil {
			row.r0 = row.reach(e.In0, func(n lofNode) bool { return n.F0 })
		}
		r = row.r0
	}
	hit := func(ids []int32) bool { return slices.ContainsFunc(ids, func(id int32) bool { return r.syms[id] }) }
	switch {
	case hit(f.Funcs), hit(f.TypeMeth), hit(f.NewMeth):
		return true
	case slices.ContainsFunc(f.Methods, func(id int32) bool { return r.names[id] }):
		return true
	case (f.Dyn || f.Vars) && r.addr:
		return true
	case (f.Reflect || f.Sink) && (r.addr || len(r.names) > 0):
		return true
	}
	return slices.ContainsFunc(f.Src, func(s [2]int32) bool { return row.inS(e.Strs[s[0]], e.Strs[s[1]]) })
}
