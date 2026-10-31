package goanalysis

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"go/build/constraint"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
	// graph, as {Pkg, Name, Sym, method name, receiver type} string ids (method name and receiver
	// type -1 for a function): S is every one of them the advisory names, whether loaded code calls
	// it or not.
	Decls [][5]int32
	// Live0 and LiveT hold the named types with methods or interface underlyings (string ids of
	// symKey(package, type name), sorted) a value of which can exist at run time in G0's or G_T's
	// program (lofLive).
	Live0, LiveT []int32
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
	// Recv is a method's receiver type (the string id of symKey(package, type name)),
	// lofRecvUnknown when it has a receiver no named type declares, -1 for a function.
	Pkg, Name, Sym, M1, M2, Recv int32
	Addr, F0, FT                 bool
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
// fails closed on. Live holds the named types (as lofEngine.Live0) a value of which the closure can
// make or reach from the types and functions it names, less G0's.
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
	Live                     []int32
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
		return e.encode()
	})
	if err != nil {
		return &lofEngine{Fail: lofGraphError}
	}
	e, err := decodeLofEngine(b)
	if err != nil {
		return &lofEngine{Fail: lofGraphError}
	}
	return e
}

// lofWire is an engine's encoding: gob for the failures and the facts, and the graph (Strs, Nodes,
// In0, InT, Decls) packed by hand as little-endian uint32s. Every analyzer request decodes the
// engine afresh, and gob decodes the graph's millions of elements one by one through reflection.
type lofWire struct {
	Fail, FailStd string
	Facts         map[string][]byte
	Graph         []byte
	Live0, LiveT  []int32
}

func (e *lofEngine) encode() ([]byte, error) {
	u32 := binary.LittleEndian.AppendUint32
	var g []byte
	g = u32(g, uint32(len(e.Strs)))
	for _, s := range e.Strs {
		g = u32(g, uint32(len(s)))
	}
	for _, s := range e.Strs {
		g = append(g, s...)
	}
	g = u32(g, uint32(len(e.Nodes)))
	for _, n := range e.Nodes {
		for _, v := range []int32{n.Pkg, n.Name, n.Sym, n.M1, n.M2, n.Recv} {
			g = u32(g, uint32(v))
		}
		var flags byte
		for i, f := range []bool{n.Addr, n.F0, n.FT, n.Synth} {
			if f {
				flags |= 1 << i
			}
		}
		g = append(g, flags)
	}
	for _, in := range [][][]int32{e.In0, e.InT} {
		g = u32(g, uint32(len(in)))
		for _, cs := range in {
			g = u32(g, uint32(len(cs)))
		}
		for _, cs := range in {
			for _, c := range cs {
				g = u32(g, uint32(c))
			}
		}
	}
	g = u32(g, uint32(len(e.Decls)))
	for _, d := range e.Decls {
		for _, v := range d {
			g = u32(g, uint32(v))
		}
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(lofWire{Fail: e.Fail, FailStd: e.FailStd, Facts: e.Facts, Graph: g, Live0: e.Live0, LiveT: e.LiveT}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeLofEngine(b []byte) (*lofEngine, error) {
	var w lofWire
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&w); err != nil {
		return nil, err
	}
	e := &lofEngine{Fail: w.Fail, FailStd: w.FailStd, Facts: w.Facts, Live0: w.Live0, LiveT: w.LiveT}
	g := w.Graph
	short := false
	next := func() uint32 {
		if len(g) < 4 {
			short = true
			return 0
		}
		v := binary.LittleEndian.Uint32(g)
		g = g[4:]
		return v
	}
	// count reads a length, refusing one the remaining bytes cannot hold at width bytes per element,
	// so a corrupt encoding fails rather than allocating without bound.
	count := func(width int) int {
		n := int(next())
		if n*width > len(g) {
			short = true
			return 0
		}
		return n
	}
	lens := make([]int, count(4))
	total := 0
	for i := range lens {
		lens[i] = int(next())
		total += lens[i]
	}
	if total > len(g) {
		return nil, errors.New("left-out engine: short graph")
	}
	all := string(g[:total])
	g = g[total:]
	e.Strs = make([]string, len(lens))
	for i, l := range lens {
		e.Strs[i], all = all[:l], all[l:]
	}
	e.Nodes = make([]lofNode, count(25))
	for i := range e.Nodes {
		n := &e.Nodes[i]
		n.Pkg, n.Name, n.Sym, n.M1, n.M2, n.Recv = int32(next()), int32(next()), int32(next()), int32(next()), int32(next()), int32(next())
		if len(g) < 1 {
			short = true
			break
		}
		flags := g[0]
		g = g[1:]
		n.Addr, n.F0, n.FT, n.Synth = flags&1 != 0, flags&2 != 0, flags&4 != 0, flags&8 != 0
	}
	for _, in := range []*[][]int32{&e.In0, &e.InT} {
		ls := make([]int, count(4))
		total := 0
		for i := range ls {
			ls[i] = int(next())
			total += ls[i]
		}
		if total*4 > len(g) {
			return nil, errors.New("left-out engine: short graph")
		}
		edges := make([]int32, total)
		for i := range edges {
			edges[i] = int32(next())
		}
		*in = make([][]int32, len(ls))
		for i, l := range ls {
			(*in)[i], edges = edges[:l:l], edges[l:]
		}
	}
	e.Decls = make([][5]int32, count(20))
	for i := range e.Decls {
		for j := range e.Decls[i] {
			e.Decls[i][j] = int32(next())
		}
	}
	if short || len(g) != 0 {
		return nil, errors.New("left-out engine: malformed graph")
	}
	return e, nil
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

	// The closures and the build's SSA program are independent; build them side by side.
	var sp *ssaProgram
	var chaG *callgraph.Graph
	ssaDone := lofGo(func() (err error) {
		if sp, err = buildSSAWith(&LoadResult{Packages: pkgs}, ssautil.AllPackages); err == nil {
			chaG = cha.CallGraph(sp.prog)
		}
		return err
	})
	cands := lofCandidates(pkgs)
	closures := map[string]*lofClosure{}
	for _, c := range cands {
		cl := w.closure(c.path, c.pkg)
		closures[c.path] = cl
		f := &lofFacts{FC: cl.fc, FCStd: cl.fcStd, Dyn: cl.dyn, Vars: cl.vars, Reflect: cl.reflect, Sink: cl.sink || (cl.held && cl.asserts),
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

	if err := ssaDone(); err != nil {
		return nil, err
	}
	entries := sp.govulncheckEntries()
	// g0 and gT share only read-only inputs (the program and chaG); build g0 while the closures'
	// roots are collected and gT is built.
	var g0 *callgraph.Graph
	var sl0, cs0 map[*ssa.Function]bool
	g0Done := lofGo(func() error {
		g0, sl0, cs0 = lofGraph(chaG, entries)
		return nil
	})

	// The loaded roots each closure adds: the functions it reaches and the methods of the named
	// types it names.
	extra := map[*ssa.Function]bool{}
	fileRoots := map[string]map[*ssa.Function]bool{}
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
		}
		fileRoots[path] = roots
	}
	rootsT := slices.Clone(entries)
	for fn := range extra {
		rootsT = append(rootsT, fn)
	}
	gT, slT, _ := lofGraph(chaG, rootsT)
	if err := g0Done(); err != nil {
		return nil, err
	}
	for path, roots := range fileRoots {
		for fn := range roots {
			if !sl0[fn] || !cs0[fn] {
				e.files[path].Novel = true
			}
		}
	}

	// What can exist at run time: every value G0's slice computes and every package variable, then
	// G_T's slice on top; and what each file's closure names, less G0's.
	globals := func(l *lofLive) {
		for _, p := range sp.prog.AllPackages() {
			for _, m := range p.Members {
				if g, ok := m.(*ssa.Global); ok {
					l.add(g.Type())
				}
			}
		}
	}
	live := newLofLive()
	globals(live)
	for fn := range sl0 {
		live.addFunc(fn)
	}
	e.Live0 = live.ids(in)
	for fn := range slT {
		live.addFunc(fn)
	}
	e.LiveT = live.ids(in)
	for path, cl := range closures {
		l := newLofLive()
		for tn := range cl.types {
			l.add(tn.Type())
		}
		for fn := range cl.funcs {
			l.add(fn.Type())
		}
		for _, id := range l.ids(in) {
			if _, ok := slices.BinarySearch(e.Live0, id); !ok {
				e.files[path].Live = append(e.files[path].Live, id)
			}
		}
	}

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
		n := lofNode{Pkg: in.id(pkg), Name: in.id(name), Sym: in.id(symKey(pkg, name)), M1: -1, M2: -1, Recv: -1, Addr: addr[fn], F0: sl0[fn], FT: slT[fn],
			Synth: fn.Object() == nil && fn.Parent() == nil && fn.Name() == "init"}
		if fn.Signature.Recv() != nil {
			n.M1 = in.id(fn.Name())
			n.Recv = lofRecvUnknown
		}
		if t, m, ok := strings.Cut(name, "."); ok {
			n.M2 = in.id(m)
			n.Recv = in.id(symKey(pkg, t))
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
				e.Decls = append(e.Decls, [5]int32{in.id(path), in.id(name), in.id(symKey(path, name)), -1, -1})
			case *types.TypeName:
				named, ok := o.Type().(*types.Named)
				if !ok || o.IsAlias() {
					continue
				}
				for i := 0; i < named.NumMethods(); i++ {
					m := named.Method(i).Name()
					sym := name + "." + m
					e.Decls = append(e.Decls, [5]int32{in.id(path), in.id(sym), in.id(symKey(path, sym)), in.id(m), in.id(symKey(path, name))})
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

// lofGo runs f on its own goroutine; the function it returns waits for f and returns its error, or
// the panic f raised as one.
func lofGo(f func() error) func() error {
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("left-out engine: %v", r)
			}
		}()
		done <- f()
	}()
	return sync.OnceValue(func() error { return <-done })
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

// lofRecvUnknown is lofNode.Recv for a method whose receiver no named type declares: its type is
// taken to exist at run time.
const lofRecvUnknown = -2

// lofLive collects the named types a value of which can exist at run time once values of the types
// it is given can: those types, and every type a value of one holds or reflection can name from it,
// through elements, keys, fields, type arguments, constraints and the parameters and results of
// its methods and of its own signature. Reflection makes a value of any type it can name
// (reflect.New, reflect.Zero), and any method it can name it can call with the values it made.
type lofLive struct {
	seen  map[types.Type]bool
	named map[*types.TypeName]bool
}

func newLofLive() *lofLive {
	return &lofLive{seen: map[types.Type]bool{}, named: map[*types.TypeName]bool{}}
}

func (l *lofLive) add(t types.Type) {
	if t == nil || l.seen[t] {
		return
	}
	l.seen[t] = true
	switch t := t.(type) {
	case *types.Alias:
		l.add(types.Unalias(t))
	case *types.Pointer:
		l.add(t.Elem())
	case *types.Slice:
		l.add(t.Elem())
	case *types.Array:
		l.add(t.Elem())
	case *types.Chan:
		l.add(t.Elem())
	case *types.Map:
		l.add(t.Key())
		l.add(t.Elem())
	case *types.Struct:
		for i := range t.NumFields() {
			l.add(t.Field(i).Type())
		}
	case *types.Tuple:
		for i := range t.Len() {
			l.add(t.At(i).Type())
		}
	case *types.Signature:
		l.add(t.Params())
		l.add(t.Results())
	case *types.Interface:
		for i := range t.NumMethods() {
			l.add(t.Method(i).Type())
		}
	case *types.TypeParam:
		l.add(t.Constraint())
	case *types.Named:
		l.named[t.Origin().Obj()] = true
		for i := range t.TypeArgs().Len() {
			l.add(t.TypeArgs().At(i))
		}
		for i := range t.NumMethods() {
			l.add(t.Method(i).Type())
		}
		l.add(t.Underlying())
	}
}

// addFunc adds the types of every value fn computes, and of its signature, type arguments,
// parameters and free variables.
func (l *lofLive) addFunc(fn *ssa.Function) {
	l.add(fn.Signature)
	for _, t := range fn.TypeArgs() {
		l.add(t)
	}
	for _, p := range fn.Params {
		l.add(p.Type())
	}
	for _, v := range fn.FreeVars {
		l.add(v.Type())
	}
	var buf [10]*ssa.Value
	for _, b := range fn.Blocks {
		for _, ins := range b.Instrs {
			if v, ok := ins.(ssa.Value); ok {
				l.add(v.Type())
			}
			for _, op := range ins.Operands(buf[:0]) {
				if op == nil || *op == nil {
					continue
				}
				l.add((*op).Type())
				if f, ok := (*op).(*ssa.Function); ok {
					for _, t := range f.TypeArgs() {
						l.add(t)
					}
				}
			}
		}
	}
}

// ids returns the string ids of symKey(package, type name), sorted, of the named types collected
// that have methods or an interface underlying.
func (l *lofLive) ids(in *lofInterner) []int32 {
	var out []int32
	for tn := range l.named {
		if tn.Pkg() == nil {
			continue
		}
		if n, ok := tn.Type().(*types.Named); ok && n.NumMethods() == 0 && !types.IsInterface(n) {
			continue
		}
		out = append(out, in.id(symKey(tn.Pkg().Path(), tn.Name())))
	}
	slices.Sort(out)
	return slices.Compact(out)
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
// method names R's functions answer to; recvs, the receiver types of R's methods (string ids of
// symKey(package, type name)), with anyRecv set when one has a receiver no named type declares;
// addr, whether R holds a function whose address the slice takes.
type lofReach struct {
	syms    map[int32]bool
	names   map[int32]bool
	recvs   map[int32]bool
	anyRecv bool
	addr    bool
}

// liveMethod reports whether R holds a method a value of whose receiver type can exist at run
// time: in the graph's program (live, sorted) or made by the file's closure (f.Live).
func (r *lofReach) liveMethod(live []int32, f *lofFacts) bool {
	if r.anyRecv {
		return true
	}
	for id := range r.recvs {
		if _, ok := slices.BinarySearch(live, id); ok {
			return true
		}
		if _, ok := slices.BinarySearch(f.Live, id); ok {
			return true
		}
	}
	return false
}

func (row *lofRow) reach(callers [][]int32, inSlice func(lofNode) bool) *lofReach {
	r := &lofReach{syms: map[int32]bool{}, names: map[int32]bool{}, recvs: map[int32]bool{}}
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
				r.recvs[d[4]] = true
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
		switch {
		case n.Recv == lofRecvUnknown:
			r.anyRecv = true
		case n.Recv >= 0:
			r.recvs[n.Recv] = true
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
//   - reflect-call: it calls reflect's Call, CallSlice, Method or MethodByName while R holds an
//     address-taken function, or a method a value of whose receiver type can exist at run time
//     (lofReach.liveMethod);
//   - reaches-S-in-source: it walks the source of a function in S;
//   - routed: it passes a value to a loaded function with a func- or interface-typed parameter
//     while R holds an address-taken function, or a method a value of whose receiver type can
//     exist at run time.
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
	live := e.Live0
	if f.Novel {
		if row.rT == nil {
			row.rT = row.reach(e.InT, func(n lofNode) bool { return n.FT })
		}
		r, live = row.rT, e.LiveT
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
	case (f.Reflect || f.Sink) && (r.addr || r.liveMethod(live, f)):
		return true
	}
	return slices.ContainsFunc(f.Src, func(s [2]int32) bool { return row.inS(e.Strs[s[0]], e.Strs[s[1]]) })
}
