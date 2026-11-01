package goanalysis

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// lofAsmObj is what the toolchain's own assembler emits for one Go assembly file, over every gc
// build that assembles it (lofAsmSession.object): the symbols its objects define, by text (with
// whether that body calls or jumps through a register) and data, and the symbols their relocations
// reference. A symbol is "path.name" for a package's, "file:name<>" for a file-local one, and the
// bare name otherwise. ok is false when some build's assembly could not be reproduced (the file
// failed to assemble, its listing did not parse, or its generated go_asm.h could not be built or
// has more variants than lofAsmHdrCap): then nothing about the file is known.
type lofAsmObj struct {
	ok   bool
	refs []string
	text map[string]bool
	data map[string]bool
}

// lofAsmHdrCap bounds the go_asm.h variants one (file, build tuple) is assembled against; more fail
// closed.
const lofAsmHdrCap = 16

// lofAsmCacheDir holds what the standard library's assembly reads across runs: its generated
// go_asm.h headers, keyed by toolchain release and root, package, build tuple and Go file set, and
// what each file assembles to, keyed by toolchain release and root, package, file and content; ""
// keeps none.
var lofAsmCacheDir = func() string {
	d, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "ferralon-assay", "goasmh")
}()

// lofAsmCacheGen names what this code reads a standard-library file and its go_asm.h to; a change
// to either moves it, so the cache never serves a read made under other rules.
const lofAsmCacheGen = "3"

// lofAsmNonce returns the -D macro a go_asm.h build passes the assembler, which no build defines, so
// the go command cannot reuse a cached build of the package and skip generating its header.
var lofAsmNonce = func() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "FERRALON_ASMHDR_" + hex.EncodeToString(b[:])
}

// lofAsmExecHook, when set, sees every command the session runs before it runs.
var lofAsmExecHook func(*exec.Cmd)

// lofAsmStdPorts, when set, keeps only the ports it holds for of those a standard-library file is
// assembled on; a filter a session's context carries under lofAsmModPortsKey does the same for any
// other file. They are a test seam: tests whose reads stand in for the real thing, rather than
// exercise port enumeration, set them (lofAsmStdPorts once, with lofAsmCacheDir to a cache of their
// own). The context carries the module filter so that tests narrowing it can run in parallel.
var lofAsmStdPorts func(lofPort) bool

type lofAsmModPortsKey struct{}

// lofAsmSession reads one engine's assembly through the toolchain: tool is the assembler's, nil when
// none can be run faithfully (off), in which case every file fails closed.
type lofAsmSession struct {
	ctx      context.Context
	cancel   context.CancelFunc
	tool     *lofAsmTool
	buildDir string
	env      []string
	goflags  string
	vendor   bool
	excluded func(constraint.Expr) bool
	modPorts func(lofPort) bool
	tmp      string
	sem      chan struct{}

	mu      sync.Mutex
	objs    map[string]*lofOnce[*lofAsmObj]
	hdrs    map[string]*lofOnce[lofAsmHdr]
	srcs    map[string]*lofOnce[*lofGoSrc]
	stdGaps map[string]bool
	// deps, depPaths and closures hold what leftoutasmdeps.go reads of packages outside the
	// standard library: the packages by directory, import paths resolved, and closures by directory.
	deps     map[string]*lofOnce[*lofDepPkg]
	depPaths map[string]string
	closures map[string]*lofOnce[lofDepFacts]
}

type lofOnce[T any] struct {
	once sync.Once
	v    T
	// cut marks a zero v that its session's cancellation or deadline may have caused.
	cut bool
}

func lofMemo[T any](mu *sync.Mutex, m map[string]*lofOnce[T], key string, f func() T) T {
	mu.Lock()
	e := m[key]
	if e == nil {
		e = &lofOnce[T]{}
		m[key] = e
	}
	mu.Unlock()
	e.once.Do(func() { e.v = f() })
	return e.v
}

// lofMemoShared is lofMemo for what sessions share, computed under the context of the session that
// asks first. A failure that session's context was done for is not kept, and a session whose own
// context is live computes again rather than take it.
func lofMemoShared[T comparable](ctx context.Context, mu *sync.Mutex, m map[string]*lofOnce[T], key string, f func() T) T {
	for {
		mu.Lock()
		e := m[key]
		if e == nil {
			e = &lofOnce[T]{}
			m[key] = e
		}
		mu.Unlock()
		e.once.Do(func() {
			var zero T
			if e.v = f(); e.v == zero && ctx.Err() != nil {
				e.cut = true
				mu.Lock()
				if m[key] == e {
					delete(m, key)
				}
				mu.Unlock()
			}
		})
		if !e.cut || ctx.Err() != nil {
			return e.v
		}
	}
}

// newLofAsmSession returns the session for a build whose go command runs in buildDir with env, and
// whose GOFLAGS (from env or the go env file) are goflags. root is the toolchain lofToolchain
// resolved, "" for the go command env finds. GOFLAGS passing assembler flags or a -toolexec (either
// changes what the assembler emits) or an -overlay (which changes the source it reads) leave the
// session off, as does a toolchain that cannot be run.
func newLofAsmSession(ctx context.Context, deadline time.Time, root, buildDir string, env []string, goflags string, goflagsOK bool, excluded func(constraint.Expr) bool) *lofAsmSession {
	if env == nil {
		env = os.Environ()
	}
	s := &lofAsmSession{
		buildDir: buildDir, env: env, goflags: goflags, excluded: excluded,
		sem:  make(chan struct{}, max(2, runtime.NumCPU())),
		objs: map[string]*lofOnce[*lofAsmObj]{}, hdrs: map[string]*lofOnce[lofAsmHdr]{}, srcs: map[string]*lofOnce[*lofGoSrc]{},
		stdGaps: map[string]bool{},
		deps:    map[string]*lofOnce[*lofDepPkg]{}, depPaths: map[string]string{}, closures: map[string]*lofOnce[lofDepFacts]{},
	}
	s.modPorts, _ = ctx.Value(lofAsmModPortsKey{}).(func(lofPort) bool)
	if deadline.IsZero() {
		s.ctx, s.cancel = context.WithCancel(ctx)
	} else {
		s.ctx, s.cancel = context.WithDeadline(ctx, deadline)
	}
	if !goflagsOK || lofAsmGoflagsOff(goflags) || lofAsmGoflagsOff(envOr(env, "GOFLAGS", "")) {
		return s
	}
	if root == "" {
		cmd := exec.CommandContext(s.ctx, "go", "env", "GOROOT")
		cmd.Dir = buildDir
		cmd.Env = env
		out, err := cmd.Output()
		if err != nil {
			return s
		}
		root = strings.TrimSpace(string(out))
	}
	if !filepath.IsAbs(root) {
		return s
	}
	s.tool = lofAsmToolFor(s.ctx, root, env)
	if s.tool == nil {
		return s
	}
	if fi, err := os.Stat(filepath.Join(buildDir, "vendor", "modules.txt")); err == nil && fi.Mode().IsRegular() {
		s.vendor = true
	}
	return s
}

// lofAsmGoflagsOff reports whether GOFLAGS change what the assembler emits or reads.
func lofAsmGoflagsOff(goflags string) bool {
	for _, f := range []string{"-asmflags", "-toolexec", "-overlay"} {
		if strings.Contains(goflags, f) {
			return true
		}
	}
	return false
}

// close releases the session's temporary files.
func (s *lofAsmSession) close() {
	s.cancel()
	s.mu.Lock()
	tmp := s.tmp
	s.tmp = ""
	s.mu.Unlock()
	if tmp != "" {
		_ = os.RemoveAll(tmp)
	}
}

// version returns the release the assembler runs as, "" when the session is off.
func (s *lofAsmSession) version() string {
	if s.tool == nil {
		return ""
	}
	return s.tool.version
}

// stdGapCount returns how many standard-library assembly files failed closed.
func (s *lofAsmSession) stdGapCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.stdGaps)
}

func (s *lofAsmSession) tempDir(pattern string) (string, error) {
	s.mu.Lock()
	if s.tmp == "" {
		d, err := os.MkdirTemp("", "lofasm")
		if err != nil {
			s.mu.Unlock()
			return "", err
		}
		s.tmp = d
	}
	root := s.tmp
	s.mu.Unlock()
	return os.MkdirTemp(root, pattern)
}

// lofAsmItem names one assembly file of package pkg in dir.
type lofAsmItem struct {
	pkg, dir, file string
	std            bool
}

// prefetch reads items side by side, so object returns them from memory.
func (s *lofAsmSession) prefetch(items []lofAsmItem) {
	var wg sync.WaitGroup
	lim := make(chan struct{}, cap(s.sem))
	for _, it := range items {
		wg.Add(1)
		lim <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-lim }()
			s.object(it)
		}()
	}
	wg.Wait()
}

// object returns what assembling the file shows, read once per session; a standard-library file
// read whole is kept for every session of the toolchain, and across runs.
func (s *lofAsmSession) object(it lofAsmItem) *lofAsmObj {
	o := lofMemo(&s.mu, s.objs, it.pkg+"\x00"+it.file, func() *lofAsmObj {
		if it.std && s.tool != nil {
			return s.stdObject(it)
		}
		if o := s.read(it); o != nil {
			return o
		}
		return &lofAsmObj{}
	})
	if !o.ok && it.std {
		s.mu.Lock()
		s.stdGaps[it.file] = true
		s.mu.Unlock()
	}
	return o
}

// lofAsmObjWire is a lofAsmObj in the cache.
type lofAsmObjWire struct {
	Refs       []string
	Text, Data map[string]bool
}

// stdObject reads a standard-library file through the toolchain's memory and the cache, once for
// the sessions that ask at the same time. Only a file read whole is kept.
func (s *lofAsmSession) stdObject(it lofAsmItem) *lofAsmObj {
	t := s.tool
	key := it.pkg + "\x00" + it.file
	o := lofMemoShared(s.ctx, &t.mu, t.std, key, func() *lofAsmObj {
		cache := t.stdCache(it)
		if cache != "" {
			var w lofAsmObjWire
			if b, err := os.ReadFile(cache); err == nil && json.Unmarshal(b, &w) == nil && w.Text != nil && w.Data != nil {
				return &lofAsmObj{ok: true, refs: w.Refs, text: w.Text, data: w.Data}
			}
		}
		o := s.read(it)
		if o == nil {
			return nil
		}
		if b, err := json.Marshal(lofAsmObjWire{o.refs, o.text, o.data}); err == nil && cache != "" && os.MkdirAll(filepath.Dir(cache), 0o755) == nil {
			lofCacheWrite(cache, b)
		}
		return o
	})
	if o == nil {
		// A later session reads the file again.
		t.mu.Lock()
		if e := t.std[key]; e != nil && e.v == nil {
			delete(t.std, key)
		}
		t.mu.Unlock()
		return &lofAsmObj{}
	}
	return o
}

// stdCache returns where the cache keeps what a standard-library file assembles to, "" for nowhere.
func (t *lofAsmTool) stdCache(it lofAsmItem) string {
	src, err := os.ReadFile(it.file)
	if err != nil || lofAsmCacheDir == "" {
		return ""
	}
	c := sha256.Sum256(src)
	sum := sha256.Sum256([]byte(strings.Join([]string{lofAsmCacheGen, t.version, t.experiment, t.root, it.pkg, it.file, hex.EncodeToString(c[:])}, "\x01")))
	key := hex.EncodeToString(sum[:])
	return filepath.Join(lofAsmCacheDir, "obj", key[:2], key+".json")
}

// read assembles the file once per build tuple that assembles it and unions what the objects
// emit; nil when any fails.
func (s *lofAsmSession) read(it lofAsmItem) *lofAsmObj {
	t := s.tool
	if t == nil || s.ctx.Err() != nil {
		return nil
	}
	src, err := os.ReadFile(it.file)
	if err != nil {
		return nil
	}
	x, err := fileConstraint(src)
	if err != nil {
		return nil
	}
	ports := t.admit(filepath.Base(it.file), x)
	keep := s.modPorts
	if it.std {
		keep = lofAsmStdPorts
	}
	if keep != nil {
		ports = slices.DeleteFunc(ports, func(p lofPort) bool { return !keep(p) })
	}
	out := &lofAsmObj{ok: true, text: map[string]bool{}, data: map[string]bool{}}
	if len(ports) == 0 {
		return out
	}
	g := s.gate(it, src)
	if g.badExp || len(g.exps) > maxFreeTags {
		return nil
	}
	tuples := t.tuples(ports, g)
	type result struct {
		l   []*lofListing
		err error
	}
	res := make([]result, len(tuples))
	var wg sync.WaitGroup
	for i, tu := range tuples {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := s.assemble(it, tu, g, x)
			res[i] = result{l, err}
		}()
	}
	wg.Wait()
	refs := map[string]bool{}
	for i, r := range res {
		if r.err != nil {
			return nil
		}
		for _, l := range r.l {
			if !s.merge(it, tuples[i], l, out, refs) {
				return nil
			}
		}
	}
	for key := range out.text {
		if _, ok := lofBareAsm(key); ok {
			refs[key] = true
		}
	}
	for key := range out.data {
		if _, ok := lofBareAsm(key); ok {
			refs[key] = true
		}
	}
	if refs["true"] || refs["false"] {
		// A bool constant of go_asm.h spells either, whichever the build's constant holds.
		refs["true"], refs["false"] = true, true
	}
	out.refs = slices.Sorted(maps.Keys(refs))
	return out
}

// lofPort is a gc port, as go tool dist list names it.
type lofPort struct{ goos, goarch string }

// lofAsmTuple is one build an assembly file is assembled for: a port, the architecture level cmd/go
// passes the assembler macros for, and the experiments the build sets on or off over the session's
// GOEXPERIMENT ("x,noy", "" for none), which cmd/asm defines GOEXPERIMENT_ macros for.
type lofAsmTuple struct {
	lofPort
	level string
	exp   string
}

// lofAsmLevels holds, by GOARCH, the variable naming its level and the level macro family cmd/go
// defines (gc.go asmArgs); a level list empty here has no macros.
var lofAsmLevels = map[string]struct {
	env, family string
	values      []string
	fixed       bool
}{
	"386":      {"GO386", "GO386_", []string{"sse2", "softfloat"}, true},
	"amd64":    {"GOAMD64", "GOAMD64_", []string{"v1", "v2", "v3", "v4"}, false},
	"arm":      {"GOARM", "GOARM_", []string{"5", "6", "7"}, true},
	"arm64":    {"GOARM64", "GOARM64_", []string{"v8.0", "v8.1"}, false},
	"mips":     {"GOMIPS", "GOMIPS_", []string{"hardfloat", "softfloat"}, false},
	"mipsle":   {"GOMIPS", "GOMIPS_", []string{"hardfloat", "softfloat"}, false},
	"mips64":   {"GOMIPS64", "GOMIPS64_", []string{"hardfloat", "softfloat"}, false},
	"mips64le": {"GOMIPS64", "GOMIPS64_", []string{"hardfloat", "softfloat"}, false},
	"ppc64":    {"GOPPC64", "GOPPC64_", []string{"power8", "power9", "power10"}, false},
	"ppc64le":  {"GOPPC64", "GOPPC64_", []string{"power8", "power9", "power10"}, false},
	"riscv64":  {"GORISCV64", "GORISCV64_", []string{"rva20u64", "rva22u64", "rva23u64"}, false},
}

// defines returns the -D flags cmd/go passes the assembler for the tuple (gc.go asmArgs).
func (tu lofAsmTuple) defines() []string {
	d := []string{"-D", "GOOS_" + tu.goos, "-D", "GOARCH_" + tu.goarch}
	add := func(m ...string) {
		for _, x := range m {
			d = append(d, "-D", x)
		}
	}
	switch tu.goarch {
	case "386":
		add("GO386_" + tu.level)
	case "amd64":
		add("GOAMD64_" + tu.level)
	case "mips", "mipsle":
		add("GOMIPS_" + tu.level)
	case "mips64", "mips64le":
		add("GOMIPS64_" + tu.level)
	case "ppc64", "ppc64le":
		switch tu.level {
		case "power10":
			add("GOPPC64_power10", "GOPPC64_power9", "GOPPC64_power8")
		case "power9":
			add("GOPPC64_power9", "GOPPC64_power8")
		default:
			add("GOPPC64_power8")
		}
	case "riscv64":
		add("GORISCV64_" + tu.level)
	case "arm":
		switch tu.level {
		case "7":
			add("GOARM_7", "GOARM_6", "GOARM_5")
		case "6":
			add("GOARM_6", "GOARM_5")
		default:
			add("GOARM_5")
		}
	case "arm64":
		if tu.level == "v8.1" {
			add("GOARM64_LSE")
		}
	}
	return d
}

// envVars returns the target variables the tuple's tools run under.
func (tu lofAsmTuple) envVars() []string {
	e := []string{"GOOS=" + tu.goos, "GOARCH=" + tu.goarch}
	if l, ok := lofAsmLevels[tu.goarch]; ok && tu.level != "" {
		e = append(e, l.env+"="+tu.level)
	}
	return e
}

func (tu lofAsmTuple) String() string {
	return tu.goos + "/" + tu.goarch + "/" + tu.level + "/" + tu.exp
}

// goexperiment returns the GOEXPERIMENT the tuple's tools run under: the session's, then the tuple's
// settings, which the toolchain applies in order.
func (tu lofAsmTuple) goexperiment(session string) string {
	switch {
	case tu.exp == "":
		return session
	case session == "":
		return tu.exp
	}
	return session + "," + tu.exp
}

// expTag returns, for a goexperiment.x build tag of an experiment the tuple sets, its value.
func (tu lofAsmTuple) expTag(tag string) (bool, bool) {
	name, ok := strings.CutPrefix(tag, "goexperiment.")
	if !ok || tu.exp == "" {
		return false, false
	}
	for _, e := range strings.Split(tu.exp, ",") {
		if e == name {
			return true, true
		}
		if e == "no"+name {
			return false, true
		}
	}
	return false, false
}

// lofAsmTargetVars are the variables a tool's environment takes from the tuple or the session alone.
var lofAsmTargetVars = []string{"GOOS", "GOARCH", "GO386", "GOAMD64", "GOARM", "GOARM64", "GOMIPS", "GOMIPS64", "GOPPC64",
	"GORISCV64", "GOWASM", "GOEXPERIMENT", "GOFLAGS", "GOTOOLCHAIN", "GOPROXY", "GONOPROXY", "GOVCS", "CGO_ENABLED", "GOTMPDIR"}

func lofAsmBaseEnv(env []string, drop ...string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if slices.Contains(lofAsmTargetVars, k) || slices.Contains(drop, k) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// lofAsmTool is one toolchain's assembler, shared across sessions.
type lofAsmTool struct {
	root, version, experiment, asm string
	minor                          int
	ports                          []lofPort
	levels                         map[string][]string
	// exps holds the release's experiment names, as GOEXPERIMENT and the GOEXPERIMENT_ macros spell
	// them; nil when they could not be read.
	exps   []string
	env    []string
	hdrSem chan struct{}

	mu     sync.Mutex
	tags   map[string]*lofOnce[map[lofPort]bool]
	cals   map[string]*lofOnce[*lofAsmCal]
	nmPath map[string]*lofOnce[string]
	// std holds the standard-library files read whole, by file, for every session of the tool.
	std map[string]*lofOnce[*lofAsmObj]
	// arches holds the ports' GOARCH values; deps the standard-library packages leftoutasmdeps.go
	// read, by directory.
	arches map[string]bool
	deps   map[string]*lofOnce[*lofDepPkg]
	// abiPkgs holds the packages cmd/asm defines GOEXPERIMENT_ macros for (lofAsmABIPkgs), nil when
	// they could not be read; effs the effective experiments of a tuple's build, by its variables.
	abiPkgs []string
	effs    map[string]*lofOnce[string]
}

var lofAsmTools = struct {
	mu sync.Mutex
	m  map[string]*lofOnce[*lofAsmTool]
}{m: map[string]*lofOnce[*lofAsmTool]{}}

// lofAsmToolFor returns the assembler of the toolchain at root, run as env's GOEXPERIMENT selects;
// nil when it cannot be found or asked its ports.
func lofAsmToolFor(ctx context.Context, root string, env []string) *lofAsmTool {
	key := root + "\x00" + envOr(env, "GOEXPERIMENT", "") + "\x00" + envOr(env, "GOENV", "")
	t := lofMemoShared(ctx, &lofAsmTools.mu, lofAsmTools.m, key, func() *lofAsmTool {
		t, err := newLofAsmTool(ctx, root, env)
		if err != nil {
			return nil
		}
		return t
	})
	if t == nil {
		// Let a later session try again: the failure may be this session's deadline.
		lofAsmTools.mu.Lock()
		delete(lofAsmTools.m, key)
		lofAsmTools.mu.Unlock()
	}
	return t
}

func newLofAsmTool(ctx context.Context, root string, env []string) (*lofAsmTool, error) {
	tmp, err := os.MkdirTemp("", "lofasmtool")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	base := append(lofAsmBaseEnv(env, "GOWORK"), "GOTOOLCHAIN=local", "GOFLAGS=", "GOWORK=off")
	if x := envOr(env, "GOEXPERIMENT", ""); x != "" {
		base = append(base, "GOEXPERIMENT="+x)
	}
	gobin := filepath.Join(root, "bin", "go")
	run := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, gobin, args...)
		cmd.Dir = tmp
		cmd.Env = base
		if lofAsmExecHook != nil {
			lofAsmExecHook(cmd)
		}
		return cmd.Output()
	}
	out, err := run("env", "GOVERSION", "GOTOOLDIR", "GOEXPERIMENT")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) < 3 {
		return nil, errors.New("go env")
	}
	t := &lofAsmTool{
		root: root, version: strings.TrimSpace(lines[0]), experiment: strings.TrimSpace(lines[2]),
		asm: filepath.Join(strings.TrimSpace(lines[1]), "asm"), hdrSem: make(chan struct{}, 2),
		tags: map[string]*lofOnce[map[lofPort]bool]{}, cals: map[string]*lofOnce[*lofAsmCal]{}, nmPath: map[string]*lofOnce[string]{}, std: map[string]*lofOnce[*lofAsmObj]{},
	}
	r, ok := parseGoRelease(t.version)
	if !ok || r.major != 1 {
		return nil, errors.New("go version")
	}
	t.minor = r.minor
	t.env = lofAsmBaseEnv(env, "GOWORK")
	if t.experiment != "" {
		t.env = append(t.env, "GOEXPERIMENT="+t.experiment)
	}
	if !lofRegular(t.asm) {
		return nil, errors.New("no assembler")
	}
	out, err = run("tool", "dist", "list")
	if err != nil {
		return nil, err
	}
	for _, l := range strings.Fields(string(out)) {
		goos, goarch, ok := strings.Cut(l, "/")
		if ok {
			t.ports = append(t.ports, lofPort{goos, goarch})
		}
	}
	if len(t.ports) == 0 {
		return nil, errors.New("no ports")
	}
	t.arches, t.deps = map[string]bool{}, map[string]*lofOnce[*lofDepPkg]{}
	for _, p := range t.ports {
		t.arches[p.goarch] = true
	}
	slices.SortFunc(t.ports, func(a, b lofPort) int {
		return strings.Compare(a.goarch+"/"+a.goos, b.goarch+"/"+b.goos)
	})
	// A level value counts only where this release's buildcfg accepts it.
	cfg, err := os.ReadFile(filepath.Join(root, "src", "internal", "buildcfg", "cfg.go"))
	if err != nil {
		return nil, err
	}
	t.levels = map[string][]string{}
	for arch, l := range lofAsmLevels {
		for _, v := range l.values {
			if l.fixed || bytes.Contains(cfg, []byte(strconv.Quote(v))) {
				t.levels[arch] = append(t.levels[arch], v)
			}
		}
	}
	t.exps = lofAsmExperiments(root)
	t.abiPkgs, t.effs = lofAsmABIPkgs(root), map[string]*lofOnce[string]{}
	return t, nil
}

// lofAsmExperiments returns the experiment names of the toolchain at root: the fields of
// goexperiment.Flags, lowercased, as internal/buildcfg (exp.go, ParseGOEXPERIMENT) names them; nil
// when they cannot be read.
func lofAsmExperiments(root string) []string {
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, "src", "internal", "goexperiment", "flags.go"), nil, parser.SkipObjectResolution)
	if err != nil {
		return nil
	}
	var out []string
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, sp := range gd.Specs {
			ts := sp.(*ast.TypeSpec)
			st, ok := ts.Type.(*ast.StructType)
			if ts.Name.Name != "Flags" || !ok {
				continue
			}
			for _, fl := range st.Fields.List {
				for _, n := range fl.Names {
					out = append(out, strings.ToLower(n.Name))
				}
			}
		}
	}
	return out
}

// nm returns the path of the toolchain's nm, "" when it cannot be had.
func (t *lofAsmTool) nm(ctx context.Context) string {
	return lofMemoShared(ctx, &t.mu, t.nmPath, "", func() string {
		cmd := exec.CommandContext(ctx, filepath.Join(t.root, "bin", "go"), "tool", "-n", "nm")
		cmd.Env = append(slices.Clone(t.env), "GOTOOLCHAIN=local", "GOFLAGS=", "GOWORK=off")
		cmd.Dir = t.root
		if lofAsmExecHook != nil {
			lofAsmExecHook(cmd)
		}
		out, err := cmd.Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	})
}

// tagValue returns, for a tag go/build knows as a GOOS or GOARCH value or unix, the ports it holds
// on; nil for any other tag.
func (t *lofAsmTool) tagValue(tag string) map[lofPort]bool {
	return lofMemo(&t.mu, t.tags, tag, func() map[lofPort]bool {
		if !lofIdentTag(tag) {
			return nil
		}
		known := tag == "unix"
		for _, p := range []lofPort{{"linux", "amd64"}, {"windows", "arm64"}} {
			if !lofMatchName(p, "x_"+tag+".s") {
				known = true
			}
		}
		if !known {
			return nil
		}
		m := map[lofPort]bool{}
		for _, p := range t.ports {
			m[p] = lofMatchContent(p, "//go:build "+tag+"\n")
		}
		return m
	})
}

func lofIdentTag(tag string) bool {
	for _, r := range tag {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return tag != ""
}

func lofBuildContext(p lofPort, content string) *build.Context {
	return &build.Context{
		GOOS: p.goos, GOARCH: p.goarch, Compiler: "gc",
		JoinPath: filepath.Join, IsDir: func(string) bool { return false },
		OpenFile: func(string) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(content)), nil },
	}
}

// lofMatchName reports whether go/build's file name rules select name on the port.
func lofMatchName(p lofPort, name string) bool {
	ok, err := lofBuildContext(p, "").MatchFile("/", name)
	return err == nil && ok
}

func lofMatchContent(p lofPort, content string) bool {
	ok, err := lofBuildContext(p, content).MatchFile("/", "x.s")
	return err == nil && ok
}

// lofTagKind classifies a build tag for one port: fixed true or false, or free.
func (t *lofAsmTool) tagFixed(tag string, p lofPort) (bool, bool) {
	switch tag {
	case "gc":
		return true, true
	case "gccgo":
		return false, true
	}
	if n, ok := releaseTagMinor(tag); ok {
		return n <= t.minor, true
	}
	if m := t.tagValue(tag); m != nil {
		return m[p], true
	}
	return false, false
}

// lofExprTags returns the tags x names, in order of first appearance.
func lofExprTags(x constraint.Expr, out []string) []string {
	switch x := x.(type) {
	case *constraint.TagExpr:
		if !slices.Contains(out, x.Tag) {
			out = append(out, x.Tag)
		}
	case *constraint.NotExpr:
		out = lofExprTags(x.X, out)
	case *constraint.AndExpr:
		out = lofExprTags(x.Y, lofExprTags(x.X, out))
	case *constraint.OrExpr:
		out = lofExprTags(x.Y, lofExprTags(x.X, out))
	}
	return out
}

// admit returns the gc ports whose file name rules and build constraint x some assignment of the
// free tags (every tag not a GOOS or GOARCH value, a release or the compiler) selects the file
// named name on.
func (t *lofAsmTool) admit(name string, x constraint.Expr) []lofPort {
	var free []string
	for _, tag := range lofExprTags(x, nil) {
		if _, fixed := t.tagFixed(tag, t.ports[0]); !fixed {
			free = append(free, tag)
		}
	}
	var out []lofPort
	for _, p := range t.ports {
		if !lofMatchName(p, name) {
			continue
		}
		if x == nil || len(free) > maxFreeTags {
			out = append(out, p)
			continue
		}
		for mask := 0; mask < 1<<len(free); mask++ {
			if x.Eval(func(tag string) bool {
				if v, fixed := t.tagFixed(tag, p); fixed {
					return v
				}
				return mask&(1<<slices.Index(free, tag)) != 0
			}) {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// tuples returns the builds to assemble a file on, from the ports that admit it. A GOOS collapses to
// one port per GOARCH, and a level to the lowest, unless the file or a header it may include names
// that macro family, may include a header that was not read, or includes go_asm.h, whose Go file
// set may vary with either; GOARM always varies, as the assembler itself rewrites float
// instructions by it. Each build then runs once per assignment of the experiments the file or a
// header it may include tests a GOEXPERIMENT_ macro of.
func (t *lofAsmTool) tuples(ports []lofPort, g *lofAsmGate) []lofAsmTuple {
	wide := g.unresolved || g.needsHdr
	byArch := map[string][]lofPort{}
	var arches []string
	for _, p := range ports {
		if byArch[p.goarch] == nil {
			arches = append(arches, p.goarch)
		}
		byArch[p.goarch] = append(byArch[p.goarch], p)
	}
	var out []lofAsmTuple
	for _, arch := range arches {
		ps := byArch[arch]
		if !wide && !g.goos {
			rep := ps[0]
			for _, p := range ps {
				if p.goos == "linux" {
					rep = p
				}
			}
			ps = []lofPort{rep}
		}
		levels := t.levels[arch]
		if len(levels) == 0 {
			levels = []string{""}
		} else if l := lofAsmLevels[arch]; !wide && arch != "arm" && !g.families[l.family] {
			levels = levels[:1]
		}
		for _, p := range ps {
			for _, l := range levels {
				for mask := 0; mask < 1<<len(g.exps); mask++ {
					var exp []string
					for i, x := range g.exps {
						if mask&(1<<i) == 0 {
							x = "no" + x
						}
						exp = append(exp, x)
					}
					out = append(out, lofAsmTuple{p, l, strings.Join(exp, ",")})
				}
			}
		}
	}
	return out
}

// lofAsmGate is what the raw text of an assembly file and every header it may include shows: the
// macro families named, the identifiers, the names #ifdef and #ifndef test, and whether some
// include could not be read or is the generated go_asm.h.
type lofAsmGate struct {
	goos     bool
	families map[string]bool
	idents   map[string]bool
	ifdefs   []string
	badIfdef bool
	// exps holds the experiments of the release whose GOEXPERIMENT_ macro an #ifdef or #ifndef tests;
	// badExp is set when one is tested and the release's experiments could not be read.
	exps       []string
	badExp     bool
	unresolved bool
	needsHdr   bool
	// hfiles holds the package's headers cmd/go copies into the build's object directory under
	// a GOOS and GOARCH free name.
	hfiles []string
}

var lofAsmIfdef = regexp.MustCompile(`#(?:[ \t]|/\*(?s:.*?)\*/)*(?:ifdef|ifndef)\b`)

// lofAsmIdentRune reports whether r continues (i > 0) or starts (i == 0) an identifier as cmd/asm's
// tokenizer reads one (isIdentRune, cmd/asm/internal/lex/tokenizer.go): a letter, '_', the middle
// dot and the division slash, and a digit after the first rune.
func lofAsmIdentRune(r rune, i int) bool {
	switch {
	case unicode.IsLetter(r), r == '_', r == '\u00B7', r == '\u2215':
		return true
	}
	return i > 0 && unicode.IsDigit(r)
}

// gate reads the file's text and, transitively, every header an #include in it may name, as cmd/asm
// resolves one: from the package directory, then the build's object directory (go_asm.h and the
// renamed GOOS/GOARCH headers), then $GOROOT/pkg/include.
func (s *lofAsmSession) gate(it lofAsmItem, src []byte) *lofAsmGate {
	g := &lofAsmGate{families: map[string]bool{}, idents: map[string]bool{}}
	ents, _ := os.ReadDir(it.dir)
	var hs []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".h") {
			hs = append(hs, e.Name())
		}
	}
	g.hfiles = hs
	read := map[string]bool{it.file: true}
	var scan func(text []byte)
	scan = func(text []byte) {
		ts := string(text)
		g.goos = g.goos || strings.Contains(ts, "GOOS")
		for _, l := range lofAsmLevels {
			if strings.Contains(ts, l.family) {
				g.families[l.family] = true
			}
		}
		for _, id := range strings.FieldsFunc(ts, func(r rune) bool { return !lofAsmIdentRune(r, 1) }) {
			// A run that starts with digits is a number, then an identifier.
			if id = strings.TrimLeftFunc(id, unicode.IsDigit); id != "" {
				g.idents[id] = true
			}
		}
		for _, m := range lofAsmIfdef.FindAllStringIndex(ts, -1) {
			rest := ts[m[1]:]
			for {
				t := strings.TrimLeft(rest, " \t")
				if c, ok := strings.CutPrefix(t, "/*"); ok {
					if _, after, ok := strings.Cut(c, "*/"); ok {
						rest = after
						continue
					}
				}
				rest = t
				break
			}
			n := len(rest)
			for i, r := range rest {
				if !lofAsmIdentRune(r, i) {
					n = i
					break
				}
			}
			if n == 0 {
				g.badIfdef = true
				continue
			}
			g.ifdefs = append(g.ifdefs, rest[:n])
		}
		for _, name := range asmIncludes(text) {
			for _, h := range s.includeCands(it, name, hs, g) {
				if read[h] {
					continue
				}
				read[h] = true
				ht, err := os.ReadFile(h)
				if err != nil {
					g.unresolved = true
					continue
				}
				scan(ht)
			}
		}
	}
	scan(src)
	addExp := func(x string) {
		switch {
		case s.tool.exps == nil:
			g.badExp = true
		case slices.Contains(s.tool.exps, x) && !slices.Contains(g.exps, x):
			g.exps = append(g.exps, x)
		}
	}
	// cmd/asm defines a GOEXPERIMENT_ macro per enabled experiment only in the packages
	// allowAsmABIPkgs lists (cmd/internal/objabi/pkgspecial.go; cmd/asm/main.go): elsewhere an
	// #ifdef of one tests a name never defined.
	if s.tool.abiPkgs == nil || slices.Contains(s.tool.abiPkgs, it.pkg) {
		for _, d := range g.ifdefs {
			if x, ok := strings.CutPrefix(d, "GOEXPERIMENT_"); ok {
				addExp(x)
			}
		}
	}
	// A go_asm.h name may take its value from a file an experiment selects, in the package or a
	// package it imports: each experiment a file declaring one, or what its declaration mentions,
	// is constrained on is enumerated.
	if g.needsHdr || g.unresolved {
		var f lofDepFacts
		if src := s.goSrc(it.dir); g.unresolved || g.badIfdef || src.err {
			f = s.closure(it.dir)
		} else {
			var names []string
			for id := range g.idents {
				if n := lofAsmHdrCandidate(src, id); n != "" {
					names = append(names, n)
				}
			}
			f = s.slice(it.dir, names)
		}
		g.badExp = g.badExp || f.bad
		for _, x := range f.exps {
			addExp(x)
		}
	}
	slices.Sort(g.exps)
	return g
}

func (s *lofAsmSession) includeCands(it lofAsmItem, name string, hs []string, g *lofAsmGate) []string {
	if name == "" {
		g.unresolved = true
		return nil
	}
	c := name
	if !filepath.IsAbs(c) {
		c = filepath.Join(it.dir, c)
	}
	if lofRegular(c) {
		return []string{c}
	}
	if filepath.IsAbs(name) {
		g.unresolved = true
		return nil
	}
	if name == "go_asm.h" {
		g.needsHdr = true
		return nil
	}
	for _, suf := range []string{"_GOOS_GOARCH.h", "_GOARCH.h", "_GOOS.h"} {
		if prefix, ok := strings.CutSuffix(name, suf); ok && !strings.Contains(prefix, "/") {
			var out []string
			for _, h := range hs {
				if strings.HasPrefix(h, prefix+"_") {
					out = append(out, filepath.Join(it.dir, h))
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	if c := filepath.Join(s.tool.root, "pkg", "include", name); lofRegular(c) {
		return []string{c}
	}
	g.unresolved = true
	return nil
}

// objdir makes the build's object directory for a tuple: the package's GOOS and GOARCH headers
// under the names cmd/go copies them to (exec.go), and the go_asm.h hdr when given.
func (s *lofAsmSession) objdir(it lofAsmItem, tu lofAsmTuple, g *lofAsmGate, hdr []byte) (string, error) {
	d, err := s.tempDir("obj")
	if err != nil {
		return "", err
	}
	gg, ga, gs := "_"+tu.goos+"_"+tu.goarch, "_"+tu.goarch, "_"+tu.goos
	for _, h := range g.hfiles {
		if !lofMatchName(tu.lofPort, h) {
			continue
		}
		name := strings.TrimSuffix(h, ".h")
		targ := ""
		switch {
		case strings.HasSuffix(name, gg):
			targ = strings.TrimSuffix(name, gg) + "_GOOS_GOARCH.h"
		case strings.HasSuffix(name, ga):
			targ = strings.TrimSuffix(name, ga) + "_GOARCH.h"
		case strings.HasSuffix(name, gs):
			targ = strings.TrimSuffix(name, gs) + "_GOOS.h"
		default:
			continue
		}
		b, err := os.ReadFile(filepath.Join(it.dir, h))
		if err != nil {
			return d, err
		}
		if err := os.WriteFile(filepath.Join(d, targ), b, 0o644); err != nil {
			return d, err
		}
	}
	if hdr != nil {
		if err := os.WriteFile(filepath.Join(d, "go_asm.h"), hdr, 0o644); err != nil {
			return d, err
		}
	}
	return d, nil
}

var (
	errLofAsm          = errors.New("assembly failed")
	errLofAsmHdrSrc    = errors.New("go_asm.h: Go files unreadable")
	errLofAsmHdrCap    = errors.New("go_asm.h: variants over the cap")
	errLofAsmHdrBuild  = errors.New("go_asm.h: build failed")
	errLofAsmHdrString = errors.New("go_asm.h: string constant in a listing-relevant position")
	// errLofAsmNoBuild marks a variant whose package does not compile: no build assembles the file
	// against it.
	errLofAsmNoBuild = errors.New("go_asm.h: the package does not compile")
)

// asm runs the assembler on file for the tuple, with cmd/go's flags and objdir as the build's object
// directory, and returns its listing and object.
func (s *lofAsmSession) asm(dir, file, pkg string, tu lofAsmTuple, objdir string) (stdout, stderr []byte, obj string, err error) {
	t := s.tool
	obj = filepath.Join(objdir, "x.o")
	args := append([]string{"-p", pkg, "-I", objdir, "-I", filepath.Join(t.root, "pkg", "include")}, tu.defines()...)
	args = append(args, "-o", obj, "-S", "./"+filepath.Base(file))
	cmd := exec.CommandContext(s.ctx, t.asm, args...)
	cmd.Dir = dir
	cmd.Env = append(slices.Clone(t.env), tu.envVars()...)
	if tu.exp != "" {
		cmd.Env = append(cmd.Env, "GOEXPERIMENT="+tu.goexperiment(t.experiment))
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if lofAsmExecHook != nil {
		lofAsmExecHook(cmd)
	}
	s.sem <- struct{}{}
	err = cmd.Run()
	<-s.sem
	return out.Bytes(), errb.Bytes(), obj, err
}

// lofListing is one object's listing, with the object it came from.
type lofListing struct {
	syms []*lofListSym
	obj  string
	cal  *lofAsmCal
}

// lofListSym is one symbol the listing heads: its name, kind and attributes, its instructions (the
// first being its TEXT) and its relocations.
type lofListSym struct {
	name, kind      string
	static, nosplit bool
	insts           []lofInst
	rels            []lofRel
}

// text reports whether the symbol is a function body: STEXT, or a variant such as STEXTFIPS.
func (s *lofListSym) text() bool { return strings.HasPrefix(s.kind, "STEXT") }

type lofInst struct{ pos, op, args string }

type lofRel struct{ typ, name string }

var lofListInst = regexp.MustCompile(`^\t0x[0-9a-f]+ +[0-9]+ \(`)
var lofListHex = regexp.MustCompile(`^\t0x[0-9a-f]+(?: [0-9a-f]{2})+(?: {2,}.*)?$`)

// parseListing parses the assembler's -S listing; false when a line has no known shape.
func parseListing(b []byte) ([]*lofListSym, bool) {
	var out []*lofListSym
	var cur *lofListSym
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(nil, 1<<26)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
		case !strings.HasPrefix(line, "\t"):
			f := strings.Fields(line)
			if len(f) < 2 || !lofListKind(f[1]) {
				return nil, false
			}
			cur = &lofListSym{name: f[0], kind: f[1], static: slices.Contains(f[2:], "static"), nosplit: slices.Contains(f[2:], "nosplit")}
			out = append(out, cur)
		case cur == nil:
			return nil, false
		case strings.HasPrefix(line, "\trel "):
			f := strings.Fields(line)
			if len(f) < 3 || !strings.HasPrefix(f[2], "t=") {
				return nil, false
			}
			r := lofRel{typ: strings.TrimPrefix(f[2], "t=")}
			switch len(f) {
			case 3:
			case 4:
				i := strings.LastIndexByte(f[3], '+')
				if i < 0 {
					return nil, false
				}
				r.name = f[3][:i]
			default:
				return nil, false
			}
			cur.rels = append(cur.rels, r)
		case lofListInst.MatchString(line):
			rest := line[strings.IndexByte(line, '(')+1:]
			pos, text, ok := strings.Cut(rest, ")\t")
			if !ok {
				return nil, false
			}
			op, args, _ := strings.Cut(text, "\t")
			cur.insts = append(cur.insts, lofInst{pos, op, args})
		case lofListHex.MatchString(line):
		default:
			return nil, false
		}
	}
	if sc.Err() != nil {
		return nil, false
	}
	return out, true
}

func lofListKind(k string) bool {
	if len(k) < 2 || k[0] != 'S' {
		return false
	}
	for _, r := range k[1:] {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// assemble assembles the file for one tuple: against no go_asm.h first, then, when the assembly
// asks for one, against each variant the Go file sets may generate (headers).
func (s *lofAsmSession) assemble(it lofAsmItem, tu lofAsmTuple, g *lofAsmGate, x constraint.Expr) ([]*lofListing, error) {
	cal, err := s.calibrate(tu, it.pkg)
	if err != nil {
		return nil, err
	}
	one := func(hdr []byte) (*lofListing, bool, error) {
		d, err := s.objdir(it, tu, g, hdr)
		if d != "" {
			defer os.RemoveAll(d)
		}
		if err != nil {
			return nil, false, err
		}
		out, errb, obj, err := s.asm(it.dir, it.file, it.pkg, tu, d)
		if err != nil {
			return nil, hdr == nil && bytes.Contains(errb, []byte("go_asm.h")), errLofAsm
		}
		syms, ok := parseListing(out)
		if !ok {
			return nil, false, errLofAsm
		}
		l := &lofListing{syms: syms, cal: cal}
		if lofListingNeedsNm(syms) {
			// Keep the object for nm: copy it out of the directory removed on return.
			keep, err := s.tempDir("o")
			if err != nil {
				return nil, false, err
			}
			b, err := os.ReadFile(obj)
			if err != nil {
				return nil, false, err
			}
			l.obj = filepath.Join(keep, "x.o")
			if err := os.WriteFile(l.obj, b, 0o644); err != nil {
				return nil, false, err
			}
		}
		return l, false, nil
	}
	l, needHdr, err := one(nil)
	if err == nil {
		return []*lofListing{l}, nil
	}
	if !needHdr {
		return nil, err
	}
	hdrs, err := s.headers(it, tu, g, x)
	if err != nil {
		return nil, err
	}
	var out []*lofListing
	for _, h := range hdrs {
		l, _, err := one(h.text)
		if err != nil && h.rejected[filepath.Base(it.file)] {
			// The toolchain's own build of the variant fails assembling the file: no build has it.
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, nil
}

// lofListingNeedsNm reports whether a relocation names a file-local symbol the object also defines,
// which the listing prints without its <>: only the object's symbol table tells a reference to
// a global of that name apart.
func lofListingNeedsNm(syms []*lofListSym) bool {
	static := map[string]bool{}
	for _, s := range syms {
		if s.static {
			static[s.name] = true
		}
	}
	for _, s := range syms {
		for _, r := range s.rels {
			if static[r.name] {
				return true
			}
		}
	}
	return false
}

// lofAsmCal is what the assembler synthesizes for one tuple and package, measured on a calibration
// file: by TEXT flavour (nosplit, needctxt), the most relocations of each name a function's own
// prologue and epilogue emit, and whether an instruction on the TEXT line spells it; and the forms
// a return prints in.
type lofAsmCal struct {
	max     map[[2]bool]map[string]int
	visible map[[2]bool]map[string]bool
	rets    map[string]bool
}

const lofAsmCalSrc = `#include "textflag.h"
TEXT ·lofcal0(SB),NOSPLIT|NOFRAME,$0-0
	RET
TEXT ·lofcal1(SB),0,$64-0
	CALL ·lofcal0(SB)
	RET
TEXT ·lofcal2(SB),NEEDCTXT,$64-0
	CALL ·lofcal0(SB)
	RET
TEXT ·lofcal3(SB),WRAPPER,$64-0
	CALL ·lofcal0(SB)
	RET
TEXT ·lofcal4(SB),WRAPPER|NEEDCTXT,$64-0
	CALL ·lofcal0(SB)
	RET
TEXT ·lofcal5(SB),0,$65536-0
	CALL ·lofcal0(SB)
	RET
TEXT ·lofcal6(SB),NOSPLIT|WRAPPER,$64-0
	CALL ·lofcal0(SB)
	RET
TEXT ·lofcal7(SB),NOSPLIT,$0-0
	CALL ·lofcal0(SB)
	RET
TEXT ·lofcal8(SB),0,$0-0
	CALL ·lofcal0(SB)
	RET
TEXT ·lofcal9(SB),NEEDCTXT,$65536-0
	CALL ·lofcal0(SB)
	RET
TEXT ·lofcal10(SB),NOSPLIT|NEEDCTXT,$64-0
	CALL ·lofcal0(SB)
	RET
`

func lofAsmFlavour(s *lofListSym) [2]bool {
	needctxt := len(s.insts) > 0 && strings.Contains(s.insts[0].args, "NEEDCTXT")
	return [2]bool{s.nosplit, needctxt}
}

// calibrate measures what the assembler synthesizes for the tuple and package.
func (s *lofAsmSession) calibrate(tu lofAsmTuple, pkg string) (*lofAsmCal, error) {
	t := s.tool
	var cerr error
	c := lofMemoShared(s.ctx, &t.mu, t.cals, tu.String()+"\x00"+pkg, func() *lofAsmCal {
		d, err := s.tempDir("cal")
		if err != nil {
			return nil
		}
		defer os.RemoveAll(d)
		if err := os.WriteFile(filepath.Join(d, "lofcal.s"), []byte(lofAsmCalSrc), 0o644); err != nil {
			return nil
		}
		out, _, _, err := s.asm(d, filepath.Join(d, "lofcal.s"), pkg, tu, d)
		if err != nil {
			return nil
		}
		syms, ok := parseListing(out)
		if !ok {
			return nil
		}
		c := &lofAsmCal{max: map[[2]bool]map[string]int{}, visible: map[[2]bool]map[string]bool{}, rets: map[string]bool{}}
		zero := pkg + ".lofcal0"
		for _, sym := range syms {
			if sym.name == zero {
				for _, in := range sym.insts[1:] {
					if in.op != "FUNCDATA" && in.op != "PCDATA" {
						c.rets[in.op+"\t"+in.args] = true
					}
				}
				continue
			}
			if !strings.HasPrefix(sym.name, pkg+".lofcal") || len(sym.insts) == 0 {
				continue
			}
			fl := lofAsmFlavour(sym)
			n := map[string]int{}
			for _, r := range sym.rels {
				if lofAsmIgnoredRel(r) || r.name == zero || r.name == sym.name {
					continue
				}
				n[r.name]++
			}
			if c.max[fl] == nil {
				c.max[fl], c.visible[fl] = map[string]int{}, map[string]bool{}
			}
			for name, k := range n {
				c.max[fl][name] = max(c.max[fl][name], k)
				for _, in := range sym.insts {
					if in.pos == sym.insts[0].pos && strings.Contains(in.args, name+"(SB)") {
						c.visible[fl][name] = true
					}
				}
			}
		}
		return c
	})
	if c == nil {
		cerr = errLofAsm
	}
	return c, cerr
}

// lofAsmIgnoredRel reports whether a relocation references no symbol code can reach: a
// thread-local access, or a constant-pool symbol ("$f64.…").
func lofAsmIgnoredRel(r lofRel) bool {
	return strings.HasPrefix(r.typ, "R_TLS") || strings.HasPrefix(r.name, "$")
}

// lofAsmDynOps are the mnemonics of a call or jump, as listings print them.
var lofAsmDynOps = map[string]bool{"CALL": true, "JMP": true, "BL": true, "B": true, "BR": true, "BLR": true, "JAL": true,
	"JALR": true, "BCTRL": true, "BCTR": true, "CALLINDIRECT": true}

// lofAsmIndirect reports whether an instruction calls or jumps to an address held in a register:
// a call or jump whose target is neither a symbol, a pc-relative or absolute pc, nor the return
// form the calibration printed.
func lofAsmIndirect(in lofInst, cal *lofAsmCal) bool {
	op, _, _ := strings.Cut(strings.ToUpper(in.op), ".")
	if !lofAsmDynOps[op] || cal.rets[in.op+"\t"+in.args] {
		return false
	}
	target := in.args
	if i := strings.LastIndex(target, ", "); i >= 0 {
		target = target[i+2:]
	}
	target = strings.TrimSpace(target)
	if strings.Contains(target, "(SB)") || strings.Contains(target, "(PC)") {
		return false
	}
	if _, err := strconv.ParseInt(strings.TrimPrefix(target, "$"), 0, 64); err == nil {
		return false
	}
	return true
}

// merge adds one listing's definitions, references and dynamic calls to out. The prologue and
// epilogue relocations the calibration shows the assembler synthesizes for a body's flavour are
// dropped, at most as many as it synthesizes and, for a name it spells, as many as the body's TEXT
// line spells.
func (s *lofAsmSession) merge(it lofAsmItem, tu lofAsmTuple, l *lofListing, out *lofAsmObj, refs map[string]bool) bool {
	key := func(name string, static bool) string {
		if static {
			return it.file + ":" + strings.TrimPrefix(name, it.pkg+".") + "<>"
		}
		return name
	}
	static, global := map[string]bool{}, map[string]bool{}
	for _, sym := range l.syms {
		if sym.static {
			static[sym.name] = true
		} else {
			global[sym.name] = true
		}
	}
	var undef map[string]bool
	nmUndef := func() (map[string]bool, bool) {
		if undef != nil {
			return undef, true
		}
		nm := s.tool.nm(s.ctx)
		if nm == "" || l.obj == "" {
			return nil, false
		}
		cmd := exec.CommandContext(s.ctx, nm, l.obj)
		if lofAsmExecHook != nil {
			lofAsmExecHook(cmd)
		}
		b, err := cmd.Output()
		if err != nil {
			return nil, false
		}
		undef = map[string]bool{}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && f[0] == "U" {
				undef[f[1]] = true
			}
		}
		return undef, true
	}
	for _, sym := range l.syms {
		if strings.HasPrefix(sym.name, "$") {
			continue
		}
		k := key(sym.name, sym.static)
		if !sym.text() {
			out.data[k] = true
		} else {
			dyn := out.text[k]
			for _, in := range sym.insts[min(1, len(sym.insts)):] {
				dyn = dyn || lofAsmIndirect(in, l.cal)
			}
			out.text[k] = dyn
		}
		var drop map[string]int
		if sym.text() && len(sym.insts) > 0 {
			fl := lofAsmFlavour(sym)
			drop = map[string]int{}
			for name, n := range l.cal.max[fl] {
				if l.cal.visible[fl][name] {
					spelt := 0
					for _, in := range sym.insts {
						if in.pos == sym.insts[0].pos && strings.Contains(in.args, name+"(SB)") {
							spelt++
						}
					}
					n = min(n, spelt)
				}
				drop[name] = n
			}
		}
		for _, r := range sym.rels {
			switch {
			case strings.Contains(r.typ, "CALLIND"):
				out.text[k] = true
				continue
			case r.name == "":
				if sym.text() {
					out.text[k] = true
				}
				continue
			case lofAsmIgnoredRel(r):
				continue
			case drop[r.name] > 0:
				drop[r.name]--
				continue
			case r.name == sym.name && !sym.static:
				continue
			}
			if static[r.name] {
				refs[key(r.name, true)] = true
				if !global[r.name] {
					u, ok := nmUndef()
					if !ok {
						return false
					}
					if !u[r.name] {
						continue
					}
				}
			}
			refs[r.name] = true
		}
	}
	return true
}

// lofGoSrc is a package directory's non-test Go files, as far as go_asm.h depends on them: each
// file's constraint, whether it is a cgo file, the constants and types it declares, and the
// package-level names each declaration's right-hand side mentions.
type lofGoSrc struct {
	err   bool
	files []lofGoSrcFile
	// consts and types index, by name, the files declaring it.
	consts, types map[string][]int
}

type lofGoSrcFile struct {
	name string
	expr constraint.Expr
	cgo  bool
	// deps maps each const and type the file declares to the identifiers its declaration mentions.
	deps map[string][]string
	// names holds every package-level name the file declares.
	names []string
}

// goSrc reads dir's Go files, of every package clause a build may compile with the assembly.
func (s *lofAsmSession) goSrc(dir string) *lofGoSrc {
	return lofMemo(&s.mu, s.srcs, dir, func() *lofGoSrc {
		g := &lofGoSrc{consts: map[string][]int{}, types: map[string][]int{}}
		ents, err := os.ReadDir(dir)
		if err != nil {
			g.err = true
			return g
		}
		for _, e := range ents {
			n := e.Name()
			if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
				continue
			}
			full := filepath.Join(dir, n)
			src, err := os.ReadFile(full)
			if err != nil {
				g.err = true
				continue
			}
			x, err := fileConstraint(src)
			if err != nil {
				g.err = true
				continue
			}
			if s.excluded != nil && s.excluded(x) {
				continue
			}
			af, err := parser.ParseFile(token.NewFileSet(), full, src, parser.SkipObjectResolution)
			if err != nil {
				g.err = true
				continue
			}
			if af.Name.Name == "documentation" {
				continue
			}
			f := lofGoSrcFile{name: n, expr: x, deps: map[string][]string{}}
			f.cgo = slices.ContainsFunc(af.Imports, func(im *ast.ImportSpec) bool { return im.Path.Value == `"C"` })
			idx := len(g.files)
			for _, d := range af.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					if d.Recv == nil {
						f.names = append(f.names, d.Name.Name)
					}
				case *ast.GenDecl:
					var last []string
					for _, spec := range d.Specs {
						switch sp := spec.(type) {
						case *ast.TypeSpec:
							f.names = append(f.names, sp.Name.Name)
							if _, ok := sp.Type.(*ast.StructType); !ok || sp.Assign.IsValid() || sp.TypeParams != nil {
								// A struct literal's go_asm.h names, its size and its own fields,
								// stand whatever its field types are; any other type may or may not
								// be a struct as what it names varies.
								f.deps[sp.Name.Name] = lofIdents(sp.Type)
							}
							g.types[sp.Name.Name] = append(g.types[sp.Name.Name], idx)
						case *ast.ValueSpec:
							ids := lofIdents(sp.Type)
							for _, v := range sp.Values {
								ids = append(ids, lofIdents(v)...)
							}
							if d.Tok == token.CONST {
								if len(sp.Values) == 0 && sp.Type == nil {
									// An implicit repetition of the previous spec's expression.
									ids = last
								}
								last = ids
							}
							for _, nm := range sp.Names {
								f.names = append(f.names, nm.Name)
								if d.Tok == token.CONST {
									f.deps[nm.Name] = ids
									g.consts[nm.Name] = append(g.consts[nm.Name], idx)
								}
							}
						}
					}
				}
			}
			g.files = append(g.files, f)
		}
		return g
	})
}

func lofIdents(n ast.Node) []string {
	if n == nil {
		return nil
	}
	var out []string
	ast.Inspect(n, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			// A qualified name or a field: only its operand names a package-level declaration.
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

// lofAsmHdr is one generated go_asm.h, or the failure to build it.
type lofAsmHdr struct {
	text []byte
	// rejected holds the package's assembly files the build's own assembler rejected against it.
	rejected map[string]bool
	err      error
}

// lofAsmHdrFailedLine prefixes the line a cached header records rejected files on.
const lofAsmHdrFailedLine = "// lofasm rejected:"

// headers returns the go_asm.h variants the file is assembled against for the tuple. A header holds
// the package's constants and struct layouts, so the Go file set the build compiles (under the
// tuple and an assignment of the free tags) decides which names it defines. Every variant counts
// when that can change the assembly's references: an #ifdef or #ifndef of the file or a header names
// something some variant may define (const_C for a package-level constant C, T_… for a type T), or
// cannot be read, an include cannot be read, or a name the text spells is declared by different
// files, or through declarations that differ, across variants. More than lofAsmHdrCap variants
// then fail closed. Otherwise one variant stands for all: every one differs only in values. Past
// maxFreeTags free tags the enumeration is cut short, and one variant stands for all only when the
// text spells no name the header may define and no constraint that can select the file or a Go file
// of the port names a tag beyond the cut; else, and when the cut enumeration builds no header, the
// file fails closed.
func (s *lofAsmSession) headers(it lofAsmItem, tu lofAsmTuple, g *lofAsmGate, x constraint.Expr) ([]lofAsmHdr, error) {
	src := s.goSrc(it.dir)
	if src.err || len(src.files) == 0 {
		return nil, errLofAsmHdrSrc
	}
	t := s.tool
	// The free tags, and whether each file is selected by name on the tuple's port.
	// Each tag's value on the port, or its bit among the free tags, resolved once: the enumeration
	// below evaluates every file's constraint for every variant.
	var free []string
	fixed := map[string]bool{}
	bit := map[string]int{}
	addTag := func(tag string) {
		if _, ok := fixed[tag]; ok {
			return
		}
		if _, ok := bit[tag]; ok {
			return
		}
		if v, ok := tu.expTag(tag); ok {
			fixed[tag] = v
			return
		}
		if v, ok := t.tagFixed(tag, tu.lofPort); ok {
			fixed[tag] = v
			return
		}
		bit[tag] = len(free)
		free = append(free, tag)
	}
	cgo := false
	for _, f := range src.files {
		cgo = cgo || f.cgo
		for _, tag := range lofExprTags(f.expr, nil) {
			addTag(tag)
		}
	}
	for _, tag := range lofExprTags(x, nil) {
		addTag(tag)
	}
	if cgo {
		if _, ok := fixed["cgo"]; !ok {
			addTag("cgo")
		}
	}
	named := make([]bool, len(src.files))
	for i, f := range src.files {
		named[i] = lofMatchName(tu.lofPort, f.name)
	}
	relevant := g.badIfdef || g.unresolved
	for _, d := range g.ifdefs {
		relevant = relevant || lofAsmHdrCandidate(src, d) != ""
	}
	if n := strings.Count(tu.exp, ",") + 1; tu.exp != "" && len(free)+n > maxFreeTags {
		// The experiments the build enumerates count among its free tags, and are never cut short.
		return nil, errLofAsmHdrCap
	}
	over := len(free) > maxFreeTags
	if over {
		// Too many tags to enumerate: the first variant found stands for all, which holds only when no
		// name the text spells may come from the header and no constraint that selects the file or a
		// Go file of the port names a tag left out of the enumeration.
		if relevant {
			return nil, errLofAsmHdrCap
		}
		for id := range g.idents {
			if lofAsmHdrCandidate(src, id) != "" {
				return nil, errLofAsmHdrCap
			}
		}
		beyond := func(e constraint.Expr) bool {
			return slices.ContainsFunc(lofExprTags(e, nil), func(tag string) bool {
				i, ok := bit[tag]
				return ok && i >= maxFreeTags
			})
		}
		if beyond(x) {
			return nil, errLofAsmHdrCap
		}
		for i, f := range src.files {
			if named[i] && beyond(f.expr) {
				return nil, errLofAsmHdrCap
			}
		}
	}
	eval := func(e constraint.Expr, mask uint64) bool {
		return e == nil || e.Eval(func(tag string) bool {
			if v, ok := fixed[tag]; ok {
				return v
			}
			i, ok := bit[tag]
			return ok && i < 64 && mask&(1<<i) != 0
		})
	}
	cgoBit, ok := bit["cgo"]
	if !ok {
		cgoBit = -1
	}
	type variant struct {
		mask uint64
		sel  []bool
	}
	var variants []variant
	groups := map[string]bool{}
	limit := uint64(1) << min(len(free), maxFreeTags)
	for mask := uint64(0); mask < limit; mask++ {
		if !eval(x, mask) {
			continue
		}
		on := cgoBit >= 0 && mask&(1<<cgoBit) != 0
		sel := make([]bool, len(src.files))
		skip := false
		var key strings.Builder
		for i, f := range src.files {
			sel[i] = named[i] && eval(f.expr, mask) && (!f.cgo || on)
			if sel[i] && f.cgo {
				// A cgo build hands the package's assembly to the C compiler.
				skip = true
				break
			}
			if sel[i] {
				key.WriteString(f.name)
				key.WriteByte(0)
			}
		}
		if skip {
			continue
		}
		variants = append(variants, variant{mask, sel})
		groups[key.String()] = true
		if over {
			break
		}
	}
	if len(variants) == 0 && !over {
		// No build of the port assembles the file against a go_asm.h: none compiles it.
		return nil, nil
	}
	if !relevant && !over && len(variants) > 0 {
		relevant = !lofAsmHdrStable(src, g, variants[0].sel, func(yield func([]bool) bool) {
			for _, v := range variants {
				if !yield(v.sel) {
					return
				}
			}
		})
	}
	if relevant && len(groups) > lofAsmHdrCap {
		return nil, errLofAsmHdrCap
	}
	var pick []variant
	if relevant {
		seen := map[string]bool{}
		for _, v := range variants {
			var key strings.Builder
			for i, on := range v.sel {
				if on {
					key.WriteString(src.files[i].name)
					key.WriteByte(0)
				}
			}
			if !seen[key.String()] {
				seen[key.String()] = true
				pick = append(pick, v)
			}
		}
	} else {
		pick = variants[:min(1, len(variants))]
	}
	var out []lofAsmHdr
	for _, v := range pick {
		var tags []string
		var names []string
		for i, tag := range free {
			if i < 64 && v.mask&(1<<i) != 0 {
				tags = append(tags, tag)
			}
		}
		for i, on := range v.sel {
			if on {
				names = append(names, src.files[i].name)
			}
		}
		h := s.header(it, tu, tags, names)
		if h.err == errLofAsmNoBuild {
			continue
		}
		if h.err != nil {
			return nil, h.err
		}
		if lofAsmHdrString(h.text, g) {
			return nil, errLofAsmHdrString
		}
		out = append(out, h)
	}
	if over && len(out) == 0 {
		// A truncated enumeration that found no compiling build proves none exists only for the tags
		// it tried.
		return nil, errLofAsmHdrCap
	}
	return out, nil
}

// lofAsmHdrCandidate returns the package-level constant or type a go_asm.h macro name may come from,
// "" for none.
func lofAsmHdrCandidate(src *lofGoSrc, id string) string {
	if c, ok := strings.CutPrefix(id, "const_"); ok && len(src.consts[c]) > 0 {
		return c
	}
	for i := 1; i < len(id); i++ {
		if id[i] == '_' && len(src.types[id[:i]]) > 0 {
			return id[:i]
		}
	}
	return ""
}

// lofAsmHdrStable reports whether every go_asm.h name the text spells is declared alike in every
// variant: by the same files, through declarations that mention no name a varying file declares.
func lofAsmHdrStable(src *lofGoSrc, g *lofAsmGate, first []bool, variants func(func([]bool) bool)) bool {
	varying := make([]bool, len(src.files))
	variants(func(sel []bool) bool {
		for i := range sel {
			varying[i] = varying[i] || sel[i] != first[i]
		}
		return true
	})
	moved := map[string]bool{}
	for i, f := range src.files {
		if varying[i] {
			for _, n := range f.names {
				moved[n] = true
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for i, f := range src.files {
			if varying[i] {
				continue
			}
			for n, deps := range f.deps {
				if moved[n] {
					continue
				}
				if slices.ContainsFunc(deps, func(d string) bool { return moved[d] }) {
					moved[n], changed = true, true
				}
			}
		}
	}
	for id := range g.idents {
		if c := lofAsmHdrCandidate(src, id); c != "" && moved[c] {
			return false
		}
	}
	return true
}

// lofAsmHdrString reports whether the header defines, as a string, a name the text spells: the
// assembler would read a string where the listing cannot show what it means.
func lofAsmHdrString(h []byte, g *lofAsmGate) bool {
	for _, line := range strings.Split(string(h), "\n") {
		rest, ok := strings.CutPrefix(line, "#define ")
		if !ok {
			continue
		}
		name, val, _ := strings.Cut(rest, " ")
		if g.idents[name] && !lofAsmHdrValue(val) {
			return true
		}
	}
	return false
}

// lofAsmHdrValue reports whether a go_asm.h value is one the listing shows the effect of: an integer
// or a bool (dumpasmhdr, cmd/compile/internal/gc/export.go, emits only integer, bool and string
// constants and integer sizes and offsets).
func lofAsmHdrValue(v string) bool {
	v = strings.TrimSpace(v)
	if v == "true" || v == "false" {
		return true
	}
	_, err := strconv.ParseInt(strings.TrimPrefix(v, "-"), 10, 64)
	if err == nil {
		return true
	}
	// An integer constant beyond 64 bits prints in full.
	return v != "" && strings.Trim(strings.TrimPrefix(v, "-"), "0123456789") == ""
}

// hdrKey returns the key of the go_asm.h a build of the package with tags compiles on the port at
// level with the effective experiments exp. The file set covers the package's own files, not a
// dependency's level- or experiment-tagged files a constant may take its value from: level is ""
// only where no file the package's import closure holds is level-specific (hdrLevel), and exp is
// the experiment set the build resolves (effective), so only builds that resolve alike share a key.
func (t *lofAsmTool) hdrKey(it lofAsmItem, tu lofAsmTuple, level, exp string, tags, files []string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{lofAsmCacheGen, t.version, t.experiment, t.root, it.pkg, tu.goos, tu.goarch, level, exp,
		strings.Join(files, "\x00"), strings.Join(tags, ",")}, "\x01")))
	return hex.EncodeToString(sum[:])
}

// hdrLevel returns the level a go_asm.h of the package on the tuple is keyed by: the tuple's where
// some file of the package's import closure, compiled at one level or not, is level-specific;
// otherwise "", as every level then compiles the same files.
func (s *lofAsmSession) hdrLevel(it lofAsmItem, tu lofAsmTuple) string {
	if tu.level == "" || !s.levelDep(it) {
		return ""
	}
	return tu.level
}

// header generates the go_asm.h a build of the package with tags compiles on the tuple: a go build
// of the package with a nonce assembler macro, which makes the go command rebuild it rather than
// reuse a cached build. It never fetches: modules come from the module cache or vendor directory
// only. The standard library's headers are cached across runs.
// hdrKey returns the key of the go_asm.h a build of the package with tags compiles on the tuple.
func (s *lofAsmSession) hdrKey(it lofAsmItem, tu lofAsmTuple, tags, files []string) string {
	return s.tool.hdrKey(it, tu, s.hdrLevel(it, tu), s.tool.effective(tu), tags, files)
}

func (s *lofAsmSession) header(it lofAsmItem, tu lofAsmTuple, tags, files []string) lofAsmHdr {
	key := s.hdrKey(it, tu, tags, files)
	cache := ""
	if it.std && lofAsmCacheDir != "" {
		cache = filepath.Join(lofAsmCacheDir, key[:2], key+".h")
	}
	return lofMemo(&s.mu, s.hdrs, key+"\x00"+it.dir, func() lofAsmHdr {
		if cache != "" {
			if b, err := os.ReadFile(cache); err == nil {
				return lofAsmHdrDecode(b)
			}
			if lofRegular(cache + ".nobuild") {
				return lofAsmHdr{err: errLofAsmNoBuild}
			}
		}
		h := s.buildHeader(it, tu, tags)
		if cache == "" {
			return h
		}
		var b []byte
		path := cache
		switch {
		case h.err == errLofAsmNoBuild:
			path = cache + ".nobuild"
		case h.err != nil:
			return h
		default:
			b = lofAsmHdrEncode(h)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err == nil {
			lofCacheWrite(path, b)
		}
		return h
	})
}

// lofCacheWrite puts b at path whole or not at all: through a temporary file of its own, which
// concurrent writers of the same path, in this process or another, never share.
func lofCacheWrite(path string, b []byte) {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return
	}
	tmp := f.Name()
	_, werr := f.Write(b)
	cerr := f.Close()
	if werr != nil || cerr != nil || os.Chmod(tmp, 0o644) != nil || os.Rename(tmp, path) != nil {
		_ = os.Remove(tmp)
	}
}

func lofAsmHdrEncode(h lofAsmHdr) []byte {
	if len(h.rejected) == 0 {
		return h.text
	}
	line := lofAsmHdrFailedLine + " " + strings.Join(slices.Sorted(maps.Keys(h.rejected)), " ") + "\n"
	return append([]byte(line), h.text...)
}

func lofAsmHdrDecode(b []byte) lofAsmHdr {
	first, rest, ok := bytes.Cut(b, []byte("\n"))
	names, isFail := bytes.CutPrefix(first, []byte(lofAsmHdrFailedLine))
	if !ok || !isFail {
		return lofAsmHdr{text: b}
	}
	h := lofAsmHdr{text: rest, rejected: map[string]bool{}}
	for _, n := range strings.Fields(string(names)) {
		h.rejected[n] = true
	}
	return h
}

var lofAsmWorkInc = regexp.MustCompile(`-I (\$WORK/b[0-9]+/) `)

func (s *lofAsmSession) buildHeader(it lofAsmItem, tu lofAsmTuple, tags []string) lofAsmHdr {
	b, rejected, err := s.runHeaderBuild(it, tu, tags)
	return lofAsmHdr{text: b, rejected: rejected, err: err}
}

// runHeaderBuild runs the go build that generates the package's go_asm.h, and returns the header and
// the package's assembly files the build's assembler rejected.
func (s *lofAsmSession) runHeaderBuild(it lofAsmItem, tu lofAsmTuple, tags []string) ([]byte, map[string]bool, error) {
	t := s.tool
	gotmp, err := s.tempDir("gobuild")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(gotmp)
	nonce := lofAsmNonce()
	for strings.Contains(s.goflags, nonce) || strings.Contains(envOr(s.env, "GOFLAGS", ""), nonce) {
		nonce = lofAsmNonce()
	}
	args := []string{"build", "-x", "-work", "-o", os.DevNull, "-asmflags=" + it.pkg + "=-D=" + nonce}
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	args = append(args, it.pkg)
	cmd := exec.CommandContext(s.ctx, filepath.Join(t.root, "bin", "go"), args...)
	env := append(lofAsmBaseEnv(s.env), tu.envVars()...)
	env = append(env, "GOPROXY=off", "GONOPROXY=none.invalid", "GOVCS=*:off", "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOTMPDIR="+gotmp)
	if x := tu.goexperiment(t.experiment); x != "" {
		env = append(env, "GOEXPERIMENT="+x)
	}
	if it.std {
		cmd.Dir = gotmp
		env = append(env, "GOFLAGS=", "GOWORK=off")
	} else {
		cmd.Dir = s.buildDir
		if s.vendor {
			env = append(env, "GOFLAGS=-mod=vendor")
		} else {
			env = append(env, "GOFLAGS=-mod=readonly")
		}
	}
	cmd.Env = env
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if lofAsmExecHook != nil {
		lofAsmExecHook(cmd)
	}
	t.hdrSem <- struct{}{}
	runErr := cmd.Run()
	<-t.hdrSem
	if s.ctx.Err() != nil {
		return nil, nil, errLofAsmHdrBuild
	}
	work, objdir := "", ""
	for _, line := range strings.Split(errb.String(), "\n") {
		if w, ok := strings.CutPrefix(line, "WORK="); ok {
			work = w
		}
		if strings.Contains(line, "-D="+nonce) {
			if m := lofAsmWorkInc.FindStringSubmatch(line); m != nil {
				objdir = m[1]
			}
		}
	}
	if work == "" || !strings.HasPrefix(work, gotmp) {
		return nil, nil, errLofAsmHdrBuild
	}
	if runErr != nil && lofAsmCompileFailed(errb.String(), it, cmd.Dir) {
		return nil, nil, errLofAsmNoBuild
	}
	if objdir != "" {
		// The package compiled: its header stands, whatever later failed.
		if b, err := os.ReadFile(filepath.Join(work, strings.TrimPrefix(objdir, "$WORK/"), "go_asm.h")); err == nil {
			var rejected map[string]bool
			if runErr != nil {
				rejected = lofAsmRejected(errb.String(), it, cmd.Dir)
			}
			return b, rejected, nil
		}
	}
	return nil, nil, errLofAsmHdrBuild
}

// lofAsmRejected returns the package's assembly files a failed go build's assembler reported errors
// in.
func lofAsmRejected(stderr string, it lofAsmItem, cwd string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(stderr, "\n") {
		file, rest, ok := strings.Cut(line, ".s:")
		if !ok || strings.HasPrefix(line, "\t") || strings.Contains(file, " ") || rest == "" || rest[0] < '0' || rest[0] > '9' {
			continue
		}
		file += ".s"
		if !filepath.IsAbs(file) {
			file = filepath.Join(cwd, file)
		}
		if filepath.Dir(file) == filepath.Clean(it.dir) {
			out[filepath.Base(file)] = true
		}
	}
	return out
}

// lofAsmCompileFailed reports whether a go build's failure is the package's own Go source failing to
// type-check for the variant, which no build of it then gets past: the go command ran the package's
// compile, and the compiler rejected one of the package's own files.
func lofAsmCompileFailed(stderr string, it lofAsmItem, cwd string) bool {
	ran, rejected := false, false
	for _, line := range strings.Split(stderr, "\n") {
		if strings.Contains(line, "/compile ") && strings.Contains(line, " -p "+it.pkg+" ") && strings.Contains(line, "-asmhdr ") {
			ran = true
		}
		file, rest, ok := strings.Cut(line, ".go:")
		if !ok || strings.HasPrefix(line, "\t") || strings.Contains(file, " ") {
			continue
		}
		if !filepath.IsAbs(file) {
			file = filepath.Join(cwd, file)
		}
		if filepath.Dir(file) == filepath.Clean(it.dir) && rest != "" && rest[0] >= '0' && rest[0] <= '9' {
			rejected = true
		}
	}
	return ran && rejected
}
