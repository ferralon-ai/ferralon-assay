package goanalysis

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain gives the package's standard-library assembly reads a cache of their own, shared by
// every test, and assembles that assembly on two ports: those tests read the standard library to
// reach its definers and gaps, while module fixtures, which keep every port, exercise the port
// enumeration.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "lofasmcache")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	lofAsmCacheDir = dir
	lofAsmStdPorts = func(p lofPort) bool {
		return p == lofPort{"linux", "amd64"} || p == lofPort{"darwin", "arm64"}
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// lofAsmTestSession returns a session for the module tree files, whose GOFLAGS are goflags, and the
// item for its assembly file file.
func lofAsmTestSession(t *testing.T, files map[string]string, file string, env []string, goflags string) (*lofAsmSession, lofAsmItem) {
	t.Helper()
	dir := writeTree(t, files)
	s := newLofAsmSession(context.Background(), time.Time{}, "", dir, env, goflags, true, ignored)
	t.Cleanup(s.close)
	path := filepath.Join(dir, filepath.FromSlash(file))
	pkg := "example.com/v"
	if d := filepath.ToSlash(filepath.Dir(file)); d != "." {
		pkg += "/" + d
	}
	return s, lofAsmItem{pkg: pkg, dir: filepath.Dir(path), file: path}
}

// lofAsmHook sets lofAsmExecHook for the test.
func lofAsmHook(t *testing.T, f func(*exec.Cmd)) {
	t.Helper()
	lofAsmExecHook = f
	t.Cleanup(func() { lofAsmExecHook = nil })
}

// lofEnvLast returns the value cmd's environment ends up with for key: the last entry wins.
func lofEnvLast(env []string, key string) (string, bool) {
	v, ok := "", false
	for _, e := range env {
		if k, val, found := strings.Cut(e, "="); found && k == key {
			v, ok = val, true
		}
	}
	return v, ok
}

// TestLofAsmObj: what a file's objects define and reference is what the assembler emits for it
// over every gc port, from go tool dist list, that some build of it admits; a file some such build
// cannot assemble, or whose generated go_asm.h cannot be reproduced, is not known (ok is false).
func TestLofAsmObj(t *testing.T) {
	mod := map[string]string{"go.mod": "module example.com/v\n\ngo 1.22\n", "p/p.go": "package p\n"}
	// hdrConst declares decl in b.go, left out under t0, for a text that includes go_asm.h.
	hdrConst := func(decl, body string) map[string]string {
		return merge(mod, map[string]string{"p/b.go": "//go:build !t0\n\npackage p\n\n" + decl + "\n",
			"p/p.s": "#include \"go_asm.h\"\n\nTEXT ·f(SB),0,$0\n" + body + "\tRET\n"})
	}
	text := func(body string) map[string]string {
		return merge(mod, map[string]string{"p/p.s": "TEXT ·f(SB),0,$0\n" + body + "\tRET\n"})
	}
	cases := []struct {
		name  string
		files map[string]string
		ok    bool
		refs  []string // each in the object's references
		text  []string // each defined as text
	}{
		{"M: the listing spells a package path with dots and slashes", text("\tCALL example·com∕v∕vuln·Bad(SB)\n"), true,
			[]string{"example.com/v/vuln.Bad"}, []string{"example.com/v/p.f"}},
		{"a file that does not assemble", merge(mod, map[string]string{"p/p.s": "GARBAGE\n"}), false, nil, nil},
		{"a file some admitted port does not assemble", merge(mod, map[string]string{"p/p.s": "TEXT ·f(SB),0,$0\n\tMOVQ AX, BX\n\tRET\n"}), false, nil, nil},
		{"a file only gccgo builds", merge(mod, map[string]string{"p/p.s": "//go:build gccgo\n\nGARBAGE\n"}), true, nil, nil},
		{"a file only a GOOS with no gc port builds", merge(mod, map[string]string{"p/p.s": "//go:build zos\n\nGARBAGE\n"}), true, nil, nil},
		{"a file a gc port builds, not gccgo", merge(mod, map[string]string{"p/p.s": "//go:build linux && !gccgo\n\nGARBAGE\n"}), false, nil, nil},
		{"a GOOS macro selects a reference", text("#ifdef GOOS_windows\n\tCALL winonly(SB)\n#endif\n#ifdef GOOS_plan9\n\tCALL plan9only(SB)\n#endif\n"), true,
			[]string{"winonly", "plan9only"}, nil},
		{"a level macro selects a reference", text("#ifdef GOAMD64_v3\n\tCALL v3only(SB)\n#endif\n#ifdef GOARM64_LSE\n\tCALL lseonly(SB)\n#endif\n"), true,
			[]string{"v3only", "lseonly"}, nil},
		{"GOARM varies without a macro family named", text("#ifdef GOARM_7\n\tCALL arm7(SB)\n#endif\n"), true, []string{"arm7"}, nil},
		{"an architecture macro selects a reference on the first and last port", text("#ifdef GOARCH_386\n\tCALL first(SB)\n#endif\n#ifdef GOARCH_wasm\n\tCALL last(SB)\n#endif\n"), true,
			[]string{"first", "last"}, nil},
		{"FUNCDATA operands are not references", merge(mod, map[string]string{"p/p.s": "#include \"funcdata.h\"\n\nTEXT ·f(SB),0,$0\n\tNO_LOCAL_POINTERS\n\tRET\n"}), true, nil, []string{"example.com/v/p.f"}},
		{"P7: a bool constant of go_asm.h spells either bool", merge(mod, map[string]string{
			"p/p.go": "package p\n\nconst B = true\n", "p/p.s": "#include \"go_asm.h\"\n\nTEXT ·f(SB),0,$0\n\tCALL const_B(SB)\n\tRET\n"}), true,
			[]string{"true", "false"}, nil},
		// F1: go_asm.h names are read as cmd/asm's tokenizer reads identifiers; a constant some build
		// leaves out (b.go under !t0) is undefined there, so each row's reference is in some build.
		{"F1: an #ifndef of a constant named with a non-ASCII letter", hdrConst("const Bä = 1", "#ifndef const_Bä\n\tCALL ext(SB)\n#endif\n"), true,
			[]string{"ext"}, nil},
		{"F1: a bool constant named with a non-ASCII letter", hdrConst("const Bä = true", "\tCALL const_Bä(SB)\n"), true,
			[]string{"const_Bä", "true", "false"}, nil},
		{"F1: an #ifndef of a constant named with a non-ASCII digit", hdrConst("const B٣ = 1", "#ifndef const_B٣\n\tCALL ext(SB)\n#endif\n"), true,
			[]string{"ext"}, nil},
		{"F1: a middle dot joins the constant's name into a symbol", hdrConst("const B = true", "\tCALL ·const_B(SB)\n"), true,
			[]string{"example.com/v/p.const_B"}, nil},
		{"F1: a division slash joins the constant's name into a symbol", hdrConst("const B = true", "\tCALL x∕const_B(SB)\n"), true,
			[]string{"x/const_B"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, it := lofAsmTestSession(t, tc.files, "p/p.s", nil, "")
			o := s.object(it)
			if o.ok != tc.ok {
				t.Fatalf("ok = %v, want %v (refs %v)", o.ok, tc.ok, o.refs)
			}
			for _, r := range tc.refs {
				if !slices.Contains(o.refs, r) {
					t.Errorf("refs %v lack %s", o.refs, r)
				}
			}
			for _, n := range tc.text {
				if _, ok := o.text[n]; !ok {
					t.Errorf("text %v lacks %s", o.text, n)
				}
			}
			if strings.Contains(tc.name, "FUNCDATA") {
				for _, r := range o.refs {
					if strings.Contains(r, "stackmap") {
						t.Errorf("refs %v hold a FUNCDATA operand", o.refs)
					}
				}
			}
		})
	}
}

// TestLofAsmObjPorts: the ports are go tool dist list's for the resolved toolchain.
func TestLofAsmObjPorts(t *testing.T) {
	s, _ := lofAsmTestSession(t, map[string]string{"go.mod": "module example.com/v\n\ngo 1.22\n"}, "p.s", nil, "")
	if s.tool == nil {
		t.Fatal("no assembler")
	}
	out, err := exec.Command(filepath.Join(s.tool.root, "bin", "go"), "tool", "dist", "list").Output()
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, l := range strings.Fields(string(out)) {
		want = append(want, l)
	}
	var got []string
	for _, p := range s.tool.ports {
		got = append(got, p.goos+"/"+p.goarch)
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("ports %v, want dist list %v", got, want)
	}
}

// TestLofAsmObjHeader: a file including go_asm.h is assembled against each variant of the header
// whose differences can reach its listing, up to lofAsmHdrCap of them; a string constant the text
// names, a variant count over the cap, or a header the go command cannot build without fetching
// leaves the file unknown.
func TestLofAsmObjHeader(t *testing.T) {
	// tagged returns n files, each declaring its own constant under its own free tag: 2^n Go file sets.
	tagged := func(n int) map[string]string {
		m := map[string]string{"go.mod": "module example.com/v\n\ngo 1.22\n", "p/p.go": "package p\n",
			"p/p.s": "//go:build linux && amd64\n\n#include \"go_asm.h\"\n\nTEXT ·f(SB),0,$0\n#ifdef const_C0\n\tCALL c0(SB)\n#endif\n\tRET\n"}
		for i := range n {
			d := string(rune('0' + i))
			m["p/c"+d+".go"] = "//go:build t" + d + "\n\npackage p\n\nconst C" + d + " = " + d + "\n"
		}
		return m
	}
	str := func(v string) map[string]string {
		return map[string]string{"go.mod": "module example.com/v\n\ngo 1.22\n", "p/p.go": "package p\n\nconst S = " + v + "\n",
			"p/p.s": "//go:build linux && amd64\n\n#include \"go_asm.h\"\n\nTEXT ·f(SB),0,$0\n#ifdef const_S\n\tCALL s(SB)\n#endif\n\tRET\n"}
	}
	// many returns a package whose text includes go_asm.h under constraint x, with Go files
	// fileNN.go for NN below n, each under its own free tag tNN, and files besides.
	many := func(x, text string, n int, file string, files map[string]string) map[string]string {
		m := map[string]string{"go.mod": "module example.com/v\n\ngo 1.22\n", "p/p.go": "package p\n",
			"p/p.s": "//go:build " + x + "\n\n#include \"go_asm.h\"\n\nTEXT ·f(SB),0,$0\n" + text + "\tRET\n"}
		for i := range n {
			d := fmt.Sprintf("%02d", i)
			m["p/"+strings.ReplaceAll(file, "NN", d)] = "//go:build t" + d + "\n\npackage p\n\nconst C" + d + " = 1\n"
		}
		maps.Copy(m, files)
		return m
	}
	boolB := map[string]string{"p/b.go": "//go:build !b0\n\npackage p\n\nconst B = true\n"}
	cases := []struct {
		name  string
		files map[string]string
		err   error // what headers returns for linux/amd64, nil for none
		refs  []string
	}{
		{"variants up to the cap", tagged(4), nil, []string{"c0"}},
		{"F2 control: a bool constant some variant leaves out, tags up to the cap", many("linux && amd64", "\tCALL const_B(SB)\n", 15, "wNN_windows.go", boolB),
			nil, []string{"const_B", "true"}},
		{"F2: a bool constant some variant leaves out, tags over the cap", many("linux && amd64", "\tCALL const_B(SB)\n", 16, "wNN_windows.go", boolB),
			errLofAsmHdrCap, nil},
		{"F2: a Go file of the port under a tag past the cap", many("linux && amd64", "", 17, "cNN.go", nil), errLofAsmHdrCap, nil},
		{"F2b: the file under a tag past the cap", many("linux && amd64 && t16", "", 16, "cNN.go", nil), errLofAsmHdrCap, nil},
		{"F2b: the file under a tag past the cap some variant holds", many("linux && amd64 && !t16", "", 16, "cNN.go", nil), errLofAsmHdrCap, nil},
		{"F2: a truncated enumeration builds no header", many("linux && amd64", "", 17, "wNN_windows.go", map[string]string{"p/p.go": "package p\n\nvar _ = undefined\n"}),
			errLofAsmHdrCap, nil},
		{"variants over the cap", tagged(5), errLofAsmHdrCap, nil},
		{"N1: an experiment the text tests counts among the free tags", many("linux && amd64", "#ifdef GOEXPERIMENT_fieldtrack\n\tCALL x(SB)\n#endif\n", 16, "cNN.go", nil),
			errLofAsmHdrCap, nil},
		{"an integer constant the text names", str("1"), nil, []string{"s"}},
		{"a string constant the text names", str(`"x"`), errLofAsmHdrString, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, it := lofAsmTestSession(t, tc.files, "p/p.s", nil, "")
			src, err := os.ReadFile(it.file)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(src, []byte("GOEXPERIMENT_")) {
				// cmd/asm defines GOEXPERIMENT_ macros only for the packages objabi allows ABI selectors in.
				it.pkg = "internal/runtime/startlinetest"
			}
			x, _ := fileConstraint(src)
			g := s.gate(it, src)
			tu := s.tool.tuples([]lofPort{{"linux", "amd64"}}, g)[0]
			if _, err := s.headers(it, tu, g, x); !errors.Is(err, tc.err) {
				t.Errorf("headers: %v, want %v", err, tc.err)
			}
			o := s.object(it)
			if o.ok != (tc.err == nil) {
				t.Fatalf("ok = %v, want %v", o.ok, tc.err == nil)
			}
			for _, r := range tc.refs {
				if !slices.Contains(o.refs, r) {
					t.Errorf("refs %v lack %s", o.refs, r)
				}
			}
		})
	}
}

// TestLofAsmObjExperiments: a GOEXPERIMENT_ macro the file or a header it includes tests is defined
// by cmd/asm, for the packages it allows ABI selectors in, in builds whose GOEXPERIMENT sets the
// experiment, whatever the session's: the file is assembled with each experiment it tests set on and
// off. A file testing more experiments than maxFreeTags is not known.
func TestLofAsmObjExperiments(t *testing.T) {
	const exp = "fieldtrack"
	mod := map[string]string{"go.mod": "module example.com/v\n\ngo 1.22\n", "p/p.go": "package p\n"}
	body := func(text string) string {
		return "//go:build linux && amd64\n\n" + text + "TEXT ·f(SB),0,$0\n\tCALLX\n\tRET\n"
	}
	ifdef := "#ifdef GOEXPERIMENT_" + exp + "\n#define CALLX CALL ·sym(SB)\n#else\n#define CALLX\n#endif\n"
	probe, _ := lofAsmTestSession(t, mod, "p/p.go", nil, "")
	if !slices.Contains(probe.tool.exps, exp) {
		t.Fatalf("experiments %v lack %s", probe.tool.exps, exp)
	}
	if v, _ := lofEnvLast(probe.tool.env, "GOEXPERIMENT"); strings.Contains(","+v+",", ","+exp+",") {
		t.Fatalf("the session sets %s", exp)
	}
	var many strings.Builder
	for _, x := range probe.tool.exps[:maxFreeTags+1] {
		many.WriteString("#ifdef GOEXPERIMENT_" + x + "\n#endif\n")
	}
	dep := merge(mod, map[string]string{
		"d/on.go":  "//go:build goexperiment." + exp + "\n\npackage d\n\nconst K = 1\n",
		"d/off.go": "//go:build !goexperiment." + exp + "\n\npackage d\n\nconst K = 1.5\n",
		"p/p.go":   "package p\n\nimport \"example.com/v/d\"\n\nconst K = d.K\n",
		"p/p.s":    body("#include \"go_asm.h\"\n\n#ifdef const_K\n#define CALLX CALL ·sym(SB)\n#else\n#define CALLX\n#endif\n"),
	})
	cases := []struct {
		name  string
		files map[string]string
		// pkg is the package the file is assembled for, when not one objabi allows ABI selectors in.
		pkg  string
		ok   bool
		refs []string
	}{
		{"N1: the file tests an experiment the session leaves unset", merge(mod, map[string]string{"p/p.s": body(ifdef)}), "", true,
			[]string{"internal/runtime/startlinetest.sym"}},
		{"N1: a header the file includes tests it", merge(mod, map[string]string{"p/x.h": ifdef, "p/p.s": body("#include \"x.h\"\n\n")}), "", true,
			[]string{"internal/runtime/startlinetest.sym"}},
		{"N1: the file tests more experiments than the cap", merge(mod, map[string]string{"p/p.s": body(many.String() + "#define CALLX\n")}), "", false, nil},
		// go_asm.h emits const_K only where K is an integer: with the experiment on, which the
		// session leaves off.
		{"a go_asm.h constant a dependency's experiment-tagged file sets, outside the ABI packages", dep, "example.com/v/p", true,
			[]string{"example.com/v/p.sym"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, it := lofAsmTestSession(t, tc.files, "p/p.s", nil, "")
			// cmd/asm defines GOEXPERIMENT_ macros only for the packages objabi allows ABI selectors in.
			it.pkg = "internal/runtime/startlinetest"
			if tc.pkg != "" {
				it.pkg = tc.pkg
			}
			o := s.read(it)
			if (o != nil) != tc.ok {
				t.Fatalf("read = %v, want ok %v", o, tc.ok)
			}
			for _, r := range tc.refs {
				if !slices.Contains(o.refs, r) {
					t.Errorf("refs %v lack %s", o.refs, r)
				}
			}
		})
	}
	// Outside those packages an #ifdef GOEXPERIMENT_ tests a name never defined: no experiment is
	// enumerated for it.
	for _, pkg := range []string{"internal/runtime/startlinetest", "example.com/v/p"} {
		s, it := lofAsmTestSession(t, merge(mod, map[string]string{"p/p.s": body(ifdef)}), "p/p.s", nil, "")
		it.pkg = pkg
		src, err := os.ReadFile(it.file)
		if err != nil {
			t.Fatal(err)
		}
		if got, abi := s.gate(it, src).exps, pkg != "example.com/v/p"; slices.Contains(got, exp) != abi {
			t.Errorf("%s: experiments enumerated %v", pkg, got)
		}
	}
}

// TestLofAsmHdrKey: a go_asm.h is keyed by the toolchain root and the experiments the build sets,
// and by the architecture level wherever a file of the package's import closure is level-specific,
// whether a build at one level compiles it (GoFiles), sets it aside (IgnoredGoFiles) or rejects it
// (InvalidGoFiles, which a file whose constraint cannot be read keys as unknown): such a file may
// change a constant the package takes from it.
func TestLofAsmHdrKey(t *testing.T) {
	a := &lofAsmTool{root: "/a", version: "go1.26.3"}
	b := &lofAsmTool{root: "/b", version: "go1.26.3"}
	it := lofAsmItem{pkg: "runtime", std: true}
	tu := lofAsmTuple{lofPort{"linux", "amd64"}, "v1", ""}
	v3, on, off := tu, tu, tu
	v3.level, on.exp, off.exp = "v3", "fieldtrack", "nofieldtrack"
	if a.hdrKey(it, tu, "v1", "on:", nil, []string{"a.go"}) == b.hdrKey(it, tu, "v1", "on:", nil, []string{"a.go"}) {
		t.Errorf("N2: another root shares the key")
	}

	mod := map[string]string{
		"go.mod": "module example.com/v\n\ngo 1.22\n",
		"d/a.go": "package d\n\nconst K = 1\n",
		"p/p.go": "package p\n\nimport \"example.com/v/d\"\n\nconst K = d.K\n",
		"p/p.s":  "#include \"go_asm.h\"\n",
	}
	for _, c := range []struct {
		name, file, src string
		split           bool
	}{
		{"level-tagged dependency file compiled at v1 (GoFiles)", "d/l.go", "//go:build !amd64.v3\n\npackage d\n\nconst L = 1\n", true},
		{"level-tagged dependency file left out at v1 (IgnoredGoFiles)", "d/l.go", "//go:build amd64.v3\n\npackage d\n\nconst K2 = 1\n", true},
		{"level-tagged dependency file go/build rejects (InvalidGoFiles)", "d/z.go", "//go:build amd64.v3\n//go:build amd64.v3\n\npackage d\n\nconst K2 = 1\n", true},
		{"level-named dependency file", "d/race_v3_amd64.go", "package d\n", true},
		{"no level-specific file in the closure", "d/l.go", "package d\n\nconst L = 1\n", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, it := lofAsmTestSession(t, merge(mod, map[string]string{c.file: c.src}), "p/p.s", nil, "")
			if s.tool == nil {
				t.Skip("no toolchain")
			}
			k1 := s.hdrKey(it, tu, nil, []string{"p.go"})
			k3 := s.hdrKey(it, v3, nil, []string{"p.go"})
			if split := k1 != k3; split != c.split {
				t.Errorf("v1 and v3 keys differ: %v, want %v", split, c.split)
			}
			if c.split {
				return
			}
			// The experiments: GOEXPERIMENT spellings the toolchain resolves to one experiment set share
			// an entry, and only those.
			if k := s.hdrKey(it, off, nil, []string{"p.go"}); k != k1 {
				t.Errorf("nofieldtrack, which the session's experiments already leave unset, keys apart")
			}
			if k := s.hdrKey(it, on, nil, []string{"p.go"}); k == k1 {
				t.Errorf("fieldtrack shares the key of a build without it")
			}
		})
	}
}

// TestLofAsmObjHeaderNoFetch: the go build that generates a module package's go_asm.h runs with
// GOPROXY=off and -mod=readonly, so a dependency missing from the module cache fails the file
// rather than being fetched.
func TestLofAsmObjHeaderNoFetch(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/v\n\ngo 1.22\n\nrequire example.com/nowhere v1.0.0\n",
		"go.sum": "example.com/nowhere v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" +
			"example.com/nowhere v1.0.0/go.mod h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
		"p/p.go": "package p\n\nimport _ \"example.com/nowhere\"\n",
		"p/p.s":  "//go:build linux && amd64\n\n#include \"go_asm.h\"\n\nTEXT ·f(SB),0,$0\n\tRET\n",
	}
	env := append(os.Environ(), "GOMODCACHE="+t.TempDir(), "GOPROXY=https://proxy.golang.org", "GOFLAGS=", "GOWORK=off")
	var mu sync.Mutex
	var builds []*exec.Cmd
	var stderr bytes.Buffer
	lofAsmHook(t, func(c *exec.Cmd) {
		if len(c.Args) > 1 && c.Args[1] == "build" {
			mu.Lock()
			builds = append(builds, c)
			c.Stderr = io.MultiWriter(c.Stderr, &stderr)
			mu.Unlock()
		}
	})
	s, it := lofAsmTestSession(t, files, "p/p.s", env, "")
	if o := s.object(it); o.ok {
		t.Fatalf("ok with a dependency the module cache lacks (refs %v)", o.refs)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(builds) == 0 {
		t.Fatal("no go build ran")
	}
	for _, c := range builds {
		if v, _ := lofEnvLast(c.Env, "GOPROXY"); v != "off" {
			t.Errorf("go build GOPROXY = %q, want off", v)
		}
		if v, _ := lofEnvLast(c.Env, "GOFLAGS"); v != "-mod=readonly" {
			t.Errorf("go build GOFLAGS = %q, want -mod=readonly", v)
		}
	}
	if !strings.Contains(stderr.String(), "GOPROXY=off") {
		t.Errorf("go build did not stop at GOPROXY=off:\n%s", stderr.String())
	}
}

// TestLofAsmObjGoflags: GOFLAGS that pass assembler flags, a -toolexec or an -overlay, from the
// session's GOFLAGS or the environment's, leave the session off and every file unknown; the nonce
// a header build passes never equals text the user's GOFLAGS hold.
func TestLofAsmObjGoflags(t *testing.T) {
	files := map[string]string{"go.mod": "module example.com/v\n\ngo 1.22\n", "p/p.go": "package p\n",
		"p/p.s": "TEXT ·f(SB),0,$0\n\tCALL ext(SB)\n\tRET\n"}
	for _, tc := range []struct {
		name, goflags, env string
		ok                 bool
	}{
		{"no GOFLAGS", "", "", true},
		{"-trimpath", "-trimpath", "", true},
		{"-asmflags", "-asmflags=-D=LOFN=ext", "", false},
		{"-asmflags defining the header build's macro prefix", "-asmflags=-D=FERRALON_ASMHDR_0", "", false},
		{"-toolexec", "-toolexec=/usr/bin/env", "", false},
		{"-overlay", "-overlay=/nonexistent.json", "", false},
		{"-toolexec in the environment's GOFLAGS", "", "-toolexec=/usr/bin/env", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := append(os.Environ(), "GOFLAGS="+tc.env)
			s, it := lofAsmTestSession(t, files, "p/p.s", env, tc.goflags)
			if o := s.object(it); o.ok != tc.ok {
				t.Errorf("ok = %v, want %v", o.ok, tc.ok)
			}
			if (s.version() != "") != tc.ok {
				t.Errorf("version %q with the session on = %v", s.version(), tc.ok)
			}
		})
	}
	t.Run("the nonce avoids text of the user's GOFLAGS", func(t *testing.T) {
		n := 0
		old := lofAsmNonce
		lofAsmNonce = func() string { n++; return "FERRALON_ASMHDR_" + string(rune('0'+n-1)) }
		t.Cleanup(func() { lofAsmNonce = old })
		var mu sync.Mutex
		var args []string
		lofAsmHook(t, func(c *exec.Cmd) {
			if len(c.Args) > 1 && c.Args[1] == "build" {
				mu.Lock()
				args = append(args, c.Args...)
				mu.Unlock()
			}
		})
		hdr := merge(files, map[string]string{"p/p.s": "//go:build linux && amd64\n\n#include \"go_asm.h\"\n\nTEXT ·f(SB),0,$0\n\tRET\n"})
		s, it := lofAsmTestSession(t, hdr, "p/p.s", append(os.Environ(), "GOFLAGS="), "-tags=FERRALON_ASMHDR_0")
		if o := s.object(it); !o.ok {
			t.Fatal("not ok")
		}
		mu.Lock()
		defer mu.Unlock()
		if !slices.Contains(args, "-asmflags=example.com/v/p=-D=FERRALON_ASMHDR_1") || slices.ContainsFunc(args, func(a string) bool { return strings.HasSuffix(a, "-D=FERRALON_ASMHDR_0") }) {
			t.Errorf("header build args %v: want the nonce FERRALON_ASMHDR_1", args)
		}
	})
}

// TestLeftOutEngine_AsmListing: the review rows against the assembler's listing. x.go's assembly
// reaches Bad exactly when what cmd/asm emits for it, and for every definer of a bare symbol it
// references, does. Rows E, H and Hdef pass the -D a CI command line would; the engine cannot see
// it, so they record what the listing without it shows.
func TestLeftOutEngine_AsmListing(t *testing.T) {
	base := map[string]string{
		"go.mod":          "module example.com/m\n\ngo 1.22.0\n\nrequire example.com/v v0.0.0\n\nreplace example.com/v => ./_v\n",
		"main.go":         "package main\n\nimport \"example.com/v/vuln\"\n\nfunc main() { vuln.Safe() }\n",
		"_v/go.mod":       "module example.com/v\n\ngo 1.22\n",
		"_v/vuln/vuln.go": "package vuln\n\nfunc Bad() {}\n\nfunc Safe() {}\n",
		"_v/def/def.go":   "package def\n",
		"lib/lib.go":      "package lib\n",
		"lib/y_alt.go":    "//go:build lofother\n\npackage lib\n\nimport _ \"example.com/v/def\"\n",
		"x.go":            "//go:build lofalt\n\npackage main\n\nfunc asm()\n\nfunc init() { asm() }\n",
	}
	bad := symKey("example.com/v/vuln", "Bad")
	asm := func(pre, stmt string) map[string]string {
		return map[string]string{"x_lofalt.s": "//go:build lofalt\n\n" + pre + "TEXT ·asm(SB),0,$0\n\t" + stmt + "\n\tRET\n"}
	}
	asm64 := func(pre, stmt string) map[string]string {
		return map[string]string{
			"x.go":       "//go:build lofalt && amd64\n\npackage main\n\nfunc asm()\n\nfunc init() { asm() }\n",
			"x_lofalt.s": "//go:build lofalt && amd64\n\n" + pre + "TEXT ·asm(SB),0,$0\n\t" + stmt + "\n\tRET\n",
		}
	}
	definer := func(name string) map[string]string {
		return map[string]string{"_v/def/def.s": "TEXT " + name + "(SB),0,$0\n\tCALL example·com∕v∕vuln·Bad(SB)\n\tRET\n"}
	}
	ext := definer("ext")
	hdr := func(body string) map[string]string { return map[string]string{"x.h": body} }
	// sys is an x/sys/unix-style module package outside the link that x.go's assembly calls, whose
	// own assembly calls a bare symbol only the standard library's assembly defines: nistec's
	// p256IsZero, in the link through crypto/ecdh.
	sys := merge(asm("", "CALL example·com∕v∕sys·Raw(SB)"), map[string]string{
		"main.go":       "package main\n\nimport (\n\t_ \"crypto/ecdh\"\n\n\t\"example.com/v/vuln\"\n)\n\nfunc main() { vuln.Safe() }\n",
		"_v/sys/sys.go": "package sys\n\nfunc Raw()\n",
		"_v/sys/sys.s":  "TEXT ·Raw(SB),0,$0\n\tCALL p256IsZero(SB)\n\tRET\n",
	})
	// failNistecAsm makes every assembly of nistec's files fail, on a fresh assembler whose cache
	// holds nothing of nistec's to answer from.
	// p7 is x.go's assembly calling go_asm.h's bool constant, on every port a main package builds on
	// with cgo off.
	p7 := map[string]string{
		"x.go":       "//go:build lofalt && !android && !ios\n\npackage main\n\nfunc asm()\n\nfunc init() { asm() }\n",
		"x_lofalt.s": "//go:build lofalt && !android && !ios\n\n#include \"go_asm.h\"\n\nTEXT ·asm(SB),0,$0\n\tCALL const_B(SB)\n\tRET\n",
		"b.go":       "package main\n\nconst B = true\n",
	}
	failNistecAsm := func(t *testing.T) {
		t.Setenv("GOENV", "off")
		goroot, err := exec.Command("go", "env", "GOROOT").Output()
		if err != nil {
			t.Fatal(err)
		}
		tool := lofAsmToolFor(context.Background(), strings.TrimSpace(string(goroot)), os.Environ())
		if tool == nil {
			t.Fatal("no assembler")
		}
		dir := filepath.Join(tool.root, "src", "crypto", "internal", "fips140", "nistec")
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		const pkg = "crypto/internal/fips140/nistec"
		tool.mu.Lock()
		for k := range tool.std {
			if strings.HasPrefix(k, pkg+"\x00") {
				delete(tool.std, k)
			}
		}
		tool.mu.Unlock()
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".s") {
				continue
			}
			if c := tool.stdCache(lofAsmItem{pkg: pkg, dir: dir, file: filepath.Join(dir, e.Name()), std: true}); c != "" {
				if err := os.Remove(c); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
			}
		}
		lofAsmHook(t, func(c *exec.Cmd) {
			if filepath.Base(c.Path) == "asm" && strings.HasSuffix(filepath.ToSlash(c.Dir), "/fips140/nistec") {
				c.Path, c.Args[0] = "/usr/bin/false", "/usr/bin/false"
			}
		})
	}
	cases := []struct {
		name    string
		files   map[string]string
		goflags string
		setup   func(*testing.T)
		reach   bool   // x.go's closure reaches Bad
		item    string // what x.go's closure fails closed on, when set
		stdGaps bool   // the run records standard-library assembly it could not read
	}{
		// (i) funcdata.h's comment words are no definer; a module's TEXT of the name is.
		{"(i) funcdata.h's comment word open", merge(asm("", "CALL open(SB)"), map[string]string{
			"_v/def/fd.s": "#include \"funcdata.h\"\n\nTEXT ·f(SB),0,$0\n\tNO_LOCAL_POINTERS\n\tRET\n", "_v/def/def.go": "package def\n\nfunc f()\n"}), "", nil, false, "", false},
		{"(i) control: a module TEXT open", merge(asm("", "CALL open(SB)"), definer("open")), "", nil, true, "", false},
		// (ii) a bare symbol only the standard library defines, from a module package.
		{"(ii) a definer only the standard library holds", sys, "", nil, false, "", false},
		{"(ii) a definer only the standard library holds, whose assembly fails", sys, "", failNistecAsm, false, lofAsmSymbol, true},
		// Review 113.
		{"A: a macro supplying (", merge(asm("#define LP (\n\n", "CALL ext LP SB)"), ext), "", nil, true, "", false},
		{"G: a macro supplying name(", merge(asm("#define E ext(\n\n", "CALL E SB)"), ext), "", nil, true, "", false},
		{"D: a macro taking the name and SB", merge(asm("#define F(a,b) CALL a(b)\n\n", "F(ext, SB)"), ext), "", nil, true, "", false},
		{"C: a macro taking SB", merge(asm("#define F(r) CALL ext(r)\n\n", "F(SB)"), ext), "", nil, true, "", false},
		{"B: a macro naming the symbol", merge(asm("#define LOFN ext\n\n", "CALL LOFN(SB)"), ext), "", nil, true, "", false},
		{"Bh: B's macro in a header", merge(asm("#include \"x.h\"\n\n", "CALL LOFN(SB)"), hdr("#define LOFN ext\n"), ext), "", nil, true, "", false},
		{"Ch: C's macro in a header", merge(asm("#include \"x.h\"\n\n", "F(SB)"), hdr("#define F(r) CALL ext(r)\n"), ext), "", nil, true, "", false},
		{"Udef: a macro naming a definer's TEXT", merge(asm("", "CALL ext(SB)"), map[string]string{
			"_v/def/def.s": "#define LOFN ext\nTEXT LOFN(SB),0,$0\n\tCALL example·com∕v∕vuln·Bad(SB)\n\tRET\n"}), "", nil, true, "", false},
		{"E (residue): CALL ext(S) without -D S=SB does not assemble", merge(asm("", "CALL ext(S)"), ext), "", nil, false, lofAsmSymbol, false},
		{"H (residue): CALL LOFN(SB) without -D LOFN=ext calls LOFN", merge(asm("", "CALL LOFN(SB)"), ext), "", nil, false, "", false},
		{"Hdef (residue): TEXT LOFN(SB) without -D LOFN=ext defines LOFN", merge(asm("", "CALL ext(SB)"), definer("LOFN")), "", nil, false, "", false},
		{"M: the dotted path spelling", asm("", "CALL example·com∕v∕vuln·Bad(SB)"), "", nil, true, "", false},
		// Review 117.
		{"P1: a macro closing the operand and adding a CALL", merge(asm64("#define X 0(FP), AX; CALL ext+0\n\n", "MOVQ ·asm+X(SB)"), ext), "", nil, true, "", false},
		{"P1h: P1's macro in a header", merge(asm64("#include \"x.h\"\n\n", "MOVQ ·asm+X(SB)"), hdr("#define X 0(FP), AX; CALL ext+0\n"), ext), "", nil, true, "", false},
		{"P2: a comment inside the offset", merge(asm("", "CALL /* ·asm+ */ ext(SB)"), ext), "", nil, true, "", false},
		{"P2b: a comment glued to the name", merge(asm("", "CALL /* ·asm-0 */ext(SB)"), ext), "", nil, true, "", false},
		{"P7: go_asm.h's bool constant", merge(p7, definer("true")), "", nil, true, "", false},
		{"P7: the other bool's definer", merge(p7, definer("false")), "", nil, true, "", false},
		// A main package's go_asm.h on a port that links only externally (android but arm64, ios/arm64)
		// cannot be generated with cgo off: the go command refuses the build before compiling.
		{"P7 (residue): a main package's go_asm.h on a port that links only externally", merge(asm("#include \"go_asm.h\"\n\n", "CALL const_B(SB)"), definer("true"), map[string]string{
			"b.go": "package main\n\nconst B = true\n"}), "", nil, false, lofAsmSymbol, false},
		{"GOFLAGS passing a -toolexec wrapper", merge(asm("", "CALL ext(SB)"), ext), "-toolexec=/usr/bin/env", nil, false, lofAsmSymbol, false},
	}
	goVersion, err := exec.Command("go", "env", "GOVERSION").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup(t)
			}
			var prepare func(*LoadResult)
			if tc.goflags != "" {
				prepare = func(*LoadResult) { t.Setenv("GOFLAGS", tc.goflags) }
			}
			got := lofRun(t, writeTree(t, merge(base, tc.files)), "example.com/v", map[string][]string{"example.com/v/vuln": {"Bad"}}, false, prepare)
			f := got.facts["x.go"]
			if f == nil {
				t.Fatalf("the engine holds no x.go (facts %s)", lofDescribe(got))
			}
			var fc []string
			if tc.item != "" {
				fc = []string{tc.item}
			}
			if !slices.Equal(f.FC, fc) || len(f.FCStd) > 0 {
				t.Errorf("x.go fails closed on %v (standard library %v), want %v", f.FC, f.FCStd, fc)
			}
			if reached := slices.ContainsFunc(f.Funcs, func(id int32) bool { return got.engine.Strs[id] == bad }); reached != tc.reach {
				t.Errorf("x.go reaches Bad = %v, want %v", reached, tc.reach)
			}
			if want := tc.reach || tc.item != ""; got.withheld != want {
				t.Errorf("withheld = %v, want %v (facts %s)", got.withheld, want, lofDescribe(got))
			}
			if (got.engine.StdGaps > 0) != tc.stdGaps {
				t.Errorf("run record: %d standard-library gaps, want any = %v", got.engine.StdGaps, tc.stdGaps)
			}
			want := strings.TrimSpace(string(goVersion))
			if tc.goflags != "" {
				want = ""
			}
			if got.engine.AsmToolchain != want {
				t.Errorf("run record: assembler toolchain %q, want %q", got.engine.AsmToolchain, want)
			}
		})
	}
}
