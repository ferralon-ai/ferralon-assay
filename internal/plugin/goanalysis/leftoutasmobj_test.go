package goanalysis

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

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
	cases := []struct {
		name  string
		files map[string]string
		err   error // what headers returns for linux/amd64, nil for none
		refs  []string
	}{
		{"variants up to the cap", tagged(4), nil, []string{"c0"}},
		{"variants over the cap", tagged(5), errLofAsmHdrCap, nil},
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
			x, _ := fileConstraint(src)
			g := s.gate(it, src)
			tu := lofAsmTuple{lofPort{"linux", "amd64"}, s.tool.levels["amd64"][0]}
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
	// failNistecAsm makes every assembly of nistec's files fail, on a fresh assembler with no cache
	// to answer from.
	// p7 is x.go's assembly calling go_asm.h's bool constant, on every port a main package builds on
	// with cgo off.
	p7 := map[string]string{
		"x.go":       "//go:build lofalt && !android && !ios\n\npackage main\n\nfunc asm()\n\nfunc init() { asm() }\n",
		"x_lofalt.s": "//go:build lofalt && !android && !ios\n\n#include \"go_asm.h\"\n\nTEXT ·asm(SB),0,$0\n\tCALL const_B(SB)\n\tRET\n",
		"b.go":       "package main\n\nconst B = true\n",
	}
	failNistecAsm := func(t *testing.T) {
		t.Setenv("GOENV", "off")
		old := lofAsmCacheDir
		lofAsmCacheDir = ""
		t.Cleanup(func() { lofAsmCacheDir = old })
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
