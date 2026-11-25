package goanalysis

import (
	"go/token"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestLofAsm_Read(t *testing.T) {
	const textflag = "#define NOSPLIT 4\n"
	for _, tc := range []struct {
		name string
		// files are the package directory's files; a .s file is one of its assembly files.
		files map[string]string
		cgo   bool
		// gone adds an assembly file that does not exist.
		gone   bool
		text   []string
		refs   [][2]string
		opaque bool
	}{
		{name: "a local call", files: map[string]string{"a.s": "TEXT ·f(SB),0,$0\n\tCALL ·g(SB)\n\tRET\n"},
			text: []string{"f"}, refs: [][2]string{{"", "g"}}},
		{name: "a standard-library call", files: map[string]string{"a.s": "TEXT ·f(SB),0,$0\n\tCALL runtime·entersyscall(SB)\n\tRET\n"},
			text: []string{"f"}, refs: [][2]string{{"runtime", "entersyscall"}}},
		{name: "a dotless module's symbol", files: map[string]string{"a.s": "TEXT ·f(SB),0,$0\n\tCALL m∕q·F(SB)\n\tMOVQ $m∕q·G(SB), AX\n\tRET\n"},
			text: []string{"f"}, refs: [][2]string{{"m/q", "F"}, {"m/q", "G"}}},
		{name: "the package's own path", files: map[string]string{"a.s": "TEXT m∕p·f(SB),0,$0\n\tCALL m∕p·g(SB)\n\tRET\n"},
			text: []string{"f"}, refs: [][2]string{{"", "g"}}},
		{name: "a macro standing for a symbol", files: map[string]string{"a.s": "#define TGT x∕y·Bar\nTEXT ·f(SB),0,$0\n\tCALL TGT(SB)\n\tRET\n"},
			text: []string{"f"}, refs: [][2]string{{"x/y", "Bar"}}},
		{name: "a macro redefined", files: map[string]string{"a.s": "#define TGT x∕y·Bar\n#undef TGT\n#define TGT libc_bar\nTEXT ·f(SB),0,$0\n\tCALL TGT(SB)\n\tRET\n"},
			text: []string{"f"}, refs: [][2]string{{"x/y", "Bar"}}, opaque: true},
		{name: "a macro standing for other text", files: map[string]string{"a.s": "#define TGT libc_bar\nTEXT ·f(SB),0,$0\n\tCALL TGT(SB)\n\tRET\n"},
			text: []string{"f"}, opaque: true},
		{name: "SB hidden in a macro", files: map[string]string{"a.s": "#define BASE SB\nTEXT ·f(SB),0,$0\n\tCALL libc_bar(BASE)\n\tRET\n"},
			text: []string{"f"}, opaque: true},
		{name: "file-local and ABI-selected symbols", files: map[string]string{"a.s": "TEXT ·f<ABI0>(SB),0,$0\n\tCALL ·g<>(SB)\n\tRET\nTEXT ·g<>(SB),0,$0\n\tMOVQ ·tab<>+8(SB), AX\n\tRET\nGLOBL ·tab<>(SB),8,$16\n"},
			text: []string{"f"}, refs: [][2]string{{"", "g<>"}, {"", "tab<>"}}},
		{name: "a C symbol", files: map[string]string{"a.s": "TEXT ·f(SB),0,$0\n\tJMP libc_x(SB)\n"},
			text: []string{"f"}, opaque: true},
		{name: "a C symbol's address", files: map[string]string{"a.s": "TEXT ·f(SB),0,$0\n\tMOVQ $libc_x+0(SB), AX\n\tRET\n"},
			text: []string{"f"}, opaque: true},
		{name: "an assembly-only helper", files: map[string]string{"a.s": "TEXT ·f(SB),0,$0\n\tJMP helper<>(SB)\nTEXT helper<>(SB),0,$0\n\tRET\n"},
			text: []string{"f"}},
		{name: "a compiler-made name", files: map[string]string{"a.s": "TEXT ·f(SB),0,$0\n\tCALL ·f.func1(SB)\n\tRET\n"},
			text: []string{"f"}, opaque: true},
		{name: "a dotted import path", files: map[string]string{"a.s": "TEXT ·f(SB),0,$0\n\tCALL golang.org∕x∕sys·F(SB)\n\tRET\n"},
			text: []string{"f"}, opaque: true},
		{name: "a missing header", files: map[string]string{"a.s": "#include \"missing.h\"\nTEXT ·f(SB),0,$0\n\tRET\n"},
			text: []string{"f"}, opaque: true},
		{name: "go_asm.h", files: map[string]string{"a.s": "#include \"go_asm.h\"\nTEXT ·f(SB),0,$0\n\tRET\n"},
			text: []string{"f"}},
		{name: "the toolchain's header", files: map[string]string{"a.s": "#include \"textflag.h\"\nTEXT ·f(SB),NOSPLIT,$0\n\tRET\n"},
			text: []string{"f"}},
		{name: "the package's header", files: map[string]string{"a.s": "#include \"h.h\"\nTEXT ·f(SB),0,$0\n\tRET\n", "h.h": "#define CALLH CALL ·h(SB)\n"},
			text: []string{"f"}, refs: [][2]string{{"", "h"}}},
		{name: "another package's body", files: map[string]string{"a.s": "TEXT m∕q·F(SB),0,$0\n\tRET\n"}},
		{name: "a comment and a string", files: map[string]string{"a.s": "// CALL ·x(SB)\nTEXT ·f(SB),0,$0\n\tRET\n/* CALL libc_y(SB) */\n#include \"textflag.h\" // \"·z\"\n"},
			text: []string{"f"}},
		{name: "a file that cannot be read", files: map[string]string{"a.s": "TEXT ·f(SB),0,$0\n\tRET\n"}, gone: true,
			text: []string{"f"}, opaque: true},
		{name: "text the assembler cannot read", files: map[string]string{"a.s": "TEXT ·f(SB),0,$0\n\tMOVQ $\"x, AX\n"},
			opaque: true},
		// go/build links a .syso without reading a build constraint from it.
		{name: "a .syso object", files: map[string]string{"a.s": "TEXT ·f(SB),0,$0\n\tRET\n", "x_amd64.syso": "//go:build ignore\n"},
			opaque: true},
		{name: "a .S file", files: map[string]string{"a.s": "TEXT ·f(SB),0,$0\n\tRET\n", "x.S": "TEXT ·g(SB),0,$0\n\tRET\n"},
			opaque: true},
		{name: "an excluded .S file", files: map[string]string{"a.s": "TEXT ·f(SB),0,$0\n\tRET\n", "x.S": "//go:build ignore\n\nTEXT ·g(SB),0,$0\n\tRET\n"},
			text: []string{"f"}},
		{name: "a C file without cgo", files: map[string]string{"a.s": "TEXT ·f(SB),0,$0\n\tRET\n", "x.c": "void f(void) {}\n"},
			text: []string{"f"}},
		{name: "a C file with cgo", files: map[string]string{"a.s": "TEXT ·f(SB),0,$0\n\tRET\n", "x.c": "void f(void) {}\n"}, cgo: true,
			opaque: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, goroot := t.TempDir(), t.TempDir()
			if err := os.MkdirAll(filepath.Join(goroot, "pkg", "include"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(goroot, "pkg", "include", "textflag.h"), []byte(textflag), 0o644); err != nil {
				t.Fatal(err)
			}
			p := &lofPkg{path: "m/p", dir: dir}
			for _, n := range slices.Sorted(maps.Keys(tc.files)) {
				full := filepath.Join(dir, n)
				if err := os.WriteFile(full, []byte(tc.files[n]), 0o644); err != nil {
					t.Fatal(err)
				}
				switch {
				case filepath.Ext(n) == ".s":
					p.asmFiles = append(p.asmFiles, full)
				case lofForeignExt[filepath.Ext(n)]:
					p.foreign = append(p.foreign, full)
				}
			}
			if tc.gone {
				p.asmFiles = append(p.asmFiles, filepath.Join(dir, "gone.s"))
			}
			if tc.cgo {
				p.files = []*lofFile{{pkg: p, cgo: true}}
			}
			w := &lofWorld{goroot: goroot, excluded: ignored}
			a := w.asmOf(p)
			if a.opaque != tc.opaque {
				t.Errorf("opaque = %v, want %v", a.opaque, tc.opaque)
			}
			if got := slices.Sorted(maps.Keys(a.text)); !slices.Equal(got, tc.text) {
				t.Errorf("text = %v, want %v", got, tc.text)
			}
			if !slices.Equal(a.refs, tc.refs) {
				t.Errorf("refs = %v, want %v", a.refs, tc.refs)
			}
		})
	}
}

func TestLofWalk_Asm(t *testing.T) {
	loaded := func(path, name string, funcs ...string) *lofPkg {
		tp := types.NewPackage(path, name)
		for _, f := range funcs {
			tp.Scope().Insert(types.NewFunc(token.NoPos, tp, f, types.NewSignatureType(nil, nil, nil, nil, nil, false)))
		}
		return &lofPkg{path: path, std: !slices.Contains([]string{"m/q"}, path), loaded: &packages.Package{Types: tp}}
	}
	const head = "TEXT ·f(SB),0,$0\n"
	for _, tc := range []struct {
		name string
		asm  string
		// fn is the bodyless function followed; "f" when empty.
		fn     string
		std    bool
		fc     []string
		fcStd  []string
		asmTo  []string
		pushed []string
	}{
		{name: "a call in its own package", asm: head + "\tCALL ·g(SB)\n\tRET\n", asmTo: []string{"m/p"}, pushed: []string{"g"}},
		{name: "an assembly-only helper", asm: head + "\tJMP ·h(SB)\nTEXT ·h(SB),0,$0\n\tRET\n", asmTo: []string{"m/p"}},
		{name: "a name nothing declares", asm: head + "\tCALL ·nope(SB)\n\tRET\n", fc: []string{lofAssembly}, asmTo: []string{"m/p"}},
		{name: "a standard-library function", asm: head + "\tCALL runtime·entersyscall(SB)\n\tRET\n", asmTo: []string{"m/p", "runtime"}},
		{name: "a standard-library symbol nothing declares", asm: head + "\tCALL runtime·load_g(SB)\n\tRET\n", fcStd: []string{lofAssembly}, asmTo: []string{"m/p"}},
		{name: "a dotless module's function", asm: head + "\tCALL m∕q·F(SB)\n\tRET\n", asmTo: []string{"m/p", "m/q"}},
		{name: "a dotless module's symbol nothing declares", asm: head + "\tCALL m∕q·Nope(SB)\n\tRET\n", fc: []string{lofAssembly}, asmTo: []string{"m/p"}},
		{name: "a package that cannot be found", asm: head + "\tCALL m∕gone·F(SB)\n\tRET\n", fc: []string{lofUnresolvedImport}, asmTo: []string{"m/p"}},
		{name: "a function its assembly does not define", asm: head + "\tRET\n", fn: "g", fc: []string{lofAssembly}},
		{name: "a C symbol", asm: head + "\tJMP libc_x(SB)\n", fc: []string{lofAssembly}},
		{name: "a compiler-made name", asm: head + "\tCALL ·g.func1(SB)\n\tRET\n", fc: []string{lofAssembly}},
		{name: "a missing header", asm: "#include \"missing.h\"\n" + head + "\tRET\n", fc: []string{lofAssembly}},
		{name: "a standard-library package's assembly", asm: head + "\tCALL ·g(SB)\n\tRET\n", std: true, fcStd: []string{lofAssembly}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			full := filepath.Join(dir, "a.s")
			if err := os.WriteFile(full, []byte(tc.asm), 0o644); err != nil {
				t.Fatal(err)
			}
			p := &lofPkg{path: "m/p", dir: dir, std: tc.std, asmFiles: []string{full}, decls: map[string][]*lofDecl{}}
			for _, n := range []string{"f", "g"} {
				p.decls[n] = []*lofDecl{{name: n}}
			}
			w := &lofWorld{excluded: ignored, pkgs: map[string]*lofPkg{
				"runtime": loaded("runtime", "runtime", "entersyscall"),
				"m/q":     loaded("m/q", "q", "F"),
				"m/gone":  {path: "m/gone", missing: lofUnresolvedImport},
			}}
			k := &lofWalk{w: w, out: newLofClosure(), epoch: 1, entered: map[*lofPkg]bool{}, touched: map[*lofFile]bool{}}
			fn := tc.fn
			if fn == "" {
				fn = "f"
			}
			k.asm(p, fn)
			if !slices.Equal(k.out.fc, tc.fc) || !slices.Equal(k.out.fcStd, tc.fcStd) {
				t.Errorf("fails closed on %v, standard library only on %v; want %v and %v", k.out.fc, k.out.fcStd, tc.fc, tc.fcStd)
			}
			if got := slices.Sorted(maps.Keys(k.out.asmTo)); !slices.Equal(got, tc.asmTo) {
				t.Errorf("assembly targets = %v, want %v", got, tc.asmTo)
			}
			var pushed []string
			for _, d := range k.queue {
				pushed = append(pushed, d.name)
			}
			if !slices.Equal(pushed, tc.pushed) {
				t.Errorf("pushed %v, want %v", pushed, tc.pushed)
			}
			if !k.out.dyn {
				t.Error("assembly is not a dynamic call")
			}
			if narrowed := len(tc.asmTo) > 0; k.out.sink != narrowed {
				t.Errorf("sink = %v, want %v", k.out.sink, narrowed)
			}
		})
	}
}
