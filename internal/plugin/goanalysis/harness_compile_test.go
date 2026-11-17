package goanalysis

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// harnessFixture is a module whose packages hold one sink of each shape a skeleton must handle.
var harnessFixture = map[string]string{
	"go.mod": "module example.com/h\n\ngo 1.21\n",
	"sinks/sinks.go": `package sinks

import (
	"context"
	"io"
)

type Opts struct{ N int }

type hidden struct{}

type T struct{}

type I interface{ M(s string) }

func Zero() {}

func One(s string) error { return nil }

func Several(ctx context.Context, b []byte, r io.Reader, n int, o Opts, p *Opts, m map[string][]Opts, f func(int) error) (int, error) {
	return 0, nil
}

func Variadic(prefix string, parts ...string) {}

func VariadicOpts(opts ...Opts) int { return 0 }

func (T) Val(s string) {}

func (*T) Ptr(b []byte) error { return nil }

func Generic[X any](x X) {}

func Hidden(h hidden) {}

func unexported(s string) {}
`,
	"v2/sinks.go":           "package sinks\n\nimport \"strings\"\n\nfunc Read(r *strings.Reader, in int) {}\n",
	"internal/deep/deep.go": "package deep\n\nfunc In(s string) {}\n",
	"a/internal/b/b.go":     "package b\n\nfunc In(s string) {}\n",
	"cmd/tool/main.go":      "package main\n\nfunc main() {}\n\nfunc Run(s string) {}\n",
}

// TestGenerateHarness_SkeletonsCompile writes the skeleton of every sink shape into the fixture
// module, with the signature resolved and without, and requires that all of them vet and that a
// fuzz skeleton starts fuzzing.
func TestGenerateHarness_SkeletonsCompile(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the go command")
	}
	dir := t.TempDir()
	for name, src := range harnessFixture {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name string
		sink string // the SCIP descriptor under example.com/h/
		want string // a line the resolved skeleton holds
	}{
		{"zero", "sinks/Zero().", "sink.Zero()"},
		{"one", "sinks/One().", "_ = sink.One(in)"},
		{"several", "sinks/Several().", "_, _ = sink.Several(context.Background(), []byte(in), strings.NewReader(in), a3, a4, a5, a6, a7)"},
		{"variadic", "sinks/Variadic().", "sink.Variadic(in, in)"},
		{"variadicopts", "sinks/VariadicOpts().", "_ = sink.VariadicOpts(a0...)"},
		{"valmethod", "sinks/T#Val().", "recv.Val(in)"},
		{"ptrmethod", "sinks/T#Ptr().", "_ = recv.Ptr([]byte(in))"},
		{"ifacemethod", "sinks/I#M().", "t.Skip("},
		{"generic", "sinks/Generic().", "t.Skip("},
		{"hiddenparam", "sinks/Hidden().", "t.Skip("},
		{"unexported", "sinks/unexported().", "t.Skip("},
		{"aliasclash", "v2/Read().", "sink.Read(a0, a1)"},
		{"rootinternal", "internal/deep/In().", "sink.In(in)"},
		{"deepinternal", "a/internal/b/In().", "t.Skip("},
		{"mainpkg", "cmd/tool/Run().", "t.Skip("},
	}
	ctx := context.Background()
	write := func(sub, src string) {
		t.Helper()
		assertParses(t, src)
		path := filepath.Join(dir, "zzharness", sub, "harness_test.go")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range cases {
		for _, kind := range []string{"unit", "fuzz"} {
			req := plugin.GenerateHarnessRequest{Sink: "scip-go gomod example.com/h . example.com/h/" + tc.sink, Kind: kind}
			resolved, err := generateHarness(ctx, req, dir)
			if err != nil {
				t.Fatalf("%s/%s: %v", tc.name, kind, err)
			}
			if !strings.Contains(resolved.Source, tc.want) {
				t.Errorf("%s/%s: resolved skeleton lacks %q:\n%s", tc.name, kind, tc.want, resolved.Source)
			}
			if !strings.Contains(resolved.Source, "TODO") {
				t.Errorf("%s/%s: resolved skeleton carries no TODO:\n%s", tc.name, kind, resolved.Source)
			}
			write(tc.name+"_"+kind+"_resolved", resolved.Source)

			unresolved, err := GenerateHarness(ctx, req)
			if err != nil {
				t.Fatalf("%s/%s: %v", tc.name, kind, err)
			}
			// Without a signature a generic sink, an interface method and a sink in a main package
			// cannot be told apart from an ordinary one, so those are checked only resolved.
			if tc.name == "generic" || tc.name == "mainpkg" || tc.name == "ifacemethod" {
				continue
			}
			if !strings.Contains(unresolved.Source, "t.Skip(") {
				t.Errorf("%s/%s: unresolved skeleton does not skip:\n%s", tc.name, kind, unresolved.Source)
			}
			write(tc.name+"_"+kind+"_unresolved", unresolved.Source)
		}
	}
	if t.Failed() {
		return
	}

	goCmd := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("go", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	goCmd("vet", "./...")
	goCmd("test", "-count=1", "./zzharness/...")
	if out := goCmd("test", "-run=^$", "-fuzz=FuzzSink", "-fuzztime=1s", "./zzharness/one_fuzz_resolved"); !strings.Contains(out, "fuzz: elapsed") {
		t.Errorf("the fuzz skeleton did not start fuzzing:\n%s", out)
	}
}
