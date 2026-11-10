package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
)

func writeTree(t *testing.T, dir string, files []string) {
	t.Helper()
	for _, f := range files {
		p := filepath.Join(dir, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDotNetRestoreTargets(t *testing.T) {
	tests := []struct {
		name  string
		files []string
		want  []string
	}{
		{"no projects", []string{"README.md", "src/app.js"}, nil},
		{"restore output present", []string{"App/App.csproj", "App/obj/project.assets.json"}, nil},
		{"lock file present", []string{"App/App.csproj", "App/packages.lock.json"}, nil},
		{"project without either", []string{"App/App.csproj"}, []string{"App/App.csproj"}},
		{"fsproj and vbproj, any case", []string{"A/A.fsproj", "B/B.VBPROJ"}, []string{"A/A.fsproj", "B/B.VBPROJ"}},
		{"only the unrestored project", []string{"A/A.csproj", "A/obj/project.assets.json", "B/B.csproj"}, []string{"B/B.csproj"}},
		{"assets file in the wrong place", []string{"App/App.csproj", "App/project.assets.json", "obj/project.assets.json"}, []string{"App/App.csproj"}},
		{"root solution preferred", []string{"App.sln", "App/App.csproj", "Lib/Lib.csproj"}, []string{"App.sln"}},
		{"root slnx preferred", []string{"App.slnx", "App/App.csproj"}, []string{"App.slnx"}},
		{"solution ignored when all restored", []string{"App.sln", "App/App.csproj", "App/packages.lock.json"}, nil},
		{"two root solutions, per project", []string{"A.sln", "B.sln", "App/App.csproj"}, []string{"App/App.csproj"}},
		{"nested solution is not a root solution", []string{"sub/App.sln", "sub/App/App.csproj"}, []string{"sub/App/App.csproj"}},
		{"skipped directories", []string{
			"bin/X/X.csproj", "obj/X/X.csproj", "packages/P/P.csproj",
			"node_modules/n/N.csproj", "TestResults/T.csproj", ".git/G.csproj", ".vs/V.csproj",
		}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTree(t, dir, tt.files)
			if got := dotnetRestoreTargets(dir); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("targets = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDotNetRestoreTargets_SymlinkedProjectIgnored(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, []string{"real/App.csproj.txt"})
	if err := os.Symlink(filepath.Join(dir, "real", "App.csproj.txt"), filepath.Join(dir, "App.csproj")); err != nil {
		t.Skip(err)
	}
	if got := dotnetRestoreTargets(dir); got != nil {
		t.Fatalf("targets = %q, want none", got)
	}
}

// fakeDotNet puts a dotnet script on PATH that appends its arguments to a log and exits with code.
// When restoring a solution it also creates each file named in slnWrites (relative to its working
// directory, in a directory that exists), standing in for the projects the solution lists.
func fakeDotNet(t *testing.T, code, slnWrites string) string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(bin, "args.log")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\necho 'restore output https://feed.example/secret'\n" +
		"case \"$2\" in *.sln|*.slnx) for f in " + slnWrites + "; do : > \"$f\"; done;; esac\nexit " + code + "\n"
	if err := os.WriteFile(filepath.Join(bin, "dotnet"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	return log
}

func TestRestoreDotNet(t *testing.T) {
	tests := []struct {
		name      string
		files     []string
		tool      string // "" means no dotnet on PATH
		slnWrites string
		wantArgs  []string
		wantLog   string // substring of w; "" means w stays empty
	}{
		{"nothing to restore runs nothing", []string{"App/App.csproj", "App/packages.lock.json"}, "0", "", nil, ""},
		{"solution restored", []string{"App.sln", "App/App.csproj"}, "0", "App/packages.lock.json", []string{"restore App.sln"}, "restore"},
		{"project outside the solution restored after it", []string{"App.sln", "App/App.csproj", "Gen/Gen.csproj"}, "0", "App/packages.lock.json",
			[]string{"restore App.sln", "restore Gen/Gen.csproj"}, "restore"},
		{"failed solution falls back to each project", []string{"App.sln", "A/A.csproj", "B/B.csproj"}, "1", "",
			[]string{"restore App.sln", "restore A/A.csproj", "restore B/B.csproj"}, "dotnet restore: tool_failed:restore\n"},
		{"each project restored", []string{"A/A.csproj", "B/B.csproj"}, "0", "", []string{"restore A/A.csproj", "restore B/B.csproj"}, "restore"},
		{"dotnet absent", []string{"App.sln", "App/App.csproj"}, "", "", nil, "dotnet restore: toolchain_absent\n"},
		{"restore fails", []string{"App/App.csproj"}, "1", "", []string{"restore App/App.csproj"}, "dotnet restore: tool_failed:restore\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTree(t, dir, tt.files)
			var log string
			if tt.tool == "" {
				t.Setenv("PATH", t.TempDir())
			} else {
				log = fakeDotNet(t, tt.tool, tt.slnWrites)
			}
			var w bytes.Buffer
			restoreDotNet(context.Background(), dir, &w)
			var args []string
			if log != "" {
				if b, err := os.ReadFile(log); err == nil {
					args = strings.Split(strings.TrimSpace(strings.ReplaceAll(string(b), dir+string(filepath.Separator), "")), "\n")
				}
			}
			if !reflect.DeepEqual(args, tt.wantArgs) {
				t.Fatalf("dotnet calls = %q, want %q", args, tt.wantArgs)
			}
			if tt.wantLog == "" {
				if w.Len() != 0 {
					t.Fatalf("w = %q, want empty", w.String())
				}
			} else if !strings.Contains(w.String(), tt.wantLog) {
				t.Fatalf("w = %q, want it to contain %q", w.String(), tt.wantLog)
			}
			if strings.Contains(w.String(), "feed.example") {
				t.Fatalf("restore output leaked to the log: %q", w.String())
			}
		})
	}
}

func TestRunDotNetRestore_KeepsFirstFailure(t *testing.T) {
	log := fakeDotNet(t, "1", "")
	f := runDotNetRestore(context.Background(), t.TempDir(), []string{"A/A.csproj", "B/B.csproj"})
	if f == nil || f.Kind != buildgraph.KindToolFailed || f.Detail != "restore" {
		t.Fatalf("failure = %+v, want tool_failed:restore", f)
	}
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "\n"); n != 2 {
		t.Fatalf("dotnet ran %d times, want 2 (the second target after the first failed)", n)
	}
}

func TestRunDotNetRestore_StartErrorIsToolFailed(t *testing.T) {
	fakeDotNet(t, "0", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := runDotNetRestore(ctx, t.TempDir(), []string{"A/A.csproj"})
	if f == nil || f.Kind != buildgraph.KindToolFailed || f.Detail != "restore" || !strings.Contains(f.Log, "context canceled") {
		t.Fatalf("failure = %+v, want tool_failed:restore carrying the start error", f)
	}
}
