package buildgraph

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func exe(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

const mavenFailure = `[INFO] Compiling 3 source files
[ERROR] /w/src/main/java/p/App.java:[3,1] ';' expected
[INFO] BUILD FAILURE
[ERROR] Failed to execute goal org.apache.maven.plugins:maven-compiler-plugin:3.13.0:compile (default-compile) on project demo: Compilation failure
[ERROR] 
[ERROR] -> [Help 1]
[ERROR] 
[ERROR] To see the full stack trace of the errors, re-run Maven with the -e switch.
`

func TestCompile(t *testing.T) {
	var gotExe string
	var gotArgs []string
	var gotDir string
	stub := func(out string, err error) func(context.Context, string, []string, string, []string) ([]byte, error) {
		return func(_ context.Context, dir string, _ []string, exe string, args []string) ([]byte, error) {
			gotExe, gotArgs, gotDir = exe, args, dir
			return []byte(out), err
		}
	}
	tests := []struct {
		name       string
		tool       string
		wrapper    string // file made executable in the repository
		onPath     string // file made executable on PATH
		cond       Conditions
		exec       func(context.Context, string, []string, string, []string) ([]byte, error)
		wantExe    string // "" for the wrapper path
		wantArgs   string
		wantCmd    string
		wantKind   string
		wantInLog  []string
		wantNotLog []string
	}{
		{name: "maven on PATH", tool: ToolMaven, onPath: "mvn", exec: stub("", nil), wantExe: "PATH", wantArgs: "-B compile", wantCmd: "mvn -B compile"},
		{name: "maven wrapper preferred", tool: ToolMaven, wrapper: "mvnw", onPath: "mvn", exec: stub("", nil), wantArgs: "-B compile", wantCmd: "./mvnw -B compile"},
		{name: "maven profiles and properties", tool: ToolMaven, onPath: "mvn", cond: Conditions{Profiles: []string{"a", "!b"}, Properties: map[string]string{"z": "1", "k": "v"}},
			exec: stub("", nil), wantExe: "PATH", wantArgs: "-B -P a,!b -Dk=v -Dz=1 compile", wantCmd: "mvn -B -P a,!b -Dk=v -Dz=1 compile"},
		{name: "gradle wrapper", tool: ToolGradle, wrapper: "gradlew", exec: stub("", nil), wantArgs: "--console=plain classes", wantCmd: "./gradlew --console=plain classes"},
		{name: "gradle on PATH with properties", tool: ToolGradle, onPath: "gradle", cond: Conditions{Properties: map[string]string{"x": "y"}},
			exec: stub("", nil), wantExe: "PATH", wantArgs: "--console=plain -Px=y classes", wantCmd: "gradle --console=plain -Px=y classes"},
		{name: "no tool", tool: ToolMaven, exec: stub("", nil), wantCmd: "mvn -B compile", wantKind: KindToolchainAbsent, wantInLog: []string{"no ./mvnw and no mvn on PATH"}},
		{name: "maven failure keeps the compiler error and the goal, not the footer", tool: ToolMaven, onPath: "mvn",
			exec: stub(mavenFailure, errors.New("exit status 1")), wantExe: "PATH", wantArgs: "-B compile", wantCmd: "mvn -B compile", wantKind: KindToolFailed,
			wantInLog: []string{"App.java:[3,1] ';' expected", "Failed to execute goal"}, wantNotLog: []string{"Help 1", "full stack trace"}},
		{name: "gradle failure keeps what went wrong", tool: ToolGradle, wrapper: "gradlew",
			exec:     stub("> Task :compileJava FAILED\n\nFAILURE: Build failed with an exception.\n\n* What went wrong:\nExecution failed for task ':compileJava'.\n> Compilation failed\n\n* Try:\n> Run with --stacktrace\n", errors.New("exit status 1")),
			wantArgs: "--console=plain classes", wantCmd: "./gradlew --console=plain classes", wantKind: KindToolFailed,
			wantInLog: []string{"Execution failed for task ':compileJava'", "Compilation failed"}, wantNotLog: []string{"stacktrace", "FAILURE: Build failed"}},
		{name: "missing Java is toolchain_absent", tool: ToolMaven, onPath: "mvn",
			exec: stub("The JAVA_HOME environment variable is not defined correctly\n", errors.New("exit status 1")), wantExe: "PATH", wantArgs: "-B compile", wantCmd: "mvn -B compile", wantKind: KindToolchainAbsent},
		{name: "long output keeps its beginning and its end", tool: ToolMaven, onPath: "mvn",
			exec:    stub("[ERROR] FIRSTCAUSE\n"+strings.Repeat("[ERROR] filler line of output\n", 400)+"[ERROR] LASTCAUSE\n", errors.New("exit status 1")),
			wantExe: "PATH", wantArgs: "-B compile", wantCmd: "mvn -B compile", wantKind: KindToolFailed, wantInLog: []string{"FIRSTCAUSE", "LASTCAUSE"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotExe, gotArgs, gotDir = "", nil, ""
			dir, bin := t.TempDir(), t.TempDir()
			if tc.wrapper != "" {
				exe(t, filepath.Join(dir, tc.wrapper))
			}
			if tc.onPath != "" {
				exe(t, filepath.Join(bin, tc.onPath))
			}
			cmd, f := Compile(context.Background(), CompileRequest{Dir: dir, Tool: tc.tool, Conditions: tc.cond, Env: []string{"PATH=" + bin}, Exec: tc.exec})
			if cmd != tc.wantCmd {
				t.Errorf("command = %q, want %q", cmd, tc.wantCmd)
			}
			if tc.wantKind == "" {
				if f != nil {
					t.Fatalf("failure %v", f)
				}
			} else {
				if f == nil || f.Kind != tc.wantKind {
					t.Fatalf("failure = %+v, want kind %s", f, tc.wantKind)
				}
				for _, s := range tc.wantInLog {
					if !strings.Contains(f.Log, s) {
						t.Errorf("cause %q lacks %q", f.Log, s)
					}
				}
				for _, s := range tc.wantNotLog {
					if strings.Contains(f.Log, s) {
						t.Errorf("cause %q holds %q", f.Log, s)
					}
				}
				if len(f.Log) > compileCauseMax+10 {
					t.Errorf("cause is %d bytes", len(f.Log))
				}
			}
			if tc.name == "no tool" && gotExe != "" {
				t.Errorf("ran %s with no tool", gotExe)
			}
			if tc.wantArgs == "" {
				return
			}
			if strings.Join(gotArgs, " ") != tc.wantArgs {
				t.Errorf("argv = %q, want %q", strings.Join(gotArgs, " "), tc.wantArgs)
			}
			want := filepath.Join(dir, tc.wrapper)
			if tc.wantExe == "PATH" {
				want = filepath.Join(bin, tc.onPath)
			}
			if gotExe != want {
				t.Errorf("ran %s, want %s", gotExe, want)
			}
			if gotDir != dir {
				t.Errorf("ran in %s, want %s", gotDir, dir)
			}
		})
	}
}

func TestCompileTimeout(t *testing.T) {
	dir, bin := t.TempDir(), t.TempDir()
	exe(t, filepath.Join(bin, "mvn"))
	start := time.Now()
	cmd, f := Compile(context.Background(), CompileRequest{
		Dir: dir, Tool: ToolMaven, Env: []string{"PATH=" + bin}, Timeout: 30 * time.Millisecond,
		Exec: func(ctx context.Context, _ string, _ []string, _ string, _ []string) ([]byte, error) {
			<-ctx.Done()
			return []byte("[ERROR] Downloading from central\n"), ctx.Err()
		},
	})
	if time.Since(start) > 5*time.Second {
		t.Fatal("the time limit was not honoured")
	}
	if f == nil || f.Kind != KindToolFailed || !strings.Contains(f.Log, "time limit") || !strings.Contains(f.Log, "Downloading from central") {
		t.Fatalf("failure = %+v", f)
	}
	if cmd != "mvn -B compile" {
		t.Errorf("command = %q", cmd)
	}
}

func TestCompileCanceled(t *testing.T) {
	dir, bin := t.TempDir(), t.TempDir()
	exe(t, filepath.Join(bin, "mvn"))
	ctx, cancel := context.WithCancel(context.Background())
	_, f := Compile(ctx, CompileRequest{
		Dir: dir, Tool: ToolMaven, Env: []string{"PATH=" + bin}, Timeout: time.Hour,
		Exec: func(ctx context.Context, _ string, _ []string, _ string, _ []string) ([]byte, error) {
			cancel()
			<-ctx.Done()
			return []byte("[ERROR] Downloading from central\n"), ctx.Err()
		},
	})
	if f == nil || f.Kind != KindToolFailed || strings.Contains(f.Log, "time limit") || !strings.Contains(f.Log, "canceled") || !strings.Contains(f.Log, "Downloading from central") {
		t.Fatalf("failure = %+v", f)
	}
}

func TestCompileCommand(t *testing.T) {
	dir := t.TempDir()
	if got := CompileCommand(dir, ToolMaven, Conditions{}); got != "mvn -B compile" {
		t.Errorf("no wrapper: %q", got)
	}
	exe(t, filepath.Join(dir, "mvnw"))
	if got := CompileCommand(dir, ToolMaven, Conditions{}); got != "./mvnw -B compile" {
		t.Errorf("wrapper: %q", got)
	}
}
