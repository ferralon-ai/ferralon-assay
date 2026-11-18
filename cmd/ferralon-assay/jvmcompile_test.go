package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
)

const appJava = "package p;\npublic class App { }\n"

func put(t *testing.T, dir, rel, body string, mod time.Time) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if !mod.IsZero() {
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
}

func TestJVMOutputGap(t *testing.T) {
	old, now := time.Now().Add(-time.Hour), time.Now()
	tests := []struct {
		name  string
		files map[string]time.Time // path -> mtime, body is appJava or "x"
		want  string               // substring of the gap; "" for none
	}{
		{"no sources", map[string]time.Time{"pom.xml": now}, ""},
		{"sources, no output", map[string]time.Time{"src/main/java/p/App.java": now}, "no compiled main classes for the repository root"},
		{"sources and current output", map[string]time.Time{"src/main/java/p/App.java": old, "target/classes/p/App.class": now}, ""},
		{"gradle output", map[string]time.Time{"src/main/java/p/App.java": old, "build/classes/java/main/p/App.class": now}, ""},
		{"output older than source", map[string]time.Time{"src/main/java/p/App.java": now, "target/classes/p/App.class": old}, "class file for p/App.java is older than its source"},
		{"a type with no class", map[string]time.Time{"src/main/java/p/App.java": old, "src/main/java/p/B.java": old, "target/classes/p/App.class": now}, "no class file for p/B.java"},
		{"a file naming no type of its own is not held to a class", map[string]time.Time{"src/main/java/p/App.java": old, "src/main/java/p/package-info.java": old, "target/classes/p/App.class": now}, ""},
		{"test sources are not main", map[string]time.Time{"src/test/java/p/T.java": now}, ""},
		{"module without output", map[string]time.Time{"a/src/main/java/p/App.java": old, "a/target/classes/p/App.class": now, "b/src/main/java/p/App.java": old}, "no compiled main classes for b"},
		{"kotlin sources, no output", map[string]time.Time{"src/main/kotlin/p/App.kt": now}, "no compiled main classes"},
		{"kotlin sources with output", map[string]time.Time{"src/main/kotlin/p/App.kt": old, "build/classes/kotlin/main/p/AppKt.class": now}, ""},
		{"fixture project under test resources is not held to output", map[string]time.Time{"src/main/java/p/App.java": old, "target/classes/p/App.class": now, "src/test/resources/fx/src/main/java/p/F.java": now}, ""},
		{"maven-plugin it project is not held to output", map[string]time.Time{"src/main/java/p/App.java": old, "target/classes/p/App.class": now, "src/it/basic/src/main/java/p/I.java": now}, ""},
		{"integration test source set is not held to output", map[string]time.Time{"src/main/java/p/App.java": old, "target/classes/p/App.class": now, "src/integrationTest/fx/src/main/kotlin/p/K.kt": now}, ""},
		{"build output dirs are not source", map[string]time.Time{"target/generated/src/main/java/p/App.java": now}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for rel, mod := range tc.files {
				body := "x"
				if strings.HasSuffix(rel, ".java") && !strings.HasSuffix(rel, "package-info.java") {
					body = "package p;\npublic class " + strings.TrimSuffix(filepath.Base(rel), ".java") + " { }\n"
				}
				put(t, dir, rel, body, mod)
			}
			got := jvmOutputGap(dir)
			if tc.want == "" && got != "" || !strings.Contains(got, tc.want) {
				t.Errorf("gap = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCompileJVM(t *testing.T) {
	failure := &buildgraph.Failure{Kind: buildgraph.KindToolFailed, Detail: "compile", Log: "App.java:[3,1] error: ';' expected\nFailed to execute goal compiler:compile"}
	tests := []struct {
		name      string
		build     map[string]string // files at the root
		classes   bool              // class output already present
		mode      string
		stated    string
		compile   func(dir string, req buildgraph.CompileRequest) (string, *buildgraph.Failure)
		wantCalls []string
		wantNote  []string // substrings; nil means the note is empty
	}{
		{
			name:  "output absent, maven",
			build: map[string]string{"pom.xml": "x"},
			compile: func(dir string, req buildgraph.CompileRequest) (string, *buildgraph.Failure) {
				put(t, dir, "target/classes/p/App.class", "x", time.Now().Add(time.Minute))
				return "mvn -B compile", nil
			},
			wantCalls: []string{"maven"},
		},
		{
			name:      "output present, not compiled",
			build:     map[string]string{"pom.xml": "x"},
			classes:   true,
			wantCalls: nil,
		},
		{
			name:      "gradle",
			build:     map[string]string{"build.gradle": "x"},
			compile:   func(string, buildgraph.CompileRequest) (string, *buildgraph.Failure) { return "./gradlew classes", nil },
			wantCalls: []string{"gradle"},
			wantNote:  []string{"`./gradlew classes` ran and the output still does not cover the sources"},
		},
		{
			name:  "failure names command and cause",
			build: map[string]string{"pom.xml": "x"},
			compile: func(string, buildgraph.CompileRequest) (string, *buildgraph.Failure) {
				return "./mvnw -B compile", failure
			},
			wantCalls: []string{"maven"},
			wantNote:  []string{"no compiled main classes", "`./mvnw -B compile` failed (tool_failed:compile:", "error: ';' expected", "Failed to execute goal compiler:compile"},
		},
		{
			name:  "toolchain absent",
			build: map[string]string{"pom.xml": "x"},
			compile: func(string, buildgraph.CompileRequest) (string, *buildgraph.Failure) {
				return "mvn -B compile", &buildgraph.Failure{Kind: buildgraph.KindToolchainAbsent, Log: "no ./mvnw and no mvn on PATH"}
			},
			wantCalls: []string{"maven"},
			wantNote:  []string{"`mvn -B compile` failed (toolchain_absent: no ./mvnw and no mvn on PATH)"},
		},
		{
			name:   "stated tool wins over detection",
			build:  map[string]string{"pom.xml": "x", "build.gradle": "x"},
			stated: buildgraph.ToolGradle,
			compile: func(string, buildgraph.CompileRequest) (string, *buildgraph.Failure) {
				return "gradle classes", failure
			},
			wantCalls: []string{"gradle"},
			wantNote:  []string{"`gradle classes` failed"},
		},
		{
			name:      "both tools, the second runs when the first leaves a gap",
			build:     map[string]string{"pom.xml": "x", "build.gradle": "x"},
			compile:   func(string, buildgraph.CompileRequest) (string, *buildgraph.Failure) { return "x", failure },
			wantCalls: []string{"maven", "gradle"},
			wantNote:  []string{"failed", "failed"},
		},
		{
			name:      "a graph file means no build tool run, and the note says what to run",
			build:     map[string]string{"pom.xml": "x"},
			mode:      "graph.json",
			wantCalls: nil,
			wantNote:  []string{"this run does not run the build tool, so run `mvn -B compile` first"},
		},
		{
			name:      "build graph off means no build tool run",
			build:     map[string]string{"build.gradle": "x"},
			mode:      buildGraphOff,
			wantCalls: nil,
			wantNote:  []string{"run `gradle --console=plain classes` first"},
		},
		{
			name:      "no build tool files",
			build:     map[string]string{},
			wantCalls: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			now := time.Now()
			put(t, dir, "src/main/java/p/App.java", appJava, now.Add(-time.Hour))
			if tc.classes {
				put(t, dir, "target/classes/p/App.class", "x", now)
			}
			for f, b := range tc.build {
				put(t, dir, f, b, time.Time{})
			}
			var calls []string
			prev := compileTool
			defer func() { compileTool = prev }()
			compileTool = func(_ context.Context, req buildgraph.CompileRequest) (string, *buildgraph.Failure) {
				calls = append(calls, req.Tool)
				if req.Timeout != jvmCompileTimeout || req.Dir != dir {
					t.Errorf("request = %+v", req)
				}
				return tc.compile(dir, req)
			}
			mode := tc.mode
			if mode == "" {
				mode = buildGraphAuto
			}
			var w bytes.Buffer
			note := compileJVM(context.Background(), dir, graphRequest{mode: mode, tool: tc.stated}, &w)
			if strings.Join(calls, ",") != strings.Join(tc.wantCalls, ",") {
				t.Errorf("compiled with %v, want %v", calls, tc.wantCalls)
			}
			if tc.wantNote == nil && note != "" {
				t.Errorf("note = %q, want none", note)
			}
			for _, s := range tc.wantNote {
				if !strings.Contains(note, s) {
					t.Errorf("note %q lacks %q", note, s)
				}
			}
		})
	}
}
