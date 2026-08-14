package checkout

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveVendored_OK(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := ResolveVendored(dir)
	if err != nil {
		t.Fatalf("ResolveVendored: %v", err)
	}
	prim := plan.Primary()
	got, lang := prim.Root, prim.Language
	if !filepath.IsAbs(got) {
		t.Fatalf("want absolute path, got %q", got)
	}
	want, _ := filepath.Abs(dir)
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if lang != LangGo {
		t.Fatalf("a go.mod tree must resolve as %q, got %q", LangGo, lang)
	}
}

// TestResolveVendored_JavaNoGoMod is the reproduce-first guard for the live-gate failure:
// a Java repro (NO go.mod, with .java sources) was rejected by the Go-centric go.mod stat,
// aborting codebase_inventory. After the language-aware fix it resolves and reports "java".
// Before the fix this test fails ("has no go.mod"); after, it passes.
func TestResolveVendored_JavaNoGoMod(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src", "main", "java", "com", "example", "web")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "UrlFetcher.java"),
		[]byte("package com.example.web;\npublic class UrlFetcher {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pom.xml"),
		[]byte("<project></project>\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	plan, err := ResolveVendored(dir)
	if err != nil {
		t.Fatalf("ResolveVendored on a Java repro must succeed (no go.mod required), got: %v", err)
	}
	prim := plan.Primary()
	got, lang := prim.Root, prim.Language
	if want, _ := filepath.Abs(dir); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if lang != LangJava {
		t.Fatalf("a .java source tree must resolve as %q, got %q", LangJava, lang)
	}
}

// TestResolveVendored_JSNoGoMod is the JS Increment-1 analog of the Java guard: a JS
// repro (NO go.mod, NO .java, with .js/.ts sources) must check out and report "js" so
// codebase_inventory routes it to the JS plugin instead of aborting. It also confirms
// the precedence chain (go.mod → java → js) does not misclassify a JS-only tree.
func TestResolveVendored_JSNoGoMod(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "app.js"),
		[]byte("function handler(req, res) { res.end('ok'); }\nmodule.exports = { handler };\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"),
		[]byte("{\"name\":\"repro\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	plan, err := ResolveVendored(dir)
	if err != nil {
		t.Fatalf("ResolveVendored on a JS repro must succeed (no go.mod required), got: %v", err)
	}
	prim := plan.Primary()
	got, lang := prim.Root, prim.Language
	if want, _ := filepath.Abs(dir); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if lang != LangJS {
		t.Fatalf("a .js source tree must resolve as %q, got %q", LangJS, lang)
	}
}

// TestResolveVendored_TypeScriptTree confirms a .ts tree (no go.mod, no .java) also
// resolves as JS, and that a .d.ts declaration-only file does NOT count as source.
func TestResolveVendored_TypeScriptTree(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "types.d.ts"),
		[]byte("export declare function f(): void;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// With only a .d.ts the tree is unrecognized (declaration-only, no bodies).
	if _, err := ResolveVendored(dir); err == nil {
		t.Fatal("a .d.ts-only tree must NOT be recognized as a JS source tree")
	}
	if err := os.WriteFile(filepath.Join(dir, "route.ts"),
		[]byte("export default function handler(req: any, res: any) { res.end(); }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := ResolveVendored(dir)
	if err != nil {
		t.Fatalf("ResolveVendored on a .ts tree must succeed: %v", err)
	}
	lang := plan.Primary().Language
	if lang != LangJS {
		t.Fatalf("a .ts source tree must resolve as %q, got %q", LangJS, lang)
	}
}

func TestResolveVendored_MissingPath(t *testing.T) {
	if _, err := ResolveVendored(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("want error for absent path, got nil")
	}
}

// TestResolveVendored_UnrecognizedTree confirms a tree that is NEITHER a Go module NOR a
// Java source tree is still rejected (inv.5: no silent half-checkout of an inventory-less tree).
func TestResolveVendored_UnrecognizedTree(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveVendored(dir); err == nil {
		t.Fatal("want error for a tree with no recognized source markers, got nil")
	}
}

func TestResolveVendored_EmptyPath(t *testing.T) {
	if _, err := ResolveVendored(""); err == nil {
		t.Fatal("want error for empty path, got nil")
	}
}
