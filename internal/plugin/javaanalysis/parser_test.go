package javaanalysis

import (
	"strings"
	"testing"
)

// declNames returns the names of declarations of the given kind from a parse.
func declNames(pr parseResult, kind declKind) []string {
	var out []string
	for _, d := range pr.decls {
		if d.kind == kind {
			out = append(out, d.name)
		}
	}
	return out
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func TestParseFile_ParsesPackage(t *testing.T) {
	pr := parseFile("package com.example.foo;\nclass A {}\n")
	if pr.pkg != "com.example.foo" {
		t.Errorf("pkg = %q, want com.example.foo", pr.pkg)
	}
}

func TestParseFile_DefaultPackageIsEmpty(t *testing.T) {
	pr := parseFile("class A {}\n")
	if pr.pkg != "" {
		t.Errorf("pkg = %q, want empty (default package)", pr.pkg)
	}
}

func TestParseFile_CommentsAndStringsDoNotCreateDecls(t *testing.T) {
	src := `
package p;
// class Ghost { void ghost(); }
/* interface AlsoGhost { int x; } */
class Real {
    String s = "class NotAType { void notAMethod() {} }";
    char c = '}';
    void method() {
        String inner = "} class StillGhost {";
    }
}
`
	pr := parseFile(src)
	types := declNames(pr, kindType)
	if contains(types, "Ghost") || contains(types, "AlsoGhost") || contains(types, "NotAType") || contains(types, "StillGhost") {
		t.Errorf("a comment/string literal produced a phantom type: %v", types)
	}
	if !contains(types, "Real") {
		t.Errorf("expected the real type Real, got %v", types)
	}
	methods := declNames(pr, kindMethod)
	if contains(methods, "notAMethod") {
		t.Errorf("string literal produced a phantom method: %v", methods)
	}
	if !contains(methods, "method") {
		t.Errorf("expected the real method 'method', got %v", methods)
	}
}

func TestParseFile_GenericsAndExtendsClauseSkipped(t *testing.T) {
	src := `
package p;
class Box<T extends Comparable<T>> extends Base implements Iface, Other {
    T value;
    T get() { return value; }
}
`
	pr := parseFile(src)
	if !contains(declNames(pr, kindType), "Box") {
		t.Errorf("expected type Box, got %v", declNames(pr, kindType))
	}
	if !contains(declNames(pr, kindMethod), "get") {
		t.Errorf("expected method get, got %v", declNames(pr, kindMethod))
	}
	if !contains(declNames(pr, kindField), "value") {
		t.Errorf("expected field value, got %v", declNames(pr, kindField))
	}
}

func TestParseFile_AnnotationTypeDeclaresPartiality(t *testing.T) {
	// An annotation type "@interface" is a construct this engine does not model
	// (the '@' precedes the 'interface' keyword and its members use a different
	// grammar). It must be flagged so the index declares partiality.
	src := `
package p;
public @interface MyAnno {
    String value() default "x";
}
`
	pr := parseFile(src)
	if !pr.skipped {
		t.Error("expected an @interface annotation type to set skipped=true (declared partiality)")
	}
}

func TestParseFile_NamedArgAnnotationDoesNotDropDeclarations(t *testing.T) {
	// Regression: a method annotation with an assignment-style argument
	// (@Scheduled(fixedRate = 60000), @Config(timeout = 30)) must be stepped over
	// as a unit. Before the member loop skipped the annotation group, its
	// "name = value" arg parsed as a field whose skip-to-';' swallowed the real
	// method declaration that followed — zeroing the file's method decls (and thus
	// its call graph). Both methods must still be declared here.
	src := `
package p;
class Jobs {
    @Scheduled(fixedRate = 60000)
    void reconcile() { sink(); }
    @Config(timeout = 30, retries = 3)
    void refresh() {}
    void sink() {}
}
`
	pr := parseFile(src)
	for _, want := range []string{"reconcile", "refresh", "sink"} {
		if !contains(declNames(pr, kindMethod), want) {
			t.Errorf("named-arg annotation dropped method %q; got methods %v", want, declNames(pr, kindMethod))
		}
	}
}

func TestStripJava_PreservesNewlines(t *testing.T) {
	src := "a\n// comment\nb\n/* multi\nline */\nc"
	got := stripJava(src)
	if strings.Count(got, "\n") != strings.Count(src, "\n") {
		t.Errorf("stripJava changed newline count: %q", got)
	}
	if strings.Contains(got, "comment") || strings.Contains(got, "multi") {
		t.Errorf("stripJava left comment content: %q", got)
	}
}
