package javaanalysis

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// A class literal is an expression: "class" after a '.' can never start a type header,
// so it must neither skip the file nor hide the declarations around it.
func TestParseFile_ClassLiteralsAreExpressions(t *testing.T) {
	for _, tc := range []struct {
		name, body string
	}{
		{"return", "return B.class;"},
		{"arguments", "foo(A.class, int[].class);"},
		{"getClass", "Object c = x.getClass();"},
		{"primitive", "Class<?> c = int.class;"},
		{"qualified", "Class<?> c = java.util.Map.Entry.class;"},
		{"array of qualified", "Class<?> c = java.lang.String[][].class;"},
		{"chained", "String n = B.class.getName();"},
		{"line break", "Class<?> c = B\n        .class;"},
		{"void", "Class<?> c = void.class;"},
		{"field named record", "if (x.record instanceof B) { foo(1); }"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "package p;\npublic class Holder {\n  Object field;\n  Object m(Object x) {\n    " + tc.body + "\n    return null;\n  }\n  void after() {}\n}\n"
			pr := parseFile(src)
			if pr.skipped {
				t.Fatalf("class literal skipped the file:\n%s", src)
			}
			methods := declNames(pr, kindMethod)
			for _, want := range []string{"m", "after"} {
				if !contains(methods, want) {
					t.Errorf("method %q missing after the class literal; methods=%v", want, methods)
				}
			}
			if types := declNames(pr, kindType); len(types) != 1 || types[0] != "Holder" {
				t.Errorf("types = %v, want [Holder]", types)
			}
		})
	}
}

// A local class inside a method body is still a declaration.
func TestParseFile_LocalClassStillDeclares(t *testing.T) {
	pr := parseFile("package p;\nclass Outer {\n  void m() {\n    class Local { void inner() {} }\n    Object o = Local.class;\n  }\n}\n")
	if pr.skipped {
		t.Fatal("local class plus class literal skipped the file")
	}
	if types := declNames(pr, kindType); !contains(types, "Local") {
		t.Errorf("local class not declared: %v", types)
	}
}

// End to end: a file full of class literals indexes completely.
func TestIndexSymbols_ClassLiteralsKeepIndexComplete(t *testing.T) {
	dir := t.TempDir()
	src := `package com.acme;
public class Registry {
  public Class<?> kind() { return Registry.class; }
  public void register() { bind(String.class, int[].class); Object o = this.getClass(); }
  private void bind(Class<?> a, Class<?> b) {}
}
`
	path := filepath.Join(dir, "src", "main", "java", "com", "acme", "Registry.java")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Partiality.Complete {
		t.Fatalf("want a complete index, got %+v", res.Partiality)
	}
	names := displayNames(res.Symbols)
	for _, want := range []string{"Registry.kind()", "Registry.register()", "Registry.bind(2)"} {
		if !contains(names, want) {
			t.Errorf("symbol %q missing: %v", want, names)
		}
	}
}

// The call and bean scanners share the declaration scanner's rule: a type keyword after a
// '.' is a member, never a header. "record" is a legal field name, and "x.record instanceof
// T" would otherwise read as a type named "instanceof" whose body is the if-block.
var memberNamedLikeTypeKeyword = []struct{ name, body string }{
	{"record field instanceof", "if (this.record instanceof Foo) { handle(1); }"},
	{"record field pattern", "if (h.record instanceof Foo f) { handle(1); }"},
	{"record field, nested block", "if (this.record instanceof Foo) { synchronized (h) { handle(1); } }"},
	{"class literal", "Object o = Foo.class; handle(1);"},
}

func TestParseCalls_MemberNamedLikeTypeKeyword(t *testing.T) {
	for _, tc := range memberNamedLikeTypeKeyword {
		t.Run(tc.name, func(t *testing.T) {
			src := "package p;\nclass Holder {\n  void m(Object h) {\n    " + tc.body + "\n  }\n}\n"
			calls, _ := parseCallsAndIngresses([]rune(stripJava(src)), []rune(src))
			found := false
			for _, c := range calls {
				if c.calleeName == "handle" && c.calleeArity == 1 {
					found = true
					if c.callerName != "m" || c.callerArity != 1 || len(c.callerEnclosing) != 1 || c.callerEnclosing[0] != "Holder" {
						t.Errorf("handle/1 attributed to %v.%s/%d, want Holder.m/1", c.callerEnclosing, c.callerName, c.callerArity)
					}
				}
			}
			if !found {
				t.Errorf("call handle/1 missing; calls=%+v", calls)
			}
		})
	}
}

func TestScanSourceClasses_MemberNamedLikeTypeKeyword(t *testing.T) {
	for _, tc := range memberNamedLikeTypeKeyword {
		t.Run(tc.name, func(t *testing.T) {
			src := "package p;\nclass Holder {\n  void m(Object h) {\n    " + tc.body + "\n  }\n}\n"
			classes := scanSrc("p", src)
			var names []string
			for _, c := range classes {
				names = append(names, c.name)
			}
			if len(names) != 1 || names[0] != "Holder" {
				t.Errorf("classes = %v, want [Holder]", names)
			}
		})
	}
}
