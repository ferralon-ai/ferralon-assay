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

func TestParseFile_AnnotationTypeBody(t *testing.T) {
	// An annotation type is skipped (declared partiality) unless its body provably
	// holds no executable code. Accepted bodies are an allow-list: element and
	// constant declarations whose values are literals, class literals, enum
	// constants, annotations, or arrays of those.
	tests := []struct {
		name        string
		body        string
		wantSkipped bool
	}{
		{"petclinic constraint shape", `
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = PetAgeValidator.class)
public @interface PetAgeValidation {
    String message() default "Pet age is invalid";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}`, false},
		{"empty body", `@interface Marker {}`, false},
		{"stray semicolons", `@interface Marker { ; ; }`, false},
		{"literals of every kind", `@interface A {
    int i() default -1;
    long l() default 1_000L;
    double d() default 1.5e-3;
    int h() default 0xE;
    char c() default 'x';
    boolean b() default true;
    String s() default "a\"b";
    String t() default """
        block""";
}`, false},
		{"class literal and array class literal", `@interface A {
    Class<?> c() default Object.class;
    Class<?>[] cs() default {String.class, int[].class, java.util.Map.class};
}`, false},
		{"enum constants and trailing comma", `@interface A {
    Level l() default Level.HIGH;
    Level[] ls() default {Level.LOW, HIGH,};
}`, false},
		{"annotation values", `@interface A {
    Inner a() default @Inner;
    Inner b() default @Inner(x = 1, y = {"p", "q"});
    Inner[] c() default {@Inner(2), @pkg.Inner};
}`, false},
		{"annotated and modified elements", `@interface A {
    @AliasFor("value") String name() default "";
    public abstract String other();
}`, false},
		{"literal constants", `@interface A {
    int MAX = 5;
    String NAME = "x";
    Class<?> TYPE = Foo.class;
    Level LEVEL = Level.HIGH;
    public static final int[] XS = {1, 2};
    Other O = @Other(1);
}`, false},
		{"element without default", `@interface A { String value(); }`, false},

		{"nested class", `@interface A { String v(); class Holder { int x; } }`, true},
		{"nested enum", `@interface A { enum Mode { ON, OFF } Mode m() default Mode.ON; }`, true},
		{"nested interface", `@interface A { interface Callback { void run(); } }`, true},
		{"nested record", `@interface A { record R(int x) {} }`, true},
		{"nested annotation type", `@interface A { @interface B { String v(); } }`, true},
		{"static initializer block", `@interface A { int X = 1; static { init(); } }`, true},
		{"method with body", `@interface A { String v() { return ""; } }`, true},
		{"constant from method invocation", `@interface A { int X = Foo.compute(); }`, true},
		{"unqualified invocation constant", `@interface A { int X = compute(); }`, true},
		{"default from method invocation", `@interface A { String v() default Foo.bar(); }`, true},
		{"default is a code block", `@interface A { String[] v() default { foo(); }; }`, true},
		{"new expression constant", `@interface A { Object O = new Object(); }`, true},
		{"new array default", `@interface A { int[] v() default new int[] {1}; }`, true},
		{"lambda constant", `@interface A { Runnable R = () -> {}; }`, true},
		{"lambda without parens", `@interface A { Fn F = x -> x; }`, true},
		{"binary expression constant", `@interface A { int X = 1 + 2; }`, true},
		{"ternary default", `@interface A { int v() default B ? 1 : 2; }`, true},
		{"invocation inside annotation value", `@interface A { Inner i() default @Inner(x = Foo.f()); }`, true},
		{"element with parameters", `@interface A { String v(int x); }`, true},
		{"multiple declarators", `@interface A { int X = 1, Y = 2; }`, true},
		{"constant without initializer", `@interface A { int X; }`, true},
		{"unbalanced braces", `@interface A { String v() default "x";`, true},
		{"unbalanced array default", `@interface A { String[] v() default {"a"; }`, true},
		{"eof inside header", `@interface A`, true},
		{"header without body", `@interface A;`, true},
		{"header is not a bare name", `@interface A; int X = 1; }`, true},
		{"declaration missing its terminator", `@interface A { String v() default "x" int y = 1; }`, true},
		{"element parens never close", `@interface A { String v(;; }`, true},
		{"empty type and name", `@interface A { (); }`, true},
		{"class as a type word", `@interface A { class X = 1; }`, true},
		{"enum as a type word", `@interface A { enum X = 1; }`, true},
		{"interface as a type word", `@interface A { interface X = 1; }`, true},
		{"record as a type word", `@interface A { record X = 1; }`, true},
		{"new as a type word", `@interface A { new X = 1; }`, true},
		{"reserved word as a name", `@interface A { int new = 1; }`, true},
		{"nested annotation type header", `@interface A { @interface String v(); }`, true},
		{"annotation arguments run together", `@interface A { Inner i() default @Inner(1 2); }`, true},
		{"array values run together", `@interface A { Level[] ls() default {A B}; }`, true},
		{"new as a value", `@interface A { int X = new; }`, true},
		{"new as a selected member", `@interface A { int X = Foo.new; }`, true},
		{"negated name", `@interface A { int X = -Y; }`, true},
		{"qualifier with no member", `@interface A { Foo.[] X = 1; }`, true},
		{"generic with code", `@interface A { Map<String, Foo.bar()> m(); }`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pr := parseFile("package p;\n" + tt.body + "\n")
			if pr.skipped != tt.wantSkipped {
				t.Errorf("skipped = %v, want %v", pr.skipped, tt.wantSkipped)
			}
			if got := declNames(pr, kindMethod); !tt.wantSkipped && len(got) != 0 {
				t.Errorf("element names must stay out of decls, got methods %v", got)
			}
		})
	}
}

func TestParseFile_AnnotationTypeBesideClass(t *testing.T) {
	// The annotation type is consumed whole when inert, so the class around and
	// after it parses exactly as it would without the annotation type.
	srcs := map[string]string{
		"annotation then class": `
package p;
@interface Marker { String v() default "x"; Class<?>[] g() default {}; }
public class Service {
    private int count;
    public void run() { }
}`,
		"class then annotation": `
package p;
public class Service {
    private int count;
    public void run() { }
}
@interface Marker { String v() default "x"; }`,
		"annotation nested in class": `
package p;
public class Service {
    @interface Marker { String v() default "x"; }
    private int count;
    public void run() { }
}`,
	}
	for name, src := range srcs {
		t.Run(name, func(t *testing.T) {
			pr := parseFile(src)
			if pr.skipped {
				t.Error("an inert annotation type must not mark the file skipped")
			}
			if !contains(declNames(pr, kindType), "Service") {
				t.Errorf("expected type Service, got %v", declNames(pr, kindType))
			}
			if !contains(declNames(pr, kindMethod), "run") {
				t.Errorf("expected method run, got %v", declNames(pr, kindMethod))
			}
			if !contains(declNames(pr, kindField), "count") {
				t.Errorf("expected field count, got %v", declNames(pr, kindField))
			}
			if got := declNames(pr, kindType); contains(got, "Marker") {
				t.Errorf("annotation type must not be a decl, got %v", got)
			}
		})
	}
}

func TestParseFile_AnnotationTypeWithCodeBesideClass(t *testing.T) {
	// A rejected annotation type declares partiality; the class parses as before.
	src := `
package p;
@interface Marker { int X = Foo.compute(); }
public class Service {
    public void run() { }
}`
	pr := parseFile(src)
	if !pr.skipped {
		t.Error("an annotation type holding a method invocation must declare partiality")
	}
	if !contains(declNames(pr, kindType), "Service") {
		t.Errorf("expected type Service, got %v", declNames(pr, kindType))
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
