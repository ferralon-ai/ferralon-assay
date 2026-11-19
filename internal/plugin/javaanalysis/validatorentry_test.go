package javaanalysis

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/jvmingress"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// validatorRooted returns the "Class.method" names of the constraint_validator ingresses the
// lexical pass reports for a source tree, and checks each is also a call-graph root.
func validatorRooted(t *testing.T, files map[string]string) []string {
	t.Helper()
	dir := writeProgram(t, files)
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	cg, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	roots := map[string]bool{}
	for _, r := range cg.Roots {
		roots[r.SCIP] = true
	}
	var got []string
	for _, in := range res.Ingresses {
		if in.Kind != jvmingress.KindConstraintValidator {
			t.Errorf("unexpected ingress kind %q for %s", in.Kind, in.Symbol.SCIP)
			continue
		}
		if !roots[in.Symbol.SCIP] {
			t.Errorf("ingress %s is not a call-graph root", in.Symbol.SCIP)
		}
		got = append(got, in.Symbol.SCIP)
	}
	sort.Strings(got)
	return got
}

func TestConstraintValidatorIngress_Lexical(t *testing.T) {
	id := func(class, method string, arity int) string {
		return methodSCIP("com.acme", []string{class}, method, arity)
	}
	nested := func(outer, class, method string, arity int) string {
		return methodSCIP("com.acme", []string{outer, class}, method, arity)
	}
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{
			name: "direct implementer, jakarta",
			files: map[string]string{"com/acme/V.java": `package com.acme;
import jakarta.validation.ConstraintValidator;
public class V implements ConstraintValidator<Ann, Integer> {
    public void initialize(Ann a) {}
    public boolean isValid(Integer v, Object ctx) { return v > 0; }
    public int other(int x) { return x; }
}`},
			want: []string{id("V", "initialize", 1), id("V", "isValid", 2)},
		},
		{
			name: "direct implementer, javax, fully qualified",
			files: map[string]string{"com/acme/V.java": `package com.acme;
public class V implements javax.validation.ConstraintValidator<Ann, String> {
    public boolean isValid(String v, Object ctx) { return true; }
}`},
			want: []string{id("V", "isValid", 2)},
		},
		{
			name: "abstract base chain",
			files: map[string]string{
				"com/acme/Base.java": `package com.acme;
import jakarta.validation.ConstraintValidator;
public abstract class Base<T> implements ConstraintValidator<Ann, T> {
    public void initialize(Ann a) {}
    public abstract boolean isValid(T v, Object ctx);
}`,
				"com/acme/Mid.java": `package com.acme;
public abstract class Mid extends Base<String> {}`,
				"com/acme/Leaf.java": `package com.acme;
public class Leaf extends Mid {
    public boolean isValid(String v, Object ctx) { return true; }
}`,
			},
			// Base.isValid is abstract (no marker); Base.initialize and Leaf.isValid are concrete.
			want: []string{id("Base", "initialize", 1), id("Leaf", "isValid", 2)},
		},
		{
			name: "validator nested in its own constraint annotation",
			files: map[string]string{"com/acme/Ann.java": `package com.acme;
import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
@Constraint(validatedBy = Ann.V.class)
public @interface Ann {
    class V implements ConstraintValidator<Ann, String> {
        public boolean isValid(String v, Object ctx) { return true; }
    }
}`},
			want: []string{nested("Ann", "V", "isValid", 2)},
		},
		{
			name: "interface extends",
			files: map[string]string{
				"com/acme/Checker.java": `package com.acme;
import jakarta.validation.ConstraintValidator;
public interface Checker extends ConstraintValidator<Ann, String> {}`,
				"com/acme/Impl.java": `package com.acme;
public class Impl implements Checker {
    public boolean isValid(String v, Object ctx) { return true; }
}`,
			},
			want: []string{id("Impl", "isValid", 2)},
		},
		{
			name: "dependency ancestor over-roots",
			files: map[string]string{"com/acme/V.java": `package com.acme;
import org.lib.AbstractLibValidator;
public class V extends AbstractLibValidator {
    public boolean isValid(Object v, Object ctx) { return true; }
    public void initialize(Object a) {}
}`},
			want: []string{id("V", "initialize", 1), id("V", "isValid", 2)},
		},
		{
			name: "nested validator",
			files: map[string]string{"com/acme/Outer.java": `package com.acme;
public class Outer {
    static class Inner implements jakarta.validation.ConstraintValidator<Ann, String> {
        public boolean isValid(String v, Object ctx) { return true; }
    }
}`},
			want: []string{nested("Outer", "Inner", "isValid", 2)},
		},
		{
			name: "unrelated class with isValid is not rooted",
			files: map[string]string{"com/acme/Plain.java": `package com.acme;
public class Plain {
    public boolean isValid(String v, Object ctx) { return true; }
    public void initialize(Object a) {}
}`},
			want: nil,
		},
		{
			name: "first-party and JDK ancestors only are not rooted",
			files: map[string]string{
				"com/acme/Base.java": `package com.acme;
public class Base implements java.io.Serializable {}`,
				"com/acme/Child.java": `package com.acme;
public class Child extends Base implements Comparable<Child> {
    public boolean isValid(String v, Object ctx) { return true; }
    public int compareTo(Child c) { return 0; }
}`,
			},
			want: nil,
		},
		{
			name: "test-source validator is not rooted",
			files: map[string]string{"src/test/java/com/acme/TV.java": `package com.acme;
public class TV implements jakarta.validation.ConstraintValidator<Ann, String> {
    public boolean isValid(String v, Object ctx) { return true; }
}`},
			want: nil,
		},
		{
			name: "test-source class with a library ancestor is not rooted",
			files: map[string]string{"src/test/java/com/acme/AppTest.java": `package com.acme;
public class AppTest extends junit.framework.TestCase { public void initialize() {} }`},
			want: nil,
		},
		{
			name: "local class is not rooted",
			files: map[string]string{"com/acme/P.java": `package com.acme;
public class P {
    void m() {
        class L implements jakarta.validation.ConstraintValidator<Ann, String> {
            public boolean isValid(String v, Object ctx) { return true; }
        }
    }
}`},
			want: nil,
		},
		{
			name: "enum validator",
			files: map[string]string{"com/acme/E.java": `package com.acme;
public enum E implements jakarta.validation.ConstraintValidator<Ann, String> {
    INSTANCE;
    public boolean isValid(String v, Object ctx) { return true; }
}`},
			want: []string{id("E", "isValid", 2)},
		},
		{
			name: "record validator",
			files: map[string]string{"com/acme/R.java": `package com.acme;
public record R(int n) implements jakarta.validation.ConstraintValidator<Ann, String> {
    public boolean isValid(String v, Object ctx) { return true; }
}`},
			want: []string{id("R", "isValid", 2)},
		},
		{
			name: "dependency base, helper-only override: nothing to root",
			files: map[string]string{"com/acme/X.java": `package com.acme;
public class X extends org.lib.AbstractLibValidator {
    protected boolean helper(String v) { return true; }
}`},
			want: nil,
		},
		{
			name: "first-party class named like the dependency base",
			files: map[string]string{
				"com/acme/AbstractLibValidator.java": `package com.acme;
public class AbstractLibValidator {}`,
				"com/acme/X.java": `package com.acme;
public class X extends AbstractLibValidator {
    protected boolean helper(String v) { return true; }
}`,
			},
			want: nil,
		},
		{
			name: "arity: RuntimeException subclass with initialize() is not rooted",
			files: map[string]string{"com/acme/X.java": `package com.acme;
public class X extends RuntimeException { public void initialize() {} }`},
			want: nil,
		},
		{
			name: "arity: InitializingBean with isValid() and static initialize()",
			files: map[string]string{"com/acme/C.java": `package com.acme;
public class C implements org.springframework.beans.factory.InitializingBean {
    private static void initialize() {}
    public boolean isValid() { return true; }
    public void initialize(int a, int b) {}
}`},
			want: nil,
		},
		{
			name: "arity: validator overloads of the wrong arity are not rooted",
			files: map[string]string{"com/acme/V.java": `package com.acme;
public class V implements jakarta.validation.ConstraintValidator<Ann, String> {
    public boolean isValid(String v) { return true; }
    public boolean isValid(String v, Object ctx) { return true; }
    public void initialize() {}
}`},
			want: []string{id("V", "isValid", 2)},
		},
		{
			name: "abstract-only validator declares nothing",
			files: map[string]string{
				"com/acme/Checker.java": `package com.acme;
import jakarta.validation.ConstraintValidator;
public interface Checker extends ConstraintValidator<Ann, String> {
    boolean isValid(String v, Object ctx);
    void initialize(Ann a);
}`,
				"com/acme/Base.java": `package com.acme;
public abstract class Base implements Checker {
    public abstract boolean isValid(String v, Object ctx);
}`,
			},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validatorRooted(t, tc.files)
			want := slices.Clone(tc.want)
			sort.Strings(want)
			if !slices.Equal(got, want) {
				t.Errorf("rooted = %q, want %q", got, want)
			}
		})
	}
}

const validatorSource = `package com.acme;
import jakarta.validation.ConstraintValidator;
public class PetAgeValidator implements ConstraintValidator<Object, Object> {
    public boolean isValid(Object v, Object ctx) { return true; }
}
`

// validatorMethodsCalling emits isValid(Object,Object)Z plus a bridge-free body.
func validatorMethodsCalling(code func(b *cpb) []byte) func(b *cpb) []xmethod {
	return func(b *cpb) []xmethod {
		return []xmethod{{"isValid", "(Ljava/lang/Object;Ljava/lang/Object;)Z", accPublic, code(b)}}
	}
}

// A validator that reaches the sink is a candidate path rooted at its isValid, and its
// source marker maps to the compiled method (no unmapped withholding).
func TestBytecodeReach_ConstraintValidatorIsAnIngress(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.source("src/main/java/com/acme/PetAgeValidator.java", validatorSource)
	a.class("target/classes", "com/acme/App", mainCalling(justReturn))
	a.classI("target/classes", "com/acme/PetAgeValidator", "java/lang/Object", []string{"jakarta/validation/ConstraintValidator"}, 0x0021, validatorMethodsCalling(callFetch))

	res := a.reach(netkitSinkID)
	if len(res.Paths) != 1 {
		t.Fatalf("want one path, got %+v (partiality %+v)", res.Paths, res.Partiality)
	}
	want := methodSCIP("com.acme", []string{"PetAgeValidator"}, "isValid", 2)
	if got := res.Paths[0].Ingress.SCIP; got != want {
		t.Errorf("ingress = %q, want %q", got, want)
	}
}

// An abstract isValid has no compiled counterpart to map. It must produce no marker: an
// unmapped marker withholds Searched for every sink in the run.
func TestBytecodeReach_AbstractValidatorDoesNotWithholdSearched(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.source("src/main/java/com/acme/Checker.java", `package com.acme;
public interface Checker extends jakarta.validation.ConstraintValidator<Object, Object> {
    boolean isValid(Object v, Object ctx);
}
`)
	a.source("src/main/java/com/acme/Base.java", `package com.acme;
public abstract class Base implements Checker {
    public abstract boolean isValid(Object v, Object ctx);
}
`)
	a.class("target/classes", "com/acme/App", mainCalling(justReturn))
	abstractIsValid := func(*cpb) []xmethod {
		return []xmethod{{"isValid", "(Ljava/lang/Object;Ljava/lang/Object;)Z", accPublicAbstract, nil}}
	}
	// The validation-api interface is left off the compiled Checker: with the jar absent, the
	// container-callback walk would withhold Searched for an unrelated reason.
	a.classI("target/classes", "com/acme/Checker", "java/lang/Object", nil, 0x0601, abstractIsValid)
	a.classI("target/classes", "com/acme/Base", "java/lang/Object", []string{"com/acme/Checker"}, 0x0421, abstractIsValid)

	res := a.reach(netkitSinkID)
	if !slices.Equal(res.Searched, []string{netkitSinkID}) {
		t.Fatalf("Searched = %v, partiality %+v", res.Searched, res.Partiality)
	}
	if hasReason(res.Partiality, plugin.PartialReasonReachabilityUndetermined) {
		t.Errorf("abstract-only validator left reachability_undetermined: %+v", res.Partiality)
	}
}

func pbVarint(v uint64) []byte {
	var b []byte
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func pbBytes(field int, payload []byte) []byte {
	out := pbVarint(uint64(field<<3 | wireBytes))
	out = append(out, pbVarint(uint64(len(payload)))...)
	return append(out, payload...)
}

func pbVarintField(field int, v uint64) []byte {
	return append(pbVarint(uint64(field<<3|wireVarint)), pbVarint(v)...)
}

// scipSym is one SymbolInformation: a symbol and the symbols it implements.
type scipSym struct {
	symbol string
	impl   []string
}

// scipIndexBytes encodes one document whose definition occurrences are the given method
// symbols (one per line) and whose SymbolInformation entries are syms.
func scipIndexBytes(syms []scipSym, methods ...string) []byte {
	return scipIndexBytesAt("", syms, methods...)
}

// scipIndexBytesAt is scipIndexBytes for a document with the given relative_path.
func scipIndexBytesAt(path string, syms []scipSym, methods ...string) []byte {
	var doc []byte
	if path != "" {
		doc = pbBytes(1, []byte(path))
	}
	for i, m := range methods {
		var occ []byte
		occ = append(occ, pbBytes(1, []byte{byte(i * 10), 4, 9})...)
		occ = append(occ, pbBytes(2, []byte(m))...)
		occ = append(occ, pbVarintField(3, uint64(scipRoleDefinition))...)
		doc = append(doc, pbBytes(2, occ)...)
	}
	for _, s := range syms {
		info := pbBytes(1, []byte(s.symbol))
		for _, r := range s.impl {
			rel := append(pbBytes(1, []byte(r)), pbVarintField(3, 1)...)
			info = append(info, pbBytes(4, rel)...)
		}
		doc = append(doc, pbBytes(3, info)...)
	}
	return pbBytes(2, doc)
}

func TestConstraintValidatorIngress_SCIP(t *testing.T) {
	const (
		pre    = "semanticdb maven maven/com.acme/app 1.0 com/acme/"
		iface  = "semanticdb maven maven/jakarta.validation/jakarta.validation-api 3.0 jakarta/validation/ConstraintValidator#"
		jdkObj = "semanticdb maven jdk 21 java/lang/Object#"
		libBas = "semanticdb maven maven/org.lib/lib 2.0 org/lib/AbstractLibValidator#"
	)
	canon := func(class, method string) string {
		return "scip-java maven . . com/acme/" + class + "#" + method + "()."
	}
	cases := []struct {
		name    string
		syms    []scipSym
		methods []string
		want    []string
	}{
		{
			name: "class relationship to the interface",
			syms: []scipSym{{pre + "V#", []string{iface}}},
			methods: []string{
				pre + "V#isValid().", pre + "V#initialize().", pre + "V#other().",
			},
			want: []string{canon("V", "initialize"), canon("V", "isValid")},
		},
		{
			name: "method relationship to the interface method only",
			syms: []scipSym{
				{pre + "V#", nil},
				{pre + "V#isValid().", []string{iface[:len(iface)-1] + "#isValid()."}},
			},
			methods: []string{pre + "V#isValid().", pre + "V#initialize()."},
			want:    []string{canon("V", "isValid")},
		},
		{
			name: "chain through first-party base",
			syms: []scipSym{
				{pre + "Base#", []string{iface}},
				{pre + "Mid#", []string{pre + "Base#"}},
				{pre + "Leaf#", []string{pre + "Mid#"}},
			},
			methods: []string{pre + "Leaf#isValid(+1)."},
			want:    []string{canonicalizeSCIP(pre + "Leaf#isValid(+1).")},
		},
		{
			name:    "undefined non-JDK ancestor over-roots",
			syms:    []scipSym{{pre + "V#", []string{jdkObj, libBas}}},
			methods: []string{pre + "V#isValid()."},
			want:    []string{canon("V", "isValid")},
		},
		{
			name:    "JDK-only ancestors are not rooted",
			syms:    []scipSym{{pre + "Plain#", []string{jdkObj}}},
			methods: []string{pre + "Plain#isValid().", pre + "Plain#initialize()."},
			want:    nil,
		},
		{
			name: "first-party ancestors without the interface are not rooted",
			syms: []scipSym{
				{pre + "Base#", []string{jdkObj}},
				{pre + "Child#", []string{pre + "Base#"}},
			},
			methods: []string{pre + "Child#isValid()."},
			want:    nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, err := readSCIPIndex(scipIndexBytes(tc.syms, tc.methods...))
			if err != nil {
				t.Fatalf("readSCIPIndex: %v", err)
			}
			var got []string
			for _, in := range g.ingresses {
				if in.Kind != jvmingress.KindConstraintValidator {
					t.Errorf("unexpected kind %q", in.Kind)
				}
				got = append(got, in.Symbol.SCIP)
			}
			sort.Strings(got)
			for _, r := range got {
				if !slices.Contains(g.roots, r) {
					t.Errorf("ingress %q is not a root: %v", r, g.roots)
				}
			}
			want := slices.Clone(tc.want)
			sort.Strings(want)
			if !slices.Equal(got, want) {
				t.Errorf("ingresses = %q, want %q", got, want)
			}
		})
	}
}

// The validator needle is a supertype, not an annotation: the annotation registry must not
// classify a reference to the ConstraintValidator type as an ingress annotation.
func TestConstraintValidatorIngress_SCIPMainSourceOnly(t *testing.T) {
	const (
		pre   = "semanticdb maven maven/com.acme/app 1.0 com/acme/"
		iface = "semanticdb maven maven/jakarta.validation/jakarta.validation-api 3.0 jakarta/validation/ConstraintValidator#"
	)
	cases := []struct {
		path string
		want int
	}{
		{"src/main/java/com/acme/V.java", 1},
		{"V.java", 1},
		{"service/src/test/java/com/acme/V.java", 0},
		{"src/integrationTest/java/com/acme/V.java", 0},
		{"src/it/java/com/acme/V.java", 0},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			g, err := readSCIPIndex(scipIndexBytesAt(tc.path, []scipSym{{pre + "V#", []string{iface}}}, pre+"V#isValid()."))
			if err != nil {
				t.Fatalf("readSCIPIndex: %v", err)
			}
			if len(g.ingresses) != tc.want {
				t.Errorf("ingresses = %d, want %d: %v", len(g.ingresses), tc.want, g.ingresses)
			}
		})
	}
}

func TestConstraintValidatorNeedleIsNotAnAnnotation(t *testing.T) {
	sym := "semanticdb maven maven/jakarta.validation/jakarta.validation-api 3.0 jakarta/validation/ConstraintValidator#"
	if kind, _, ok := ingressAnnotation(sym); ok {
		t.Errorf("ConstraintValidator type reference classified as annotation ingress %q", kind)
	}
	if validatorSupertypeNeedle == "" || validatorSuper == "" || len(validatorEntryMethods) != 2 {
		t.Errorf("registry projection empty: needle %q super %q methods %v", validatorSupertypeNeedle, validatorSuper, validatorEntryMethods)
	}
}

// The family must only add roots. A marker with no compiled main-source counterpart is
// unmapped, and an unmapped marker withholds Searched for the whole run, so a test-source
// class and a local class (compiled as P$1L, scanned as P$L) must produce none.
func TestBytecodeReach_ValidatorMarkersNeverWithholdSearched(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		src   string
		class string
	}{
		{"test-source library-ancestor initialize", "src/test/java/com/acme/AppTest.java",
			"package com.acme;\npublic class AppTest extends junit.framework.TestCase { public void initialize(Object a) {} }\n", ""},
		{"test-source validator", "src/test/java/com/acme/TV.java",
			"package com.acme;\npublic class TV implements jakarta.validation.ConstraintValidator<Object, Object> {\n    public boolean isValid(Object v, Object c) { return true; }\n}\n", ""},
		{"local class validator", "src/main/java/com/acme/P.java",
			"package com.acme;\npublic class P {\n    void m() {\n        class L implements jakarta.validation.ConstraintValidator<Object, Object> {\n            public boolean isValid(Object v, Object c) { return true; }\n        }\n    }\n}\n", "com/acme/P"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newApp(t, "", false)
			a.source("src/main/java/com/acme/App.java", appSource)
			a.class("target/classes", "com/acme/App", mainCalling(justReturn))
			a.source(tc.path, tc.src)
			if tc.class != "" {
				a.class("target/classes", tc.class, func(*cpb) []xmethod { return nil })
				a.classI("target/classes", "com/acme/P$1L", "java/lang/Object", nil, 0x0020, validatorMethodsCalling(justReturn))
			}
			res := a.reach(netkitSinkID)
			if !slices.Equal(res.Searched, []string{netkitSinkID}) || hasReason(res.Partiality, plugin.PartialReasonReachabilityUndetermined) {
				t.Errorf("Searched = %v, partiality %+v; want the no-validator baseline (Searched, no reachability_undetermined)", res.Searched, res.Partiality)
			}
		})
	}
}

// rootedConstraintValidator is the predicate the annotation-type check consults: true only
// for a unique first-party class with a concrete isValid(2) rooted on it or a first-party
// ancestor.
func TestRootedConstraintValidator(t *testing.T) {
	const v = `public class %s implements jakarta.validation.ConstraintValidator<Ann, String> {
    public boolean isValid(String v, Object ctx) { return true; }
}`
	cases := []struct {
		name  string
		files map[string]string
		class string
		want  bool
	}{
		{"direct", map[string]string{"com/acme/V.java": "package com.acme;\n" + fmt.Sprintf(v, "V")}, "V", true},
		{"inherited from a first-party ancestor", map[string]string{
			"com/acme/Base.java": "package com.acme;\n" + fmt.Sprintf(v, "Base"),
			"com/acme/Leaf.java": "package com.acme;\npublic class Leaf extends Base {}",
		}, "Leaf", true},
		{"dependency base, helper-only", map[string]string{"com/acme/X.java": "package com.acme;\npublic class X extends org.lib.AbstractLibValidator { boolean helper(String v) { return true; } }"}, "X", false},
		{"simple-name collision with the dependency base", map[string]string{
			"com/acme/AbstractLibValidator.java": "package com.acme;\npublic class AbstractLibValidator {}",
			"com/acme/X.java":                    "package com.acme;\npublic class X extends AbstractLibValidator { boolean helper(String v) { return true; } }",
		}, "X", false},
		{"simple name declared twice", map[string]string{
			"com/acme/V.java":  "package com.acme;\n" + fmt.Sprintf(v, "V"),
			"com/other/V.java": "package com.other;\npublic class V {}",
		}, "V", false},
		{"validator on a name two classes share via an ancestor", map[string]string{
			"com/acme/Base.java":  "package com.acme;\n" + fmt.Sprintf(v, "Base"),
			"com/other/Base.java": "package com.other;\npublic class Base {}",
			"com/acme/Leaf.java":  "package com.acme;\npublic class Leaf extends Base {}",
		}, "Leaf", false},
		{"unresolved name", map[string]string{"com/acme/V.java": "package com.acme;\n" + fmt.Sprintf(v, "V")}, "Missing", false},
		{"test-source validator", map[string]string{"src/test/java/com/acme/V.java": "package com.acme;\n" + fmt.Sprintf(v, "V")}, "V", false},
		{"initialize only, dependency base", map[string]string{"com/acme/X.java": "package com.acme;\npublic class X extends org.lib.AbstractLibValidator { public void initialize(Ann a) {} }"}, "X", false},
		{"simple name declared twice, validator sorts later", map[string]string{
			"com/other/V.java": "package com.other;\npublic class V {}",
			"com/zzz/V.java":   "package com.zzz;\n" + fmt.Sprintf(v, "V"),
		}, "V", false},
		{"validator on a name two classes share via an ancestor, validator sorts later", map[string]string{
			"com/other/Base.java": "package com.other;\npublic class Base {}",
			"com/zzz/Base.java":   "package com.zzz;\n" + fmt.Sprintf(v, "Base"),
			"com/acme/Leaf.java":  "package com.acme;\npublic class Leaf extends Base {}",
		}, "Leaf", false},
		{"validator nested in its own constraint annotation", map[string]string{"com/acme/Ann.java": "package com.acme;\npublic @interface Ann {\n    " + fmt.Sprintf(v, "V") + "\n}"}, "V", true},
		{"abstract isValid only", map[string]string{"com/acme/A.java": "package com.acme;\npublic abstract class A implements jakarta.validation.ConstraintValidator<Ann, String> { public abstract boolean isValid(String v, Object c); }"}, "A", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prog, err := loadProgram(writeProgram(t, tc.files))
			if err != nil {
				t.Fatal(err)
			}
			if got := rootedConstraintValidator(prog, tc.class); got != tc.want {
				t.Errorf("rootedConstraintValidator(%q) = %v, want %v", tc.class, got, tc.want)
			}
		})
	}
}

func TestParseFile_AnnotationTypeBodyDeclaresNestedTypesOnly(t *testing.T) {
	res := parseFile(`package com.acme;
public @interface Ann {
    String message() default "x";
    int max() default 1;
    class V { boolean isValid(String s, Object c) { return true; } }
}`)
	var got []string
	for _, d := range res.decls {
		got = append(got, fmt.Sprintf("%d:%s@%v", d.kind, d.name, d.enclosing))
	}
	want := []string{fmt.Sprintf("%d:V@[Ann]", kindType), fmt.Sprintf("%d:isValid@[Ann V]", kindMethod)}
	if !slices.Equal(got, want) {
		t.Errorf("decls = %q, want %q", got, want)
	}
}

func TestParseFile_AnnotationTypeFrameInCallPass(t *testing.T) {
	tests := []struct {
		name      string
		src       string
		wantCalls []string
		wantDecls []string
	}{
		{
			name: "validator nested in its own constraint annotation",
			src: `package com.acme;
public @interface Ann {
    class V {
        boolean isValid(String s, Object c) { return helper(s); }
        boolean helper(String s) { return true; }
    }
}`,
			wantCalls: []string{"[Ann V]#isValid -> helper"},
			wantDecls: []string{"V@[Ann]", "isValid@[Ann V]", "helper@[Ann V]"},
		},
		{
			name: "annotation type nested in a class",
			src: `package com.acme;
public class Outer {
    public @interface Ann {
        class V {
            boolean isValid(String s, Object c) { return helper(s); }
            boolean helper(String s) { return true; }
        }
    }
}`,
			wantCalls: []string{"[Outer Ann V]#isValid -> helper"},
			wantDecls: []string{"Outer@[]", "V@[Outer Ann]", "isValid@[Outer Ann V]", "helper@[Outer Ann V]"},
		},
		{
			name: "elements with defaults produce no calls or declarations",
			src: `package com.acme;
public @interface Ann {
    String message() default "x";
    Class<?>[] groups() default {};
    Object value() default Foo.make();
    int max() default 1;
}`,
		},
		{
			name: "route meta-annotation on a member annotation type stays off the next method",
			src: `package com.acme;
public class Api {
    @RequestMapping("/api") @interface ApiRoute {}
    void helper() { exec(x); }
}`,
			wantCalls: []string{"[Api]#helper -> exec"},
			wantDecls: []string{"Api@[]", "helper@[Api]"},
		},
		{
			name: "class after the annotation type keeps its chain",
			src: `package com.acme;
public @interface Ann {
    String message() default "x";
}
class After {
    void run() { go(); }
    void go() {}
}`,
			wantCalls: []string{"[After]#run -> go"},
			wantDecls: []string{"After@[]", "run@[After]", "go@[After]"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := parseFile(tc.src)
			var calls []string
			for _, c := range res.calls {
				calls = append(calls, fmt.Sprintf("%v#%s -> %s", c.callerEnclosing, c.callerName, c.calleeName))
			}
			var decls []string
			for _, d := range res.decls {
				if d.name == "Ann" && len(d.enclosing) == 0 {
					continue
				}
				decls = append(decls, fmt.Sprintf("%s@%v", d.name, d.enclosing))
			}
			if !slices.Equal(calls, tc.wantCalls) {
				t.Errorf("calls = %q, want %q", calls, tc.wantCalls)
			}
			if !slices.Equal(decls, tc.wantDecls) {
				t.Errorf("decls = %q, want %q", decls, tc.wantDecls)
			}
			if len(res.ingresses) != 0 {
				t.Errorf("ingresses = %+v, want none", res.ingresses)
			}
			if !res.skipped {
				t.Error("skipped must stay set for an @interface file")
			}
		})
	}
}

func TestInTypeBodyFrame_AnnotationBodyIsNotATypeBody(t *testing.T) {
	tests := []struct {
		name  string
		stack []bodyFrame
		want  bool
	}{
		{"empty", nil, false},
		{"class body", []bodyFrame{{typeName: "C"}}, true},
		{"annotation body", []bodyFrame{{typeName: "Ann", annotation: true}}, false},
		{"class nested in annotation body", []bodyFrame{{typeName: "Ann", annotation: true}, {typeName: "V"}}, true},
		{"method body", []bodyFrame{{typeName: "C"}, {methodName: "m"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := inTypeBodyFrame(tc.stack); got != tc.want {
				t.Errorf("inTypeBodyFrame = %v, want %v", got, tc.want)
			}
		})
	}
}
