package javaanalysis

import (
	"context"
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
	var doc []byte
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
func TestConstraintValidatorNeedleIsNotAnAnnotation(t *testing.T) {
	sym := "semanticdb maven maven/jakarta.validation/jakarta.validation-api 3.0 jakarta/validation/ConstraintValidator#"
	if kind, _, ok := ingressAnnotation(sym); ok {
		t.Errorf("ConstraintValidator type reference classified as annotation ingress %q", kind)
	}
	if validatorSupertypeNeedle == "" || validatorSuper == "" || len(validatorEntryMethods) != 2 {
		t.Errorf("registry projection empty: needle %q super %q methods %v", validatorSupertypeNeedle, validatorSuper, validatorEntryMethods)
	}
}
