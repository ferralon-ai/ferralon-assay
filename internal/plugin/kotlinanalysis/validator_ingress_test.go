package kotlinanalysis

import (
	"context"
	"slices"
	"sort"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/jvmingress"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// validatorClass is one fixture class: its name, superclass, superinterfaces and methods.
type validatorClass struct {
	name    string
	super   string
	ifaces  []string
	methods []validatorMethod
}

type validatorMethod struct {
	name, desc string
	abstract   bool
}

func symbolLabel(s plugin.Symbol) string { return s.Package + "." + s.Enclosing + "." + s.Name }

func validatorIngressNames(t *testing.T, classes []validatorClass) (names []string, searchedRefs []string) {
	t.Helper()
	dir := t.TempDir()
	for _, c := range classes {
		b := newKClassBuilder()
		b.interfaces = c.ifaces
		for _, m := range c.methods {
			if m.abstract {
				b.addMethodAccess(accPublic|accAbstract, m.name, m.desc, nil)
				continue
			}
			b.addMethod(m.name, m.desc, []byte{opReturn})
		}
		writeClassFixture(t, dir, c.name, b.build(c.name, c.super))
	}
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	for _, in := range res.Ingresses {
		if in.Kind != jvmingress.KindConstraintValidator {
			t.Errorf("unexpected ingress kind %q (%s)", in.Kind, in.Symbol.SCIP)
			continue
		}
		names = append(names, symbolLabel(in.Symbol))
	}
	prog, err := loadProgram(dir)
	if err != nil {
		t.Fatalf("loadProgram: %v", err)
	}
	for _, r := range frameworkIngressRefs(prog.classes) {
		searchedRefs = append(searchedRefs, symbolLabel(SymbolFromMethodRef(r)))
	}
	sort.Strings(names)
	sort.Strings(searchedRefs)
	return names, searchedRefs
}

func TestFindIngresses_ConstraintValidator(t *testing.T) {
	const (
		jak   = "jakarta/validation/ConstraintValidator"
		jvx   = "javax/validation/ConstraintValidator"
		obj   = "java/lang/Object"
		isV   = "(Ljava/lang/Object;Ljakarta/validation/ConstraintValidatorContext;)Z"
		initD = "(Ljava/lang/annotation/Annotation;)V"
	)
	cases := []struct {
		name    string
		classes []validatorClass
		want    []string
	}{
		{
			name:    "direct implementer, jakarta",
			classes: []validatorClass{{"com/acme/V", obj, []string{jak}, []validatorMethod{{"isValid", isV, false}, {"initialize", initD, false}, {"other", "()V", false}}}},
			want:    []string{"com.acme.V.initialize", "com.acme.V.isValid"},
		},
		{
			name:    "direct implementer, javax",
			classes: []validatorClass{{"com/acme/V", obj, []string{jvx}, []validatorMethod{{"isValid", isV, false}}}},
			want:    []string{"com.acme.V.isValid"},
		},
		{
			name: "bridge and typed isValid are both rooted",
			classes: []validatorClass{{"com/acme/V", obj, []string{jak}, []validatorMethod{
				{"isValid", "(Ljava/lang/String;Ljakarta/validation/ConstraintValidatorContext;)Z", false},
				{"isValid", isV, false},
			}}},
			want: []string{"com.acme.V.isValid", "com.acme.V.isValid"},
		},
		{
			name: "abstract base chain",
			classes: []validatorClass{
				{"com/acme/Base", obj, []string{jak}, []validatorMethod{{"isValid", isV, true}}},
				{"com/acme/Mid", "com/acme/Base", nil, nil},
				{"com/acme/Leaf", "com/acme/Mid", nil, []validatorMethod{{"isValid", isV, false}}},
			},
			want: []string{"com.acme.Leaf.isValid"},
		},
		{
			name: "interface extends",
			classes: []validatorClass{
				{"com/acme/Checker", obj, []string{jak}, nil},
				{"com/acme/Impl", obj, []string{"com/acme/Checker"}, []validatorMethod{{"isValid", isV, false}}},
			},
			want: []string{"com.acme.Impl.isValid"},
		},
		{
			name:    "ancestor missing from the build output over-roots",
			classes: []validatorClass{{"com/acme/V", "org/lib/AbstractValidator", nil, []validatorMethod{{"isValid", isV, false}}}},
			want:    []string{"com.acme.V.isValid"},
		},
		{
			name:    "unrelated class with isValid is not rooted",
			classes: []validatorClass{{"com/acme/Plain", obj, nil, []validatorMethod{{"isValid", isV, false}, {"initialize", initD, false}}}},
		},
		{
			name: "platform and first-party ancestors only are not rooted",
			classes: []validatorClass{
				{"com/acme/Base", obj, []string{"java/io/Serializable"}, nil},
				{"com/acme/Child", "com/acme/Base", []string{"java/lang/Comparable"}, []validatorMethod{{"isValid", isV, false}}},
			},
		},
		{
			name: "arity: wrong-arity isValid and initialize are not rooted",
			classes: []validatorClass{{"com/acme/V", obj, []string{jak}, []validatorMethod{
				{"isValid", "()Z", false},
				{"isValid", "(Ljava/lang/String;)Z", false},
				{"initialize", "()V", false},
				{"initialize", "(II)V", false},
			}}},
		},
		{
			name:    "arity: library ancestor with initialize() is not rooted",
			classes: []validatorClass{{"com/acme/X", "java/lang/RuntimeException", nil, []validatorMethod{{"initialize", "()V", false}}}},
		},
		{
			name:    "arity: array and primitive parameters are counted",
			classes: []validatorClass{{"com/acme/V", obj, []string{jak}, []validatorMethod{{"isValid", "([JILjava/lang/Object;)Z", false}, {"isValid", "([[JLjava/lang/Object;)Z", false}}}},
			want:    []string{"com.acme.V.isValid"},
		},
		{
			name:    "Kotlin object validator",
			classes: []validatorClass{{"com/acme/Obj", obj, []string{jak}, []validatorMethod{{"isValid", isV, false}}}},
			want:    []string{"com.acme.Obj.isValid"},
		},
		{
			name: "companion object validator",
			classes: []validatorClass{
				{"com/acme/Outer", obj, nil, nil},
				{"com/acme/Outer$Companion", obj, []string{jak}, []validatorMethod{{"isValid", isV, false}}},
			},
			want: []string{"com.acme.Outer$Companion.isValid"},
		},
		{
			name:    "abstract-only validator is not rooted",
			classes: []validatorClass{{"com/acme/Checker", obj, []string{jak}, []validatorMethod{{"isValid", isV, true}}}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, refs := validatorIngressNames(t, tc.classes)
			want := slices.Clone(tc.want)
			sort.Strings(want)
			if !slices.Equal(got, want) {
				t.Errorf("disclosed ingresses = %q, want %q", got, want)
			}
			// The roots reachability searches from are the same set as the disclosed list.
			if !slices.Equal(refs, want) {
				t.Errorf("reachability roots = %q, want %q", refs, want)
			}
		})
	}
}
