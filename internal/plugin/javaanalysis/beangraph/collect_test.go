package beangraph

import (
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

// anno builds an annotation with optional first string element value.
func anno(desc string, value ...string) classfile.Annotation {
	a := classfile.Annotation{Type: desc}
	if len(value) > 0 {
		a.Elements = []classfile.AnnotationElement{{Name: "value", Value: value[0]}}
	}
	return a
}

const (
	svc     = "Lorg/springframework/stereotype/Service;"
	comp    = "Lorg/springframework/stereotype/Component;"
	config  = "Lorg/springframework/context/annotation/Configuration;"
	beanA   = "Lorg/springframework/context/annotation/Bean;"
	primary = "Lorg/springframework/context/annotation/Primary;"
	autow   = "Lorg/springframework/beans/factory/annotation/Autowired;"
	qual    = "Lorg/springframework/beans/factory/annotation/Qualifier;"
)

func TestBeansFromClasses_Stereotype(t *testing.T) {
	classes := []classfile.Class{
		{
			Name:        "com/ex/UserServiceImpl",
			Interfaces:  []string{"com/ex/UserService"},
			Annotations: []classfile.Annotation{anno(svc)},
		},
		{Name: "com/ex/UserService"}, // the interface, no stereotype
	}
	beans := BeansFromClasses(classes)
	if len(beans) != 1 {
		t.Fatalf("want 1 bean, got %d: %+v", len(beans), beans)
	}
	b := beans[0]
	if b.Impl != "com/ex/UserServiceImpl" || b.Origin != OriginStereotype {
		t.Fatalf("unexpected bean: %+v", b)
	}
	// Satisfies must include the interface so an interface-typed IP resolves.
	if !reflect.DeepEqual(b.Satisfies, []string{"com/ex/UserService", "com/ex/UserServiceImpl"}) {
		t.Errorf("Satisfies = %v", b.Satisfies)
	}
	// The default bean name is the decapitalized simple class name.
	if !containsStr(b.Qualifiers, "userServiceImpl") {
		t.Errorf("Qualifiers missing default bean name: %v", b.Qualifiers)
	}

	// End-to-end: an interface-typed injection point resolves to the impl.
	r := NewRegistry(beans)
	got := r.Resolve(InjectionPoint{DeclaredType: "com/ex/UserService"})
	if !got.Found || got.Impl != "com/ex/UserServiceImpl" {
		t.Errorf("Resolve = %+v", got)
	}
}

func TestBeansFromClasses_BeanMethodAndPrimary(t *testing.T) {
	classes := []classfile.Class{
		{
			Name:        "com/ex/AppConfig",
			Annotations: []classfile.Annotation{anno(config)},
			Methods: []classfile.Method{
				{
					Ref:         classfile.MethodRef{Owner: "com/ex/AppConfig", Name: "primaryMailer", Descriptor: "()Lcom/ex/SmtpMailer;"},
					Annotations: []classfile.Annotation{anno(beanA), anno(primary)},
				},
			},
		},
		{
			Name:        "com/ex/SmtpMailer",
			Interfaces:  []string{"com/ex/Mailer"},
			Annotations: []classfile.Annotation{anno(comp)},
		},
		{
			Name:        "com/ex/SesMailer",
			Interfaces:  []string{"com/ex/Mailer"},
			Annotations: []classfile.Annotation{anno(comp)},
		},
	}
	beans := BeansFromClasses(classes)
	// AppConfig(stereotype) + primaryMailer(@Bean SmtpMailer) + SmtpMailer + SesMailer.
	if len(beans) != 4 {
		t.Fatalf("want 4 beans, got %d: %+v", len(beans), beans)
	}
	r := NewRegistry(beans)
	// Mailer has two component impls; the @Bean(@Primary) SmtpMailer wins by primary.
	got := r.Resolve(InjectionPoint{DeclaredType: "com/ex/Mailer"})
	if !got.Found || got.Impl != "com/ex/SmtpMailer" {
		t.Errorf("Resolve(Mailer) = %+v, want SmtpMailer via primary", got)
	}
}

func TestBeansFromClasses_TransitiveSupertype(t *testing.T) {
	// Impl -> Mid (abstract) -> BaseService (interface). An IP typed as BaseService must
	// still resolve to Impl through the transitive closure.
	classes := []classfile.Class{
		{Name: "com/ex/Impl", Super: "com/ex/Mid", Annotations: []classfile.Annotation{anno(svc)}},
		{Name: "com/ex/Mid", Interfaces: []string{"com/ex/BaseService"}},
		{Name: "com/ex/BaseService"},
	}
	r := NewRegistry(BeansFromClasses(classes))
	got := r.Resolve(InjectionPoint{DeclaredType: "com/ex/BaseService"})
	if !got.Found || got.Impl != "com/ex/Impl" {
		t.Errorf("Resolve(BaseService) = %+v, want Impl via transitive closure", got)
	}
}

func TestInjectionPointsFromClasses_FieldAndCtor(t *testing.T) {
	classes := []classfile.Class{
		{
			Name: "com/ex/Ctrl",
			Fields: []classfile.Field{
				{Name: "repo", Descriptor: "Lcom/ex/UserRepo;", Annotations: []classfile.Annotation{anno(autow)}},
				{Name: "plain", Descriptor: "Lcom/ex/Other;"}, // no @Autowired → not an IP
			},
			Methods: []classfile.Method{
				{
					// sole constructor, implicit autowiring; param 0 @Qualifier("ses")
					Ref: classfile.MethodRef{Owner: "com/ex/Ctrl", Name: "<init>", Descriptor: "(Lcom/ex/Mailer;I)V"},
					ParameterAnnotations: [][]classfile.Annotation{
						{anno(qual, "ses")},
						nil,
					},
				},
			},
		},
	}
	ips := InjectionPointsFromClasses(classes)
	want := []InjectionPoint{
		{Owner: "com/ex/Ctrl", Site: "ctorParam", DeclaredType: "com/ex/Mailer", Qualifier: "ses"},
		{Owner: "com/ex/Ctrl", Site: "field", DeclaredType: "com/ex/UserRepo", Qualifier: ""},
	}
	if !reflect.DeepEqual(ips, want) {
		t.Errorf("injection points:\n got %+v\nwant %+v", ips, want)
	}
}

func TestDescriptorParamTypes(t *testing.T) {
	tests := []struct {
		desc string
		want []string
	}{
		{"()V", nil},
		{"(Lcom/ex/A;)V", []string{"com/ex/A"}},
		{"(Lcom/ex/A;ILcom/ex/B;)V", []string{"com/ex/A", "", "com/ex/B"}},
		{"([Lcom/ex/A;J)V", []string{"com/ex/A", ""}},
	}
	for _, tt := range tests {
		if got := descriptorParamTypes(tt.desc); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("descriptorParamTypes(%q) = %v, want %v", tt.desc, got, tt.want)
		}
	}
}
