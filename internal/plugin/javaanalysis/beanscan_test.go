package javaanalysis

import (
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

func TestReadAutoConfig_ImportsFormat(t *testing.T) {
	resources := map[string][]byte{
		"META-INF/spring/com.acme.MyAutoConfiguration.imports": []byte(
			"# a comment\ncom.acme.FooAutoConfiguration\n\ncom.acme.BarAutoConfiguration\n"),
	}
	got := readAutoConfig(resources)
	want := []string{"com.acme.BarAutoConfiguration", "com.acme.FooAutoConfiguration"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("readAutoConfig = %v, want %v", got, want)
	}
}

func TestReadAutoConfig_FactoriesFormat(t *testing.T) {
	resources := map[string][]byte{
		"META-INF/spring.factories": []byte(
			"org.springframework.boot.autoconfigure.EnableAutoConfiguration=\\\n" +
				"com.acme.AAutoConfiguration,\\\n" +
				"com.acme.BAutoConfiguration\n" +
				"some.other.Key=ignored\n"),
	}
	got := readAutoConfig(resources)
	want := []string{"com.acme.AAutoConfiguration", "com.acme.BAutoConfiguration"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("readAutoConfig = %v, want %v", got, want)
	}
}

func TestAutoConfigResourcePredicate(t *testing.T) {
	cases := map[string]bool{
		"META-INF/spring.factories": true,
		"META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports": true,
		"META-INF/spring/com.acme.MyModule.imports":                                        true,
		"com/acme/Foo.class":   false,
		"META-INF/MANIFEST.MF": false,
	}
	for name, want := range cases {
		if got := autoConfigResourcePredicate(name); got != want {
			t.Errorf("autoConfigResourcePredicate(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestComponentScanPackagesFromSource(t *testing.T) {
	pending := []parsedAnno{
		{name: "ComponentScan", value: "com.acme.services"},
		{name: "Service", value: ""},
	}
	got := componentScanPackagesFromSource(pending)
	if len(got) != 1 || got[0] != "com.acme.services" {
		t.Errorf("componentScanPackagesFromSource = %v", got)
	}
}

func TestImportedTypesFromClasses(t *testing.T) {
	classes := []classfile.Class{
		{
			Name: "com/ex/AppConfig",
			Annotations: []classfile.Annotation{
				{
					Type:          "Lorg/springframework/context/annotation/Import;",
					ClassElements: []classfile.AnnotationElement{{Name: "value", Value: "com/ex/ExtraConfig"}},
				},
			},
		},
	}
	got := importedTypesFromClasses(classes)
	if !reflect.DeepEqual(got, []string{"com/ex/ExtraConfig"}) {
		t.Errorf("importedTypesFromClasses = %v", got)
	}
}
