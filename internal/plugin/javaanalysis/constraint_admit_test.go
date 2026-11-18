package javaanalysis

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func TestParseFile_AnnotationTypeConstraint(t *testing.T) {
	// @Constraint is admitted only when it resolves to jakarta/javax.validation.Constraint
	// and carries validatedBy as class literals; parseFile returns the names and the
	// program-level pass decides whether each is a rooted first-party validator.
	tests := []struct {
		name        string
		src         string
		wantSkipped bool
		wantNames   []string
	}{
		{"jakarta by import", `package p;
import jakarta.validation.Constraint;
@Constraint(validatedBy = AgeValidator.class) @interface Age {}`, false, []string{"AgeValidator"}},
		{"javax by import", `package p;
import javax.validation.Constraint;
@Constraint(validatedBy = AgeValidator.class) @interface Age {}`, false, []string{"AgeValidator"}},
		{"fully qualified, no import", `package p;
@jakarta.validation.Constraint(validatedBy = {A.class, B.class}) @interface Age {}`, false, []string{"A", "B"}},
		{"array form, one element, trailing comma", `package p;
import javax.validation.Constraint;
@Constraint(validatedBy = {A.class,}) @interface Age {}`, false, []string{"A"}},
		{"qualified class literal keeps the simple name", `package p;
import javax.validation.Constraint;
@Constraint(validatedBy = com.acme.AgeValidator.class) @interface Age {}`, false, []string{"AgeValidator"}},
		{"with meta-annotations", `package p;
import jakarta.validation.Constraint;
import java.lang.annotation.Retention;
@Retention(RetentionPolicy.RUNTIME) @Constraint(validatedBy = V.class) @interface Age { String message() default "x"; }`, false, []string{"V"}},

		{"no import", `package p; @Constraint(validatedBy = V.class) @interface Age {}`, true, nil},
		{"wildcard import", `package p;
import jakarta.validation.*;
@Constraint(validatedBy = V.class) @interface Age {}`, true, nil},
		{"same name from another package", `package p;
import com.acme.Constraint;
@Constraint(validatedBy = V.class) @interface Age {}`, true, nil},
		{"qualified name in another package", `package p; @com.acme.Constraint(validatedBy = V.class) @interface Age {}`, true, nil},
		{"nested annotation type, simple name", `package p;
import jakarta.validation.Constraint;
class K { @Constraint(validatedBy = V.class) @interface Age {} }`, true, nil},
		{"empty validatedBy", `package p;
import jakarta.validation.Constraint;
@Constraint(validatedBy = {}) @interface Age {}`, true, nil},
		{"no arguments", `package p;
import jakarta.validation.Constraint;
@Constraint @interface Age {}`, true, nil},
		{"empty argument list", `package p;
import jakarta.validation.Constraint;
@Constraint() @interface Age {}`, true, nil},
		{"unnamed argument", `package p;
import jakarta.validation.Constraint;
@Constraint(V.class) @interface Age {}`, true, nil},
		{"constant instead of class literal", `package p;
import jakarta.validation.Constraint;
@Constraint(validatedBy = Validators.ALL) @interface Age {}`, true, nil},
		{"call in the value", `package p;
import jakarta.validation.Constraint;
@Constraint(validatedBy = Foo.compute()) @interface Age {}`, true, nil},
		{"class literal of an array", `package p;
import jakarta.validation.Constraint;
@Constraint(validatedBy = V[].class) @interface Age {}`, true, nil},
		{"another element beside validatedBy", `package p;
import jakarta.validation.Constraint;
@Constraint(validatedBy = V.class, other = 1) @interface Age {}`, true, nil},
		{"composed NotNull", `package p;
import jakarta.validation.Constraint;
@NotNull @Constraint(validatedBy = V.class) @interface Age {}`, true, nil},
		{"composed Size", `package p;
import jakarta.validation.Constraint;
@Size(min = 1) @Constraint(validatedBy = V.class) @interface Age {}`, true, nil},
		{"composed ReportAsSingleViolation", `package p;
import jakarta.validation.Constraint;
@ReportAsSingleViolation @Constraint(validatedBy = V.class) @interface Age {}`, true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pr := parseFile(tt.src)
			if pr.skipped != tt.wantSkipped {
				t.Errorf("skipped = %v, want %v", pr.skipped, tt.wantSkipped)
			}
			if !slices.Equal(pr.validatedBy, tt.wantNames) {
				t.Errorf("validatedBy = %v, want %v", pr.validatedBy, tt.wantNames)
			}
		})
	}
}

func TestConstraintValidatorsRooted(t *testing.T) {
	old := validatorSuper
	validatorSuper = "ConstraintValidator"
	defer func() { validatorSuper = old }()
	cls := func(pkg, name string, supers ...string) sourceClass {
		return sourceClass{pkg: pkg, enclosing: []string{name}, name: name, supers: supers}
	}
	tests := []struct {
		name    string
		names   []string
		classes []sourceClass
		want    bool
	}{
		{"no constraint", nil, nil, true},
		{"direct implementer", []string{"V"}, []sourceClass{cls("p", "V", "ConstraintValidator")}, true},
		{"inherited through a first-party base", []string{"V"}, []sourceClass{cls("p", "Base", "ConstraintValidator"), cls("p", "V", "Base")}, true},
		{"every name resolves", []string{"A", "B"}, []sourceClass{cls("p", "A", "ConstraintValidator"), cls("p", "B", "ConstraintValidator")}, true},
		{"one of two is a validator", []string{"A", "B"}, []sourceClass{cls("p", "A", "ConstraintValidator"), cls("p", "B")}, false},
		{"unresolved, a dependency class", []string{"V"}, []sourceClass{cls("p", "Other", "ConstraintValidator")}, false},
		{"present but not a validator", []string{"V"}, []sourceClass{cls("p", "V", "Serializable")}, false},
		{"no supertype at all", []string{"V"}, []sourceClass{cls("p", "V")}, false},
		{"ambiguous simple name", []string{"V"}, []sourceClass{cls("p", "V", "ConstraintValidator"), cls("q", "V", "ConstraintValidator")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := constraintValidatorsRooted(tt.names, tt.classes); got != tt.want {
				t.Errorf("rooted = %v, want %v", got, tt.want)
			}
		})
	}
	t.Run("family absent", func(t *testing.T) {
		validatorSuper = ""
		defer func() { validatorSuper = "ConstraintValidator" }()
		if constraintValidatorsRooted([]string{"V"}, []sourceClass{cls("p", "V", "ConstraintValidator")}) {
			t.Error("rooted with no validator family")
		}
	})
}

func TestConstraintAdmission_Program(t *testing.T) {
	ann := `package com.acme;
import jakarta.validation.Constraint;
@Constraint(validatedBy = %s.class) public @interface Age { String message() default "bad"; }`
	mk := func(v string) string { return fmt.Sprintf(ann, v) }
	validator := `package com.acme;
import jakarta.validation.ConstraintValidator;
public class AgeValidator implements ConstraintValidator<Age, Integer> {
    public boolean isValid(Integer v, Object c) { return v > 0; }
}`
	tests := []struct {
		name        string
		files       map[string]string
		wantPartial bool
	}{
		{"first-party validator", map[string]string{"com/acme/Age.java": mk("AgeValidator"), "com/acme/AgeValidator.java": validator}, false},
		{"validator is a dependency class", map[string]string{"com/acme/Age.java": mk("DepValidator"), "com/acme/Other.java": "package com.acme; public class Other {}"}, true},
		{"named class is not a validator", map[string]string{"com/acme/Age.java": mk("AgeValidator"), "com/acme/AgeValidator.java": "package com.acme; public class AgeValidator { boolean isValid(Integer v) { return true; } }"}, true},
		{"validator declared twice", map[string]string{"com/acme/Age.java": mk("AgeValidator"), "com/acme/AgeValidator.java": validator, "com/other/AgeValidator.java": "package com.other;\n" + validator[len("package com.acme;\n"):]}, true},
		{"no constraint, nothing skipped", map[string]string{"com/acme/A.java": "package com.acme; public @interface A {}"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeProgram(t, tt.files)
			cg, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			if got := hasReason(cg.Partiality, plugin.PartialReasonUnsupported); got != tt.wantPartial {
				t.Errorf("CallGraph unsupported = %v, want %v (%+v)", got, tt.wantPartial, cg.Partiality)
			}
			ix, err := IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{BuildDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			if got := hasReason(ix.Partiality, plugin.PartialReasonUnsupported); got != tt.wantPartial {
				t.Errorf("IndexSymbols unsupported = %v, want %v (%+v)", got, tt.wantPartial, ix.Partiality)
			}
			in, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			if got := hasReason(in.Partiality, plugin.PartialReasonUnsupported); got != tt.wantPartial {
				t.Errorf("FindIngresses unsupported = %v, want %v (%+v)", got, tt.wantPartial, in.Partiality)
			}
		})
	}
}
