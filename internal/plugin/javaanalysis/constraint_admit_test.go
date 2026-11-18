package javaanalysis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
		{"list without braces", `package p;
import jakarta.validation.Constraint;
@Constraint(validatedBy = A.class, B.class) @interface Age {}`, true, nil},
		{"closing brace only", `package p;
import jakarta.validation.Constraint;
@Constraint(validatedBy = A.class}) @interface Age {}`, true, nil},
		{"braces opened and not closed", `package p;
import jakarta.validation.Constraint;
@Constraint(validatedBy = {A.class) @interface Age {}`, true, nil},
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
		{"unreadable unrelated file does not fail the validator check", map[string]string{"com/acme/Age.java": mk("AgeValidator"), "com/acme/AgeValidator.java": validator, "com/acme/Bad.java": "package com.acme; class Bad {}"}, false},
		{"no constraint, nothing skipped", map[string]string{"com/acme/A.java": "package com.acme; public @interface A {}"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeProgram(t, tt.files)
			if strings.HasPrefix(tt.name, "unreadable") {
				if err := os.Chmod(filepath.Join(dir, "com/acme/Bad.java"), 0); err != nil {
					t.Fatal(err)
				}
			}
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

func TestParseFile_AnnotationTypeWildcard(t *testing.T) {
	// A meta-annotation reached through "import java.lang.annotation.*;" is admitted
	// pending the program-level same-package check, and only when nothing else in the
	// file could bind the simple name.
	const jla = "import java.lang.annotation.*;\n"
	tests := []struct {
		name        string
		src         string
		wantSkipped bool
		want        []string
	}{
		{"petclinic shape", `package p;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;
` + jla + `
@Target({ ElementType.FIELD })
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = V.class)
@Documented
public @interface Age {
    String message() default "x";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}`, false, []string{"Target", "Retention", "Documented"}},
		{"only Retention", "package p;\n" + jla + "@Retention(RetentionPolicy.RUNTIME) @interface A {}", false, []string{"Retention"}},
		{"single import wins for one name, wildcard for the other", "package p;\nimport java.lang.annotation.Target;\n" + jla + "@Target(ElementType.TYPE) @Retention(RetentionPolicy.RUNTIME) @interface A {}", false, []string{"Retention"}},
		{"qualified name needs no wildcard", "package p;\n" + jla + "@java.lang.annotation.Retention(RetentionPolicy.RUNTIME) @interface A {}", false, nil},

		{"single-type import of another Target shadows", "package p;\nimport com.acme.Target;\n" + jla + "@Target @interface A {}", true, nil},
		{"single static import of Target shadows", "package p;\nimport static com.acme.M.Target;\n" + jla + "@Target @interface A {}", true, nil},
		{"nested annotation type", "package p;\n" + jla + "class K { @Target(ElementType.TYPE) @interface A {} }", true, nil},
		{"same-file class of that name, before", "package p;\n" + jla + "class Target {}\n@Target @interface A {}", true, nil},
		{"same-file class of that name, after", "package p;\n" + jla + "@Target @interface A {}\nclass Target {}", true, nil},
		{"same-file nested type of that name", "package p;\n" + jla + "@Target @interface A {}\nclass K { interface Target {} }", true, nil},
		{"same-file annotation type of that name", "package p;\n" + jla + "@Target @interface A {}\n@interface Target {}", true, nil},
		{"another on-demand import, first-party-looking", "package p;\n" + jla + "import com.acme.*;\n@Target @interface A {}", true, nil},
		{"another on-demand import of an unenumerable package", "package p;\n" + jla + "import com.fasterxml.jackson.annotation.*;\n@Target @interface A {}", true, nil},
		{"another on-demand import, listed first", "package p;\nimport org.springframework.stereotype.*;\n" + jla + "@Target @interface A {}", true, nil},
		{"static on-demand import", "package p;\n" + jla + "import static com.acme.M.*;\n@Target @interface A {}", true, nil},
		{"on-demand import of a type's members", "package p;\n" + jla + "import com.acme.Outer.*;\n@Target @interface A {}", true, nil},
		{"no java.lang.annotation wildcard", "package p;\nimport com.acme.*;\n@Target @interface A {}", true, nil},
		{"wildcard of a sibling package", "package p;\nimport java.lang.*;\n@Target @interface A {}", true, nil},
		{"name outside the allow-list through the wildcard", "package p;\n" + jla + "@Native @interface A {}", true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pr := parseFile(tt.src)
			if pr.skipped != tt.wantSkipped {
				t.Errorf("skipped = %v, want %v", pr.skipped, tt.wantSkipped)
			}
			if !tt.wantSkipped && !slices.Equal(pr.wildcardNames, tt.want) {
				t.Errorf("wildcardNames = %v, want %v", pr.wildcardNames, tt.want)
			}
		})
	}
}

func TestWildcardAdmission_Program(t *testing.T) {
	ann := `package com.acme;
import java.lang.annotation.*;
@Target(ElementType.FIELD) @Retention(RetentionPolicy.RUNTIME) public @interface Age { String message() default "bad"; }`
	tests := []struct {
		name        string
		files       map[string]string
		wantPartial bool
	}{
		{"no same-package type of the name", map[string]string{"com/acme/Age.java": ann, "com/acme/Other.java": "package com.acme; public class Other {}"}, false},
		{"same-package class named Target", map[string]string{"com/acme/Age.java": ann, "com/acme/Target.java": "package com.acme; public class Target {}"}, true},
		{"same-package annotation type named Retention", map[string]string{"com/acme/Age.java": ann, "com/acme/Retention.java": "package com.acme; public @interface Retention {}"}, true},
		{"same-package interface named Target", map[string]string{"com/acme/Age.java": ann, "com/acme/Target.java": "package com.acme; interface Target {}"}, true},
		{"a type of that name in another package", map[string]string{"com/acme/Age.java": ann, "com/other/Target.java": "package com.other; public class Target {}"}, false},
		{"a nested type of that name in the package", map[string]string{"com/acme/Age.java": ann, "com/acme/K.java": "package com.acme; class K { class Target {} }"}, false},
		{"another file in the package skipped a construct", map[string]string{"com/acme/Age.java": ann, "com/acme/Odd.java": "package com.acme; @interface Odd { int x() default foo(); }"}, true},
		{"unreadable file", map[string]string{"com/acme/Age.java": ann, "com/acme/Bad.java": "package com.acme; class Bad {}"}, true},
		{"default package", map[string]string{"Age.java": "import java.lang.annotation.*;\n@Target(ElementType.FIELD) @interface Age {}", "Target.java": "class Target {}"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeProgram(t, tt.files)
			if tt.name == "unreadable file" {
				if err := os.Chmod(filepath.Join(dir, "com/acme/Bad.java"), 0); err != nil {
					t.Fatal(err)
				}
			}
			cg, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			if got := hasReason(cg.Partiality, plugin.PartialReasonUnsupported); got != tt.wantPartial {
				t.Errorf("CallGraph unsupported = %v, want %v", got, tt.wantPartial)
			}
			ix, err := IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{BuildDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			if got := hasReason(ix.Partiality, plugin.PartialReasonUnsupported); got != tt.wantPartial {
				t.Errorf("IndexSymbols unsupported = %v, want %v", got, tt.wantPartial)
			}
		})
	}
}

func TestWildcardCheck_SkippedPackageIsPerPackage(t *testing.T) {
	use := parseResult{pkg: "a", wildcardNames: []string{"Target"}, topLevel: []string{"Age"}}
	other := parseResult{pkg: "b", skipped: true}
	w := newWildcardCheck()
	w.add(use)
	w.add(other)
	if !w.ok() {
		t.Error("a skipped file in another package must not fail the claim")
	}
	w.add(parseResult{pkg: "a", skipped: true})
	if w.ok() {
		t.Error("a skipped file in the claimed package must fail the claim")
	}
}
