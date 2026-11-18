package javaanalysis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
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

func TestValidatedByRooted(t *testing.T) {
	// The program-level half asks #522's rootedConstraintValidator about every named class.
	prog := &program{rootedValidators: map[string]bool{"A": true, "B": true}}
	tests := []struct {
		name  string
		prog  *program
		names []string
		want  bool
	}{
		{"no constraint", prog, nil, true},
		{"every name rooted", prog, []string{"A", "B"}, true},
		{"one of two not rooted", prog, []string{"A", "C"}, false},
		{"none rooted", prog, []string{"C"}, false},
		{"family absent: no rooted set", &program{}, []string{"A"}, false},
		{"no program", nil, []string{"A"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validatedByRooted(tt.prog, tt.names); got != tt.want {
				t.Errorf("validatedByRooted = %v, want %v", got, tt.want)
			}
		})
	}
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
		{"validator extends a dependency base and overrides only a helper", map[string]string{"com/acme/Age.java": mk("AgeValidator"), "com/acme/AgeValidator.java": "package com.acme;\npublic class AgeValidator extends org.lib.AbstractLibValidator { boolean helper(Integer v) { return true; } }"}, true},
		{"validator named like a dependency base it extends", map[string]string{"com/acme/Age.java": mk("AgeValidator"), "com/acme/AbstractLibValidator.java": "package com.acme;\npublic class AbstractLibValidator {}", "com/acme/AgeValidator.java": "package com.acme;\npublic class AgeValidator extends AbstractLibValidator { boolean helper(Integer v) { return true; } }"}, true},
		{"validator without a concrete isValid", map[string]string{"com/acme/Age.java": mk("AgeValidator"), "com/acme/AgeValidator.java": "package com.acme;\npublic abstract class AgeValidator implements jakarta.validation.ConstraintValidator<Age, Integer> { public abstract boolean isValid(Integer v, Object c); }"}, true},
		{"validator in test sources", map[string]string{"com/acme/Age.java": mk("AgeValidator"), "src/test/java/com/acme/AgeValidator.java": validator}, true},
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
			// A complete dependency graph with no relevant type: the dependency half of the
			// check (TestWildcardAdmission_DependencyClasses) clears, so this row isolates the
			// first-party half.
			writeJar(t, netkitJarPath(dir), "org/lib/Util.class", emitClass(&cpb{}, "org/lib/Util", []mspec{{"m", "()V", []byte{0xB1}}}))
			cg, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir}, netkitGraph(t, dir))
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

// A name admitted through "import java.lang.annotation.*;" binds there only if no
// dependency class declares a top-level type of that name in the same package. The call
// graph, which opens the dependency jars, withholds the file when one does, or when the
// jars cannot be enumerated.
func TestWildcardAdmission_DependencyClasses(t *testing.T) {
	const ann = `package com.acme;
import java.lang.annotation.*;
@Retention(RetentionPolicy.RUNTIME) public @interface Flag {}`
	jarWith := func(t *testing.T, build string, class string) {
		t.Helper()
		b := &cpb{}
		writeJar(t, netkitJarPath(build), class+".class", emitClass(b, class, []mspec{{"m", "()V", []byte{0xB1}}}))
	}
	tests := []struct {
		name        string
		class       string // class in the dependency jar ("" = no jar written)
		noGraph     bool
		wantPartial bool
	}{
		{"jar declares no such type", "org/lib/Util", false, false},
		{"jar declares the type in another package", "org/lib/Retention", false, false},
		{"jar declares a nested type of that name in the package", "com/acme/Outer$Retention", false, false},
		{"jar declares the type in the same package", "com/acme/Retention", false, true},
		{"jar declared by the graph is missing", "", false, true},
		{"no build graph", "org/lib/Util", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			build := writeProgram(t, map[string]string{"com/acme/Flag.java": ann})
			if tt.class != "" {
				jarWith(t, build, tt.class)
			}
			var opts []Option
			if !tt.noGraph {
				opts = append(opts, netkitGraph(t, build))
			}
			cg, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: build}, opts...)
			if err != nil {
				t.Fatal(err)
			}
			if got := hasReason(cg.Partiality, plugin.PartialReasonUnsupported); got != tt.wantPartial {
				t.Errorf("CallGraph unsupported = %v, want %v (%+v)", got, tt.wantPartial, cg.Partiality)
			}
		})
	}
}

func TestWildcardClearOfDependencies(t *testing.T) {
	claims := []wildcardClaim{{pkg: "com.acme", names: []string{"Target"}}, {pkg: "", names: []string{"Retention"}}}
	dg := func(complete bool, names ...string) *dependencyGraph {
		g := &dependencyGraph{Complete: complete}
		for _, n := range names {
			g.Classes = append(g.Classes, classfile.Class{Name: n})
		}
		return g
	}
	tests := []struct {
		name   string
		claims []wildcardClaim
		dg     *dependencyGraph
		want   bool
	}{
		{"no claim needs no graph", nil, nil, true},
		{"no dependency class of the name", claims, dg(true, "org/lib/Util"), true},
		{"same name, other package", claims, dg(true, "org/lib/Target"), true},
		{"same package, other name", claims, dg(true, "com/acme/Util"), true},
		{"same package and name", claims, dg(true, "com/acme/Target"), false},
		{"default package", claims, dg(true, "Retention"), false},
		{"incomplete graph", claims, dg(false, "org/lib/Util"), false},
		{"absent graph", claims, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wildcardClearOfDependencies(tt.claims, tt.dg); got != tt.want {
				t.Errorf("clear = %v, want %v", got, tt.want)
			}
		})
	}
}
