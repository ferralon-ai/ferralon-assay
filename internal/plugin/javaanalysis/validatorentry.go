package javaanalysis

import (
	"os"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/jvmingress"
)

// jdkSupertypeNames are the simple names of JDK types a class commonly lists as a
// supertype. A non-first-party supertype outside this set might be a dependency class that
// itself implements ConstraintValidator, so the lexical pass cannot clear it. The scan has no
// import resolution; a name here is cleared by name alone.
var jdkSupertypeNames = map[string]bool{
	"Object": true, "Serializable": true, "Cloneable": true, "Comparable": true,
	"Runnable": true, "AutoCloseable": true, "Closeable": true, "Iterable": true,
}

// rootConstraintValidators adds a constraint_validator ingress marker to files for every
// concrete isValid(2) and initialize(1) method of a first-party main-source class that is a
// ConstraintValidator by direct or inherited supertype (a first-party base class, or an
// interface extending it). The bean provider calls those two signatures only.
//
// A class with an inherited supertype that is neither first-party nor a known JDK name may
// inherit ConstraintValidator from a dependency, so its methods are rooted too: the pass
// errs toward more roots. classes must hold the main-source classes only. A marker needs a
// compiled counterpart to map to (ingressRoots withholds Searched run-wide for one it cannot
// map), so a test-source file, a local class and a method without a body get none.
// Matching is by simple name, like every other family here.
//
// The result lists the simple names for which rootedConstraintValidator holds.
func rootConstraintValidators(buildDir string, files []fileParse, classes []sourceClass) map[string]bool {
	if validatorSuper == "" {
		return nil
	}
	supers := map[string][]string{}
	firstParty := map[string]bool{}
	declared := map[string]int{}
	for _, sc := range classes {
		firstParty[sc.name] = true
		declared[sc.name]++
		supers[sc.name] = append(supers[sc.name], sc.supers...)
	}
	memo := map[string]bool{}
	isValidator := func(name string) bool {
		if v, ok := memo[name]; ok {
			return v
		}
		v := false
		for _, s := range supertypeClosureNames(name, supers) {
			if s != name && (s == validatorSuper || (!firstParty[s] && !jdkSupertypeNames[s])) {
				v = true
				break
			}
		}
		memo[name] = v
		return v
	}
	owners := map[string]bool{}
	for _, sc := range classes {
		if !sc.local && isValidator(sc.name) {
			owners[ownerKey(sc.pkg, sc.enclosing)] = true
		}
	}
	if len(owners) == 0 {
		return nil
	}
	rooted := map[string]bool{} // owner keys holding a rooted isValid(2)
	for i := range files {
		fp := &files[i]
		if !isMainSource(buildDir, fp.path) {
			continue
		}
		for _, d := range fp.decls {
			arity, entry := validatorEntryArity[d.name]
			if d.kind != kindMethod || d.abstract || !validatorEntryMethods[d.name] || (entry && d.arity != arity) || !owners[ownerKey(fp.pkg, d.enclosing)] {
				continue
			}
			fp.ingresses = append(fp.ingresses, ingressMarker{
				enclosing: d.enclosing,
				name:      d.name,
				arity:     d.arity,
				kind:      jvmingress.KindConstraintValidator,
			})
			if d.name == "isValid" {
				rooted[ownerKey(fp.pkg, d.enclosing)] = true
			}
		}
	}
	byName := map[string]sourceClass{}
	for _, sc := range classes {
		byName[sc.name] = sc
	}
	out := map[string]bool{}
	for name := range byName {
		if rootedConstraintValidatorIn(name, supers, firstParty, declared, byName, rooted) {
			out[name] = true
		}
	}
	return out
}

// rootedConstraintValidatorIn reports whether name is a first-party class with a concrete
// isValid(2) rooted on it or on a first-party ancestor. It answers false whenever the
// answer would rest on a simple name two first-party classes share, or on an ancestor the
// scan cannot see: a validator whose isValid is inherited from a dependency class, and a
// first-party class named like such a dependency class, are not claimed.
func rootedConstraintValidatorIn(name string, supers map[string][]string, firstParty map[string]bool, declared map[string]int, byName map[string]sourceClass, rooted map[string]bool) bool {
	for _, c := range supertypeClosureNames(name, supers) {
		if !firstParty[c] {
			continue
		}
		if declared[c] != 1 {
			return false
		}
	}
	for _, c := range supertypeClosureNames(name, supers) {
		sc, ok := byName[c]
		if ok && !sc.local && rooted[ownerKey(sc.pkg, sc.enclosing)] {
			return true
		}
	}
	return false
}

// rootedConstraintValidator is the question the annotation-type check asks about the class
// named by a constraint annotation's validatedBy: is it a first-party class whose concrete
// isValid(2) this family roots, on the class itself or on a first-party ancestor? It is false
// for a class that is not first-party, a simple name more than one first-party class holds,
// an isValid inherited only from a dependency class, and anything unresolved.
func rootedConstraintValidator(prog *program, name string) bool {
	return prog != nil && prog.rootedValidators[name]
}

// validatedByRooted reports whether every class an admitted @Constraint names is a class
// rootedConstraintValidator accepts and is the class the literal denotes. The rooted check
// is by simple name, so a literal that names a dependency class (a qualified name, or an
// import) while a first-party class shares the simple name would otherwise pass: the
// unique first-party declaration of the simple name must have a qualified name the literal
// can denote (package plus enclosing path). An empty list holds trivially; any name that is
// unresolved, ambiguous, dependency-backed, a different class, or without a rooted
// isValid(2) makes it false and the run stays partial: the annotation's validatedBy class
// would run with no root.
func validatedByRooted(prog *program, classes []validatedClass) bool {
	for _, c := range classes {
		if !rootedConstraintValidator(prog, c.name) {
			return false
		}
		if !slices.Contains(c.quals, prog.firstPartyQualified[c.name]) {
			return false
		}
	}
	return true
}

// firstPartyQualifiedNames maps the simple name of each non-local first-party class that
// is declared once to its qualified name: package plus enclosing path, with nested types
// dot-joined. A name declared more than once has no entry.
func firstPartyQualifiedNames(classes []sourceClass) map[string]string {
	count := map[string]int{}
	for _, sc := range classes {
		count[sc.name]++
	}
	out := map[string]string{}
	for _, sc := range classes {
		if count[sc.name] == 1 && !sc.local {
			out[sc.name] = qualify(sc.pkg, strings.Join(sc.enclosing, "."))
		}
	}
	return out
}

// validatorProgramOf runs the validator rooting over the given source files and returns a
// program holding what validatedByRooted reads, for callers (the symbol index) that have no
// full program. Only main-source classes count, as in loadProgram: a test-source class
// gets no marker from rootConstraintValidators and is not a first-party declaration here.
func validatorProgramOf(buildDir string, files []string) *program {
	var parsed []fileParse
	var main []sourceClass
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		src := string(data)
		pr := parseFile(src)
		parsed = append(parsed, fileParse{path: f, pkg: pr.pkg, decls: pr.decls, calls: pr.calls, ingresses: pr.ingresses})
		if isMainSource(buildDir, f) {
			main = append(main, scanSourceClasses([]rune(stripJava(src)), []rune(src), pr.pkg)...)
		}
	}
	return &program{rootedValidators: rootConstraintValidators(buildDir, parsed, main), firstPartyQualified: firstPartyQualifiedNames(main)}
}

// scipValidatorMethods returns the isValid and initialize method symbols the SCIP index
// shows to be ConstraintValidator entries: a method whose own relationships name the
// supertype's method, or a method of a class whose supertype chain, followed through the
// index's class relationships, reaches ConstraintValidator. A supertype the index neither
// defines nor attributes to the JDK may be a dependency class that extends it, so its
// subclass's methods are returned too. The lexical pass runs beside this one and the
// results are unioned, so a relationship scip-java does not record only leaves the
// lexical roots to stand alone.
func scipValidatorMethods(idx scipIndex, defs [][]scipDefSpan) []string {
	if validatorSupertypeNeedle == "" || len(validatorEntryMethods) == 0 {
		return nil
	}
	rel := map[string][]string{}
	defined := map[string]bool{}
	for _, doc := range idx.documents {
		for _, si := range doc.symbols {
			defined[si.symbol] = true
			rel[si.symbol] = append(rel[si.symbol], si.implementsOf...)
		}
	}
	memo := map[string]bool{}
	var reaches func(class string, seen map[string]bool) bool
	reaches = func(class string, seen map[string]bool) bool {
		if seen[class] {
			return false
		}
		seen[class] = true
		for _, t := range rel[class] {
			if !strings.HasSuffix(t, "#") {
				continue
			}
			if strings.Contains(t, validatorSupertypeNeedle) {
				return true
			}
			if !defined[t] && !strings.Contains(t, " jdk ") {
				return true
			}
			if reaches(t, seen) {
				return true
			}
		}
		return false
	}
	var out []string
	seenMethod := map[string]bool{}
	for _, spans := range defs {
		for _, d := range spans {
			m := d.symbol
			hash := strings.LastIndexByte(m, '#')
			if hash < 0 || seenMethod[m] {
				continue
			}
			name, _, hasParen := strings.Cut(m[hash+1:], "(")
			if !hasParen || !validatorEntryMethods[name] {
				continue
			}
			seenMethod[m] = true
			class := m[:hash+1]
			ok := false
			for _, t := range rel[m] {
				if strings.Contains(t, validatorSupertypeNeedle+name+"(") {
					ok = true
					break
				}
			}
			if !ok {
				if v, cached := memo[class]; cached {
					ok = v
				} else {
					ok = reaches(class, map[string]bool{})
					memo[class] = ok
				}
			}
			if ok {
				out = append(out, m)
			}
		}
	}
	return out
}

// wildcardCheck is the program-level half of resolving a meta-annotation through
// "import java.lang.annotation.*;" (parseFile does the per-file conditions). The name
// binds to java.lang.annotation only if the file's package declares no top-level type of
// that name (package scope shadows an on-demand import, JLS 6.4.1). The package's type
// set is established only from first-party source: it fails closed when any file could not
// be read, when any file in the package skipped a construct (a declaration may hide in
// it), and, as a residual, it does not see dependency classes, because the lexical pass
// has no classfile graph; a split package that a dependency jar also contributes to is
// not detected.
type wildcardCheck struct {
	claims     []wildcardClaim
	top        map[string]map[string]bool // package -> top-level type names
	skipped    map[string]bool            // package -> some file skipped a construct
	readFailed bool
}

type wildcardClaim struct {
	pkg   string
	names []string
}

func newWildcardCheck() *wildcardCheck {
	return &wildcardCheck{top: map[string]map[string]bool{}, skipped: map[string]bool{}}
}

func (w *wildcardCheck) add(pr parseResult) {
	if w.top[pr.pkg] == nil {
		w.top[pr.pkg] = map[string]bool{}
	}
	for _, n := range pr.topLevel {
		w.top[pr.pkg][n] = true
	}
	if pr.skipped {
		w.skipped[pr.pkg] = true
	}
	if len(pr.wildcardNames) > 0 {
		w.claims = append(w.claims, wildcardClaim{pkg: pr.pkg, names: pr.wildcardNames})
	}
}

// ok reports whether every claimed name binds to java.lang.annotation.
func (w *wildcardCheck) ok() bool {
	if len(w.claims) == 0 {
		return true
	}
	if w.readFailed {
		return false
	}
	for _, c := range w.claims {
		if w.skipped[c.pkg] {
			return false
		}
		for _, n := range c.names {
			if w.top[c.pkg][n] {
				return false
			}
		}
	}
	return true
}

// wildcardClearOfDependencies is the dependency half of the same-package check: a name
// admitted through "import java.lang.annotation.*;" binds there only if no dependency
// class declares a top-level type of that name in the file's package (package scope
// shadows an on-demand import, JLS 6.4.1; a split package may take types from a jar). It
// needs the opened classes, so it runs where the dependency graph is built. A graph that
// is absent or not complete cannot establish the package's contents, so the claim fails
// closed. Every operation that parses first-party source runs it.
func wildcardClearOfDependencies(claims []wildcardClaim, dg *dependencyGraph) bool {
	if len(claims) == 0 {
		return true
	}
	if dg == nil || !dg.Complete {
		return false
	}
	want := map[string]bool{}
	for _, c := range claims {
		for _, n := range c.names {
			want[strings.ReplaceAll(c.pkg, ".", "/")+"/"+n] = true
			if c.pkg == "" {
				want[n] = true
			}
		}
	}
	for _, cl := range dg.Classes {
		if want[cl.Name] {
			return false
		}
	}
	return true
}

// wildcardsClearOfDependencies opens the dependency graph for an operation that has none
// and applies wildcardClearOfDependencies. With no wildcard claim it opens nothing.
func wildcardsClearOfDependencies(claims []wildcardClaim, buildDir string, opts ...Option) bool {
	if len(claims) == 0 {
		return true
	}
	dg, _ := buildDependencyGraph(buildDir, opts...)
	return wildcardClearOfDependencies(claims, dg)
}
