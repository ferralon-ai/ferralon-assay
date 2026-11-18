package javaanalysis

import (
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
// concrete isValid and initialize method of a first-party class that is a ConstraintValidator
// by direct or inherited supertype (a first-party base class, or an interface extending it).
// A class with an inherited supertype that is neither first-party nor a known JDK name may
// inherit ConstraintValidator from a dependency, so its methods are rooted too: the pass only
// adds roots. A method without a body gets no marker, since the bytecode mapping
// (ingressRoots) withholds Searched run-wide for a marker it cannot map to a compiled method.
// Matching is by simple name, like every other family here.
func rootConstraintValidators(files []fileParse, classes []sourceClass) {
	if validatorSuper == "" {
		return
	}
	isValidator := validatorClassifier(classes)
	owners := map[string]bool{}
	for _, sc := range classes {
		if isValidator(sc.name) {
			owners[ownerKey(sc.pkg, sc.enclosing)] = true
		}
	}
	if len(owners) == 0 {
		return
	}
	for i := range files {
		fp := &files[i]
		for _, d := range fp.decls {
			if d.kind != kindMethod || d.abstract || !validatorEntryMethods[d.name] || !owners[ownerKey(fp.pkg, d.enclosing)] {
				continue
			}
			fp.ingresses = append(fp.ingresses, ingressMarker{
				enclosing: d.enclosing,
				name:      d.name,
				arity:     d.arity,
				kind:      jvmingress.KindConstraintValidator,
			})
		}
	}
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

// validatorClassifier returns the lexical pass's test for "this first-party class is a
// ConstraintValidator": its supertype closure reaches the family supertype, or reaches a
// type that is neither first-party nor a known JDK name (a dependency class may extend it).
func validatorClassifier(classes []sourceClass) func(name string) bool {
	supers := map[string][]string{}
	firstParty := map[string]bool{}
	for _, sc := range classes {
		firstParty[sc.name] = true
		supers[sc.name] = append(supers[sc.name], sc.supers...)
	}
	memo := map[string]bool{}
	return func(name string) bool {
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
}

// constraintValidatorsRooted reports whether every class an admitted @Constraint names
// resolves, by a simple name unique among first-party classes, to a class that
// rootConstraintValidators roots. A name that is unresolved (a dependency class), declared
// more than once, or not a validator makes the answer false and the run stays partial: the
// annotation's validatedBy classes would run with no root. Without the family
// (validatorSuper empty) nothing is rooted, so any name fails.
func constraintValidatorsRooted(names []string, classes []sourceClass) bool {
	if len(names) == 0 {
		return true
	}
	if validatorSuper == "" {
		return false
	}
	declared := map[string]map[string]bool{}
	for _, sc := range classes {
		if declared[sc.name] == nil {
			declared[sc.name] = map[string]bool{}
		}
		declared[sc.name][ownerKey(sc.pkg, sc.enclosing)] = true
	}
	isValidator := validatorClassifier(classes)
	for _, n := range names {
		if len(declared[n]) != 1 || !isValidator(n) {
			return false
		}
	}
	return true
}
