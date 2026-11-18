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

// scipValidatorMethods returns the isValid and initialize method symbols the SCIP index
// shows to be ConstraintValidator entries: a method whose own relationships name the
// supertype's method, or a method of a class whose supertype chain, followed through the
// index's class relationships, reaches ConstraintValidator. A method defined in a document
// outside the main source (a test source set) is not returned; the relationships it
// contributes still count. A supertype the index neither
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
	for di, spans := range defs {
		if !isMainSource(".", idx.documents[di].relativePath) {
			continue
		}
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
