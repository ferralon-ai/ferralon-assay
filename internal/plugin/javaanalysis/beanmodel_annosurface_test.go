package javaanalysis

import "testing"

// annoValue returns the first parsedAnno with the given simple name off a slice, plus
// whether it was present — the read-shape the sink overlays use.
func annoValue(annos []parsedAnno, name string) (string, bool) {
	for _, a := range annos {
		if a.name == name {
			return a.value, true
		}
	}
	return "", false
}

func findMethod(sc sourceClass, name string, arity int) (sourceMethod, bool) {
	for _, m := range sc.methods {
		if m.name == name && m.arity == arity {
			return m, true
		}
	}
	return sourceMethod{}, false
}

// TestScanSourceClasses_AnnotationSurfaceRetained proves the additive annotation surface:
// a class-level annotation is readable off classAnnos, and per-method @Transactional /
// @Value("#{…}") / @PreAuthorize annotations (name AND recovered string value) are
// readable off sourceClass.methods — the exact surface the #2/#4/#5 sink overlays classify
// against. Non-annotated methods carry an empty anno list (the overlays' negative case).
func TestScanSourceClasses_AnnotationSurfaceRetained(t *testing.T) {
	src := `
package com.ex;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;

@Service
@Transactional
public class OrderService {
    @Transactional
    public void charge(String acct) { doCharge(acct); }

    @Value("#{systemProperties['rate']}")
    public String rate(String k) { return k; }

    @PreAuthorize("hasRole('ADMIN')")
    public void purge() { wipe(); }

    public void plain() { noop(); }
}
`
	classes := scanSrc("com.ex", src)
	if len(classes) != 1 {
		t.Fatalf("want 1 class, got %d", len(classes))
	}
	sc := classes[0]

	// Bean-fact derivation is unchanged: still a stereotype (the @Service marker).
	if !sc.isStereotype {
		t.Error("OrderService lost its stereotype bean fact after the additive change")
	}

	// Class-level annotation surface: the full list, including the non-bean @Transactional.
	if _, ok := annoValue(sc.classAnnos, "Service"); !ok {
		t.Error("classAnnos missing @Service")
	}
	if _, ok := annoValue(sc.classAnnos, "Transactional"); !ok {
		t.Error("classAnnos missing class-level @Transactional")
	}

	// Per-method surface: name + arity + annotation name/value.
	charge, ok := findMethod(sc, "charge", 1)
	if !ok {
		t.Fatalf("methods missing charge/1; got %+v", sc.methods)
	}
	if _, ok := annoValue(charge.annos, "Transactional"); !ok {
		t.Errorf("charge annos missing @Transactional; got %+v", charge.annos)
	}

	rate, ok := findMethod(sc, "rate", 1)
	if !ok {
		t.Fatalf("methods missing rate/1; got %+v", sc.methods)
	}
	if v, ok := annoValue(rate.annos, "Value"); !ok || v != "#{systemProperties['rate']}" {
		t.Errorf("rate @Value value = %q present=%v, want the SpEL template", v, ok)
	}

	purge, ok := findMethod(sc, "purge", 0)
	if !ok {
		t.Fatalf("methods missing purge/0; got %+v", sc.methods)
	}
	if v, ok := annoValue(purge.annos, "PreAuthorize"); !ok || v != "hasRole('ADMIN')" {
		t.Errorf("purge @PreAuthorize value = %q present=%v, want the expression string", v, ok)
	}

	// Negative case: an un-annotated method has no annotations (overlays emit nothing).
	plain, ok := findMethod(sc, "plain", 0)
	if !ok {
		t.Fatalf("methods missing plain/0; got %+v", sc.methods)
	}
	if len(plain.annos) != 0 {
		t.Errorf("plain annos = %+v, want empty", plain.annos)
	}
}
