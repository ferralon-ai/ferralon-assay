package javaanalysis

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestSpELClassifier_PresenceAtSink proves overlay #4: a first-party sink method whose
// own annotation string value carries a SpEL template (#{…}) or property placeholder
// (${…}) is flagged spel_present, a plain sink is not, and the marking is presence-only.
// Assertions are CONTAINS (never set-equality) so a sibling overlay's reasons do not
// break this test.
func TestSpELClassifier_PresenceAtSink(t *testing.T) {
	src := `
package com.ex;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;

public class RateService {
    @Value("#{systemProperties['rate']}")
    public String rate(String k) { return k; }

    @Value("${app.timeout}")
    public int timeout(String k) { return 0; }

    public void plain(String acct) { noop(acct); }
}
`
	classes := scanSrc("com.ex", src)
	if len(classes) != 1 {
		t.Fatalf("want 1 class, got %d", len(classes))
	}
	sc := classes[0]
	prog := &program{sourceClasses: classes}
	classify := newSpELClassifier(prog)

	spelID := methodSCIP(sc.pkg, sc.enclosing, "rate", 1)
	placeholderID := methodSCIP(sc.pkg, sc.enclosing, "timeout", 1)
	plainID := methodSCIP(sc.pkg, sc.enclosing, "plain", 1)

	if !containsReason(classify(spelID), plugin.PartialReasonSpELPresent) {
		t.Errorf("rate sink (@Value #{…}) not flagged spel_present; got %v", classify(spelID))
	}
	if !containsReason(classify(placeholderID), plugin.PartialReasonSpELPresent) {
		t.Errorf("timeout sink (@Value ${…}) not flagged spel_present; got %v", classify(placeholderID))
	}
	// Negative case: a plain sink with no SpEL/placeholder annotation is NOT flagged.
	if containsReason(classify(plainID), plugin.PartialReasonSpELPresent) {
		t.Errorf("plain sink was flagged spel_present; got %v", classify(plainID))
	}
}

// TestSpELClassifier_EnclosingClassAnnotation proves the enclosing-class path: a SpEL
// template on a CLASS-level annotation flags every method sink of that class (the sink's
// value-flow is guarded by an expression the analyzer cannot evaluate).
func TestSpELClassifier_EnclosingClassAnnotation(t *testing.T) {
	src := `
package com.ex;
import org.springframework.security.access.prepost.PreAuthorize;

@PreAuthorize("#{@authz.check()}")
public class AdminService {
    public void purge(String id) { wipe(id); }
}
`
	classes := scanSrc("com.ex", src)
	if len(classes) != 1 {
		t.Fatalf("want 1 class, got %d", len(classes))
	}
	sc := classes[0]
	classify := newSpELClassifier(&program{sourceClasses: classes})
	id := methodSCIP(sc.pkg, sc.enclosing, "purge", 1)
	if !containsReason(classify(id), plugin.PartialReasonSpELPresent) {
		t.Errorf("purge sink under class-level SpEL not flagged; got %v", classify(id))
	}
}

// TestSpELClassifier_SurfacesThroughFirstPartyPaths proves the reason reaches the H3
// consumer: firstPartyPaths unions spel_present for a SpEL-bearing sink id.
func TestSpELClassifier_SurfacesThroughFirstPartyPaths(t *testing.T) {
	src := `
package com.ex;
import org.springframework.beans.factory.annotation.Value;

public class RateService {
    @Value("#{systemProperties['rate']}")
    public String rate(String k) { return k; }
}
`
	classes := scanSrc("com.ex", src)
	sc := classes[0]
	sinkID := methodSCIP(sc.pkg, sc.enclosing, "rate", 1)

	prog := &program{sourceClasses: classes}
	cg := plugin.CallGraphResult{
		Edges: []plugin.CallEdge{{Caller: sym("ingress"), Callee: sym(sinkID)}},
		Roots: []plugin.Symbol{sym("ingress")},
	}
	ing := plugin.IngressResult{Ingresses: []plugin.Ingress{{Kind: "http_route", Symbol: sym("ingress")}}}

	_, reasons := firstPartyPaths(prog, cg, ing, []string{sinkID})
	if !reasons[plugin.PartialReasonSpELPresent] {
		t.Errorf("spel_present did not surface through firstPartyPaths; got %v", reasons)
	}
}

func containsReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}
