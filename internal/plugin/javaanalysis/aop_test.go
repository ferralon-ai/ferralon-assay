package javaanalysis

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// progFrom builds a minimal *program carrying only the scanned first-party classes —
// the sole input the AOP classifier reads.
func progFrom(src string) *program {
	return &program{sourceClasses: scanSrc("com.ex", src)}
}

// sinkID resolves the SCIP id the classifier keys on for one method of one scanned class,
// so a test asserts against the exact id firstPartyPaths would request.
func sinkID(t *testing.T, prog *program, class, method string, arity int) string {
	t.Helper()
	for _, sc := range prog.sourceClasses {
		if sc.name == class {
			return methodSCIP(sc.pkg, sc.enclosing, method, arity)
		}
	}
	t.Fatalf("class %s not found in scanned program", class)
	return ""
}

func containsReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}

// The fixture exercises every marker path: method-level @Async/@Scheduled (async_boundary),
// method-level @Transactional/@Cacheable and @Around advice (proxy_mediated), a method
// carrying both, class-level markers that lift every method of the class, an @Aspect class,
// and an un-annotated method (the negative case). javax vs jakarta and the various
// org.springframework namespaces all reduce to the SIMPLE name the classifier matches.
const aopFixture = `
package com.ex;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

@Service
public class OrderService {
    @Async
    public void enqueue(String acct) { doEnqueue(acct); }

    @Transactional
    public void charge(String acct) { doCharge(acct); }

    @Cacheable
    public String lookup(String k) { return k; }

    @Scheduled
    public void sweep() { doSweep(); }

    @Async
    @Transactional
    public void both(String acct) { doBoth(acct); }

    public void plain() { noop(); }
}
`

// A class-level @Async lifts async_boundary onto every method; a class-level @Transactional
// lifts proxy_mediated onto every method. Both markers on the class ⇒ both reasons.
const aopClassLevelFixture = `
package com.ex;
import org.springframework.scheduling.annotation.Async;
import org.springframework.transaction.annotation.Transactional;

@Async
@Transactional
public class Worker {
    public void run(String job) { doRun(job); }
}
`

// An @Aspect class with an @Around advice method: the class marker alone makes every method
// proxy_mediated (the advice is a generated interceptor, not a clean value-flow target).
const aopAspectFixture = `
package com.ex;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Around;

@Aspect
public class AuditAspect {
    @Around("execution(* *(..))")
    public Object trace(Object pjp) { return pjp; }
}
`

func TestAOPClassifier_SinkMarkers(t *testing.T) {
	prog := progFrom(aopFixture)
	classify := newAOPClassifier(prog)

	cases := []struct {
		name    string
		class   string
		method  string
		arity   int
		want    []string // each must be CONTAINED (never asserted as the whole set)
		notWant []string
	}{
		{name: "method @Async", class: "OrderService", method: "enqueue", arity: 1, want: []string{plugin.PartialReasonAsyncBoundary}, notWant: []string{plugin.PartialReasonProxyMediated}},
		{name: "method @Transactional", class: "OrderService", method: "charge", arity: 1, want: []string{plugin.PartialReasonProxyMediated}, notWant: []string{plugin.PartialReasonAsyncBoundary}},
		{name: "method @Cacheable", class: "OrderService", method: "lookup", arity: 1, want: []string{plugin.PartialReasonProxyMediated}},
		{name: "method @Scheduled", class: "OrderService", method: "sweep", arity: 0, want: []string{plugin.PartialReasonAsyncBoundary}},
		{name: "both markers union", class: "OrderService", method: "both", arity: 1, want: []string{plugin.PartialReasonAsyncBoundary, plugin.PartialReasonProxyMediated}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify(sinkID(t, prog, tc.class, tc.method, tc.arity))
			for _, w := range tc.want {
				if !containsReason(got, w) {
					t.Errorf("reason %q not contained in %v", w, got)
				}
			}
			for _, nw := range tc.notWant {
				if containsReason(got, nw) {
					t.Errorf("reason %q unexpectedly present in %v", nw, got)
				}
			}
		})
	}

	// Negative: an un-annotated method warrants no AOP reason.
	if got := classify(sinkID(t, prog, "OrderService", "plain", 0)); len(got) != 0 {
		t.Errorf("plain method got AOP reasons %v, want none", got)
	}
	// An id no scanned method owns is unrecognized (nil), never fabricated.
	if got := classify("not/a/real/sink#()."); got != nil {
		t.Errorf("unrecognized sink got %v, want nil", got)
	}
}

func TestAOPClassifier_ClassLevelMarkers(t *testing.T) {
	prog := progFrom(aopClassLevelFixture)
	classify := newAOPClassifier(prog)
	got := classify(sinkID(t, prog, "Worker", "run", 1))
	for _, w := range []string{plugin.PartialReasonAsyncBoundary, plugin.PartialReasonProxyMediated} {
		if !containsReason(got, w) {
			t.Errorf("class-level marker: reason %q not contained in %v", w, got)
		}
	}
}

func TestAOPClassifier_AspectClass(t *testing.T) {
	prog := progFrom(aopAspectFixture)
	classify := newAOPClassifier(prog)
	got := classify(sinkID(t, prog, "AuditAspect", "trace", 1))
	if !containsReason(got, plugin.PartialReasonProxyMediated) {
		t.Errorf("@Aspect advice: proxy_mediated not contained in %v", got)
	}
}

// TestAOPClassifier_ReasonSurfacesThroughSeam proves the reason reaches the analysis's
// partiality set through the H3 seam (firstPartyPaths), where the four overlays union into
// one reason map — so containment, never set-equality, is the correct assertion.
func TestAOPClassifier_ReasonSurfacesThroughSeam(t *testing.T) {
	prog := progFrom(aopFixture)
	sink := sinkID(t, prog, "OrderService", "charge", 1)
	ingr := sinkID(t, prog, "OrderService", "enqueue", 1)

	cg := plugin.CallGraphResult{
		Edges: []plugin.CallEdge{{Caller: sym(ingr), Callee: sym(sink)}},
		Roots: []plugin.Symbol{sym(ingr)},
	}
	ing := plugin.IngressResult{Ingresses: []plugin.Ingress{{Kind: "http_route", Symbol: sym(ingr)}}}

	// Register the real AOP factory for the duration of this test only.
	orig := len(sinkClassifiers)
	defer func() { sinkClassifiers = sinkClassifiers[:orig] }()
	registerSinkClassifier(newAOPClassifier)

	_, reasons := firstPartyPaths(prog, cg, ing, []string{sink})
	if !reasons[plugin.PartialReasonProxyMediated] {
		t.Errorf("proxy_mediated did not surface in the seam reason set %v", reasons)
	}
}
