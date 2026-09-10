package javaanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Container-invoked entrypoint discovery (GRANITE / finding G1). Spring invokes
// @Scheduled/@EventListener/@PostConstruct/@KafkaListener methods with NO
// syntactic caller, so a sink reachable only through one is falsely unreachable
// unless the method is seeded as a reachability root. These tests are the honesty
// twin of spring_lexical_test.go: they assert the lexical scanner recognizes the
// entrypoints and that seeding them makes an otherwise-dead sink reachable — while
// leaving un-annotated methods out (no over-seeding).

// TestFindIngresses_ContainerEntrypointsDetected asserts each container-invoked
// annotation is recognized as an ingress with its own Kind, and that an
// un-annotated method on the same class is NOT an ingress.
func TestFindIngresses_ContainerEntrypointsDetected(t *testing.T) {
	src := `
package com.example.jobs;
class Workers {
    @Scheduled(fixedRate = 1000)
    void reconcile() {}

    @EventListener
    void onEvent(Object e) {}

    @PostConstruct
    void init() {}

    @PreDestroy
    void shutdown() {}

    @KafkaListener(topics = "t")
    void consume(String msg) {}

    void notAnEntrypoint() {}
}
`
	dir := writeProgram(t, map[string]string{"Workers.java": src})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	for _, want := range []struct {
		method string
		arity  int
		kind   string
	}{
		{"reconcile", 0, "scheduled"},
		{"onEvent", 1, "event_listener"},
		{"init", 0, "lifecycle"},
		{"shutdown", 0, "lifecycle"},
		{"consume", 1, "message_listener"},
	} {
		sym := methodSCIP("com.example.jobs", []string{"Workers"}, want.method, want.arity)
		in, ok := ingressFor(res.Ingresses, sym)
		if !ok {
			t.Errorf("%s not found as ingress; got %+v", want.method, res.Ingresses)
			continue
		}
		if in.Kind != want.kind {
			t.Errorf("%s ingress kind = %q, want %q", want.method, in.Kind, want.kind)
		}
	}
	plain := methodSCIP("com.example.jobs", []string{"Workers"}, "notAnEntrypoint", 0)
	if _, ok := ingressFor(res.Ingresses, plain); ok {
		t.Errorf("un-annotated method notAnEntrypoint was reported as an ingress")
	}
}

// TestScheduledEntrypoint_ReachesSink is the reachability property: a sink reached
// ONLY through a @Scheduled method (no other in-tree caller, no HTTP/servlet
// ingress) is reverse-reachable from the ingress/root set precisely because the
// scheduled method is seeded as an entrypoint. Mirrors the firstParty/Spring
// integration wiring (FindIngresses + CallGraph + reverseReachable). Without the
// container-entrypoint seeding this sink would be a false "unreachable".
func TestScheduledEntrypoint_ReachesSink(t *testing.T) {
	src := `
package com.example.jobs;
class ReconcileJob {
    @Scheduled(fixedRate = 60000)
    void reconcile() {
        sink();
    }
    void sink() {}
}
`
	dir := writeProgram(t, map[string]string{"ReconcileJob.java": src})
	ctx := context.Background()

	cg, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}

	entries := map[string]bool{}
	for _, in := range ing.Ingresses {
		entries[in.Symbol.SCIP] = true
	}
	for _, r := range cg.Roots {
		entries[r.SCIP] = true
	}

	reconcile := methodSCIP("com.example.jobs", []string{"ReconcileJob"}, "reconcile", 0)
	if !entries[reconcile] {
		t.Fatalf("@Scheduled reconcile is not an ingress/root entry; entries=%v", entries)
	}
	sink := methodSCIP("com.example.jobs", []string{"ReconcileJob"}, "sink", 0)
	if !reverseReachable(cg.Edges, entries, sink) {
		t.Fatalf("sink not reachable from the @Scheduled entrypoint;\nentries=%v\nedges=%+v", entries, cg.Edges)
	}
}

// TestIngressAnnotation_SCIPClassification exercises the SCIP-space classifier
// (the twin of the lexical containerEntrypoints map) directly against scip-java
// annotation-type symbol strings, so the SCIP ingress path is covered without a
// full committed index fixture. A mapping annotation classifies as http_route; a
// container annotation classifies to its Kind; an ordinary method symbol does not.
func TestIngressAnnotation_SCIPClassification(t *testing.T) {
	for _, tc := range []struct {
		sym      string
		wantKind string
		wantOK   bool
	}{
		{"scip-java maven org.springframework 6.0 org/springframework/web/bind/annotation/GetMapping#", "http_route", true},
		{"scip-java maven org.springframework 6.0 org/springframework/scheduling/annotation/Scheduled#", "scheduled", true},
		{"scip-java maven org.springframework 6.0 org/springframework/context/event/EventListener#", "event_listener", true},
		{"scip-java maven jakarta.annotation 2.1 jakarta/annotation/PostConstruct#", "lifecycle", true},
		{"scip-java maven jakarta.annotation 2.1 jakarta/annotation/PreDestroy#", "lifecycle", true},
		{"scip-java maven org.springframework.kafka 3.0 org/springframework/kafka/annotation/KafkaListener#", "message_listener", true},
		{"scip-java maven com.example 0.0.1 com/example/web/UrlServiceImpl#fetch().", "", false},
	} {
		kind, _, ok := ingressAnnotation(tc.sym)
		if ok != tc.wantOK || kind != tc.wantKind {
			t.Errorf("ingressAnnotation(%q) = (%q, %v), want (%q, %v)", tc.sym, kind, ok, tc.wantKind, tc.wantOK)
		}
	}
}
