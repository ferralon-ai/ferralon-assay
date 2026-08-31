package kotlinanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// taint_test.go — mirrors javaanalysis/taint_test.go on the Kotlin lane's bytecode fixtures.
// ComputeTaint is call-graph PATH PRESENCE over the Kotlin/JVM call graph, so the fixtures
// are the SAME emitted-.class programs the reachability/Spring tests use, driven through the
// real classfile parser, CallGraph, and FindIngresses. Two partiality states are exercised:
// a Spring ingress→sink path (tainted, Complete) and a present-but-unreached sink
// (no_known_ingress UNKNOWN); the PrecisionNote is asserted set in every case.

// TestComputeTaint_PathPresentFromIngress is the tainted case: a @RestController handler
// invokestatic-calls the sink, so a framework-ingress→sink path exists over the Kotlin call
// graph. The path is emitted with the http handler as its ingress and, since the ingress is
// attacker-facing (not a bare program root), the result is Complete.
func TestComputeTaint_PathPresentFromIngress(t *testing.T) {
	dir := buildController(t)

	res, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{
		BuildDir: dir,
		Sinks:    []string{"com/example/dep/UrlFetcher.fetch()V"},
	})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	if res.PrecisionNote == "" {
		t.Error("taint result must carry a precision note recording the path-presence limit")
	}
	if len(res.Paths) != 1 {
		t.Fatalf("expected one path-presence path, got %d: %+v", len(res.Paths), res.Paths)
	}
	p := res.Paths[0]
	if p.Ingress.Name != "handle" {
		t.Errorf("taint path ingress = %+v, want Name=handle", p.Ingress)
	}
	if p.Sink.Name != "fetch" {
		t.Errorf("taint path sink = %+v, want Name=fetch", p.Sink)
	}
	if len(p.Trace) < 2 || p.Trace[0].Name != "handle" || p.Trace[len(p.Trace)-1].Name != "fetch" {
		t.Errorf("taint trace not ordered ingress->sink: %+v", p.Trace)
	}
	if !res.Partiality.Complete {
		t.Errorf("fully-resolved ingress path presence should be Complete, got %+v", res.Partiality)
	}
}

// TestComputeTaint_NoPathIsNoKnownIngress is the honest-partiality control (inv.5): the sink
// method genuinely exists in the compiled program but no call edge from any ingress reaches
// it. Taint must NOT render that as "not tainted" (the Reachability op's sound-negative arm)
// — it declares no_known_ingress UNKNOWN and emits no path.
func TestComputeTaint_NoPathIsNoKnownIngress(t *testing.T) {
	dir := buildControllerWithOrphan(t)

	res, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{
		BuildDir: dir,
		Sinks:    []string{"com/example/dep/UrlFetcher.orphan()V"},
	})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	if len(res.Paths) != 0 {
		t.Errorf("orphan sink must yield no path, got %+v", res.Paths)
	}
	if res.Partiality.Complete {
		t.Errorf("no path is UNKNOWN, must not be Complete (inv.5)")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonNoIngress) {
		t.Errorf("no path must declare no_known_ingress, got %+v", res.Partiality)
	}
	if res.PrecisionNote == "" {
		t.Error("precision note must be set even when no path is found")
	}
}

// TestComputeTaint_MissingBuildDirIsHardError: a nonexistent build dir is a malformed
// request, a HARD error (inv.4), not declared partiality — surfaced by loadProgram via the
// underlying CallGraph op.
func TestComputeTaint_MissingBuildDirIsHardError(t *testing.T) {
	_, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{BuildDir: "testdata/does-not-exist"})
	if err == nil {
		t.Fatal("expected a hard error for a nonexistent build dir")
	}
}

// buildControllerWithOrphan emits the same @RestController→dependency shape as
// buildController, but the dependency class also carries an `orphan` method that no ingress
// calls — the present-but-unreached sink the no_known_ingress control queries.
func buildControllerWithOrphan(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	ctrl := newKClassBuilder()
	ctrl.addClassAnnotation(ctrl.anno(descRestController))
	handlerCode := ctrl.invokeStatic("com/example/dep/UrlFetcher", "fetch", "()V")
	handlerCode = append(handlerCode, opReturn)
	ctrl.addMethodAnnotated("handle", "()V", handlerCode,
		ctrl.anno(descGetMapping, kannoElem{name: "value", value: "/fetch"}))
	writeClassFixture(t, dir, "com/example/api/UserController",
		ctrl.build("com/example/api/UserController", "java/lang/Object"))

	dep := newKClassBuilder()
	dep.addMethod("fetch", "()V", []byte{opReturn})
	dep.addMethod("orphan", "()V", []byte{opReturn}) // present, but called by nothing
	writeClassFixture(t, dir, "com/example/dep/UrlFetcher",
		dep.build("com/example/dep/UrlFetcher", "java/lang/Object"))

	return dir
}
