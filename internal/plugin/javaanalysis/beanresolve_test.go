package javaanalysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// writeModule writes name→source files into a fresh temp build dir and returns it.
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func hasEdgeContaining(edges []plugin.CallEdge, callerSub, calleeSub string) bool {
	for _, e := range edges {
		if strings.Contains(e.Caller.SCIP, callerSub) && strings.Contains(e.Callee.SCIP, calleeSub) {
			return true
		}
	}
	return false
}

// TestBeanGraph_UniqueImplResolvesEdge: an @Autowired interface field with a single
// concrete impl is bridged — the resolved caller→impl edge appears and dynamic_dispatch
// is retired for that (sole) unresolved call.
func TestBeanGraph_UniqueImplResolvesEdge(t *testing.T) {
	t.Setenv(scipAnalyzerImageEnv, "")
	dir := writeModule(t, map[string]string{
		"Greeter.java":     `package com.ex; interface Greeter { String greet(); }`,
		"GreeterImpl.java": `package com.ex; @Service class GreeterImpl implements Greeter { public String greet(){ return here(); } String here(){ return ""; } }`,
		"Hello.java":       `package com.ex; @RestController class Hello { @Autowired Greeter greeter; @GetMapping("/h") String h(){ return greeter.greet(); } }`,
	})

	cg, err := CallGraph(t.Context(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if !hasEdgeContaining(cg.Edges, "Hello#h", "GreeterImpl#greet") {
		t.Errorf("resolved bean edge Hello.h → GreeterImpl.greet not emitted; edges=%+v", cg.Edges)
	}
	// The interface hop was the only unresolved dispatch → dynamic_dispatch retired.
	if hasReason(cg.Partiality, plugin.PartialReasonDynamicDispatch) {
		t.Errorf("dynamic_dispatch not retired though the sole unresolved dispatch was bean-resolved: %+v", cg.Partiality)
	}
}

// TestBeanGraph_AmbiguousStaysPartial: two impls of an interface with no @Primary/
// @Qualifier is honest residue — NO edge is emitted, dynamic_dispatch survives, and the
// bean_ambiguous localizer is declared. inv.5: never guess a bean.
func TestBeanGraph_AmbiguousStaysPartial(t *testing.T) {
	t.Setenv(scipAnalyzerImageEnv, "")
	dir := writeModule(t, map[string]string{
		"Mailer.java":     `package com.ex; interface Mailer { void send(); }`,
		"SmtpMailer.java": `package com.ex; @Service class SmtpMailer implements Mailer { public void send(){} }`,
		"SesMailer.java":  `package com.ex; @Service class SesMailer implements Mailer { public void send(){} }`,
		"Notifier.java":   `package com.ex; @Service class Notifier { @Autowired Mailer mailer; void go(){ mailer.send(); } }`,
	})

	cg, err := CallGraph(t.Context(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if hasEdgeContaining(cg.Edges, "Notifier#go", "Mailer#send") {
		t.Errorf("an ambiguous injection was guessed to an edge (inv.5 violation); edges=%+v", cg.Edges)
	}
	if !hasReason(cg.Partiality, plugin.PartialReasonDynamicDispatch) {
		t.Errorf("dynamic_dispatch wrongly retired on an ambiguous dispatch: %+v", cg.Partiality)
	}
	if !hasReason(cg.Partiality, plugin.PartialReasonBeanAmbiguous) {
		t.Errorf("bean_ambiguous localizer not declared for the ambiguous injection: %+v", cg.Partiality)
	}
}

// TestBeanGraph_PrimaryResolvesAmbiguity: the same two impls, but one @Primary, resolves
// to a unique edge — confirming @Primary is honored and the edge lands.
func TestBeanGraph_PrimaryResolvesAmbiguity(t *testing.T) {
	t.Setenv(scipAnalyzerImageEnv, "")
	dir := writeModule(t, map[string]string{
		"Mailer.java":     `package com.ex; interface Mailer { void send(); }`,
		"SmtpMailer.java": `package com.ex; @Service @Primary class SmtpMailer implements Mailer { public void send(){} }`,
		"SesMailer.java":  `package com.ex; @Service class SesMailer implements Mailer { public void send(){} }`,
		"Notifier.java":   `package com.ex; @Service class Notifier { @Autowired Mailer mailer; void go(){ mailer.send(); } }`,
	})

	cg, err := CallGraph(t.Context(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if !hasEdgeContaining(cg.Edges, "Notifier#go", "SmtpMailer#send") {
		t.Errorf("@Primary impl edge Notifier.go → SmtpMailer.send not emitted; edges=%+v", cg.Edges)
	}
	// Two concrete send/0 impls remain, so dynamic_dispatch is NOT retired even though an
	// edge was added — retirement requires the wired impl be the SOLE concrete target.
	if !hasReason(cg.Partiality, plugin.PartialReasonDynamicDispatch) {
		t.Errorf("dynamic_dispatch retired though a second concrete send/0 competitor exists: %+v", cg.Partiality)
	}
}
