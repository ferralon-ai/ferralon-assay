package jvmingress

import "testing"

// registry_test.go — C1 guard: the shared registry is the single source of truth for the
// JVM ingress family census. If a family is ever dropped, renamed, or duplicated, this test
// fails before any adapter's behavior silently narrows.

// wantCensus is the behavior-preserving family census from
// findings/00-registry-schema.md's table: every Name the registry must declare, and the
// Kind it must carry. Exactly 19 families — no extras, no dupes.
var wantCensus = map[string]string{
	"spring.request": KindHTTPRoute,
	"spring.get":     KindHTTPRoute,
	"spring.post":    KindHTTPRoute,
	"spring.put":     KindHTTPRoute,
	"spring.delete":  KindHTTPRoute,
	"spring.patch":   KindHTTPRoute,

	"jaxrs.path":   KindHTTPRoute,
	"jaxrs.get":    KindHTTPRoute,
	"jaxrs.post":   KindHTTPRoute,
	"jaxrs.put":    KindHTTPRoute,
	"jaxrs.delete": KindHTTPRoute,

	"scheduled":               KindScheduled,
	"event.listener":          KindEventListener,
	"lifecycle.postconstruct": KindLifecycle,
	"lifecycle.predestroy":    KindLifecycle,
	"msg.kafka":               KindMessageListener,
	"msg.jms":                 KindMessageListener,
	"msg.rabbit":              KindMessageListener,

	"servlet": KindServlet,
}

// TestFamilies_MatchesBehaviorPreservingCensus is the C1 single-source guard: every expected
// Name→Kind pair from the schema is present, there are no extra families, and no family name
// is duplicated. Drop, rename, or duplicate a family and this fails.
func TestFamilies_MatchesBehaviorPreservingCensus(t *testing.T) {
	got := Families()

	if len(got) != len(wantCensus) {
		t.Errorf("Families() returned %d families, want %d (census: %+v)", len(got), len(wantCensus), got)
	}

	seen := make(map[string]bool, len(got))
	for _, f := range got {
		if seen[f.Name] {
			t.Errorf("duplicate family Name %q in Families()", f.Name)
		}
		seen[f.Name] = true

		wantKind, known := wantCensus[f.Name]
		if !known {
			t.Errorf("unexpected family %q not in the behavior-preserving census", f.Name)
			continue
		}
		if f.Kind != wantKind {
			t.Errorf("family %q Kind = %q, want %q", f.Name, f.Kind, wantKind)
		}
	}
	for name := range wantCensus {
		if !seen[name] {
			t.Errorf("expected family %q missing from Families()", name)
		}
	}
}

// TestFamilies_DeterministicNameSortedOrder is a repeat-run determinism check (per
// determinism-tests-need-a-repeat-run-not-a-golden.md — a golden slice from one call cannot
// distinguish a stable order from one that happens to match on that call). Families() must
// return the same Name-sorted sequence across independent calls.
func TestFamilies_DeterministicNameSortedOrder(t *testing.T) {
	const repeats = 5
	var runs [][]string
	for i := 0; i < repeats; i++ {
		fams := Families()
		names := make([]string, len(fams))
		for j, f := range fams {
			names[j] = f.Name
		}
		runs = append(runs, names)
	}

	for i := 1; i < len(runs[0]); i++ {
		if runs[0][i-1] > runs[0][i] {
			t.Fatalf("Families() run 0 not Name-sorted at index %d: %q > %q (full order: %v)",
				i, runs[0][i-1], runs[0][i], runs[0])
		}
	}

	for r := 1; r < repeats; r++ {
		if len(runs[r]) != len(runs[0]) {
			t.Fatalf("run %d returned %d names, run 0 returned %d", r, len(runs[r]), len(runs[0]))
		}
		for i := range runs[0] {
			if runs[r][i] != runs[0][i] {
				t.Fatalf("run %d diverged from run 0 at index %d: %q != %q (run0=%v run%d=%v)",
					r, i, runs[r][i], runs[0][i], runs[0], r, runs[r])
			}
		}
	}
}

// TestFamilies_JaxRsAndServletHaveNoSCIPNeedle guards the behavior-preservation invariant
// (registry-schema §"the load-bearing principle"): SCIP coverage must stay exactly what it
// was pre-refactor, which means every JAX-RS family and the servlet family carry an empty
// SCIPNeedle — invisible to the SCIP adapter by construction. A future accidental needle
// addition to one of these families would silently grow the SCIP-recognized set; this test
// catches that the moment it happens.
func TestFamilies_JaxRsAndServletHaveNoSCIPNeedle(t *testing.T) {
	noNeedle := map[string]bool{
		"jaxrs.path":   true,
		"jaxrs.get":    true,
		"jaxrs.post":   true,
		"jaxrs.put":    true,
		"jaxrs.delete": true,
		"servlet":      true,
	}
	for _, f := range Families() {
		if noNeedle[f.Name] {
			if f.SCIPNeedle != "" {
				t.Errorf("family %q must carry an empty SCIPNeedle (SCIP coverage unchanged contract), got %q", f.Name, f.SCIPNeedle)
			}
			continue
		}
		if f.SCIPNeedle == "" {
			t.Errorf("family %q unexpectedly carries an empty SCIPNeedle; only JAX-RS/servlet are permitted to", f.Name)
		}
	}
}
