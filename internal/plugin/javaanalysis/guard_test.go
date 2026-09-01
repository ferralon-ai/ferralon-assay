package javaanalysis

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// guardSink mints the SCIP id the guard classifier keys on for a method, matching
// how newGuardClassifier derives the sink id from the declaring sourceClass.
func guardSink(pkg string, enclosing []string, name string, arity int) string {
	return methodSCIP(pkg, enclosing, name, arity)
}

// TestGuardClassifier_Markers proves the #5 markers each raise guard_unknown for
// the guarded sink and nothing for an unguarded one. assert-CONTAINS: a case that
// expects the reason only checks presence, never set-equality.
func TestGuardClassifier_Markers(t *testing.T) {
	// A method-level @PreAuthorize sink.
	preAuth := sourceClass{
		pkg:       "com.app",
		enclosing: []string{"AccountSvc"},
		methods: []sourceMethod{
			{name: "delete", arity: 1, annos: []parsedAnno{{name: "PreAuthorize", value: "hasRole('ADMIN')"}}},
			{name: "read", arity: 1}, // sibling, unguarded
		},
	}
	// A class-level @Secured guards every method it declares.
	classSecured := sourceClass{
		pkg:        "com.app",
		enclosing:  []string{"AdminSvc"},
		classAnnos: []parsedAnno{{name: "Secured"}},
		methods:    []sourceMethod{{name: "purge", arity: 0}},
	}
	// @RolesAllowed via its simple name (spans javax↔jakarta identically).
	rolesAllowed := sourceClass{
		pkg:       "com.app",
		enclosing: []string{"BillingSvc"},
		methods:   []sourceMethod{{name: "charge", arity: 2, annos: []parsedAnno{{name: "RolesAllowed"}}}},
	}
	// A OncePerRequestFilter supertype marks every method on the request path.
	filterType := sourceClass{
		pkg:       "com.app",
		enclosing: []string{"AuthFilter"},
		supers:    []string{"OncePerRequestFilter"},
		methods:   []sourceMethod{{name: "doFilterInternal", arity: 3}},
	}
	// A plain first-party class with no control — must never raise guard_unknown.
	plain := sourceClass{
		pkg:       "com.app",
		enclosing: []string{"EchoSvc"},
		methods:   []sourceMethod{{name: "echo", arity: 1}},
	}

	prog := &program{sourceClasses: []sourceClass{preAuth, classSecured, rolesAllowed, filterType, plain}}
	classify := newGuardClassifier(prog)

	cases := []struct {
		name    string
		sink    string
		guarded bool
	}{
		{"method @PreAuthorize", guardSink("com.app", []string{"AccountSvc"}, "delete", 1), true},
		{"unguarded sibling method", guardSink("com.app", []string{"AccountSvc"}, "read", 1), false},
		{"class @Secured", guardSink("com.app", []string{"AdminSvc"}, "purge", 0), true},
		{"@RolesAllowed simple name", guardSink("com.app", []string{"BillingSvc"}, "charge", 2), true},
		{"OncePerRequestFilter supertype", guardSink("com.app", []string{"AuthFilter"}, "doFilterInternal", 3), true},
		{"plain sink", guardSink("com.app", []string{"EchoSvc"}, "echo", 1), false},
		{"empty id", "", false},
		{"unknown id", "com.app/Nope#gone().", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reasons := classify(tc.sink)
			got := containsReason(reasons, plugin.PartialReasonGuardUnknown)
			if got != tc.guarded {
				t.Fatalf("guard_unknown = %v, want %v (reasons %v)", got, tc.guarded, reasons)
			}
		})
	}
}

// TestGuardClassifier_EmptyProgram proves the classifier is inert on an empty/nil
// program — the default behavior stays byte-identical.
func TestGuardClassifier_EmptyProgram(t *testing.T) {
	if r := newGuardClassifier(&program{})("anything"); r != nil {
		t.Errorf("empty program leaked reasons: %v", r)
	}
	if r := newGuardClassifier(nil)("anything"); r != nil {
		t.Errorf("nil program leaked reasons: %v", r)
	}
}

// TestGuard_NeverRemovesReachabilityReason is the inv.5 invariant: on a guarded
// sink with NO reaching ingress, firstPartyPaths must surface guard_unknown AND
// still carry no_known_ingress — the guard ADDS partiality, it never downgrades
// exploitability or suppresses a reachability reason. assert-CONTAINS on both.
func TestGuard_NeverRemovesReachabilityReason(t *testing.T) {
	sinkID := guardSink("com.app", []string{"AccountSvc"}, "delete", 1)
	prog := &program{sourceClasses: []sourceClass{{
		pkg:       "com.app",
		enclosing: []string{"AccountSvc"},
		methods:   []sourceMethod{{name: "delete", arity: 1, annos: []parsedAnno{{name: "PreAuthorize"}}}},
	}}}

	// No ingress reaches the sink: an edge exists but not from the ingress/root set,
	// so reachPathToSink fails and no_known_ingress must be raised.
	cg := plugin.CallGraphResult{
		Edges: []plugin.CallEdge{{Caller: sym("other"), Callee: sym(sinkID)}},
	}
	ing := plugin.IngressResult{}

	_, reasons := firstPartyPaths(prog, cg, ing, []string{sinkID})

	if !reasons[plugin.PartialReasonGuardUnknown] {
		t.Error("guard_unknown not surfaced for the guarded sink")
	}
	if !reasons[plugin.PartialReasonNoIngress] {
		t.Error("no_known_ingress was removed/absent — the guard must never suppress a reachability reason (inv.5)")
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
