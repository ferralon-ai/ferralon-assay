package trigger

// Hermetic tests for guard-on-path evidence (assess.go): symbolLeaf's SCIP-id parsing
// and guardsOnPath's intersection of advisory-declared guards with the call-graph callees
// of frames on the candidate trace. No network, no Docker — the artifact store is an
// in-memory MemStore seeded with the two artifacts guardsOnPath reads (S1 normalized
// advisory + S5 reachability call graph).

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestSymbolLeaf covers the self-emitted SCIP id forms symbolLeaf must reduce to the bare
// function/method name: package function, receiver method, and the degenerate empty input.
func TestSymbolLeaf(t *testing.T) {
	cases := []struct {
		name string
		scip string
		want string
	}{
		{"package func", "scip-go gomod m . pkg/fn().", "fn"},
		{"receiver method", "scip-go gomod m . pkg/Recv#Method().", "Method"},
		{"nested package path", "scip-go gomod m . internal/x/y/isRepositoryGitPath().", "isRepositoryGitPath"},
		{"no trailing call parens", "scip-go gomod m . pkg/Const.", "Const"},
		{"bare leaf", "fn()", "fn"},
		{"js arity-disambiguated func", "scip-typescript npm . . src/app/ensureNoUnsafeProperties(1).", "ensureNoUnsafeProperties"},
		{"js zero-arity func", "scip-typescript npm . . src/app/renderTsvb().", "renderTsvb"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := symbolLeaf(tc.scip); got != tc.want {
				t.Errorf("symbolLeaf(%q) = %q; want %q", tc.scip, got, tc.want)
			}
		})
	}
}

// TestGuardsOnPath proves guardsOnPath surfaces only the advisory-declared guards that the
// call graph shows being called from a frame ON the trace, in the advisory's declared order.
// Two guards are declared; only one (isRepositoryGitPath) is a callee of the on-path frame,
// so only it is reported — presence narrows attention, it is never a verdict (inv. 5).
func TestGuardsOnPath(t *testing.T) {
	const assessmentID = "01900000-0000-7000-8000-000000000099"
	const frameSym = "scip-go gomod m . pkg/serveHTTP()."

	store := artifact.NewMemStore()
	put := func(typ artifact.Type, payload string) {
		t.Helper()
		if _, err := store.Put(&artifact.Artifact{
			AssessmentID: assessmentID,
			Type:         typ,
			Payload:      []byte(payload),
		}); err != nil {
			t.Fatalf("Put %s: %v", typ, err)
		}
	}

	// S1 normalized advisory declares two mitigating guards.
	put(artifact.TypeNormalizedAdvisory, `{"advisory_guards":["isRepositoryGitPath","hasSymlinkInPath"]}`)
	// S5 reachability records the call graph; the on-path frame calls only one of them.
	put(artifact.TypeReachability, `{"call_graph":{"edges":[`+
		`{"caller":{"scip":"`+frameSym+`"},"callee":{"scip":"scip-go gomod m . pkg/isRepositoryGitPath()."}},`+
		`{"caller":{"scip":"scip-go gomod m . pkg/other()."},"callee":{"scip":"scip-go gomod m . pkg/hasSymlinkInPath()."}}`+
		`]}}`)

	frames := []report.CallFrame{{Symbol: frameSym}}
	got := guardsOnPath(store, assessmentID, frames)

	want := []string{"isRepositoryGitPath"}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("guardsOnPath = %v; want %v (only the on-path declared guard, in declared order)", got, want)
	}
}

// TestGuardsOnPath_NoneOnPath proves the off-path guard is not reported: hasSymlinkInPath is a
// declared guard and a call-graph callee, but its caller is not a frame on the trace.
func TestGuardsOnPath_NoneOnPath(t *testing.T) {
	const assessmentID = "01900000-0000-7000-8000-0000000000a0"

	store := artifact.NewMemStore()
	put := func(typ artifact.Type, payload string) {
		t.Helper()
		if _, err := store.Put(&artifact.Artifact{AssessmentID: assessmentID, Type: typ, Payload: []byte(payload)}); err != nil {
			t.Fatalf("Put %s: %v", typ, err)
		}
	}
	put(artifact.TypeNormalizedAdvisory, `{"advisory_guards":["hasSymlinkInPath"]}`)
	put(artifact.TypeReachability, `{"call_graph":{"edges":[`+
		`{"caller":{"scip":"scip-go gomod m . pkg/offPath()."},"callee":{"scip":"scip-go gomod m . pkg/hasSymlinkInPath()."}}`+
		`]}}`)

	got := guardsOnPath(store, assessmentID, []report.CallFrame{{Symbol: "scip-go gomod m . pkg/onPath()."}})
	if len(got) != 0 {
		t.Fatalf("guardsOnPath = %v; want none (the guard's caller is not on the trace)", got)
	}
}

// TestGuardsOnPath_EmptyDeclared_AssertsNothing is the A4 honest-absent pin (cycle 2026-08-24
// corpus-scaffold): guard_symbols is data-empty across the corpus today, so an EMPTY declared-guard
// set must surface NO guards — even against a fully populated call graph whose on-path frame really
// does call a would-be guard. Emptiness is the absence of a mitigating-evidence claim, never a
// verdict input: this must not collapse to "no guards ⇒ nothing mitigates ⇒ affected". Both the
// absent (`advisory_guards` key omitted) and the explicit-empty (`[]`) shapes are covered, since the
// omitempty projection can emit either. The mirror case — a FUTURE non-empty set IS handled — is
// TestGuardsOnPath above; the same code path serves both, so no assume-absent shortcut exists to
// regress into.
func TestGuardsOnPath_EmptyDeclared_AssertsNothing(t *testing.T) {
	const frameSym = "scip-go gomod m . pkg/serveHTTP()."
	// A rich call graph whose on-path frame calls a function that WOULD be a guard if declared —
	// so a nil result can only come from the empty declared set, not from a barren graph.
	const reachability = `{"call_graph":{"edges":[` +
		`{"caller":{"scip":"` + frameSym + `"},"callee":{"scip":"scip-go gomod m . pkg/isRepositoryGitPath()."}}` +
		`]}}`

	cases := []struct {
		name    string
		advJSON string // the S1 normalized_advisory payload
	}{
		{"guards key absent", `{"vuln_id":"CVE-X"}`},
		{"guards explicitly empty", `{"advisory_guards":[]}`},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assessmentID := "01900000-0000-7000-8000-0000000000b" + string(rune('0'+i))
			store := artifact.NewMemStore()
			put := func(typ artifact.Type, payload string) {
				t.Helper()
				if _, err := store.Put(&artifact.Artifact{AssessmentID: assessmentID, Type: typ, Payload: []byte(payload)}); err != nil {
					t.Fatalf("Put %s: %v", typ, err)
				}
			}
			put(artifact.TypeNormalizedAdvisory, tc.advJSON)
			put(artifact.TypeReachability, reachability)

			got := guardsOnPath(store, assessmentID, []report.CallFrame{{Symbol: frameSym}})
			if len(got) != 0 {
				t.Fatalf("guardsOnPath = %v; want none — an empty declared-guard set must assert nothing, even against a matching call graph (honest-absent, inv.5)", got)
			}
		})
	}
}
