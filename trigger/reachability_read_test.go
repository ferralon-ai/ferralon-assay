package trigger

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestReachabilityReadersOnBadLegs pins the trigger's reachability readers on payloads whose legs
// are malformed, type-mismatched or absent: each reads exactly as the narrow json.Unmarshal of
// its own leg did, so a leg that cannot be read is absent, never a zero value reported present.
func TestReachabilityReadersOnBadLegs(t *testing.T) {
	const aid = "01900000-0000-7000-8000-000000000043"
	validReach := `{"partiality":{"complete":true},"paths":[{"sink":{"scip":"s"}}],"searched":["s"]}`
	validCG := `{"partiality":{"complete":true},"edges":[{"caller":{"scip":"a"},"callee":{"scip":"b"}}]}`
	tests := []struct {
		name    string
		payload string
		// Expected outcomes, each the one the old narrow decode gave.
		wantCG, wantEmptyUncalled, wantReach, wantFirstPath bool
	}{
		{"malformed payload", `{"reachability":` + validReach + `,"call_graph":{`, false, false, false, false},
		{"call graph leg type-mismatched", `{"reachability":` + validReach + `,"call_graph":{"edges":7}}`, false, false, true, true},
		{"call graph leg absent", `{"reachability":` + validReach + `}`, true, true, true, true},
		{"reachability leg type-mismatched", `{"reachability":{"paths":"x","searched":["s"]},"call_graph":` + validCG + `}`, true, false, false, false},
		{"reachability leg absent", `{"call_graph":` + validCG + `}`, true, false, true, false},
		{"both legs type-mismatched", `{"reachability":{"searched":["s"],"paths":"x"},"call_graph":{"partiality":{"complete":true},"edges":7}}`, false, false, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			if _, err := store.Put(&artifact.Artifact{AssessmentID: aid, Type: artifact.TypeReachability, Payload: []byte(tc.payload)}); err != nil {
				t.Fatal(err)
			}

			cg, ok := callGraph(store, aid)
			var cgOnly struct {
				CallGraph plugin.CallGraphResult `json:"call_graph"`
			}
			oldCGOK := json.Unmarshal([]byte(tc.payload), &cgOnly) == nil
			if ok != tc.wantCG || ok != oldCGOK {
				t.Errorf("callGraph ok = %v, want %v (old decode %v)", ok, tc.wantCG, oldCGOK)
			}
			if !ok && cg.EdgeCount() != 0 {
				t.Errorf("callGraph reported absent but carries %d edges", cg.EdgeCount())
			}
			if ok && cg.EdgeCount() != len(cgOnly.CallGraph.Edges) {
				t.Errorf("callGraph edges = %d, want %d", cg.EdgeCount(), len(cgOnly.CallGraph.Edges))
			}
			oldEmpty := oldCGOK && len(cgOnly.CallGraph.Edges) == 0 && !cgOnly.CallGraph.Partiality.Complete
			if got := emptyGraphUncalledComplete(store, aid); got != tc.wantEmptyUncalled || got != oldEmpty {
				t.Errorf("emptyGraphUncalledComplete = %v, want %v (old decode %v)", got, tc.wantEmptyUncalled, oldEmpty)
			}

			reach, ok := reachabilityResult(store, aid)
			var reachOnly struct {
				Reachability plugin.ReachabilityResult `json:"reachability"`
			}
			oldReachOK := json.Unmarshal([]byte(tc.payload), &reachOnly) == nil
			if ok != tc.wantReach || ok != oldReachOK {
				t.Errorf("reachabilityResult ok = %v, want %v (old decode %v)", ok, tc.wantReach, oldReachOK)
			}
			if !ok && !reflect.DeepEqual(reach, plugin.ReachabilityResult{}) {
				t.Errorf("reachabilityResult reported absent but carries %+v", reach)
			}
			if ok && !reflect.DeepEqual(reach, reachOnly.Reachability) {
				t.Errorf("reachabilityResult = %+v, want %+v", reach, reachOnly.Reachability)
			}
			oldFirst := oldReachOK && len(reachOnly.Reachability.Paths) > 0
			if _, got := firstReachPath(store, aid); got != tc.wantFirstPath || got != oldFirst {
				t.Errorf("firstReachPath ok = %v, want %v (old decode %v)", got, tc.wantFirstPath, oldFirst)
			}
		})
	}
}
