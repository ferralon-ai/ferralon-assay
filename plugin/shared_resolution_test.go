package plugin

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestSharedResolutionPartialityCodes pins the three cross-lane dependency-resolution partiality
// codes (onyx-q6). They are a shared wire vocabulary: a lane appends a "code:suffix" localiser to the
// reason STRING, so the base codes here must stay byte-stable — a drift silently breaks every lane
// that emits or classifies them. Pinned as literals, not as `== themselves`, so a rename fails here.
func TestSharedResolutionPartialityCodes(t *testing.T) {
	for _, tc := range []struct {
		got  string
		want string
	}{
		{PartialReasonEnvConditionUnresolved, "env_condition_unresolved"},
		{PartialReasonSourceUnpinned, "source_unpinned"},
		{PartialReasonRelationshipUnexpressed, "relationship_unexpressed"},
	} {
		if tc.got != tc.want {
			t.Errorf("partiality code = %q, want %q (cross-lane wire vocab must not drift)", tc.got, tc.want)
		}
	}
	// They compose with the suffix convention (§4 naming) without the base code changing: a localised
	// reason is the base code plus a ":suffix", and it still carries the base as its prefix.
	localised := PartialReasonEnvConditionUnresolved + ":python_version"
	if localised != "env_condition_unresolved:python_version" {
		t.Errorf("localised reason = %q, want the base code + suffix", localised)
	}
	// And they flow through the Partial() constructor like any other reason.
	p := Partial(PartialReasonSourceUnpinned, PartialReasonRelationshipUnexpressed)
	if p.Complete || len(p.Reasons) != 2 {
		t.Errorf("Partial(shared codes) = %+v, want two reasons and Complete=false", p)
	}
}

// TestResolveInventoryRequest_TargetEnvSelection proves the two additive §4.6 fields (onyx-q6) ride on
// the request, marshal under their wire tags when set, and are OMITTED when absent — so an old caller
// that sets neither produces the exact pre-onyx-q6 wire (BuildDir only), preserving behavior.
func TestResolveInventoryRequest_TargetEnvSelection(t *testing.T) {
	// Absent (zero) → only build_dir on the wire; the new keys omitempty out.
	zero, err := json.Marshal(ResolveInventoryRequest{BuildDir: "/x"})
	if err != nil {
		t.Fatalf("marshal zero: %v", err)
	}
	if got := string(zero); got != `{"build_dir":"/x"}` {
		t.Errorf("zero request wire = %s, want only build_dir (additive fields must omitempty)", got)
	}

	// Populated → round-trips both fields under their declared tags.
	req := ResolveInventoryRequest{
		BuildDir:  "/x",
		TargetEnv: map[string]string{"python_version": "3.11", "sys_platform": "linux"},
		Selection: []string{"dev", "test"},
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back ResolveInventoryRequest
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(back, req) {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", back, req)
	}
	// The override is request-carried, never sourced from BuildDir — the fields are independent inputs.
	if back.TargetEnv["python_version"] != "3.11" || len(back.Selection) != 2 {
		t.Errorf("target_env/selection lost: %+v", back)
	}
}
