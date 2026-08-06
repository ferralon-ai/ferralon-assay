package assessment

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestRecordCarriesNoTierConcept pins the boundary: the neutral carrier types describe what was
// assessed and nothing about who is paying for it or which matter it belongs to. Attribution,
// the parent-case join key, and fix-validation inputs are resolved by assessment id on the
// caller's side and must not reappear on this record — a caller adding them back here would
// re-introduce a tier concept into the engine.
func TestRecordCarriesNoTierConcept(t *testing.T) {
	s := NewMemStore()
	c, err := s.Create(sampleRequest())
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{"attribution", "case_id", "patch_validation", "owner_id"} {
		if strings.Contains(string(b), key) {
			t.Errorf("Assessment record serialized %q: %s", key, b)
		}
	}
}

// TestRequestWireUnchangedForNeutralFields: the four neutral blocks keep the tags they have
// always had, so removing the lifecycle fields did not disturb the submit wire.
func TestRequestWireUnchangedForNeutralFields(t *testing.T) {
	b, err := json.Marshal(sampleRequest())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"vulnerability":{"id":"GO-2021-0001","source":"osv"},` +
		`"codebase":{"repo":"github.com/acme/app","revision":"abc123","acquisition":{}},` +
		`"execution":{"kind":"compose"},"ownership_proof":{"token":"tok-123"}}`
	if string(b) != want {
		t.Fatalf("Request JSON =\n%s\nwant\n%s", b, want)
	}
}
