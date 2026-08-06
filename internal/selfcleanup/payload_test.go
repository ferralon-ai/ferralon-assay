package selfcleanup

import "testing"

const validRescan = `{
  "schema": "ferralon.rescan/v1",
  "reason": "dependabot_alert",
  "ghsa_id": "GHSA-1234-5678-9abc",
  "alert_number": 7,
  "package": {"ecosystem": "npm", "name": "left-pad"},
  "severity": "high",
  "dispatched_at": "2026-07-09T16:50:00Z"
}`

func TestParseRescanValid(t *testing.T) {
	p, ok := ParseRescanPayload(RescanEventAction, []byte(validRescan))
	if !ok {
		t.Fatal("valid rescan payload must parse")
	}
	if p.Reason != "dependabot_alert" || p.GHSAID != "GHSA-1234-5678-9abc" {
		t.Fatalf("fields wrong: %+v", p)
	}
	if p.AlertNumber != 7 || p.Package.Ecosystem != "npm" || p.Package.Name != "left-pad" {
		t.Fatalf("nested fields wrong: %+v", p)
	}
}

func TestParseRescanWrongEventFallsBack(t *testing.T) {
	if _, ok := ParseRescanPayload("push", []byte(validRescan)); ok {
		t.Fatal("non-rescan event must fall back (ok=false)")
	}
}

func TestParseRescanAbsentPayloadFallsBack(t *testing.T) {
	if _, ok := ParseRescanPayload(RescanEventAction, nil); ok {
		t.Fatal("absent payload must fall back")
	}
	if _, ok := ParseRescanPayload(RescanEventAction, []byte("")); ok {
		t.Fatal("empty payload must fall back")
	}
}

func TestParseRescanMalformedFallsBack(t *testing.T) {
	if _, ok := ParseRescanPayload(RescanEventAction, []byte("{not json")); ok {
		t.Fatal("malformed JSON must fall back, not panic")
	}
}

func TestParseRescanEmptyMetadataFallsBack(t *testing.T) {
	// Well-formed JSON but no reason and no ghsa_id → nothing to correlate.
	if _, ok := ParseRescanPayload(RescanEventAction, []byte(`{"schema":"ferralon.rescan/v1"}`)); ok {
		t.Fatal("payload with no reason/ghsa must fall back")
	}
}

func TestParseRescanToleratesSchemaBump(t *testing.T) {
	// A future schema string must not drop the correlation metadata.
	p, ok := ParseRescanPayload(RescanEventAction, []byte(`{"schema":"ferralon.rescan/v2","reason":"manual"}`))
	if !ok || p.Reason != "manual" {
		t.Fatalf("schema bump must still yield metadata, got ok=%v p=%+v", ok, p)
	}
}
