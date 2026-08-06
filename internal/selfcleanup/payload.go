package selfcleanup

import "encoding/json"

// RescanEventAction is the repository_dispatch event type the backend fires when a
// Dependabot alert should trigger an advisory re-scan (design-constants contract).
const RescanEventAction = "ferralon-advisory-rescan"

// RescanSchema is the client_payload schema string (v1).
const RescanSchema = "ferralon.rescan/v1"

// RescanPayload is the decoded github.event.client_payload for a
// ferralon-advisory-rescan repository_dispatch (schema v1). It is correlation
// metadata: the scanner threads Reason/GHSAID into the run summary and forwards them
// on the ingest POST so the platform can tie the scan back to the alert that
// triggered it. It never changes WHAT is scanned — a rescan is a normal scan with a
// known cause.
type RescanPayload struct {
	Schema      string `json:"schema"`
	Reason      string `json:"reason"`
	GHSAID      string `json:"ghsa_id"`
	AlertNumber int    `json:"alert_number"`
	Package     struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Severity     string `json:"severity"`
	DispatchedAt string `json:"dispatched_at"`
}

// ParseRescanPayload decodes the client_payload of a repository_dispatch run. action
// is github.event.action; clientPayload is the raw github.event.client_payload JSON.
// It returns (payload, true) only for a well-formed rescan dispatch carrying at least
// a reason or a GHSA id; for any other event, absent payload, or malformed JSON it
// returns (nil, false) — the caller then falls back to a normal scan. Parsing is
// deliberately lenient on the schema string (a future schema bump must not silently
// drop the correlation metadata) but strict on JSON validity.
func ParseRescanPayload(action string, clientPayload []byte) (*RescanPayload, bool) {
	if action != RescanEventAction || len(clientPayload) == 0 {
		return nil, false
	}
	var p RescanPayload
	if err := json.Unmarshal(clientPayload, &p); err != nil {
		return nil, false
	}
	if p.Reason == "" && p.GHSAID == "" {
		return nil, false
	}
	return &p, true
}
