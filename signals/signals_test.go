package signals_test

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/signals"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

const doc = `{
  "signals_version": "1.0.0",
  "record_count": 1,
  "signals_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "records": [{"identifier": "CVE-2025-8110", "epss": {"score": 0.91, "as_of": "2026-10-19"}}]
}`

// TestParseFeedsEveryTriggerRequest: a value parsed from outside the module is the very type every
// trigger request's Signals field takes, and it carries the file's values.
func TestParseFeedsEveryTriggerRequest(t *testing.T) {
	s, err := signals.Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	baseline := trigger.BaselineRequest{Signals: s}
	_ = trigger.PRInheritRequest{Signals: s}
	_ = trigger.CVEWatchRequest{Signals: s}

	e, ok := baseline.Signals.EPSS("CVE-2025-8110")
	if !ok {
		t.Fatal("EPSS lookup missed CVE-2025-8110")
	}
	if e.Score != 0.91 || e.AsOf != "2026-10-19" {
		t.Errorf("EPSS = %+v; want score 0.91 as of 2026-10-19", e)
	}
}

// TestParseRejectsOtherMajor: the public entry point keeps intel's version gate.
func TestParseRejectsOtherMajor(t *testing.T) {
	_, err := signals.Parse(strings.NewReader(strings.Replace(doc, `"1.0.0"`, `"2.0.0"`, 1)))
	if err == nil || !strings.Contains(err.Error(), "signals_version") {
		t.Fatalf("signals_version 2.0.0: err = %v; want a signals_version error", err)
	}
}
