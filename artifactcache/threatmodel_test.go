package artifactcache

import (
	"os"
	"strings"
	"testing"
)

// egressSentinel is the required struck-egress statement the not-a-threat section must
// carry. The guardrail: a threat model whose central objection is egress fails C6.
const egressSentinel = "Egress is not, by itself, a threat"

// section returns the body of the `## <heading>` section — everything from that heading
// up to the next `## ` heading (or EOF), heading line excluded. ok is false if the
// heading is absent.
func section(doc, heading string) (body string, ok bool) {
	marker := "## " + heading
	lines := strings.Split(doc, "\n")
	start := -1
	for i, ln := range lines {
		if strings.TrimSpace(ln) == marker {
			start = i + 1
			break
		}
	}
	if start == -1 {
		return "", false
	}
	var b strings.Builder
	for _, ln := range lines[start:] {
		if strings.HasPrefix(ln, "## ") {
			break
		}
		b.WriteString(ln)
		b.WriteString("\n")
	}
	return b.String(), true
}

// TestThreatModelC6 is the mechanical guardrail over threatmodel.md. It reads the doc
// from the package directory (the test's working dir IS the package dir — no `../..`
// traversal) and asserts the scored-threats substance is present and that egress is only
// ever named as a non-threat.
func TestThreatModelC6(t *testing.T) {
	raw, err := os.ReadFile("threatmodel.md")
	if err != nil {
		t.Fatalf("read threatmodel.md: %v", err)
	}
	doc := string(raw)

	// (a) Scored threats section present, with a credential threat and a
	// supply-chain/integrity threat.
	scored, ok := section(doc, "Scored threats")
	if !ok {
		t.Fatal("threatmodel.md: missing `## Scored threats` section")
	}
	scoredLower := strings.ToLower(scored)
	if !strings.Contains(scoredLower, "credential") {
		t.Error("`## Scored threats`: missing a credential threat")
	}
	if !strings.Contains(scoredLower, "supply-chain") && !strings.Contains(scoredLower, "integrity") {
		t.Error("`## Scored threats`: missing a supply-chain / integrity threat")
	}

	// (b) Explicitly-not-a-threat section present, with the struck-egress sentinel.
	notThreat, ok := section(doc, "Explicitly NOT a threat")
	if !ok {
		t.Fatal("threatmodel.md: missing `## Explicitly NOT a threat` section")
	}
	if !strings.Contains(notThreat, egressSentinel) {
		t.Errorf("`## Explicitly NOT a threat`: missing sentinel %q", egressSentinel)
	}

	// (c) The token "egress" must NOT appear inside the scored-threats section — egress
	// is only ever a non-threat. This is the guardrail that fails an egress-central model.
	if strings.Contains(scoredLower, "egress") {
		t.Error("`## Scored threats`: contains the token \"egress\"; egress must appear only in the not-a-threat section")
	}
}
