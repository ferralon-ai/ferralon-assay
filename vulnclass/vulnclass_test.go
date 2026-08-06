package vulnclass

import "testing"

// TestClassifyAdvisory_CWEIsAuthoritative verifies a recognized CWE selects the class even when the
// summary is empty or would suggest a different class — CWE is the structured, source-attributed
// signal and wins over keyword heuristics.
func TestClassifyAdvisory_CWEIsAuthoritative(t *testing.T) {
	cases := []struct {
		name string
		cwe  string
		want Class
	}{
		{"ssrf cwe-918", "CWE-918", ClassSSRF},
		{"ssrf bare number", "918", ClassSSRF},
		{"ssrf lowercase", "cwe-918", ClassSSRF},
		{"dos cwe-400", "CWE-400", ClassDoS},
		{"dos cwe-770", "CWE-770", ClassDoS},
		{"authz cwe-862", "CWE-862", ClassAuthBypass},
		{"improper-authz cwe-285", "CWE-285", ClassAuthBypass},
		{"template cwe-1336", "CWE-1336", ClassTemplateInj},
		{"reflection cwe-470", "CWE-470", ClassUnsafeRefl},
		{"memory cwe-125", "CWE-125", ClassMemorySafety},
		{"open-redirect cwe-601", "CWE-601", ClassOpenRedirect},
		{"proto-pollution cwe-1321", "CWE-1321", ClassPrototypePollution},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyAdvisory(AdvisoryClass{CWEs: []string{tc.cwe}})
			if got != tc.want {
				t.Errorf("ClassifyAdvisory(CWE=%q) = %q, want %q", tc.cwe, got, tc.want)
			}
		})
	}
}

// TestClassifyAdvisory_SummaryFallback verifies that when no recognized CWE is present, a keyword
// scan of the summary recognizes the class.
func TestClassifyAdvisory_SummaryFallback(t *testing.T) {
	cases := []struct {
		name    string
		summary string
		want    Class
	}{
		{"ssrf phrase", "A server-side request forgery in the proxy handler", ClassSSRF},
		{"dos phrase", "Uncontrolled resource consumption leads to denial of service", ClassDoS},
		{"authz phrase", "Improper access control allows authorization bypass", ClassAuthBypass},
		{"template phrase", "Server-side template injection via user input", ClassTemplateInj},
		{"traversal phrase", "Path traversal in the archive extractor", ClassPathTraversal},
		{"memory phrase", "Out-of-bounds read panic on malformed input", ClassMemorySafety},
		{"open-redirect phrase", "Open redirect via unvalidated return URL parameter", ClassOpenRedirect},
		{"proto-pollution phrase", "Prototype pollution through recursive merge", ClassPrototypePollution},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyAdvisory(AdvisoryClass{Summary: tc.summary})
			if got != tc.want {
				t.Errorf("ClassifyAdvisory(Summary=%q) = %q, want %q", tc.summary, got, tc.want)
			}
		})
	}
}

// TestClassifyAdvisory_UnknownIsHonest verifies that an advisory matching neither a recognized CWE
// nor a keyword yields ClassUnknown — the honest "not assessed" outcome, NEVER a guess and never a
// "clear" signal (ROADMAP §scope honesty / inv.5).
func TestClassifyAdvisory_UnknownIsHonest(t *testing.T) {
	got := ClassifyAdvisory(AdvisoryClass{CWEs: []string{"CWE-999999"}, Summary: "a totally novel issue with no recognized class keyword"})
	if got != ClassUnknown {
		t.Errorf("ClassifyAdvisory(unrecognized) = %q, want ClassUnknown", got)
	}
	if got != "" {
		t.Errorf("ClassUnknown must be the empty string so callers can record \"not assessed\"; got %q", got)
	}
}

// TestKnownClasses_ExcludesUnknown verifies the documentation slice never includes the honest
// default, which would make "unknown" look like a recognized class.
func TestKnownClasses_ExcludesUnknown(t *testing.T) {
	for _, c := range KnownClasses() {
		if c == ClassUnknown {
			t.Error("KnownClasses() includes ClassUnknown; the honest default must not appear as a known class")
		}
	}
}

// TestClassFromCWE_MirrorsClassifyAdvisory verifies the single-CWE accessor pipeline's
// code_execution sink_kind fan-out consumes (advisory_source.go) reads off the SAME cweClass table
// ClassifyAdvisory does, and honors the same normalizeCWE tolerance (case/prefix), never a
// re-encoded duplicate table.
func TestClassFromCWE_MirrorsClassifyAdvisory(t *testing.T) {
	for cwe, want := range cweClass {
		got, ok := ClassFromCWE(cwe)
		if !ok || got != want {
			t.Errorf("ClassFromCWE(%q) = (%q,%v), want (%q,true)", cwe, got, ok, want)
		}
	}
	// normalizeCWE tolerance carries through (bare number, lowercase).
	if got, ok := ClassFromCWE("502"); !ok || got != ClassDeserialize {
		t.Errorf("ClassFromCWE(\"502\") = (%q,%v), want (%q,true)", got, ok, ClassDeserialize)
	}
	if got, ok := ClassFromCWE("cwe-77"); !ok || got != ClassInjection {
		t.Errorf("ClassFromCWE(\"cwe-77\") = (%q,%v), want (%q,true)", got, ok, ClassInjection)
	}
	// Unrecognized CWE: honest ok=false, never a guess.
	if got, ok := ClassFromCWE("CWE-999999"); ok {
		t.Errorf("ClassFromCWE(unrecognized) = (%q,true), want ok=false", got)
	}
}
