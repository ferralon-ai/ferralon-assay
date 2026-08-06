package brand

import "testing"

// TestIssueMarker_StaysByteIdentical guards the one string that must NEVER change once
// a repo has been provisioned: the pinned-Issue find-or-create in tier1_issue.go keys on
// the literal marker string. If this test starts failing, it means IssueMarker()'s
// underlying Name changed or its format changed — either one breaks every
// already-provisioned repo's dedup, creating a duplicate dashboard Issue on the next run.
//
// The expected value is deliberately a hardcoded literal rather than a Name-derived
// expression: a brand-derived assertion would follow Name wherever it moved and could
// never detect the change this test exists to catch. Changing it is a deliberate act with
// a known cost, not a mechanical follow-on edit.
func TestIssueMarker_StaysByteIdentical(t *testing.T) {
	const want = "<!-- ferralon-assay:dashboard -->"
	if got := IssueMarker(); got != want {
		t.Fatalf("IssueMarker() = %q, want %q — rebranding this breaks find-or-create for every already-provisioned repo's pinned Issue", got, want)
	}
}

// TestRepoURL_IsTheCanonicalPublicRepo pins RepoURL to one exact value. The string is
// stamped verbatim into the SARIF informationUri (projection/report_sarif.go) and
// rendered by GitHub in the customer's code-scanning tab, so it is a customer-facing
// surface and the only correct value is the public repository this tool is distributed
// from.
//
// The assertion is positive — equality against the canonical URL — rather than a set of
// checks for values known to be wrong. An equality test forecloses every wrong value,
// including the ones nobody thought to enumerate: a scratch repo, a fork, a personal
// namespace, an internal host. A blocklist only ever catches what its author already
// remembered, and it has to name the bad value to test for it, which puts that value in
// the source tree permanently.
func TestRepoURL_IsTheCanonicalPublicRepo(t *testing.T) {
	const want = "https://github.com/ferralon-ai/ferralon-assay"
	if RepoURL != want {
		t.Errorf("RepoURL = %q, want %q — this string reaches the customer's code-scanning tab as the SARIF informationUri, and must be the public repository the tool is distributed from", RepoURL, want)
	}
}
