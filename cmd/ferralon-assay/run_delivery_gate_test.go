package main

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/resultsink/ferralon"
)

// This file holds the TEG-060 delivery-gate guards: the canonical-ref resolution, the
// analyze.ref delivery behaviour the relaxed gate now allows, and — the blast-radius
// guard — the proof that for a repository with NO analyze.ref the set of delivering runs is
// unchanged from before TEG-060.

// legacyDefaultBranchGate is the delivery condition EXACTLY as it stood before TEG-060,
// transcribed verbatim from selectRunSnapshotSink as it stood before this change:
//
//	if url == "" { return nil }
//	if refName == "" || defaultBranch == "" || refName != defaultBranch { return nil }
//
// It lives HERE, in the test, precisely so the equivalence property has a fixed reference to
// compare against: an edit to the real gate can no longer move both sides of the comparison at
// once, which is what would make a plain-repository regression silent.
func legacyDefaultBranchGate(url, refName, defaultBranch string) bool {
	if url == "" {
		return false
	}
	if refName == "" || defaultBranch == "" || refName != defaultBranch {
		return false
	}
	return true
}

// delivers composes the two halves the production path composes in publishResult: resolve the
// analyzed/canonical pair from the run's environment, then ask the gate. It is the whole
// delivery decision, and the unit the equivalence property is stated over.
func delivers(url, analyzeRef, refName, defaultBranch string) bool {
	tok := ferralon.TokenSource(func(context.Context) string { return "tok" })
	analyzed, canonical := canonicalDeliveryRefs(analyzeRef, refName, defaultBranch)
	return selectRunSnapshotSink(url, analyzed, canonical, tok) != nil
}

// TestCanonicalDeliveryRefs pins the resolution rule: canonical = analyze.ref if the repository
// set one, else the default branch; analyzed = that same analyze.ref if it redirected the scan,
// else the triggering ref (with no redirect the scan inventories the tree CI checked out).
func TestCanonicalDeliveryRefs(t *testing.T) {
	tests := []struct {
		name                           string
		analyzeRef, refName, defBranch string
		wantAnalyzed, wantCanonical    string
	}{
		{"no analyze.ref → triggering ref vs default branch", "", "main", "main", "main", "main"},
		{"no analyze.ref, feature branch → triggering ref vs default branch", "", "feature-x", "main", "feature-x", "main"},
		{"no analyze.ref, nothing known → both empty-ish, passed through", "", "", "", "", ""},
		{"analyze.ref set → designated ref is both analyzed and canonical", "release", "feature-x", "main", "release", "release"},
		{"analyze.ref set, triggered on default branch → still the designated ref", "release", "main", "main", "release", "release"},
		{"analyze.ref set, default branch unknown → the designated ref still decides", "release", "feature-x", "", "release", "release"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			analyzed, canonical := canonicalDeliveryRefs(tc.analyzeRef, tc.refName, tc.defBranch)
			if analyzed != tc.wantAnalyzed || canonical != tc.wantCanonical {
				t.Fatalf("canonicalDeliveryRefs(%q, %q, %q) = (%q, %q), want (%q, %q)",
					tc.analyzeRef, tc.refName, tc.defBranch, analyzed, canonical, tc.wantAnalyzed, tc.wantCanonical)
			}
		})
	}
}

// TestAnalyzeRefDeliversOnNonDefaultTrigger is the RED→GREEN guard. Before TEG-060
// the first case returned nil — the run had assessed exactly the ref the repository designated,
// and the assessment was dropped because the WORKFLOW happened to be triggered elsewhere.
func TestAnalyzeRefDeliversOnNonDefaultTrigger(t *testing.T) {
	const url = "https://api.example.com/runs"

	// RED before TEG-060: .github/ferralon.yml says analyze.ref: release, the push that ran the
	// workflow landed on feature-x, default_branch is main. The scan analyzed `release`.
	if !delivers(url, "release", "feature-x", "main") {
		t.Fatalf("a run that analyzed the designated canonical ref (release) must deliver, whatever branch triggered it")
	}
	// Triggered on the designated ref itself — a push to release — also delivers.
	if !delivers(url, "release", "release", "main") {
		t.Fatalf("a push to the designated ref must deliver")
	}
	// The negative half: a run that analyzed something OTHER than the canonical ref does not
	// deliver. Reached here through the gate directly, since canonicalDeliveryRefs cannot
	// currently produce a divergent pair — the gate must nonetheless be a real comparison, so
	// that any future source of the analyzed ref inherits the refusal rather than the vacuum.
	tok := ferralon.TokenSource(func(context.Context) string { return "tok" })
	if selectRunSnapshotSink(url, "feature-x", "release", tok) != nil {
		t.Fatalf("a run that analyzed a ref other than the canonical one must not deliver")
	}
}

// TestPlainRepoDeliveryEquivalence is the blast-radius guard, and the reason TEG-060 is safe to
// ship to every existing customer at once: for a repository with NO analyze.ref — which is every
// repository until one opts in — the new delivery decision equals the pre-TEG-060 one on the
// full cross-product of the inputs the gate reads. Default branch, feature branch, PR merge ref,
// tag, unknown ref, unknown default, URL set and unset: same answer, every cell.
func TestPlainRepoDeliveryEquivalence(t *testing.T) {
	urls := []string{"", "https://api.example.com/runs"}
	refs := []string{"", "main", "master", "feature-x", "42/merge", "v1.2.3", "release"}
	defBranches := []string{"", "main", "master", "release"}

	checked := 0
	for _, url := range urls {
		for _, ref := range refs {
			for _, def := range defBranches {
				// analyzeRef is fixed empty: this property is ONLY about the plain repository.
				got := delivers(url, "", ref, def)
				want := legacyDefaultBranchGate(url, ref, def)
				if got != want {
					t.Fatalf("plain-repo delivery diverged from the pre-TEG-060 gate: "+
						"url=%q GITHUB_REF_NAME=%q default_branch=%q → new=%v, old=%v",
						url, ref, def, got, want)
				}
				checked++
			}
		}
	}
	if checked != len(urls)*len(refs)*len(defBranches) {
		t.Fatalf("equivalence table did not cover the cross-product: checked %d", checked)
	}
	t.Logf("plain-repo equivalence holds over %d input combinations", checked)
}

// TestAnalyzeRefDeliveryIsAStrictSuperset states the containment directly: over the same
// cross-product, every run the OLD gate delivered is still delivered once an analyze.ref is in
// play only when it is genuinely the canonical assessment — and, crucially, no run that the old
// gate delivered for a plain repository is LOST. Delivery is only ever added, never removed.
func TestAnalyzeRefDeliveryIsAStrictSuperset(t *testing.T) {
	const url = "https://api.example.com/runs"
	refs := []string{"", "main", "feature-x", "42/merge", "v1.2.3"}
	defBranches := []string{"", "main", "release"}

	added := 0
	for _, ref := range refs {
		for _, def := range defBranches {
			old := legacyDefaultBranchGate(url, ref, def)
			if old && !delivers(url, "", ref, def) {
				t.Fatalf("delivery LOST for a plain repo: ref=%q default=%q", ref, def)
			}
			// With the repository designating `release`, the run analyzed `release` and delivers.
			if !delivers(url, "release", ref, def) {
				t.Fatalf("analyze.ref=release must deliver: ref=%q default=%q", ref, def)
			}
			if !old {
				added++
			}
		}
	}
	if added == 0 {
		t.Fatalf("the table proves nothing: no run was added by the relaxation")
	}
	t.Logf("relaxation adds delivery for %d previously-dropped run shapes (analyze.ref repos only)", added)
}
