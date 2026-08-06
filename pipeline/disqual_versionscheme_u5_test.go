// internal/pipeline/disqual_versionscheme_u5_test.go
//
// U5 (VersionScheme-from-PURL) proof: the corpus PURL alone now selects the version
// comparator versionOutsideRange dispatches. advisoryIntake.Run derives the scheme from
// the PURL (pkg:pypi→pypi, pkg:nuget→nuget, …) when no explicit VersionScheme is set, so
// the pypi/nuget comparators fire for real advisories instead of only hand-pinned fixtures.
//
// SOUNDNESS (unified-program §3, inv.5): setting the scheme only SELECTS a comparator, it
// never concludes. Every comparator returns (outside, ok) and fails OPEN on any uncertainty.
// A wrong/unknown scheme falls through to the default semver path and, if the bound is
// unparseable there, fails open — so no mis-set or unknown scheme can fabricate a
// not-affected. TestUnknownScheme_NeverFabricatesNotAffected and TestKnownSchemeOpenRange_
// StaysOpen pin exactly that (an unknown scheme, and a known scheme with no bound).
//
// The comparator selection lives ONLY on the VERSION axis; U5 does NOT extend the intake
// ecosystem-mismatch REFUTE axis (languageEcosystem) to python/dotnet, because the offline
// inventory can misdetect a codebase's language and mapping them there would fabricate an
// advisory_ecosystem_mismatch — see TestLanguageEcosystem_PythonDotNetFailOpen.
package pipeline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// TestSchemeFromPURL pins the PURL-type→VersionScheme spec. It is a fixed correspondence
// (a spec, not a judgment): every recognized PURL type maps to the comparator its packages
// order under, and an unknown or absent PURL yields "" so the default semver path runs.
func TestSchemeFromPURL(t *testing.T) {
	cases := []struct {
		purl string
		want string
	}{
		{"pkg:maven/com.example/widget@1.0", "maven"},
		{"pkg:npm/left-pad@1.0.0", "npm"},
		{"pkg:pypi/flask@2.3.1", "pypi"},
		{"pkg:nuget/Newtonsoft.Json@13.0.0", "nuget"},
		{"pkg:golang/golang.org/x/text", "gomod"},
		{"pkg:cargo/serde@1.0", ""}, // unrecognized type → default path
		{"pkg:golang/stdlib", "gomod"},
		{"not-a-purl", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := schemeFromPURL(tc.purl); got != tc.want {
			t.Errorf("schemeFromPURL(%q) = %q, want %q", tc.purl, got, tc.want)
		}
	}
}

// TestLanguageEcosystem_PythonDotNetFailOpen locks the deliberate decision that python and
// dotnet are NOT mapped in languageEcosystem. That function feeds the intake
// ecosystem-mismatch REFUTE axis (extractCodebaseEcosystem → intakeDisqualify), and the
// offline inventory can misdetect a codebase's language — the gogs symlink repro reads as
// "python" from its Docker-context beacon .py while the real codebase is Go. Mapping
// python→pypi there would turn that misdetection into a fabricated advisory_ecosystem_mismatch
// (a not-affected) against the pkg:golang gogs advisory — an inv.5 violation the honesty
// guard catches. U5's pypi/nuget lightup rides the VERSION comparator (schemeFromPURL), which
// is fail-open and needs no ecosystem mapping. So python/dotnet stay "" → fail open here.
func TestLanguageEcosystem_PythonDotNetFailOpen(t *testing.T) {
	for _, lang := range []string{"python", "dotnet"} {
		if got := languageEcosystem(lang); got != "" {
			t.Errorf("languageEcosystem(%q) = %q, want \"\" (fail-open on the intake refute axis)", lang, got)
		}
	}
}

// runIntakeDisqual drives advisory_intake (which derives the comparator scheme from the
// corpus PURL) for the given AdvisoryTable id, seeds the resolved version, then runs
// disqualification_discovery — the real derived-scheme version axis end to end. It also
// returns the scheme intake stamped onto the emitted affected range, so a test can assert
// the PURL selected the right comparator.
func runIntakeDisqual(t *testing.T, vulnID, resolvedVersion string) (DisqualResult, string) {
	t.Helper()
	store := artifact.NewMemStore()
	caseID := "case-" + vulnID
	c := &assessment.Assessment{ID: caseID, Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: vulnID, Source: "corpus"},
	}}
	if err := (advisoryIntake{}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake: %v", err)
	}
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]string{"resolved_version": resolvedVersion})
	return runDisqual(t, store, caseID), advisoryRangeScheme(t, store, caseID)
}

// advisoryRangeScheme reads back the scheme intake stamped onto the first emitted affected
// range, proving the PURL-derived comparator flowed into the artifact the version axis reads.
func advisoryRangeScheme(t *testing.T, store *artifact.MemStore, caseID string) string {
	t.Helper()
	arts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		t.Fatalf("normalized advisory missing: %v", err)
	}
	var adv struct {
		AffectedRanges []affectedRange `json:"affected_ranges"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		t.Fatalf("unmarshal advisory: %v", err)
	}
	if len(adv.AffectedRanges) == 0 {
		return ""
	}
	return adv.AffectedRanges[0].Scheme
}

// PyPI: the PURL (pkg:pypi/flask) alone selects the PEP 440 comparator. flask 2.3.2 >= fixed
// 2.3.2 is provably outside → DISQUALIFIED; 2.3.1 < 2.3.2 stays inside → PROCEEDS.
func TestPyPIDisqual_PURLSelectsComparator(t *testing.T) {
	if res, scheme := runIntakeDisqual(t, "TEGRON-PY-DEP-0001", "2.3.2"); scheme != "pypi" || !res.Disqualified || res.Reason != ReasonVersionNotInRange {
		t.Fatalf("patched flask 2.3.2: scheme=%q res=%+v; want scheme pypi, disqualified version_not_in_affected_range", scheme, res)
	}
	if res, scheme := runIntakeDisqual(t, "TEGRON-PY-DEP-0001", "2.3.1"); scheme != "pypi" || res.Disqualified || res.Reason != ReasonInsufficient {
		t.Fatalf("vulnerable flask 2.3.1: scheme=%q res=%+v; want scheme pypi, proceed insufficient", scheme, res)
	}
}

// NuGet: the PURL (pkg:nuget/Newtonsoft.Json) alone selects the NuGet comparator.
// 13.0.2 >= fixed 13.0.1 is provably outside → DISQUALIFIED; 13.0.0 < 13.0.1 → PROCEEDS.
func TestNuGetDisqual_PURLSelectsComparator(t *testing.T) {
	if res, scheme := runIntakeDisqual(t, "TEGRON-NET-DEP-0001", "13.0.2"); scheme != "nuget" || !res.Disqualified || res.Reason != ReasonVersionNotInRange {
		t.Fatalf("patched Newtonsoft 13.0.2: scheme=%q res=%+v; want scheme nuget, disqualified version_not_in_affected_range", scheme, res)
	}
	if res, scheme := runIntakeDisqual(t, "TEGRON-NET-DEP-0001", "13.0.0"); scheme != "nuget" || res.Disqualified || res.Reason != ReasonInsufficient {
		t.Fatalf("vulnerable Newtonsoft 13.0.0: scheme=%q res=%+v; want scheme nuget, proceed insufficient", scheme, res)
	}
}

// Go fixture keeps its behavior: pkg:golang derives "gomod", which is the default semver
// path (gomod is not branched in versionOutsideRange). GO-2021-0113 fixed at v0.3.7, resolved
// v0.3.7 >= bound → still DISQUALIFIES exactly as before — deriving the scheme changed nothing
// for Go advisories.
func TestGoDisqual_DerivedGomodUnchanged(t *testing.T) {
	if res, scheme := runIntakeDisqual(t, "GO-2021-0113", "v0.3.7"); scheme != "gomod" || !res.Disqualified || res.Reason != ReasonVersionNotInRange {
		t.Fatalf("GO-2021-0113 v0.3.7: scheme=%q res=%+v; want scheme gomod, disqualified", scheme, res)
	}
}

// Requirement (§3, inv.5): an advisory whose PURL yields a KNOWN scheme but whose affected
// range is open/unbounded (no sound upper bound) must stay OPEN — deriving a scheme selects a
// comparator, it never manufactures a bound. This is the shape of the gogs symlink CVE (a
// first-party path-traversal with no version fix); it must NEVER be offline version-disqualified.
// Covered two ways: (a) a table advisory with a known-scheme PURL and NO bound at all, driven
// through intake; and (b) an explicit affected range whose upper bound is empty.
func TestKnownSchemeOpenRange_StaysOpen(t *testing.T) {
	// The PURL alone resolves a real comparator...
	if got := schemeFromPURL("pkg:pypi/tegron-corpus-app"); got != "pypi" {
		t.Fatalf("precondition: schemeFromPURL = %q, want pypi", got)
	}
	// (a) ...but with no version-range fix, intake emits no range and the axis fails OPEN.
	res, _ := runIntakeDisqual(t, "TEGRON-PY-FIRSTPARTY-0001", "1.2.3")
	if res.Disqualified {
		t.Fatalf("known-scheme advisory with no bound must FAIL OPEN, got disqualified %+v", res)
	}
	if res.Reason != ReasonInsufficient {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonInsufficient)
	}

	// (b) an explicit range carrying the known pypi scheme but an EMPTY upper bound is not a
	// usable bound: extractAffectedRange withholds the whole set → OPEN, never disqualified.
	store := artifact.NewMemStore()
	caseID := "case-open-range"
	putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{
		"vuln_id":         "TEGRON-PY-FIRSTPARTY-0001",
		"affected_ranges": []map[string]string{{"upper_exclusive": "", "scheme": "pypi"}},
	})
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]string{"resolved_version": "1.2.3"})
	if res := runDisqual(t, store, caseID); res.Disqualified || res.Reason != ReasonInsufficient {
		t.Fatalf("open/unbounded pypi range must FAIL OPEN, got %+v", res)
	}
}

// The soundness guard (§3, inv.5): an UNKNOWN scheme must never fabricate a not-affected.
// With scheme "" and a non-semver bound/version (2.4.0 vs 2.3.2 — numerically "outside" if it
// were pypi), the default semver comparator cannot parse the versions, returns ok=false, and
// the axis FAILS OPEN (proceeds). A wrong comparator never disqualifies.
func TestUnknownScheme_NeverFabricatesNotAffected(t *testing.T) {
	store := artifact.NewMemStore()
	caseID := "case-unknown-scheme"
	putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{
		"vuln_id":         "TEGRON-UNKNOWN-DEP-0001",
		"affected_ranges": []map[string]string{{"upper_exclusive": "2.3.2", "scheme": ""}},
	})
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]string{"resolved_version": "2.4.0"})
	res := runDisqual(t, store, caseID)
	if res.Disqualified {
		t.Fatalf("unknown scheme with unparseable-as-semver versions must FAIL OPEN, got disqualified %+v", res)
	}
	if res.Reason != ReasonInsufficient {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonInsufficient)
	}
}
