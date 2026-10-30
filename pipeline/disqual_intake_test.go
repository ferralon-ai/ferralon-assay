// disqual_intake_test.go
//
// Hermetic proof of the M0 intake disqualification guards folded into
// disqualification_discovery (S3): the two language-agnostic short-circuits that fire BEFORE
// symbol mapping / call-graph for advisories the pipeline can never adjudicate against the resolved
// codebase.
//
//   - Guard 1 (advisory_ecosystem_mismatch): the advisory's ecosystem matches no package
//     ecosystem in the resolved codebase (npm advisory against a Java project; a native/generic
//     advisory with no managed coordinate).
//   - Guard 2 (no_manifest_entry): the advisory names a dependency the resolved manifest provably
//     lacks (a Go module absent from go.mod). First-party/app-level sinks carry no coordinate and
//     are NEVER caught here (gogs-style protection).
//
// Every uncertainty fails OPEN (inv.5): missing/ambiguous ecosystem, unreadable manifest, and an
// empty coordinate all PROCEED — the guards never fabricate a disqualification.
package pipeline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

// --- Pure predicate: intakeDisqualify ----------------------------------------

func TestIntakeDisqualify(t *testing.T) {
	cases := []struct {
		name                       string
		advEco, codeEco, coord     string
		manifestHas, manifestKnown bool
		wantDisq                   bool
		wantReason                 string
	}{
		// Guard 1: provable ecosystem mismatch → disqualify.
		{"npm advisory under maven codebase", "npm", "maven", "", false, false, true, ReasonAdvisoryEcosystemMismatch},
		{"native/generic advisory under go codebase", "generic", "golang", "", false, false, true, ReasonAdvisoryEcosystemMismatch},
		{"nuget advisory under go codebase", "nuget", "golang", "", false, false, true, ReasonAdvisoryEcosystemMismatch},
		// Guard 1: matching ecosystem → proceed.
		{"matching golang ecosystem", "golang", "golang", "", false, false, false, ReasonInsufficient},
		// Guard 1 fail-open: an unknown ecosystem on either side never disqualifies.
		{"advisory ecosystem unknown", "", "golang", "", false, false, false, ReasonInsufficient},
		{"codebase ecosystem unknown", "npm", "", "", false, false, false, ReasonInsufficient},
		{"both ecosystems unknown", "", "", "", false, false, false, ReasonInsufficient},
		// Guard 2: named coordinate provably absent from a readable manifest → disqualify.
		{"coordinate absent from readable manifest", "golang", "golang", "example.com/absent", false, true, true, ReasonNoManifestEntry},
		// Guard 2: coordinate present in manifest → proceed.
		{"coordinate present in manifest", "golang", "golang", "golang.org/x/text", true, true, false, ReasonInsufficient},
		// Guard 2 fail-open: empty coordinate (first-party/app sink) → proceed.
		{"first-party sink carries no coordinate", "golang", "golang", "", false, true, false, ReasonInsufficient},
		// Guard 2 fail-open: manifest unreadable → proceed (absence not provable).
		{"manifest unreadable", "golang", "golang", "example.com/absent", false, false, false, ReasonInsufficient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			disq, reason := intakeDisqualify(tc.advEco, tc.codeEco, tc.coord, tc.manifestHas, tc.manifestKnown)
			if disq != tc.wantDisq {
				t.Fatalf("disqualified = %v, want %v (reason %q)", disq, tc.wantDisq, reason)
			}
			if reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tc.wantReason)
			}
		})
	}
}

func TestPurlEcosystem(t *testing.T) {
	cases := map[string]string{
		"pkg:golang/golang.org/x/text@v0.3.7": "golang",
		"pkg:npm/left-pad":                    "npm",
		"pkg:maven/com.example.lib/widget":    "maven",
		"pkg:nuget/DotNetNuke.Core":           "nuget",
		"pkg:generic/sap-hana":                "generic",
		"":                                    "", // no PURL → fail open
		"not-a-purl":                          "", // malformed → fail open
		"pkg:":                                "", // no type → fail open
	}
	for purl, want := range cases {
		if got := purlEcosystem(purl); got != want {
			t.Fatalf("purlEcosystem(%q) = %q, want %q", purl, got, want)
		}
	}
}

func TestLanguageEcosystem(t *testing.T) {
	cases := map[string]string{
		"go": "golang", "java": "maven", "javascript": "npm", "js": "npm",
		// python/dotnet are DELIBERATELY absent → "" (fail open) on the intake
		// ecosystem-mismatch axis: that axis REFUTES, and the offline inventory can
		// misdetect a language (e.g. the gogs Docker-context repro reads as "python"
		// from a beacon .py while the real codebase is Go), so mapping them there would
		// fabricate an advisory_ecosystem_mismatch. U5's pypi/nuget lightup rides the
		// VERSION comparator (schemeFromPURL), not this axis. See TestSchemeFromPURL.
		"": "", "python": "", "dotnet": "", "rust": "", // unknown/undetected → fail open
	}
	for lang, want := range cases {
		if got := languageEcosystem(lang); got != want {
			t.Fatalf("languageEcosystem(%q) = %q, want %q", lang, got, want)
		}
	}
}

// --- Stage Run integration ----------------------------------------------------

// writeGoMod writes a minimal parseable go.mod into a fresh temp dir and returns the dir, for use
// as an inventory build_dir the no-manifest-entry guard reads.
func writeGoMod(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(contents), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	return dir
}

const goModWithText = "module example.com/app\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.6\n"

// Guard 1: an npm advisory assessed against a Java codebase — no npm package to reach. The
// npm-under-java archetype.
func TestIntakeRun_NpmAdvisoryUnderJava_Mismatch(t *testing.T) {
	store := artifact.NewMemStore()
	caseID := "case-npm-under-java"
	putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{
		"vuln_id": "FERRALON-JS-DEP-0001",
		"purl":    "pkg:npm/left-pad",
	})
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{
		"language": "java", "build_dir": "",
	})
	res := runDisqual(t, store, caseID)
	if !res.Disqualified || res.Reason != ReasonAdvisoryEcosystemMismatch {
		t.Fatalf("want disqualified/%s, got %+v", ReasonAdvisoryEcosystemMismatch, res)
	}
}

// Guard 1 archetype: a .NET (nuget) app-level advisory — DotNetNuke — assessed against a Go
// codebase. The advisory's ecosystem matches no package in the resolved Go build.
func TestIntakeRun_DotNetNukeUnderGo_Mismatch(t *testing.T) {
	store := artifact.NewMemStore()
	caseID := "case-dotnetnuke"
	putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{
		"vuln_id": "CVE-2021-XXXX",
		"purl":    "pkg:nuget/DotNetNuke.Core",
	})
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{
		"language": "go", "build_dir": "",
	})
	res := runDisqual(t, store, caseID)
	if !res.Disqualified || res.Reason != ReasonAdvisoryEcosystemMismatch {
		t.Fatalf("want disqualified/%s, got %+v", ReasonAdvisoryEcosystemMismatch, res)
	}
}

// Guard 1 fail-open: no PURL on the advisory (ambiguous ecosystem) MUST proceed — never a
// fabricated mismatch (inv.5).
func TestIntakeRun_NoAdvisoryPURL_FailsOpen(t *testing.T) {
	store := artifact.NewMemStore()
	caseID := "case-no-purl"
	putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{"vuln_id": "GO-2021-0113"})
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{"language": "java", "build_dir": ""})
	res := runDisqual(t, store, caseID)
	if res.Disqualified {
		t.Fatalf("ambiguous ecosystem must fail open, got %+v", res)
	}
}

// Guard 1 fail-open: undetected codebase language (hermetic stub, empty build) MUST proceed.
func TestIntakeRun_UnknownCodebaseLanguage_FailsOpen(t *testing.T) {
	store := artifact.NewMemStore()
	caseID := "case-unknown-lang"
	putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{
		"vuln_id": "FERRALON-JS-DEP-0001", "purl": "pkg:npm/left-pad",
	})
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{"build_dir": ""})
	res := runDisqual(t, store, caseID)
	if res.Disqualified {
		t.Fatalf("undetected language must fail open, got %+v", res)
	}
}

// Guard 2: a Go module advisory whose module is provably absent from the resolved go.mod — no
// dependency edge exists to reach across (the DotNetNuke/CPython "vulnerable code is not a
// resolved dependency" archetype, made sound in the Go manifest).
func TestIntakeRun_ModuleAbsentFromGoMod_NoManifestEntry(t *testing.T) {
	store := artifact.NewMemStore()
	caseID := "case-absent-module"
	buildDir := writeGoMod(t, goModWithText)
	putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{
		"vuln_id": "GO-XXXX-ABSENT",
		"module":  "example.com/never-required",
		"purl":    "pkg:golang/example.com/never-required",
	})
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{
		"language": "go", "build_dir": buildDir,
	})
	res := runDisqual(t, store, caseID)
	if !res.Disqualified || res.Reason != ReasonNoManifestEntry {
		t.Fatalf("want disqualified/%s, got %+v", ReasonNoManifestEntry, res)
	}
}

// writeGoTree writes files (relative path -> contents) into a fresh temp dir and returns it.
func writeGoTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const (
	stubRootGoMod     = "module example.com/stub\n\ngo 1.21\n"
	nestedCryptoGoMod = "module example.com/stub/receiver/a\n\ngo 1.21\n\nrequire golang.org/x/crypto v0.1.0\n"
)

// TestGoModRequires: absence is proven only against the whole manifest. A module nested below the
// build root (outside its go.work) may require what the root go.mod does not, so the root's silence
// is unknown, never absent.
func TestGoModRequires(t *testing.T) {
	cases := []struct {
		name               string
		files              map[string]string
		module             string
		wantPresent, known bool
	}{
		{"required by the root", map[string]string{"go.mod": goModWithText}, "golang.org/x/text", true, true},
		{"absent from a lone root", map[string]string{"go.mod": goModWithText}, "golang.org/x/crypto", false, true},
		{"no go.mod", map[string]string{"main.go": "package main\n"}, "golang.org/x/crypto", false, false},
		{"stub root, nested module requires it", map[string]string{
			"go.mod": stubRootGoMod, "receiver/a/go.mod": nestedCryptoGoMod,
		}, "golang.org/x/crypto", false, false},
		{"stub root, nested module requires something else", map[string]string{
			"go.mod": stubRootGoMod, "receiver/a/go.mod": nestedCryptoGoMod,
		}, "example.com/never-required", false, false},
		{"root requires it, nested module present", map[string]string{
			"go.mod": goModWithText, "receiver/a/go.mod": nestedCryptoGoMod,
		}, "golang.org/x/text", true, true},
		{"nested module under testdata is not source", map[string]string{
			"go.mod": stubRootGoMod, "testdata/a/go.mod": nestedCryptoGoMod,
		}, "golang.org/x/crypto", false, true},
		{"nested module a go.work lists", map[string]string{
			"go.mod": stubRootGoMod, "go.work": "go 1.21\n\nuse ./receiver/a\n", "receiver/a/go.mod": nestedCryptoGoMod,
		}, "golang.org/x/crypto", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			present, known := goModRequires(writeGoTree(t, tc.files), tc.module)
			if present != tc.wantPresent || known != tc.known {
				t.Fatalf("goModRequires = (present %v, known %v), want (%v, %v)", present, known, tc.wantPresent, tc.known)
			}
		})
	}
}

// A stub root go.mod that requires nothing, above a nested module that requires the advisory's
// module, cannot disqualify the advisory: the root's silence is not the manifest's.
func TestIntakeRun_StubRootNestedModule_CannotDisqualify(t *testing.T) {
	store := artifact.NewMemStore()
	caseID := "case-stub-root"
	buildDir := writeGoTree(t, map[string]string{"go.mod": stubRootGoMod, "receiver/a/go.mod": nestedCryptoGoMod})
	putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{
		"vuln_id": "CVE-2024-45337",
		"module":  "golang.org/x/crypto",
		"purl":    "pkg:golang/golang.org/x/crypto",
	})
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{
		"language": "go", "build_dir": buildDir,
	})
	res := runDisqual(t, store, caseID)
	if res.Disqualified {
		t.Fatalf("stub root above a nested module requiring the advisory's module must not disqualify, got %+v", res)
	}
}

// Guard 2 PROCEED: the advisory's module IS in the resolved manifest → the guard does not fire;
// the run falls through to the version axis (no range here → insufficient).
func TestIntakeRun_ModulePresentInGoMod_Proceeds(t *testing.T) {
	store := artifact.NewMemStore()
	caseID := "case-present-module"
	buildDir := writeGoMod(t, goModWithText)
	putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{
		"vuln_id": "GO-2021-0113",
		"module":  "golang.org/x/text",
		"purl":    "pkg:golang/golang.org/x/text",
	})
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{
		"language": "go", "build_dir": buildDir,
	})
	res := runDisqual(t, store, caseID)
	if res.Disqualified {
		t.Fatalf("module present in manifest must proceed, got %+v", res)
	}
}

// Guard 2 protection: a first-party/app-level Go sink (empty module — gogs archetype) is NEVER
// caught by the no-manifest-entry guard; it proceeds to first-party reachability downstream.
func TestIntakeRun_FirstPartyEmptyModule_Proceeds(t *testing.T) {
	store := artifact.NewMemStore()
	caseID := "case-first-party"
	buildDir := writeGoMod(t, goModWithText)
	putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{
		"vuln_id": "CVE-2024-55947",
		"purl":    "pkg:golang/gogs.io/gogs/internal/db",
	})
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{
		"language": "go", "build_dir": buildDir,
	})
	res := runDisqual(t, store, caseID)
	if res.Disqualified {
		t.Fatalf("first-party sink (empty module) must proceed, got %+v", res)
	}
}

// Guard 2 fail-open: a named module but an unreadable manifest (no go.mod at build_dir) MUST
// proceed — absence is only provable against a manifest actually parsed (inv.5).
func TestIntakeRun_ModuleNamedButManifestUnreadable_FailsOpen(t *testing.T) {
	store := artifact.NewMemStore()
	caseID := "case-no-gomod"
	buildDir := t.TempDir() // no go.mod written
	putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{
		"vuln_id": "GO-XXXX-ABSENT",
		"module":  "example.com/never-required",
		"purl":    "pkg:golang/example.com/never-required",
	})
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{
		"language": "go", "build_dir": buildDir,
	})
	res := runDisqual(t, store, caseID)
	if res.Disqualified {
		t.Fatalf("unreadable manifest must fail open, got %+v", res)
	}
}
