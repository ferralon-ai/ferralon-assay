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
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/checkout/gomodtree"
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
		writeGoFile(t, filepath.Join(dir, rel), body)
	}
	return dir
}

const (
	stubRootGoMod     = "module example.com/stub\n\ngo 1.21\n"
	nestedCryptoGoMod = "module example.com/stub/receiver/a\n\ngo 1.21\n\nrequire golang.org/x/crypto v0.1.0\n"
	// Shaped like this repository's plugins/cfamily: a module of its own beside the root, whose
	// go.mod (go 1.17 or later) lists every module it builds against, x/crypto not among them.
	unrelatedNestedGoMod = "module example.com/app/plugins/c\n\ngo 1.26\n\nrequire (\n\tgithub.com/example/c v1.0.0\n\tgolang.org/x/sys v0.1.0 // indirect\n)\n"
)

// TestGoModRequires: absence is proven only against the whole manifest. Every other module of the
// checkout that the build root's graph leaves out, and that may build against the module, makes
// the root's silence unknown, never absent; one whose complete require list omits it does not.
func TestGoModRequires(t *testing.T) {
	cases := []struct {
		name               string
		files              map[string]string
		module             string
		tree               *gomodtree.Tree // the walk's result, when not walked from the files
		wantPresent, known bool
	}{
		{"required by the root", map[string]string{"go.mod": goModWithText}, "golang.org/x/text", nil, true, true},
		{"absent from a lone root", map[string]string{"go.mod": goModWithText}, "golang.org/x/crypto", nil, false, true},
		{"no go.mod", map[string]string{"main.go": "package main\n"}, "golang.org/x/crypto", nil, false, false},
		{"stub root, nested module requires it", map[string]string{
			"go.mod": stubRootGoMod, "receiver/a/go.mod": nestedCryptoGoMod,
		}, "golang.org/x/crypto", nil, false, false},
		{"stub root, nested module requires a module holding it", map[string]string{
			"go.mod": stubRootGoMod, "receiver/a/go.mod": nestedCryptoGoMod,
		}, "golang.org/x/crypto/ssh", nil, false, false},
		{"stub root, nested module requires something else", map[string]string{
			"go.mod": stubRootGoMod, "receiver/a/go.mod": nestedCryptoGoMod,
		}, "example.com/never-required", nil, false, true},
		{"an unrelated nested module beside a root that requires", map[string]string{
			"go.mod": goModWithText, "plugins/c/go.mod": unrelatedNestedGoMod,
		}, "golang.org/x/crypto", nil, false, true},
		{"nested module below go 1.17", map[string]string{
			"go.mod": stubRootGoMod, "receiver/a/go.mod": "module example.com/stub/receiver/a\n\ngo 1.16\n",
		}, "golang.org/x/crypto", nil, false, false},
		{"nested module with no go directive", map[string]string{
			"go.mod": stubRootGoMod, "receiver/a/go.mod": "module example.com/stub/receiver/a\n",
		}, "golang.org/x/crypto", nil, false, false},
		{"nested module that does not parse", map[string]string{
			"go.mod": stubRootGoMod, "receiver/a/go.mod": "not a go.mod\n",
		}, "golang.org/x/crypto", nil, false, false},
		{"root requires it, nested module present", map[string]string{
			"go.mod": goModWithText, "receiver/a/go.mod": nestedCryptoGoMod,
		}, "golang.org/x/text", nil, true, true},
		{"nested module under testdata is not source", map[string]string{
			"go.mod": stubRootGoMod, "testdata/a/go.mod": nestedCryptoGoMod,
		}, "golang.org/x/crypto", nil, false, true},
		{"a go.work member may require it", map[string]string{
			"go.mod": stubRootGoMod, "go.work": "go 1.21\n\nuse ./receiver/a\n", "receiver/a/go.mod": nestedCryptoGoMod,
		}, "golang.org/x/crypto", nil, false, false},
		{"a go.work, the root requires it", map[string]string{
			"go.mod": goModWithText, "go.work": "go 1.21\n\nuse .\n",
		}, "golang.org/x/text", nil, true, true},
		{"a walk that could not read the whole tree", map[string]string{"go.mod": goModWithText},
			"golang.org/x/crypto", &gomodtree.Tree{Complete: false}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeGoTree(t, tc.files)
			nested := func() gomodtree.Tree { return gomodtree.Nested(dir, dir) }
			if tc.tree != nil {
				nested = func() gomodtree.Tree { return *tc.tree }
			}
			present, known := goModRequires(dir, tc.module, nested)
			if present != tc.wantPresent || known != tc.known {
				t.Fatalf("goModRequires = (present %v, known %v), want (%v, %v)", present, known, tc.wantPresent, tc.known)
			}
		})
	}
}

// TestIntakeRun_NestedGoModules: intake disqualifies a Go advisory no_manifest_entry only when no
// module of the checkout may build against its module. The walk covers the whole checkout from the
// recorded checkout root, so a sibling of the build root counts as much as a module below it.
func TestIntakeRun_NestedGoModules(t *testing.T) {
	cases := []struct {
		name         string
		files        map[string]string
		buildDir     string // relative to the checkout root
		disqualified bool
	}{
		{"stub root above a nested module that requires it", map[string]string{
			"go.mod": stubRootGoMod, "receiver/a/go.mod": nestedCryptoGoMod,
		}, "", false},
		{"an unrelated nested module keeps the disqualification", map[string]string{
			"go.mod": goModWithText, "plugins/c/go.mod": unrelatedNestedGoMod,
		}, "", true},
		{"a sibling of the build root requires it", map[string]string{
			"api/go.mod": goModWithText, "worker/go.mod": nestedCryptoGoMod,
		}, "api", false},
		{"a sibling of the build root requires something else", map[string]string{
			"api/go.mod": goModWithText, "worker/go.mod": unrelatedNestedGoMod,
		}, "api", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			caseID := "case-nested-go-modules"
			root := writeGoTree(t, tc.files)
			putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{
				"vuln_id": "CVE-2024-45337",
				"module":  "golang.org/x/crypto",
				"purl":    "pkg:golang/golang.org/x/crypto",
			})
			putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{
				"language": "go", "build_dir": filepath.Join(root, tc.buildDir), "checkout_root": root,
			})
			res := runDisqual(t, store, caseID)
			if res.Disqualified != tc.disqualified || (tc.disqualified && res.Reason != ReasonNoManifestEntry) {
				t.Fatalf("got %+v, want disqualified %v (no_manifest_entry)", res, tc.disqualified)
			}
		})
	}
}

// TestNestedModules_WalkedOncePerMemo: a scan's memo walks each (checkout root, build dir) once, so
// a module added after the first walk is not seen through it; without a memo every call walks.
func TestNestedModules_WalkedOncePerMemo(t *testing.T) {
	root := writeGoTree(t, map[string]string{"go.mod": stubRootGoMod})
	memo := WithNestedModuleMemo(context.Background())
	if WithNestedModuleMemo(memo) != memo {
		t.Fatal("a ctx carrying a memo must be returned as is")
	}
	if got := nestedModules(memo, root, root); len(got.Modules) != 0 {
		t.Fatalf("first walk = %+v, want no modules", got)
	}
	writeGoFile(t, filepath.Join(root, "receiver/a/go.mod"), nestedCryptoGoMod)
	if got := nestedModules(memo, root, root); len(got.Modules) != 0 {
		t.Fatalf("memoised walk = %+v, want the first walk's result", got)
	}
	if got := nestedModules(context.Background(), root, root); len(got.Modules) != 1 {
		t.Fatalf("unmemoised walk = %+v, want the added module", got)
	}
}

// writeGoFile writes body to path, creating its directory.
func writeGoFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
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
