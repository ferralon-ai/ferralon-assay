package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
)

// TestIsRemoteURL covers the checkout dispatch decision: an existing local directory is
// scanned in place; a URL / scp-remote / bare module path is cloned.
func TestIsRemoteURL(t *testing.T) {
	localDir := t.TempDir()

	cases := []struct {
		name   string
		target string
		want   bool
	}{
		{"existing local dir", localDir, false},
		{"dot", ".", false},
		{"https url", "https://github.com/owner/repo", true},
		{"https url .git", "https://github.com/owner/repo.git", true},
		{"git scheme", "git://github.com/owner/repo", true},
		{"ssh scheme", "ssh://git@github.com/owner/repo", true},
		{"scp style", "git@github.com:owner/repo.git", true},
		{"bare module path", "github.com/owner/repo", true},
		{"nonexistent relative path", "some/local/dir", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRemoteURL(tc.target); got != tc.want {
				t.Fatalf("isRemoteURL(%q) = %v, want %v", tc.target, got, tc.want)
			}
		})
	}
}

// TestRepoIdentity covers the neutral repo identity derived from a clone target.
func TestRepoIdentity(t *testing.T) {
	cases := map[string]string{
		"https://github.com/owner/repo.git":      "github.com/owner/repo",
		"https://github.com/owner/repo":          "github.com/owner/repo",
		"https://user@gitlab.com/g/sub/repo.git": "gitlab.com/g/sub/repo",
		"git@github.com:owner/repo.git":          "github.com/owner/repo",
		"github.com/owner/repo":                  "github.com/owner/repo",
	}
	for in, want := range cases {
		if got := repoIdentity(in); got != want {
			t.Fatalf("repoIdentity(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSelectPlugin proves the plugin registry dispatches to the analyzer whose Language()
// matches the detected source language — the wiring the pipeline's Language()-match guard
// depends on. A non-empty binary path skips PATH discovery so the test needs no real plugin
// binaries installed.
func TestSelectPlugin(t *testing.T) {
	cases := []struct {
		lang string
		want string
	}{
		{checkout.LangGo, "go"},
		{checkout.LangJava, "java"},
		{checkout.LangJS, "js"},
		{checkout.LangPython, "python"},
		{checkout.LangDotNet, "dotnet"},
	}
	for _, tc := range cases {
		t.Run(tc.lang, func(t *testing.T) {
			p, err := selectPlugin(tc.lang, "/fake/analyzer-bin")
			if err != nil {
				t.Fatalf("selectPlugin(%q): %v", tc.lang, err)
			}
			if p.Language() != tc.want {
				t.Fatalf("selectPlugin(%q).Language() = %q, want %q", tc.lang, p.Language(), tc.want)
			}
		})
	}

	if _, err := selectPlugin(checkout.LangUnknown, ""); err == nil {
		t.Fatal("selectPlugin(unknown): expected error, got nil")
	}
}

// TestAdvisoryCorpusByLanguage proves the corpus is language-scoped: each language sees only its own
// ecosystem's advisories, EVERY supported language has a non-empty default floor, and the canary
// opt-in only ever adds to it.
//
// The floors used to be Go-only: Java, JS, Python and .NET returned nil unless the canary flag was
// set, which is what halted a default scan of those languages on an empty work set. The counts below
// are the load-bearing part — a language whose default count returns to zero cannot complete a scan.
func TestAdvisoryCorpusByLanguage(t *testing.T) {
	for _, tc := range []struct {
		lang           string
		wantDefault    int
		wantWithCanary int
	}{
		// Go: five original entries, four real vuln.go.dev advisories, and the gogs chain's
		// successor CVE (the chain is two advisories, not one), plus the DOS canary on the opt-in.
		{checkout.LangGo, 10, 11},
		// The four non-Go floors are three real public advisories each (two for the ecosystems'
		// house canaries below), promoted from the authored corpus fixtures on 2026-08-05.
		{checkout.LangJava, 3, 6},
		{checkout.LangJS, 3, 5},
		{checkout.LangPython, 3, 5},
		{checkout.LangDotNet, 3, 4},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			if got := len(advisoryCorpus(tc.lang, false)); got != tc.wantDefault {
				t.Fatalf("default %s corpus size = %d, want %d", tc.lang, got, tc.wantDefault)
			}
			if got := len(advisoryCorpus(tc.lang, true)); got != tc.wantWithCanary {
				t.Fatalf("%s corpus size (canaries on) = %d, want %d", tc.lang, got, tc.wantWithCanary)
			}
		})
	}
}

// TestNoCodenameOnDefaultSurface is the regression gate on the house-canary ids: no advisory id
// reaching a default, ungated scan may carry the TEGRON- prefix, in any ecosystem.
func TestNoCodenameOnDefaultSurface(t *testing.T) {
	for _, lang := range []string{
		checkout.LangGo, checkout.LangJava, checkout.LangJS,
		checkout.LangPython, checkout.LangDotNet,
	} {
		for _, v := range advisoryCorpus(lang, false) {
			if strings.HasPrefix(v.ID, "TEGRON-") {
				t.Fatalf("default %s corpus advertises codename-bearing advisory %q on the customer-facing surface", lang, v.ID)
			}
		}
	}
}

// TestHouseCanaryOptIn proves the opt-in: the DOS house canary
// (FERRALON-APP-DOS-0001) is absent from the default Go corpus (the customer/investor surface
// stays byte-identical to before) and present ONLY when includeHouseCanaries is set (the Ferralon
// demo scan's -include-house-canaries). The SSRF canary stays scrubbed unconditionally. The
// canary is surfaced by corpus membership alone; it stays a candidate at the scan tier
// (reachable_candidate + attacker_tainted) — proof comes from the fire (inv. 5).
func TestHouseCanaryOptIn(t *testing.T) {
	const dosCanary = "FERRALON-APP-DOS-0001"
	const ssrfCanary = "FERRALON-APP-SSRF-0001"

	off := advisoryCorpus(checkout.LangGo, false)
	on := advisoryCorpus(checkout.LangGo, true)

	if containsAdvisory(off, dosCanary) {
		t.Fatalf("default Go corpus (flag off) must not contain the DOS house canary %q — the customer surface must stay clean", dosCanary)
	}
	if !containsAdvisory(on, dosCanary) {
		t.Fatalf("Go corpus with -include-house-canaries must contain the DOS house canary %q", dosCanary)
	}
	// The opt-in adds exactly the one DOS canary — nothing else moves.
	if len(on) != len(off)+1 {
		t.Fatalf("house-canary opt-in changed corpus size by %d, want +1 (only the DOS canary)", len(on)-len(off))
	}
	// The DOS canary's Source must be "osv" so the enumerator's Fireable candidate keys the same
	// advisory (osv:FERRALON-APP-DOS-0001) the fire path detonates (backend cmd/auto-prove).
	for _, v := range on {
		if v.ID == dosCanary && v.Source != "osv" {
			t.Fatalf("DOS house canary Source = %q, want \"osv\" (must match the fire path's advisory key)", v.Source)
		}
	}
	// The SSRF canary has no opt-in: scrubbed even with the flag on.
	if containsAdvisory(on, ssrfCanary) {
		t.Fatalf("SSRF house canary %q must stay scrubbed even with -include-house-canaries", ssrfCanary)
	}
}

func containsAdvisory(corpus []assessment.VulnRef, id string) bool {
	for _, v := range corpus {
		if v.ID == id {
			return true
		}
	}
	return false
}

// TestAcquireTargetLocalPath proves the local-path branch: an existing source directory is
// inventoried in place (no clone), its language detected, and the matching plugin + corpus
// selected. A Go tree routes to the Go plugin; a Java tree to the Java plugin.
func TestAcquireTargetLocalPath(t *testing.T) {
	t.Run("go tree → go plugin", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/x\n\ngo 1.22\n")

		acq, err := acquireTarget(context.Background(), dir, "", "", "/fake/bin", false)
		if err != nil {
			t.Fatalf("acquireTarget: %v", err)
		}
		defer acq.cleanup()

		if acq.language != checkout.LangGo {
			t.Fatalf("language = %q, want go", acq.language)
		}
		if acq.plugin.Language() != "go" {
			t.Fatalf("plugin = %q, want go", acq.plugin.Language())
		}
		if acq.buildDir != dir {
			t.Fatalf("buildDir = %q, want in-place %q", acq.buildDir, dir)
		}
		if len(acq.advisories) != 10 { // the full default Go corpus, house canaries off
			t.Fatalf("advisories = %d, want go corpus (10)", len(acq.advisories))
		}
		if acq.repo != filepath.Base(dir) {
			t.Fatalf("repo = %q, want %q", acq.repo, filepath.Base(dir))
		}
	})

	t.Run("java tree → java plugin", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "App.java"), "class App {}\n")

		// The default (customer-facing) acquire resolves the three real Maven advisories, with no
		// canary among them. Emptiness is still judged later, on the resolved work set
		// (scanWorkSet), because the OSV widening runs off this acquisition — acquisition itself
		// never refuses a scan.
		bare, err := acquireTarget(context.Background(), dir, "", "acme/app", "/fake/bin", false)
		if err != nil {
			t.Fatalf("acquireTarget (canaries off): %v", err)
		}
		bare.cleanup()
		if len(bare.advisories) != 3 {
			t.Fatalf("default java floor = %d advisories, want 3 (the real Maven corpus)", len(bare.advisories))
		}

		acq, err := acquireTarget(context.Background(), dir, "", "acme/app", "/fake/bin", true)
		if err != nil {
			t.Fatalf("acquireTarget (canaries on): %v", err)
		}
		defer acq.cleanup()

		if acq.language != checkout.LangJava {
			t.Fatalf("language = %q, want java", acq.language)
		}
		if acq.plugin.Language() != "java" {
			t.Fatalf("plugin = %q, want java", acq.plugin.Language())
		}
		if acq.repo != "acme/app" {
			t.Fatalf("repo = %q, want override acme/app", acq.repo)
		}
		if len(acq.advisories) != 6 {
			t.Fatalf("advisories (canaries on) = %d, want java corpus (6: 3 real + 3 canaries)", len(acq.advisories))
		}
	})

	t.Run("unrecognized tree errors", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "README.txt"), "nothing to analyze\n")
		if _, err := acquireTarget(context.Background(), dir, "", "", "/fake/bin", false); err == nil {
			t.Fatal("expected error for unrecognized source tree, got nil")
		}
	})
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}
