package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/plugin"
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
		{checkout.LangCFamily, "cfamily"}, // row-zero skeleton lane: routes even though not in supportedLanguages
	}
	for _, tc := range cases {
		t.Run(tc.lang, func(t *testing.T) {
			p, err := selectPlugin(tc.lang, "/fake/analyzer-bin", nil, nil, nil, nil)
			if err != nil {
				t.Fatalf("selectPlugin(%q): %v", tc.lang, err)
			}
			if p.Language() != tc.want {
				t.Fatalf("selectPlugin(%q).Language() = %q, want %q", tc.lang, p.Language(), tc.want)
			}
		})
	}

	if _, err := selectPlugin(checkout.LangUnknown, "", nil, nil, nil, nil); err == nil {
		t.Fatal("selectPlugin(unknown): expected error, got nil")
	}
}

// TestHouseCanariesByLanguage pins the scanner's only built-in work-set membership: nothing unless
// the scan opted the house canaries in, and with the opt-in each language's own canaries and no
// other ecosystem's.
func TestHouseCanariesByLanguage(t *testing.T) {
	for _, tc := range []struct {
		lang string
		want []string
	}{
		{checkout.LangGo, []string{"FERRALON-APP-DOS-0001"}},
		{checkout.LangJava, []string{"FERRALON-JAVA-SSRF-0001", "FERRALON-JAVA-SPRING-SSRF-0001", "FERRALON-JAVA-DEP-0001"}},
		{checkout.LangKotlin, []string{"FERRALON-KOTLIN-DEP-0001"}},
		{checkout.LangJS, []string{"FERRALON-JS-SSRF-0001", "FERRALON-JS-DEP-0001"}},
		{checkout.LangPython, []string{"FERRALON-PY-AIRFLOW-EXPAPI-0001", "FERRALON-PY-DEP-0001"}},
		{checkout.LangDotNet, []string{"FERRALON-NET-DEP-0001"}},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			if got := houseCanaries(tc.lang, false); len(got) != 0 {
				t.Fatalf("houseCanaries(%s, false) = %v, want none: a scan that did not opt in carries no advisories", tc.lang, got)
			}
			var got []string
			for _, v := range houseCanaries(tc.lang, true) {
				got = append(got, v.ID)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("houseCanaries(%s, true) = %v, want %v", tc.lang, got, tc.want)
			}
		})
	}
}

// TestHouseCanaryOptIn pins the DOS canary's work-set key: its Source must be "osv" so the
// enumerator's Fireable candidate keys the same advisory (osv:FERRALON-APP-DOS-0001) the fire path
// proves (backend cmd/auto-prove). The SSRF canary has no opt-in: it stays out even with the flag.
func TestHouseCanaryOptIn(t *testing.T) {
	const dosCanary = "FERRALON-APP-DOS-0001"
	const ssrfCanary = "FERRALON-APP-SSRF-0001"

	on := houseCanaries(checkout.LangGo, true)
	if !containsAdvisory(on, dosCanary) {
		t.Fatalf("Go canaries with -include-house-canaries must contain %q", dosCanary)
	}
	for _, v := range on {
		if v.ID == dosCanary && v.Source != "osv" {
			t.Fatalf("DOS house canary Source = %q, want \"osv\" (must match the fire path's advisory key)", v.Source)
		}
	}
	if containsAdvisory(on, ssrfCanary) {
		t.Fatalf("SSRF house canary %q must stay out even with -include-house-canaries", ssrfCanary)
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
// inventoried in place (no clone), its language detected, and the matching plugin selected. A Go tree routes to the Go plugin; a Java tree to the Java plugin.
func TestAcquireTargetLocalPath(t *testing.T) {
	t.Run("go tree → go plugin", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/x\n\ngo 1.22\n")

		acq, err := acquireTarget(context.Background(), dir, "", "", "/fake/bin", false, graphRequest{mode: buildGraphOff})
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
		if len(acq.advisories) != 0 { // house canaries off: the scanner carries no advisories of its own
			t.Fatalf("advisories = %v, want none", ids(acq.advisories))
		}
		if acq.repo != filepath.Base(dir) {
			t.Fatalf("repo = %q, want %q", acq.repo, filepath.Base(dir))
		}
	})

	t.Run("java tree → java plugin", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "App.java"), "class App {}\n")

		// The default acquire carries no advisories. Emptiness is judged later, on the resolved
		// work set (scanWorkSet), because the corpus policy and the OSV widening run off this
		// acquisition — acquisition itself never refuses a scan.
		bare, err := acquireTarget(context.Background(), dir, "", "acme/app", "/fake/bin", false, graphRequest{mode: buildGraphOff})
		if err != nil {
			t.Fatalf("acquireTarget (canaries off): %v", err)
		}
		bare.cleanup()
		if len(bare.advisories) != 0 {
			t.Fatalf("default java floor = %v, want none", ids(bare.advisories))
		}

		acq, err := acquireTarget(context.Background(), dir, "", "acme/app", "/fake/bin", true, graphRequest{mode: buildGraphOff})
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
		if len(acq.advisories) != 3 {
			t.Fatalf("advisories (canaries on) = %v, want the 3 java house canaries", ids(acq.advisories))
		}
	})

	t.Run("c tree → cfamily plugin, honest-absent floor", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "main.c"), "int main(void){return 0;}\n")
		writeFile(t, filepath.Join(dir, "util.h"), "#pragma once\n")

		acq, err := acquireTarget(context.Background(), dir, "", "", "/fake/bin", false, graphRequest{mode: buildGraphOff})
		if err != nil {
			t.Fatalf("acquireTarget: %v", err)
		}
		defer acq.cleanup()

		if acq.language != checkout.LangCFamily {
			t.Fatalf("language = %q, want cfamily", acq.language)
		}
		if acq.plugin.Language() != "cfamily" {
			t.Fatalf("plugin = %q, want cfamily", acq.plugin.Language())
		}
		// Row-zero fail-open: the skeleton lane has no advisory floor. An empty floor makes a scan of
		// a C/C++ tree halt at the empty-work-set gate (never a false clean verdict), which is the
		// honest Phase-0 posture — NOT a fabricated floor forced in to make the scan complete.
		if len(acq.advisories) != 0 {
			t.Fatalf("cfamily default floor = %d advisories, want 0 (honest-absent skeleton)", len(acq.advisories))
		}
	})

	t.Run("unrecognized tree errors", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "README.txt"), "nothing to analyze\n")
		if _, err := acquireTarget(context.Background(), dir, "", "", "/fake/bin", false, graphRequest{mode: buildGraphOff}); err == nil {
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

// A C/C++ scan hands every cfamily spawn one private per-scan wasm cache dir and removes it at
// scan end; an operator-set cache dir wins and nothing is created.
func TestAcquireTarget_CFamilyWasmCacheDir(t *testing.T) {
	spawn := func(t *testing.T, acq *acquired, out string) string {
		t.Helper()
		_, _ = acq.plugin.IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{BuildDir: acq.buildDir})
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("the fake plugin did not run: %v", err)
		}
		return string(got)
	}
	setup := func(t *testing.T) (dir, bin, out string) {
		t.Helper()
		dir = t.TempDir()
		writeFile(t, filepath.Join(dir, "main.c"), "int main(void){return 0;}\n")
		tools := t.TempDir()
		out = filepath.Join(tools, "env")
		bin = filepath.Join(tools, "assay-plugin-cfamily")
		script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' \"$%s\" > %q\n", plugin.CFamilyWasmCacheDirEnv, out)
		if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		return dir, bin, out
	}

	t.Run("per-scan dir, private, removed at scan end", func(t *testing.T) {
		t.Setenv(envCFamilyWasmCacheDir, "")
		dir, bin, out := setup(t)
		acq, err := acquireTarget(context.Background(), dir, "", "", bin, false, graphRequest{mode: buildGraphOff})
		if err != nil {
			t.Fatalf("acquireTarget: %v", err)
		}
		cache := spawn(t, acq, out)
		if cache == "" || !filepath.IsAbs(cache) {
			acq.cleanup()
			t.Fatalf("spawn saw cache dir %q, want an absolute per-scan dir", cache)
		}
		fi, err := os.Stat(cache)
		if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			acq.cleanup()
			t.Fatalf("cache dir %q: %v, %v; want a 0700 directory", cache, fi, err)
		}
		acq.cleanup()
		if _, err := os.Stat(cache); !os.IsNotExist(err) {
			t.Errorf("cache dir %q survives the scan: %v", cache, err)
		}
	})

	t.Run("operator-set dir wins", func(t *testing.T) {
		mine := t.TempDir()
		t.Setenv(envCFamilyWasmCacheDir, mine)
		dir, bin, out := setup(t)
		acq, err := acquireTarget(context.Background(), dir, "", "", bin, false, graphRequest{mode: buildGraphOff})
		if err != nil {
			t.Fatalf("acquireTarget: %v", err)
		}
		got := spawn(t, acq, out)
		acq.cleanup()
		if got != mine {
			t.Errorf("spawn saw cache dir %q, want the operator's %q", got, mine)
		}
		if _, err := os.Stat(mine); err != nil {
			t.Errorf("scan end removed the operator's dir: %v", err)
		}
	})
}
