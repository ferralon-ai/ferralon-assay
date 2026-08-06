// action_wiring_test.go — the missing edge: every supported language must end up REACHABLE through
// the published Action, not merely baked into the tarball.
//
// # The gap this closes
//
// Three artifacts have to agree about the language set, and until this file there were only two
// edges between them:
//
//	supportedLanguages  --TestBakedTargetsCoverEverySupportedLanguage-->  scripts/build-release.sh
//	scripts/build-release.sh  ------------------- (nothing) ------------>  action.yml
//
// So the release could bake an analyzer for a language and the Action could still fail to expose it.
// That is exactly what shipped: action.yml carried two hand-typed lists — a chmod list and a symlink
// list — naming the CLI plus Go, Python and JS. Java and .NET were extracted from the tarball onto
// the runner's disk and then left with no `tegron-plugin-<lang>` lookup name, so the CLI's
// exec.LookPath found nothing and the run died at the customer's runner. In-module every language
// completed a scan; through the Action two of them could not start one.
//
// # Why this test runs the shell instead of reading it
//
// A test that greps action.yml for `tegron-plugin-java` passes the moment somebody writes that
// literal back — it locks in the very failure mode being removed (a second spelling of a value that
// should be derived). So this file extracts the wiring block from action.yml VERBATIM, runs it
// against a staged directory holding the REAL baked asset names, and asserts on the lookup names
// that come out the other side. What is under test is the derivation, not its transcription.
//
// The staged asset names are not typed here either: they come from `scripts/build-release.sh
// binaries`, the one target table. The chain is therefore closed end to end —
//
//	supportedLanguages -> build-release.sh -> the baked asset names -> action.yml's derivation
//	                                                                -> tegron-plugin-<lang>
//
// — and every link is exercised rather than asserted.
//
// Hermetic: no network, no `go build`, no release download. `build-release.sh binaries` only prints
// the table, and the wiring block's only input is a directory of files this test creates.
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	actionYMLPath      = "../../action.yml"
	buildReleasePath   = "../../scripts/build-release.sh"
	wiringBeginMarker  = ">>> BEGIN plugin wiring >>>"
	wiringEndMarker    = "<<< END plugin wiring <<<"
	cliAssetName       = "ferralon-assay-scan"
	pluginAssetPrefix  = "ferralon-assay-scan-plugin"
	pluginLookupPrefix = "tegron-plugin-"
)

// actionWiringScript extracts the plugin-wiring block from the published action.yml and returns it
// as a runnable script whose sole argument is the extraction directory.
//
// The block lives inside a YAML literal `run: |` scalar, so it is uniformly indented; the common
// indent is stripped. `set -euo pipefail` is prepended because that is the first line of the step
// the block is embedded in — running it under laxer settings would test a shell the Action never
// executes.
func actionWiringScript(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile(actionYMLPath)
	if err != nil {
		t.Fatalf("reading the published Action at %s: %v", actionYMLPath, err)
	}

	var block []string
	var inBlock bool
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.Contains(line, wiringBeginMarker):
			if inBlock {
				t.Fatalf("%s contains a second %q before the block was closed", actionYMLPath, wiringBeginMarker)
			}
			inBlock = true
		case strings.Contains(line, wiringEndMarker):
			if !inBlock {
				t.Fatalf("%s closes the wiring block without opening it", actionYMLPath)
			}
			inBlock = false
		case inBlock:
			block = append(block, line)
		}
	}
	if inBlock {
		t.Fatalf("%s opens the wiring block with %q and never closes it with %q",
			actionYMLPath, wiringBeginMarker, wiringEndMarker)
	}
	if len(block) == 0 {
		t.Fatalf("no plugin-wiring block found in %s between %q and %q — the Action's plugin "+
			"discovery is no longer where this lock reads it, so nothing was tested",
			actionYMLPath, wiringBeginMarker, wiringEndMarker)
	}

	indent := -1
	for _, line := range block {
		if strings.TrimSpace(line) == "" {
			continue
		}
		n := len(line) - len(strings.TrimLeft(line, " "))
		if indent < 0 || n < indent {
			indent = n
		}
	}
	for i, line := range block {
		if len(line) >= indent {
			block[i] = line[indent:]
		} else {
			block[i] = strings.TrimLeft(line, " ")
		}
	}

	return "set -euo pipefail\nWORK=\"$1\"\n" + strings.Join(block, "\n") + "\n"
}

// runActionWiring runs the extracted block against work and returns its combined output plus the
// error, if any. The caller decides whether a non-zero exit is the expected result.
func runActionWiring(t *testing.T, work string) (string, error) {
	t.Helper()

	script := filepath.Join(t.TempDir(), "wiring.sh")
	if err := os.WriteFile(script, []byte(actionWiringScript(t)), 0o700); err != nil {
		t.Fatalf("staging the wiring script: %v", err)
	}
	// Deliberately no os/exec PATH inheritance concerns: the block shells out only to coreutils.
	cmd := exec.Command("bash", script, work)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// bakedAssetNames returns the release payload's binary names, read from the ONE target table by
// asking the script itself rather than by parsing it. An unreadable table is a failure, never a
// skip: scripts/build-release.sh is in-module and present on every surface this test runs on.
func bakedAssetNames(t *testing.T) []string {
	t.Helper()

	out, err := exec.Command("bash", buildReleasePath, "binaries").Output()
	if err != nil {
		t.Fatalf("asking %s for the baked asset names: %v", buildReleasePath, err)
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			names = append(names, line)
		}
	}
	if len(names) == 0 {
		t.Fatalf("%s reported no baked binaries", buildReleasePath)
	}
	return names
}

// stageExtraction writes each name as a NON-executable regular file, standing in for a fresh
// `tar -xzf` of the release tarball. Non-executable on purpose: the wiring block is responsible for
// the chmod, and a pre-executable fixture would hide a dropped one.
func stageExtraction(t *testing.T, names ...string) string {
	t.Helper()

	work := t.TempDir()
	for _, name := range names {
		body := "#!/bin/sh\nexit 0\n"
		if err := os.WriteFile(filepath.Join(work, name), []byte(body), 0o600); err != nil {
			t.Fatalf("staging %s: %v", name, err)
		}
	}
	return work
}

// lookupNames lists the plugin dir the wiring produced, resolving each entry and requiring it to be
// an executable file. A dangling or non-executable symlink is a PATH entry the CLI's exec.LookPath
// will skip, which is indistinguishable at the runner from the language never having been wired.
func lookupNames(t *testing.T, work string) []string {
	t.Helper()

	dir := filepath.Join(work, "plugin-path")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the plugin dir the wiring exported: %v", err)
	}
	var names []string
	for _, e := range entries {
		full := filepath.Join(dir, e.Name())
		info, err := os.Stat(full) // follows the symlink
		if err != nil {
			t.Errorf("%s does not resolve: %v — a dangling entry is not a reachable analyzer", e.Name(), err)
			continue
		}
		if info.IsDir() {
			t.Errorf("%s resolves to a directory, not an analyzer binary", e.Name())
			continue
		}
		if info.Mode().Perm()&0o111 == 0 {
			t.Errorf("%s resolves to a non-executable file (mode %v) — exec.LookPath skips it, so the "+
				"language is unreachable even though the symlink exists", e.Name(), info.Mode().Perm())
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// TestActionWiringExposesEverySupportedLanguage is the missing edge.
//
// It stages the real baked asset names, runs the Action's real wiring, and requires a
// `tegron-plugin-<lang>` lookup name for every supported language. Drop a language from the
// derivation — including by removing the bare-name arm that maps `ferralon-assay-scan-plugin` to Go
// — and this goes red.
func TestActionWiringExposesEverySupportedLanguage(t *testing.T) {
	assets := bakedAssetNames(t)
	work := stageExtraction(t, assets...)

	out, err := runActionWiring(t, work)
	if err != nil {
		t.Fatalf("the Action's plugin wiring failed against a complete extraction: %v\n%s", err, out)
	}

	got := lookupNames(t, work)
	have := make(map[string]bool, len(got))
	for _, name := range got {
		have[name] = true
	}

	for _, language := range supportedLanguages {
		want := pluginLookupPrefix + language
		if !have[want] {
			t.Errorf("the Action exposes no %s: %s is a supported language whose analyzer IS in the "+
				"tarball, but the wiring gives it no lookup name, so exec.LookPath finds nothing and "+
				"the run dies at the runner.\n  exposed: %v\n  wiring output:\n%s",
				want, language, got, out)
		}
	}

	// The other direction: every lookup name must correspond to a plugin asset that was actually
	// extracted. A stray name means the derivation invented a language, which would route a repo to
	// an analyzer that is not there.
	wantCount := 0
	for _, a := range assets {
		if strings.HasPrefix(a, pluginAssetPrefix) {
			wantCount++
		}
	}
	if len(got) != wantCount {
		t.Errorf("the extraction carried %d analyzer plugin(s) but the wiring exposed %d lookup name(s) %v — "+
			"the two must correspond one-for-one", wantCount, len(got), got)
	}
	for _, name := range got {
		if !strings.HasPrefix(name, pluginLookupPrefix) {
			t.Errorf("the wiring exposed %q, which is not a %s* lookup name", name, pluginLookupPrefix)
		}
	}

	t.Logf("plugin-path from a %d-asset extraction: %v", len(assets), got)
}

// TestActionWiringFailsClosed pins the other half: a wiring step that silently exports an empty
// plugin dir converts a packaging failure into a confusing analysis failure several steps later,
// where nothing still points at the download.
func TestActionWiringFailsClosed(t *testing.T) {
	t.Run("no plugins", func(t *testing.T) {
		work := stageExtraction(t, cliAssetName)

		out, err := runActionWiring(t, work)
		if err == nil {
			t.Fatalf("the wiring succeeded on an extraction carrying no analyzer plugins; it exported "+
				"a plugin dir with nothing on it:\n%s", out)
		}
		if !strings.Contains(out, "no analyzer plugins") {
			t.Errorf("the abort does not say what was wrong (want a mention of the missing plugins):\n%s", out)
		}
		if !strings.Contains(out, cliAssetName) {
			t.Errorf("the abort does not name what it DID find in the extraction, which is the only "+
				"thing that makes it diagnosable:\n%s", out)
		}
	})

	t.Run("no CLI", func(t *testing.T) {
		work := stageExtraction(t) // an empty extraction

		out, err := runActionWiring(t, work)
		if err == nil {
			t.Fatalf("the wiring succeeded on an empty extraction:\n%s", out)
		}
		if !strings.Contains(out, cliAssetName) {
			t.Errorf("the abort does not name the missing CLI:\n%s", out)
		}
	})
}
