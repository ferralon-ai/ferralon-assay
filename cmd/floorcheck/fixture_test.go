package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCorpusRel = "intel/corpus-test/full.jsonl.gz"

func sha(body string) string {
	h := sha256.Sum256([]byte(body))
	return hex.EncodeToString(h[:])
}

// testFloor is a floor root holding one shared corpus release and a fixtures directory.
type testFloor struct {
	root, fixtures string
}

func newTestFloor(t *testing.T) testFloor {
	t.Helper()
	root := t.TempDir()
	write(t, root, testCorpusRel, "corpus")
	write(t, root, "intel/corpus-test/signals.json.gz", "signals")
	return testFloor{root: root, fixtures: filepath.Join(root, "fixtures")}
}

// scenarioYAML is a valid go scenario whose intel block is the given YAML (indented two spaces).
func scenarioYAML(intel string) string {
	return `schema: ferralon.floor-scenario.v1
repo: https://github.com/o/r
commit: ` + testCommit + `
lang: go
build:
  go: 1.23.12
  goos: linux
  goarch: amd64
  cgo: false
intel:
  policy: full
` + intel
}

func sharedIntel() string {
	return "  corpus:\n    path: " + testCorpusRel + "\n    sha256: " + sha("corpus") + "\n" +
		"  signals:\n    path: intel/corpus-test/signals.json.gz\n    sha256: " + sha("signals") + "\n"
}

const expectYAML = `schema: ferralon.floor-expect.v1
scan: complete
findings:
  - advisory: GO-1
    package: m@v1
    truth: reachable
    floor: reachable_candidate
`

// fixture writes a fixture directory with the given scenario and expect bodies.
func (f testFloor) fixture(t *testing.T, name, scenario, expect string) string {
	t.Helper()
	dir := filepath.Join(f.fixtures, name)
	write(t, dir, fileScenario, scenario)
	write(t, dir, fileExpect, expect)
	return dir
}

// advisoryManifest is a directory corpus's manifest.json with one record; digest overrides the
// record's pinned digest when not empty.
func advisoryManifest(digest string) string {
	if digest == "" {
		digest = "sha256:" + sha(`{"id":"GO-1"}`)
	}
	return `{"schema_version":"v2","record_count":1,
"records":[{"identifier":"GO-1","path":"GO-1.json","output_digest":"` + digest + `"}]}`
}

// advisoryDir writes a scanner-readable directory corpus inside a fixture.
func advisoryDir(t *testing.T, dir, digest string) {
	t.Helper()
	write(t, dir, "intel/advisories/GO-1.json", `{"id":"GO-1"}`)
	write(t, dir, "intel/advisories/manifest.json", advisoryManifest(digest))
}

// advisoriesIntel is the intel block pinning a manifest at path whose body is advisoryManifest(digest).
func advisoriesIntel(path, digest string) string {
	return "  advisories:\n    path: " + path + "\n    sha256: " + sha(advisoryManifest(digest)) + "\n"
}

const localManifest = "intel/advisories/manifest.json"

func TestLoadFixtureResolution(t *testing.T) {
	f := newTestFloor(t)
	dir := f.fixture(t, "shared", scenarioYAML(sharedIntel()), expectYAML)
	fx, err := loadFixture(dir, f.root, defaultRules)
	if err != nil {
		t.Fatal(err)
	}
	realRoot, _ := filepath.EvalSymlinks(f.root)
	if want := filepath.Join(realRoot, testCorpusRel); fx.CorpusPath != want {
		t.Errorf("corpus %s, want it resolved under the floor root: %s", fx.CorpusPath, want)
	}
	if want := filepath.Join(realRoot, "intel/corpus-test/signals.json.gz"); fx.SignalsPath != want {
		t.Errorf("signals %s, want %s", fx.SignalsPath, want)
	}

	local := f.fixture(t, "local", scenarioYAML(advisoriesIntel(localManifest, "")), expectYAML)
	advisoryDir(t, local, "")
	fx, err = loadFixture(local, f.root, defaultRules)
	if err != nil {
		t.Fatal(err)
	}
	realLocal, _ := filepath.EvalSymlinks(local)
	if want := filepath.Join(realLocal, "intel/advisories"); fx.CorpusPath != want || fx.SignalsPath != "" {
		t.Errorf("advisories %s (signals %q), want them resolved inside the fixture: %s", fx.CorpusPath, fx.SignalsPath, want)
	}
}

func TestLoadFixtureRejects(t *testing.T) {
	corpus := func(path, digest string) string {
		return "  corpus:\n    path: " + path + "\n    sha256: " + digest + "\n"
	}
	for _, tc := range []struct {
		name     string
		scenario string
		expect   string
		setup    func(t *testing.T, f testFloor, dir string)
		kind     string
		msg      string
	}{
		{name: "corpus digest mismatch", scenario: scenarioYAML(corpus(testCorpusRel, sha("other"))), kind: KindIntelUnverified, msg: "scenario pins"},
		{name: "signals digest mismatch", scenario: scenarioYAML(corpus(testCorpusRel, sha("corpus")) +
			"  signals:\n    path: intel/corpus-test/signals.json.gz\n    sha256: " + sha("x") + "\n"), kind: KindIntelUnverified, msg: "intel.signals"},
		{name: "corpus missing", scenario: scenarioYAML(corpus("intel/corpus-gone/full.jsonl.gz", sha("corpus"))), kind: KindIntelUnverified, msg: "no such file"},
		{name: "no corpus", scenario: scenarioYAML(""), kind: KindIntelUnverified, msg: "names no corpus"},
		{name: "corpus and advisories", scenario: scenarioYAML(sharedIntel() + advisoriesIntel(localManifest, "")),
			setup: func(t *testing.T, _ testFloor, dir string) { advisoryDir(t, dir, "") }, kind: KindIntelUnverified, msg: "both"},
		{name: "corpus climbs out of intel", scenario: scenarioYAML(corpus("../outside.gz", sha("x"))),
			setup: func(t *testing.T, f testFloor, _ string) { write(t, filepath.Dir(f.root), "outside.gz", "x") }, kind: KindIntelUnverified, msg: "leaves its directory"},
		{name: "corpus absolute", scenario: scenarioYAML(corpus("/etc/hosts", sha("x"))), kind: KindIntelUnverified, msg: "absolute"},
		{name: "corpus in the floor root but outside intel", scenario: scenarioYAML(corpus("fixtures/stray.gz", sha("x"))),
			setup: func(t *testing.T, f testFloor, _ string) { write(t, f.fixtures, "stray.gz", "x") }, kind: KindIntelUnverified, msg: "resolves outside intel/"},
		{name: "corpus symlink out of intel", scenario: scenarioYAML(corpus("intel/link.gz", sha("x"))),
			setup: func(t *testing.T, f testFloor, _ string) {
				write(t, f.root, "elsewhere.gz", "x")
				if err := os.Symlink(filepath.Join(f.root, "elsewhere.gz"), filepath.Join(f.root, "intel/link.gz")); err != nil {
					t.Fatal(err)
				}
			}, kind: KindIntelUnverified, msg: "resolves outside"},
		{name: "advisories climb out of the fixture", scenario: scenarioYAML(advisoriesIntel("../other/"+localManifest, "")),
			setup: func(t *testing.T, f testFloor, _ string) { advisoryDir(t, filepath.Join(f.fixtures, "other"), "") }, kind: KindIntelUnverified, msg: "leaves its directory"},
		{name: "advisories symlink out of the fixture", scenario: scenarioYAML(advisoriesIntel(localManifest, "")),
			setup: func(t *testing.T, f testFloor, dir string) {
				other := filepath.Join(f.fixtures, "other")
				advisoryDir(t, other, "")
				if err := os.MkdirAll(filepath.Join(dir, "intel"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(other, "intel/advisories"), filepath.Join(dir, "intel/advisories")); err != nil {
					t.Fatal(err)
				}
			}, kind: KindIntelUnverified, msg: "resolves outside"},
		{name: "advisories under the shared intel are not fixture intel", scenario: scenarioYAML(advisoriesIntel("../../intel/corpus-test/manifest.json", "")),
			kind: KindIntelUnverified, msg: "leaves its directory"},
		{name: "advisory manifest digest mismatch", scenario: scenarioYAML(advisoriesIntel(localManifest, "")),
			setup: func(t *testing.T, _ testFloor, dir string) {
				advisoryDir(t, dir, "")
				write(t, dir, localManifest, advisoryManifest("")+"\n")
			}, kind: KindIntelUnverified, msg: "scenario pins"},
		{name: "advisories pin a directory, not its manifest", scenario: scenarioYAML(strings.Replace(advisoriesIntel(localManifest, ""), localManifest, "intel/advisories", 1)),
			setup: func(t *testing.T, _ testFloor, dir string) { advisoryDir(t, dir, "") }, kind: KindIntelUnverified, msg: "manifest.json"},
		{name: "advisory record digest mismatch", scenario: scenarioYAML(advisoriesIntel(localManifest, "sha256:"+sha("nope"))),
			setup: func(t *testing.T, _ testFloor, dir string) { advisoryDir(t, dir, "sha256:"+sha("nope")) }, kind: KindIntelUnverified, msg: "manifest pins"},
		{name: "unpinned signals.json beside the advisories", scenario: scenarioYAML(advisoriesIntel(localManifest, "")),
			setup: func(t *testing.T, _ testFloor, dir string) {
				advisoryDir(t, dir, "")
				write(t, dir, "intel/advisories/signals.json", "{}")
			}, kind: KindIntelUnverified, msg: "unpinned"},
		{name: "advisory manifest in the test-fixture shape", scenario: scenarioYAML("  advisories:\n    path: " + localManifest + "\n    sha256: " +
			sha(`{"advisories":{"GO-1":{"file":"GO-1.json","digest":"x"}}}`) + "\n"),
			setup: func(t *testing.T, _ testFloor, dir string) {
				write(t, dir, localManifest, `{"advisories":{"GO-1":{"file":"GO-1.json","digest":"x"}}}`)
			}, kind: KindIntelUnverified, msg: "does not read"},
		{name: "repo smuggles a git option", scenario: strings.Replace(scenarioYAML(sharedIntel()), "repo: https://github.com/o/r",
			`repo: "--upload-pack=touch /tmp/MARKER; echo #://h/o/r"`, 1), kind: KindFixtureInvalid, msg: "is not https://"},
		{name: "repo with whitespace", scenario: strings.Replace(scenarioYAML(sharedIntel()), "https://github.com/o/r", `"https://github.com/o/r x"`, 1),
			kind: KindFixtureInvalid, msg: "is not https://"},
		{name: "repo over another transport", scenario: strings.Replace(scenarioYAML(sharedIntel()), "https://github.com/o/r", "ext::sh -c touch% /tmp/x", 1),
			kind: KindFixtureInvalid, msg: "is not https://"},
		{name: "repo over ssh", scenario: strings.Replace(scenarioYAML(sharedIntel()), "https://github.com/o/r", "ssh://github.com/o/r", 1),
			kind: KindFixtureInvalid, msg: "is not https://"},
		{name: "repo with credentials", scenario: strings.Replace(scenarioYAML(sharedIntel()), "https://github.com/o/r", "https://u:p@github.com/o/r", 1),
			kind: KindFixtureInvalid, msg: "is not https://"},
		{name: "repo owner reads as an option", scenario: strings.Replace(scenarioYAML(sharedIntel()), "https://github.com/o/r", "https://github.com/-o/r", 1),
			kind: KindFixtureInvalid, msg: "is not https://"},
		{name: "repo with a deeper path", scenario: strings.Replace(scenarioYAML(sharedIntel()), "https://github.com/o/r", "https://github.com/o/r/tree/main", 1),
			kind: KindFixtureInvalid, msg: "is not https://"},
		{name: "go version without its patch", scenario: strings.Replace(scenarioYAML(sharedIntel()), "go: 1.23.12", "go: 1.23", 1), kind: KindFixtureInvalid, msg: "exact Go version"},
		{name: "go release candidate", scenario: strings.Replace(scenarioYAML(sharedIntel()), "go: 1.23.12", "go: 1.24rc1", 1), kind: KindFixtureInvalid, msg: "exact Go version"},
		{name: "go fields on a python scenario", scenario: strings.Replace(scenarioYAML(sharedIntel()), "lang: go", "lang: python", 1), kind: KindFixtureInvalid, msg: "belong to the go lane"},
		{name: "jdk on a go scenario", scenario: strings.Replace(scenarioYAML(sharedIntel()), "  cgo: false\n", "  cgo: false\n  jdk: \"17\"\n", 1), kind: KindFixtureInvalid, msg: "build.jdk belongs"},
		{name: "node on a python scenario", scenario: laneScenario("python", `  node: "20"`), kind: KindFixtureInvalid, msg: "build.node belongs"},
		{name: "python on a js scenario", scenario: laneScenario("js", `  python: "3.12"`), kind: KindFixtureInvalid, msg: "build.python belongs"},
		{name: "jdk not a major", scenario: laneScenario("java", `  jdk: "17.0.2"`), kind: KindFixtureInvalid, msg: "JDK major"},
		{name: "python without its minor", scenario: laneScenario("python", `  python: "3"`), kind: KindFixtureInvalid, msg: "Python version"},
		{name: "short commit", scenario: strings.Replace(scenarioYAML(sharedIntel()), testCommit, "0123456", 1), kind: KindFixtureInvalid, msg: "full 40-hex"},
		{name: "unknown scenario field", scenario: scenarioYAML(sharedIntel()) + "extra: 1\n", kind: KindFixtureInvalid, msg: "not found"},
		{name: "go scenario without a toolchain", scenario: strings.Replace(scenarioYAML(sharedIntel()), "  go: 1.23.12\n", "", 1), kind: KindFixtureInvalid, msg: "pins build.go"},
		{name: "scan.flags restates a harness flag", scenario: scenarioYAML(sharedIntel()) + "scan:\n  flags: [\"-scan-timeout=1m\"]\n", kind: KindFixtureInvalid, msg: "-scan-timeout"},
		{name: "unknown truth", expect: strings.Replace(expectYAML, "truth: reachable", "truth: maybe", 1), kind: KindFixtureInvalid, msg: "truth"},
		{name: "always-wrong floor", expect: strings.Replace(strings.Replace(expectYAML, "truth: reachable", "truth: unreachable", 1),
			"floor: reachable_candidate", "floor: disqualified", 1), kind: KindFixtureInvalid, msg: "always wrong"},
		{name: "basis where the best verdict has none", expect: expectYAML + "    basis: vulnerable_symbol_unreachable\n", kind: KindFixtureInvalid, msg: "carries no basis"},
		{name: "partial without reasons", expect: strings.Replace(expectYAML, "scan: complete", "scan: partial", 1), kind: KindFixtureInvalid, msg: "no partiality"},
		{name: "duplicate expectation", expect: expectYAML + strings.SplitN(expectYAML, "findings:\n", 2)[1], kind: KindFixtureInvalid, msg: "second expectation"},
		{name: "review packet escapes", expect: expectYAML + "    review:\n      by: r\n      packet: ../../x\n", kind: KindFixtureInvalid, msg: "review.packet"},
		{name: "review without a reviewer", expect: expectYAML + "    review:\n      path_sha: abc\n", kind: KindFixtureInvalid, msg: "review.by"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTestFloor(t)
			scenario, exp := tc.scenario, tc.expect
			if scenario == "" {
				scenario = scenarioYAML(sharedIntel())
			}
			if exp == "" {
				exp = expectYAML
			}
			dir := f.fixture(t, "fx", scenario, exp)
			if tc.setup != nil {
				tc.setup(t, f, dir)
			}
			_, err := loadFixture(dir, f.root, defaultRules)
			if err == nil {
				t.Fatal("loaded")
			}
			if loadKind(err) != tc.kind || !strings.Contains(err.Error(), tc.msg) {
				t.Errorf("error %s: %v, want %s containing %q", loadKind(err), err, tc.kind, tc.msg)
			}
		})
	}
}

// laneScenario is a valid non-go scenario of the given lang with the given build lines.
func laneScenario(lang, build string) string {
	return `schema: ferralon.floor-scenario.v1
repo: https://github.com/o/r.git
commit: ` + testCommit + `
lang: ` + lang + `
build:
` + build + `
intel:
  policy: full
` + sharedIntel()
}

// TestLoadFixtureLanes: each lane loads with its own runtime pin, and with none.
func TestLoadFixtureLanes(t *testing.T) {
	f := newTestFloor(t)
	for name, sc := range map[string]string{
		"java":        laneScenario("java", `  jdk: "17"`),
		"kotlin":      laneScenario("kotlin", `  jdk: "21"`),
		"js":          laneScenario("js", `  node: "20"`),
		"python":      laneScenario("python", `  python: "3.12"`),
		"python bare": strings.Replace(laneScenario("python", ""), "build:\n\n", "", 1),
	} {
		if _, err := loadFixture(f.fixture(t, strings.ReplaceAll(name, " ", "-"), sc, expectYAML), f.root, defaultRules); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestLoadFixtureReviewOptional: review and its path_sha are optional; a reviewed expectation loads.
func TestLoadFixtureReviewOptional(t *testing.T) {
	f := newTestFloor(t)
	for name, exp := range map[string]string{
		"bare":         expectYAML,
		"reviewed":     expectYAML + "    review:\n      by: r\n      date: 2026-11-16\n",
		"with path":    expectYAML + "    review:\n      by: r\n      path_sha: abc\n      packet: packets/GO-1\n",
		"no findings":  "schema: ferralon.floor-expect.v1\nscan: complete\nfindings: []\n",
		"partial scan": strings.Replace(expectYAML, "scan: complete", "scan: partial\npartiality: [scan_cut_short]", 1),
	} {
		if _, err := loadFixture(f.fixture(t, strings.ReplaceAll(name, " ", "-"), scenarioYAML(sharedIntel()), exp), f.root, defaultRules); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
