// golden_outputs_test.go — pins the byte-exact serialized outputs a baseline scan writes.
//
// What it pins. For each fixture in goldenCases it runs the production baseline path in-process —
// acquireTarget, scanWorkSet, trigger.RunBaseline, then the same projection step publishResult runs
// (buildResult) into the same Local sink — and compares report.json, openvex.json,
// report.sarif.json and report.html against the files under testdata/golden/<case>/. The schema
// identifiers, field names, field order, verdicts and rendered text are all inside that comparison,
// so a change that alters any emitted byte for any of these inputs fails here.
//
// Why it exists. A refactor that renames packages, binaries, identifiers or fixtures must not change
// what the tool emits. "Tests still pass" does not show that: the assertions elsewhere are
// semantic. This test is the byte-level check, committed before the refactor so the refactor's
// commits are judged against it. A commit that renames a fixture's advisory id is expected to
// change the goldens by exactly that substitution and nothing else; review the golden diff, then
// regenerate.
//
// Hermeticity. Nothing here reaches the network and nothing needs docker:
//
//   - The JS, Python and Java cases run the real analyzer plugin subprocesses, built from this
//     module with `go build` into a temp dir. Those analyzers are offline on these fixtures.
//   - The Go analyzer cannot be run whole: its Reachability op drives govulncheck, which always
//     fetches the vulnerability database from vuln.go.dev and has no offline switch. goldenGoPlugin
//     therefore runs the real Go plugin for every op except Reachability, which answers as
//     govulncheck does against an empty database: no findings, carrying the call graph's own
//     partiality. Reachable Go findings in these fixtures come from the first-party call-graph
//     fallback (pipeline.firstPartyReachPaths), which does not use govulncheck.
//   - GOPROXY=off and GOTOOLCHAIN=local keep `go` from fetching modules or toolchains; every fixture
//     here declares no third-party dependency, or carries its lockfile.
//   - trapEgress fails the test on any HTTP request made through net/http's default transport.
//
// Normalization. Exactly one field is nondeterministic: the provenance timestamp, which the
// pipeline stamps from the wall clock. scrubTimestamps rewrites that one JSON field, wherever it
// appears (report.json, the JSON the HTML embeds, openvex.json), to a fixed token. Nothing else is
// rewritten. assertNoHostPaths fails the run if an absolute fixture or temp path leaks into any
// output, so the scrubber cannot grow to cover one silently.
//
// Regenerating. Run `ASSAY_GOLDEN_UPDATE=1 go test ./cmd/ferralon-assay -run TestGoldenOutputs`
// and review the diff under testdata/golden. Not covered: Kotlin and .NET (their analyzers need a
// JVM / dotnet SDK on PATH) and the partiality shapes only a failing analyzer produces.
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
	"github.com/ferralon-ai/ferralon-assay/statestore"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

const (
	// goldenUpdateEnv, when "1", rewrites the goldens from the current output instead of comparing.
	goldenUpdateEnv = "ASSAY_GOLDEN_UPDATE"

	goldenDir = "testdata/golden"

	// goldenCommit and goldenRevision are the provenance a caller supplies with -commit / -revision;
	// fixed so the Report's subject is identical on every run.
	goldenCommit   = "0123456789abcdef0123456789abcdef01234567"
	goldenRevision = "main"

	goldenTimestampToken = "<TIMESTAMP>"
)

// goldenOutputs are the files resultsink.Local writes, in the order they are compared.
var goldenOutputs = []string{
	resultsink.FileReportJSON,
	resultsink.FileOpenVEX,
	resultsink.FileSARIF,
	resultsink.FileReportHTML,
}

// goldenCase is one fixture scanned end to end. name keys the golden directory and is deliberately
// independent of the fixture's own name, so renaming a fixture directory edits one field here and
// leaves the golden files in place.
type goldenCase struct {
	name     string
	language string // plugin language, selects which analyzer binary drives the scan
	fixture  string // directory under corpus/testdata/repros
	note     string // what the case contributes; documentation only
}

// goldenCases cover, per language, a reachable finding and a finding that is not reachable or not
// affected. The FERRALON-* advisory ids carried by the house canaries appear in the
// reports of every case in their language, because -include-house-canaries is on.
var goldenCases = []goldenCase{
	{"go-reachable-house-canary", "go", "FERRALON-APP-DOS-0001-vulnerable", "reachable_candidate via first-party call graph"},
	{"go-not-reachable-house-canary", "go", "FERRALON-APP-SSRF-0001-patched", "same floor, no reachable house-canary sink"},
	{"js-reachable-direct-lockfile", "js", "CVE-2022-46175-reachable-direct", "reachable_candidate, npm lockfile SBOM"},
	{"js-version-outside-range", "js", "CVE-2022-46175-outofrange", "disqualified on the version axis"},
	{"js-reachable-transitive-yarn", "js", "CVE-2023-26136-reachable-transitive", "reachable_candidate, yarn.lock SBOM"},
	{"js-reachable-house-canary", "js", "FERRALON-JS-SSRF-0001-vulnerable", "house advisory id, reachable_candidate"},
	{"py-house-canary-ssrf", "python", "FERRALON-PY-SSRF-0001-REACHABLE", "house advisory id, undetermined rows"},
	{"py-version-outside-range", "python", "FERRALON-PY-JINJA2-SSTI-0001-OUTOFRANGE", "house advisory id, not_exploitable rows"},
	{"java-reachable-house-canary", "java", "FERRALON-JAVA-SPRING-SSRF-0001-vulnerable", "house advisory id, reachable_candidate"},
	{"java-dependency-house-canary", "java", "FERRALON-JAVA-DEP-0001-vulnerable", "house advisory id, pom SBOM"},
}

// goldenGoPlugin is the real Go analyzer with Reachability answered hermetically: see the file
// comment. Every other op is the real plugin subprocess.
type goldenGoPlugin struct {
	plugin.LanguagePlugin
}

// Reachability returns what goanalysis.Reachability returns when govulncheck reports no finding for
// the advisory: no paths, and the call graph's partiality, with an incomplete graph that names no
// reason declared as undetermined.
func (p goldenGoPlugin) Reachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	cg, err := p.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.ReachabilityResult{}, err
	}
	part := cg.Partiality
	if !part.Complete && len(part.Reasons) == 0 {
		part = plugin.Partial(plugin.PartialReasonReachabilityUndetermined)
	}
	return plugin.ReachabilityResult{Partiality: part}, nil
}

func TestGoldenOutputs(t *testing.T) {
	update := os.Getenv(goldenUpdateEnv) == "1"
	isolateToolEnv(t)
	trapEgress(t)

	binDir := t.TempDir()
	plugins := map[string]string{}
	for _, c := range goldenCases {
		if _, ok := plugins[c.language]; !ok {
			plugins[c.language] = buildAnalyzerPlugin(t, c.language, binDir)
		}
	}

	for _, c := range goldenCases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := runGoldenScan(t, c, plugins[c.language])
			for _, name := range goldenOutputs {
				path := filepath.Join(goldenDir, c.name, name)
				if update {
					if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
						t.Fatalf("create golden dir: %v", err)
					}
					if err := os.WriteFile(path, got[name], 0o644); err != nil {
						t.Fatalf("write golden %s: %v", path, err)
					}
					continue
				}
				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read golden %s: %v (regenerate with %s=1)", path, err, goldenUpdateEnv)
				}
				if !bytes.Equal(got[name], want) {
					t.Errorf("%s differs from %s: %s\nregenerate with %s=1 after reviewing the change",
						name, path, describeFirstDiff(want, got[name]), goldenUpdateEnv)
				}
			}
		})
	}
}

// runGoldenScan is runBaseline's body minus the pieces that read the ambient environment (sink
// selection from the GitHub Actions env, the StateStore flags, rescan context). It returns each
// output file's scrubbed bytes.
func runGoldenScan(t *testing.T, c goldenCase, pluginBin string) map[string][]byte {
	t.Helper()
	ctx := context.Background()

	fixture, err := filepath.Abs(filepath.Join("..", "..", "corpus", "testdata", "repros", c.fixture))
	if err != nil {
		t.Fatalf("resolve fixture: %v", err)
	}
	if _, err := os.Stat(fixture); err != nil {
		t.Fatalf("fixture %s: %v", c.fixture, err)
	}

	// -include-house-canaries is on: the house advisory ids are what the fixture-rename work needs
	// to see in the goldens.
	acq, err := acquireTarget(ctx, fixture, goldenRevision, "example.com/golden/"+c.name, pluginBin, true)
	if err != nil {
		t.Fatalf("acquireTarget: %v", err)
	}
	t.Cleanup(acq.cleanup)
	if acq.language != c.language {
		t.Fatalf("fixture %s detected as %q, case declares %q", c.fixture, acq.language, c.language)
	}

	analyzer := acq.plugin
	if c.language == "go" {
		analyzer = goldenGoPlugin{LanguagePlugin: analyzer}
	}

	f := runFlagsFor(t)
	ws, err := f.scanWorkSet(ctx, acq)
	if err != nil {
		t.Fatalf("scanWorkSet: %v", err)
	}

	revision, commit := acq.provenance(goldenRevision, goldenCommit)
	rep, err := trigger.RunBaseline(ctx, statestore.NewMemStore(), trigger.BaselineRequest{
		Subject: trigger.Subject{Repo: acq.repo, Revision: revision, ResolvedCommit: commit},
		Codebase: assessment.CodebaseRef{
			Repo:        acq.repo,
			Revision:    revision,
			Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: acq.buildDir},
		},
		Advisories:    ws.advisories,
		WorkSetLimits: ws.partiality,
		AssessOptions: []pipeline.AssessOption{pipeline.WithPlugin(analyzer)},
	})
	if err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}

	// publishResult's first two steps, then the Local sink it always includes.
	intel := f.intelProvenance(ws)
	rep.Provenance.Intel = &intel
	res, err := buildResult(rep)
	if err != nil {
		t.Fatalf("buildResult: %v", err)
	}
	outDir := t.TempDir()
	if err := resultsink.NewLocal(outDir).Publish(ctx, res); err != nil {
		t.Fatalf("publish to local sink: %v", err)
	}

	out := make(map[string][]byte, len(goldenOutputs))
	for _, name := range goldenOutputs {
		raw, err := os.ReadFile(filepath.Join(outDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		scrubbed, n := scrubTimestamps(raw)
		if name == resultsink.FileReportJSON && n == 0 {
			t.Fatalf("%s carries no provenance timestamp; the scrubber is matching nothing", name)
		}
		assertNoHostPaths(t, name, scrubbed, fixture, outDir, os.TempDir())
		out[name] = scrubbed
	}
	return out
}

// timestampField matches the one nondeterministic field: a JSON "timestamp" holding an RFC 3339
// UTC instant, as written by report.Provenance and the OpenVEX document.
var timestampField = regexp.MustCompile(`"timestamp": "\d{4}-\d{2}-\d{2}T[0-9:.]+Z"`)

func scrubTimestamps(b []byte) ([]byte, int) {
	n := len(timestampField.FindAll(b, -1))
	return timestampField.ReplaceAll(b, []byte(`"timestamp": "`+goldenTimestampToken+`"`)), n
}

func assertNoHostPaths(t *testing.T, name string, b []byte, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if p != "" && p != "/" && bytes.Contains(b, []byte(p)) {
			t.Fatalf("%s contains the host path %q; it would make the golden machine-specific", name, p)
		}
	}
}

// buildAnalyzerPlugin compiles the language's analyzer plugin into dir and returns its path. The
// plugin's main package is found by glob rather than by name so the test does not depend on how
// the binaries are named.
func buildAnalyzerPlugin(t *testing.T, language, dir string) string {
	t.Helper()
	root := filepath.Join("..", "..")
	matches, err := filepath.Glob(filepath.Join(root, "cmd", "*-plugin-"+language))
	if err != nil || len(matches) != 1 {
		t.Fatalf("want exactly one cmd/*-plugin-%s package, got %v (err %v)", language, matches, err)
	}
	bin := filepath.Join(dir, "plugin-"+language)
	cmd := exec.Command("go", "build", "-o", bin, "./"+filepath.ToSlash(strings.TrimPrefix(matches[0], root+string(filepath.Separator))))
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s analyzer: %v\n%s", language, err, out)
	}
	return bin
}

// goldenRunEnv is every environment variable a golden run keeps: what the Go command and the
// analyzer subprocesses need to find their toolchain, caches and scratch space. isolateToolEnv
// unsets everything else, so no configuration of the tool, the CI platform or telemetry can steer
// the scan away from its defaults.
var goldenRunEnv = map[string]bool{
	"PATH": true, "HOME": true, "TMPDIR": true,
	"GOROOT": true, "GOPATH": true, "GOCACHE": true, "GOMODCACHE": true,
}

// isolateToolEnv reduces the environment to goldenRunEnv and pins the Go command to the installed
// toolchain with no module proxy.
func isolateToolEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if !goldenRunEnv[k] {
			t.Setenv(k, "")
			_ = os.Unsetenv(k)
		}
	}
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOWORK", "off")
	// With cgo enabled, a linux host builds the Go fixtures' standard-library dependencies with
	// cgo where darwin does not; the call graph then reports cgo partiality and the Go advisories
	// come out undetermined. Pinning cgo off makes the analyzed package set, and so every golden,
	// the same on every host.
	t.Setenv("CGO_ENABLED", "0")
}

// describeFirstDiff names the first differing line so a failure points at the change without
// dumping two 25 KB documents.
func describeFirstDiff(want, got []byte) string {
	wl, gl := strings.Split(string(want), "\n"), strings.Split(string(got), "\n")
	for i := 0; i < len(wl) || i < len(gl); i++ {
		var w, g string
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if w != g || i >= len(wl) || i >= len(gl) {
			return fmt.Sprintf("first difference at line %d:\n  want: %q\n  got:  %q\n  (%d lines want, %d lines got)", i+1, w, g, len(wl), len(gl))
		}
	}
	return "no line differs; the files differ only in length"
}
