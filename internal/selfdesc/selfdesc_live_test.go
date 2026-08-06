//go:build live

// selfdesc_live_test.go — does the SHIPPED BINARY describe itself correctly?
//
// OPT-IN via the `live` build tag, like checkout/git_live_test.go and
// internal/plugin/goanalysis/reach_toolchain_live_test.go, because it compiles the CLI and runs a
// real scan — seconds, not milliseconds. It is excluded from the default `go test ./...`, which
// must stay hermetic and fast. It needs NO network: the scan target is a two-file module written
// into a temp dir, -osv-work-set defaults off, and the advisory facts come from the built-in table.
//
// Run it by hand:
//
//	GOWORK=off go test -tags live ./internal/selfdesc/ -v
//
// It is also step 2b of deploy/assay/publish.sh, which invokes it with
// ASSAY_SELFDESC_VERSION set to the version it is about to cut. A release whose binary
// misdescribes itself therefore aborts BEFORE anything is packaged or published.
//
// # The shape of every assertion here
//
// Expected values are COMPUTED from the source of truth; actual values are SCRAPED from the
// artifacts a customer receives. Nothing is snapshotted. Concretely:
//
//	expected                                    actual
//	--------                                    ------
//	brand.Name                                  the name the binary prints / stamps
//	the -X brand.Version stamp this test applied  the version the binary prints / stamps
//	statestore.DefaultRef                       every refs/<ns>/state in the CLI help
//
// The version stamp is the load-bearing one, because it is where the tool most recently had two
// identities and nothing reconciling them: `var version` in package main drove the `version`
// subcommand and the help banner, while brand.Version drove brand.AnalyzerVersion() — Report
// provenance, the SARIF driver, the HTML report. publish.sh stamped only the first, so a release
// changed what the CLI SAID and not what its ARTIFACTS RECORDED. The two are now one symbol:
// main.version is `var version = brand.Version` and publish.sh stamps brand.Version.
//
// This test stamps that single symbol and requires every surface — spoken and recorded — to carry
// it. Asserting both halves against one stamp is what keeps the collapse from silently coming
// apart again: re-introduce a second identity and whichever surface stops tracking the stamp names
// itself in the failure.
package selfdesc

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// defaultStamp is the version stamped when ASSAY_SELFDESC_VERSION is unset. It is deliberately not
// a plausible release version: if it shows up in a bug report, the reporter is running this test's
// binary, and if a failure message quotes it the reader knows it came from the -X stamp rather than
// from a const compiled into the tree.
const defaultStamp = "v0.0.0-selfdesc"

// stampEnv lets publish.sh pin the stamp to the version it is actually cutting, so the release gate
// tests the identity it is about to publish rather than a stand-in.
const stampEnv = "ASSAY_SELFDESC_VERSION"

// stateRefPattern matches any refs/<namespace>/state spelling, whatever the namespace. The test
// then requires the namespace to be the one statestore actually writes — matching only the correct
// spelling would make a drifted surface invisible instead of failing.
var stateRefPattern = regexp.MustCompile(`refs/[A-Za-z0-9._-]+/state`)

// stamp is the version identity this run stamps into the binary.
func stamp() string {
	if v := os.Getenv(stampEnv); v != "" {
		return v
	}
	return defaultStamp
}

var (
	buildOnce sync.Once
	builtBin  string
	buildErr  error
	buildDir  string
)

// binary compiles cmd/ferralon-assay with the release's reproducible recipe and returns its path.
//
// The flags are copied from scripts/build-release.sh's ldflags_for/build_into — the one recipe both
// release surfaces build through — minus GOOS/GOARCH: the release cross-compiles linux/amd64, which
// cannot be EXECUTED on a maintainer's machine, and the self-descriptions under test are
// target-independent (they come from ldflags and from brand, not from the platform). GOWORK=off
// matches both that script and the OSS Action's build env, so this build also proves the module
// resolves without the monorepo's go.work replace.
func binary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		buildDir, buildErr = os.MkdirTemp("", "selfdesc-bin-")
		if buildErr != nil {
			return
		}
		builtBin = filepath.Join(buildDir, brand.Name)
		cmd := exec.Command("go", "build",
			"-trimpath", "-buildvcs=false",
			"-ldflags", "-s -w -buildid= -X github.com/ferralon-ai/ferralon-assay/internal/brand.Version="+stamp(),
			"-o", builtBin, "./cmd/ferralon-assay")
		cmd.Dir = moduleRoot
		cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = err
			t.Logf("go build failed:\n%s", out)
		}
	})
	if buildErr != nil {
		t.Fatalf("building %s with the publish.sh recipe: %v", brand.Name, buildErr)
	}
	return builtBin
}

// TestMain removes the shared build directory once, after every test in the package has used it.
func TestMain(m *testing.M) {
	code := m.Run()
	if buildDir != "" {
		_ = os.RemoveAll(buildDir)
	}
	os.Exit(code)
}

// runCLI invokes the built binary and returns its combined output. A non-zero exit is NOT an error
// here: `-h` exits 2 by design (flag.ErrHelp) and `state` with no subcommand exits 1 after printing
// its usage, and both of those are surfaces under test.
func runCLI(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command(binary(t), args...)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		t.Fatalf("%s %s: no output and %v", brand.Name, strings.Join(args, " "), err)
	}
	return string(out)
}

// TestSelfDesc_VersionCommandCarriesTheStamp is the anchor: it proves the stamp reached the binary.
// If this fails, every other version assertion below is untrustworthy — the build, not the tool,
// is what went wrong.
func TestSelfDesc_VersionCommandCarriesTheStamp(t *testing.T) {
	want := brand.Name + " " + stamp()
	got := strings.TrimSpace(lastLine(runCLI(t, "version")))
	if got != want {
		t.Fatalf("`%s version` must print the brand name and the stamped build identity\n"+
			"  got:  %q\n"+
			"  want: %q  (brand.Name + \" \" + the -X brand.Version stamp)", brand.Name, got, want)
	}
}

// TestSelfDesc_HelpTextNamesTheRefTheToolWrites checks every refs/<ns>/state the CLI documents
// against the ref statestore actually creates.
//
// This is the class of defect that makes our own documented uninstall wrong: a customer who follows
// `-ref` help text or the `state` usage banner deletes a ref that was never written and leaves the
// real one behind. The test scrapes ANY refs/<ns>/state spelling and requires the namespace to be
// statestore.DefaultRef's, so a future third spelling fails the same way.
func TestSelfDesc_HelpTextNamesTheRefTheToolWrites(t *testing.T) {
	surfaces := [][]string{
		{"help"},
		{"baseline", "-h"},
		{"pr-inherit", "-h"},
		{"cve-watch", "-h"},
		{"state"},
		{"state", "show", "-h"},
		{"state", "export", "-h"},
	}
	for _, args := range surfaces {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			out := runCLI(t, args...)
			for _, found := range unique(stateRefPattern.FindAllString(out, -1)) {
				if found != statestore.DefaultRef {
					t.Errorf("`%s %s` documents the state ref as %q, but statestore writes %q\n"+
						"  the help text is a re-inlined literal; derive it from statestore.DefaultRef\n"+
						"  (a customer following this help deletes a ref that does not exist and leaves the real one behind)",
						brand.Name, strings.Join(args, " "), found, statestore.DefaultRef)
				}
			}
		})
	}
}

// scanArtifacts runs one real baseline scan and returns the output directory. The subject is a
// minimal module written into a temp dir: enough for the pipeline to produce a Report and its
// projections, with nothing to fetch and no plugin required.
func scanArtifacts(t *testing.T) string {
	t.Helper()
	subject := t.TempDir()
	write(t, filepath.Join(subject, "go.mod"), "module example.com/selfdesc\n\ngo 1.22\n")
	write(t, filepath.Join(subject, "selfdesc.go"), "package selfdesc\n")

	out := filepath.Join(t.TempDir(), "out")
	cmd := exec.Command(binary(t), "baseline", "-target", subject, "-out", out)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("baseline scan of a trivial module must succeed: %v\n%s", err, b)
	}
	return out
}

// TestSelfDesc_ArtifactsRecordTheStampedIdentity is the report.json / SARIF half of the version
// reconciliation. These are the fields a customer's code-scanning tab and any downstream consumer
// read to answer "which build produced this verdict?" — the citation anchor for every claim the
// tool makes. Under a stamped build they must carry the stamped identity.
func TestSelfDesc_ArtifactsRecordTheStampedIdentity(t *testing.T) {
	// Computed from the sources of truth, not snapshotted: the name comes from brand, the version
	// from the stamp this test applied. brand.AnalyzerVersion() is deliberately NOT used as the
	// expectation — it would fold in whatever brand.Version this TEST binary was compiled with
	// ("dev"), so it agrees with the scanned artifact no matter what the stamped CLI recorded. The
	// stamp is the only expectation that can fail.
	want := brand.Name + "/" + stamp()
	out := scanArtifacts(t)

	t.Run("report.json_provenance", func(t *testing.T) {
		var rep struct {
			Provenance struct {
				AnalyzerVersion string `json:"analyzer_version"`
			} `json:"provenance"`
		}
		decode(t, filepath.Join(out, resultsink.FileReportJSON), &rep)
		if got := rep.Provenance.AnalyzerVersion; got != want {
			t.Errorf("%s provenance.analyzer_version = %q, want %q\n"+
				"  the CLI was stamped %q but the Report records brand.Version instead;\n"+
				"  the CLI was stamped but the Report records an unstamped brand.Version;\n"+
				"  a second version identity has re-appeared between the binary and its artifacts",
				resultsink.FileReportJSON, got, want, stamp())
		}
	})

	t.Run("sarif_driver", func(t *testing.T) {
		var sarif struct {
			Runs []struct {
				Tool struct {
					Driver struct {
						Name            string `json:"name"`
						Version         string `json:"version"`
						SemanticVersion string `json:"semanticVersion"`
						InformationURI  string `json:"informationUri"`
					} `json:"driver"`
				} `json:"tool"`
			} `json:"runs"`
		}
		decode(t, filepath.Join(out, resultsink.FileSARIF), &sarif)
		if len(sarif.Runs) == 0 {
			t.Fatalf("%s carries no runs", resultsink.FileSARIF)
		}
		d := sarif.Runs[0].Tool.Driver
		if d.Name != brand.Name {
			t.Errorf("SARIF driver.name = %q, want brand.Name %q", d.Name, brand.Name)
		}
		if d.InformationURI != brand.RepoURL {
			t.Errorf("SARIF driver.informationUri = %q, want brand.RepoURL %q", d.InformationURI, brand.RepoURL)
		}
		for _, f := range []struct{ field, got string }{
			{"version", d.Version},
			{"semanticVersion", d.SemanticVersion},
		} {
			if f.got != want {
				t.Errorf("SARIF driver.%s = %q, want %q (the stamped build identity)", f.field, f.got, want)
			}
		}
	})
}

// TestSelfDesc_NoUnstampedIdentityLeaks is the other direction, and it is the cheap one: under a
// stamped build the unstamped identity must appear in NO customer-facing artifact.
//
// Asserting only that the right value is present would pass a build that emitted both. This asserts
// the wrong value is absent, which is what makes the pair complete. The needle is COMPUTED
// (brand.Name + "/" + brand.Version), so a rebrand or a change of the placeholder version keeps the
// check meaningful without an edit here.
func TestSelfDesc_NoUnstampedIdentityLeaks(t *testing.T) {
	unstamped := brand.Name + "/" + brand.Version
	if stamp() == brand.Version {
		t.Skipf("stamp %q equals brand.Version — nothing to distinguish", stamp())
	}
	out := scanArtifacts(t)
	for _, name := range []string{
		resultsink.FileReportJSON,
		resultsink.FileSARIF,
		resultsink.FileReportHTML,
		resultsink.FileOpenVEX,
	} {
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(out, name))
			if err != nil {
				t.Fatalf("reading %s: %v", name, err)
			}
			if bytes.Contains(b, []byte(unstamped)) {
				t.Errorf("%s contains the UNSTAMPED analyzer identity %q under a build stamped %q\n"+
					"  a released artifact that says %q tells the reader nothing about which build produced it",
					name, unstamped, stamp(), unstamped)
			}
		})
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func decode(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
}

// lastLine returns the final non-empty line, dropping the telemetry no-op notice the CLI logs to
// stderr before every command.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return lines[i]
		}
	}
	return ""
}

func unique(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
