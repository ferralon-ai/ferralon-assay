package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/internal/selfcleanup"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
)

// A C/C++ tree scanned with no analyzer plugin on PATH (an empty PATH, as on a release whose
// tarball ships no cfamily plugin) publishes a zero-finding Report whose did_not_run note names the
// language and the missing plugin, and the run exits 0, in every run mode. The C/C++ floor is empty,
// so an exit 0 also proves the empty-work-set gate never ran. Each mode also sets the scan-truncated
// output false and, linked to a console, sends the self-cleanup revoke beacon.
func TestAnalyzerMissing_PublishesUnsupportedReport(t *testing.T) {
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "main.c"), "int main(void) { return 0; }\n")
	t.Setenv("PATH", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	args := os.Args
	t.Cleanup(func() { os.Args = args })

	var beacons []selfcleanup.BeaconRequest
	ingest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b selfcleanup.BeaconRequest
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			t.Errorf("decode beacon: %v", err)
		}
		beacons = append(beacons, b)
	}))
	t.Cleanup(ingest.Close)
	t.Setenv(envLinkToConsole, "true")
	t.Setenv(envIngestURL, ingest.URL)
	t.Setenv(envGitHubRepo, "example/widget")
	t.Setenv(envGitHubSHA, "")
	t.Setenv(envOIDCToken, "test-token")
	t.Setenv(envRevokePubKey, "")
	t.Setenv(envEventAction, "")

	for _, mode := range []string{"baseline", "pr-inherit", "cve-watch"} {
		t.Run(mode, func(t *testing.T) {
			out := t.TempDir()
			ghOut := filepath.Join(t.TempDir(), "github_output")
			t.Setenv(envGitHubOut, ghOut)
			beacons = nil
			os.Args = []string{"ferralon-assay", mode, "-target", src, "-out", out, "-revision", "main", "-commit", "abc123", "-git-dir", t.TempDir()}
			if code := run(); code != 0 {
				t.Fatalf("exit code = %d, want 0", code)
			}

			if got, err := os.ReadFile(ghOut); err != nil || string(got) != "scan-truncated=false\n" {
				t.Fatalf("step output = %q (%v), want scan-truncated=false", got, err)
			}
			if len(beacons) != 1 || beacons[0].Org != "example" || beacons[0].Repo != "widget" || beacons[0].Commit != "abc123" {
				t.Fatalf("revoke beacons = %+v, want one for example/widget at abc123", beacons)
			}

			raw, err := os.ReadFile(filepath.Join(out, resultsink.FileReportJSON))
			if err != nil {
				t.Fatalf("no Report published: %v", err)
			}
			var rep report.Report
			if err := json.Unmarshal(raw, &rep); err != nil {
				t.Fatalf("decode report: %v", err)
			}
			if len(rep.Advisories) != 0 || len(rep.SBOM.Packages) != 0 {
				t.Fatalf("Report has %d findings and %d packages, want none", len(rep.Advisories), len(rep.SBOM.Packages))
			}
			if rep.Subject.Revision != "main" || rep.Subject.ResolvedCommit != "abc123" {
				t.Fatalf("subject = %+v, want the -revision / -commit labels", rep.Subject)
			}
			if len(rep.Partiality) != 1 {
				t.Fatalf("partiality = %+v, want one note", rep.Partiality)
			}
			n := rep.Partiality[0]
			if n.Reason != plugin.PartialReasonNoPlugin || n.EffectiveClass() != report.PartialityDidNotRun {
				t.Fatalf("note = %+v, want reason %q in the did_not_run arm", n, plugin.PartialReasonNoPlugin)
			}
			for _, want := range []string{"C/C++", checkout.LangCFamily, plugin.BinaryName(checkout.LangCFamily)} {
				if !strings.Contains(n.Detail, want) {
					t.Fatalf("note detail %q does not name %q", n.Detail, want)
				}
			}
		})
	}
}

// A missing analyzer is a neutral, published outcome only for a language outside the release. For a
// language the release ships it is an install fault: acquireTarget returns the plugin's error, and the
// run fails without publishing, so an earlier run's Report, dashboard Issue and SARIF stay as they were.
func TestAnalyzerMissing_OnlyOutsideTheRelease(t *testing.T) {
	t.Setenv("PATH", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	args := os.Args
	t.Cleanup(func() { os.Args = args })

	cases := []struct {
		language    string
		file, src   string
		wantNeutral bool
	}{
		{checkout.LangCFamily, "main.c", "int main(void) { return 0; }\n", true},
		{checkout.LangGo, "go.mod", "module example.com/widget\n\ngo 1.22\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.language, func(t *testing.T) {
			if releaseLanguage(tc.language) == tc.wantNeutral {
				t.Fatalf("releaseLanguage(%q) = %v, want %v", tc.language, tc.wantNeutral, !tc.wantNeutral)
			}
			src := t.TempDir()
			writeFile(t, filepath.Join(src, tc.file), tc.src)

			_, err := acquireTarget(context.Background(), src, "", "", "", false, graphRequest{mode: buildGraphOff})
			var missing *analyzerMissingError
			var notInstalled *plugin.NotInstalledError
			if !errors.As(err, &notInstalled) {
				t.Fatalf("err = %v, want the plugin's not-installed error", err)
			}
			if errors.As(err, &missing) != tc.wantNeutral {
				t.Fatalf("err = %v (%T): analyzer-missing = %v, want %v", err, err, !tc.wantNeutral, tc.wantNeutral)
			}
			if tc.wantNeutral {
				return
			}

			out := t.TempDir()
			os.Args = []string{"ferralon-assay", "baseline", "-target", src, "-out", out, "-revision", "main", "-commit", "abc123"}
			if code := run(); code == 0 {
				t.Fatalf("exit code = 0, want a failure for a release language with no analyzer")
			}
			if entries, err := os.ReadDir(out); err != nil || len(entries) != 0 {
				t.Fatalf("out dir holds %v (%v), want nothing published", entries, err)
			}
		})
	}
}

func TestLanguageLabel(t *testing.T) {
	cases := map[string]string{
		checkout.LangCFamily: "C/C++",
		checkout.LangGo:      "Go",
		checkout.LangDotNet:  ".NET",
		"rust":               "rust",
	}
	for language, want := range cases {
		if got := languageLabel(language); got != want {
			t.Errorf("languageLabel(%q) = %q, want %q", language, got, want)
		}
	}
}

// selectPlugin's default arm is not where an unsupported language such as Rust or Ruby stops.
// DetectLanguage has no bucket for their sources, so the tree is unrecognized and checkout refuses
// it before a plugin is chosen. The error is checkout's, never selectPlugin's and never a missing
// analyzer: those languages are not detected at all, so there is no language to name on a Report.
func TestUnrecognizedLanguagesStopAtCheckout(t *testing.T) {
	t.Setenv("PATH", "")
	cases := map[string]map[string]string{
		"rust": {"Cargo.toml": "[package]\nname = \"x\"\n", "src/main.rs": "fn main() {}\n"},
		"ruby": {"Gemfile": "source \"https://rubygems.org\"\n", "app.rb": "puts 1\n"},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for path, content := range files {
				if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, path)), 0o755); err != nil {
					t.Fatal(err)
				}
				writeFile(t, filepath.Join(dir, path), content)
			}
			if got := checkout.DetectLanguage(dir); got != checkout.LangUnknown {
				t.Fatalf("DetectLanguage = %q, want unknown", got)
			}
			_, err := acquireTarget(context.Background(), dir, "", "", "", false, graphRequest{mode: buildGraphOff})
			var missing *analyzerMissingError
			if err == nil || errors.As(err, &missing) {
				t.Fatalf("err = %v, want checkout's refusal", err)
			}
			if !strings.Contains(err.Error(), "not a recognized source tree") || strings.Contains(err.Error(), "no analyzer plugin") {
				t.Fatalf("err = %q, want checkout's unrecognized-tree error, not selectPlugin's", err)
			}
		})
	}
}
