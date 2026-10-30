package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
)

// A C/C++ tree scanned with no analyzer plugin on PATH (an empty PATH, as on a release whose
// tarball ships no cfamily plugin) publishes a zero-finding Report whose did_not_run note names the
// language and the missing plugin, and the run exits 0, in every run mode. The C/C++ floor is empty,
// so an exit 0 also proves the empty-work-set gate never ran.
func TestAnalyzerMissing_PublishesUnsupportedReport(t *testing.T) {
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "main.c"), "int main(void) { return 0; }\n")
	t.Setenv("PATH", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	args := os.Args
	t.Cleanup(func() { os.Args = args })

	for _, mode := range []string{"baseline", "pr-inherit", "cve-watch"} {
		t.Run(mode, func(t *testing.T) {
			out := t.TempDir()
			os.Args = []string{"ferralon-assay", mode, "-target", src, "-out", out, "-revision", "main", "-commit", "abc123"}
			if code := run(); code != 0 {
				t.Fatalf("exit code = %d, want 0", code)
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
