package main

import (
	"archive/zip"
	"context"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// newStateStore builds a local git-ref StateStore against a fresh temp bare repo
// and seeds it with one baseline Report. It returns the store and the committed
// ref's commit SHA (the CAS token), so tests can assert read-only operations leave
// the ref unchanged.
func newStateStore(t *testing.T) (*statestore.GitRefStore, string) {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command("git", "-C", dir, "init", "--bare", "-q")
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init bare: %v: %s", err, out)
	}
	store := statestore.NewGitRefStore(statestore.Config{GitDir: dir})

	rep := seedReport()
	committed, err := store.Write(context.Background(), &statestore.State{Report: &rep, SBOM: rep.SBOM})
	if err != nil {
		t.Fatalf("seed Write: %v", err)
	}
	if committed.CommitSHA == "" {
		t.Fatalf("seed write returned empty commit SHA")
	}
	return store, committed.CommitSHA
}

func seedReport() report.Report {
	pkg := report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.7"}
	return report.NewBuilder(report.Subject{Repo: "github.com/example/widget", Revision: "main", ResolvedCommit: "deadbeef"}).
		AddPackages(pkg).
		Disqualified(report.Advisory{ID: "GO-2021-0001", Source: "osv"}, &pkg, verdict.BasisVersionNotAffected, "resolved version below first affected").
		WithProvenance(report.Provenance{AnalyzerVersion: "ferralon-assay test", Timestamp: time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)}).
		Build()
}

func TestStateShow_WritesFileSafeHTML(t *testing.T) {
	store, _ := newStateStore(t)
	out := t.TempDir()

	if err := runStateShowWithStore(store, out, true); err != nil {
		t.Fatalf("state show: %v", err)
	}

	htmlPath := filepath.Join(out, "report.html")
	b, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read report.html: %v", err)
	}
	html := string(b)
	if !strings.HasPrefix(strings.TrimSpace(html), "<!DOCTYPE html>") {
		t.Fatalf("report.html is not a complete HTML document")
	}

	// file://-safe: no external references, no runtime network primitives (reusing
	// the invariant from projection's TestReportHTML_FileSafe_NoExternalRefs). The
	// only permitted absolute URL is the www.w3.org SVG namespace.
	banned := []*regexp.Regexp{
		regexp.MustCompile(`(?i)<script[^>]*\bsrc\s*=`),
		regexp.MustCompile(`(?i)<link\b`),
		regexp.MustCompile(`(?i)<iframe\b`),
		regexp.MustCompile(`(?i)<img[^>]*\bsrc\s*=\s*["']https?:`),
	}
	for _, re := range banned {
		if re.MatchString(html) {
			t.Fatalf("file://-safe VIOLATION: %q matched", re.String())
		}
	}
	for _, tok := range []string{"fetch(", "XMLHttpRequest", "WebSocket"} {
		if strings.Contains(html, tok) {
			t.Fatalf("file://-safe VIOLATION: runtime network primitive %q present", tok)
		}
	}
	// Any http(s) URL that is NOT the w3.org SVG namespace is a violation.
	for _, m := range regexp.MustCompile(`https?://[^\s"'<>)]+`).FindAllString(html, -1) {
		if !strings.Contains(m, "www.w3.org") {
			t.Fatalf("file://-safe VIOLATION: external URL %q present", m)
		}
	}
}

func TestStateExport_ProducesZipAndDoesNotMutateRef(t *testing.T) {
	store, shaBefore := newStateStore(t)
	zipPath := filepath.Join(t.TempDir(), "state.zip")

	if err := runStateExportWithStore(store, zipPath); err != nil {
		t.Fatalf("state export: %v", err)
	}

	// The ref SHA must be UNCHANGED — export is read-only with respect to the store.
	after, err := store.Read(context.Background())
	if err != nil {
		t.Fatalf("re-read after export: %v", err)
	}
	if after.CommitSHA != shaBefore {
		t.Fatalf("export mutated the ref: before=%s after=%s", shaBefore, after.CommitSHA)
	}

	// The ZIP carries report.json + the three projections.
	got := zipEntries(t, zipPath)
	for _, want := range []string{"report.json", "report.html", "report.sarif.json", "openvex.json"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("export ZIP missing %q (have %v)", want, keys(got))
		}
	}
	if !strings.HasPrefix(strings.TrimSpace(string(got["report.html"])), "<!DOCTYPE html>") {
		t.Fatalf("export ZIP report.html is not valid HTML")
	}
	if len(got["report.json"]) == 0 {
		t.Fatalf("export ZIP report.json is empty")
	}
}

// TestStateStoreSelection covers the flag-driven StateStore selection: -git-dir
// builds a local store, -repo builds the GitHub store, both-or-neither error.
func TestStateStoreSelection(t *testing.T) {
	t.Run("git-dir builds local", func(t *testing.T) {
		sf := selectorFor(t, "-git-dir", t.TempDir())
		s, err := sf.resolve()
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if _, ok := s.(*statestore.GitRefStore); !ok {
			t.Fatalf("expected *GitRefStore, got %T", s)
		}
	})
	t.Run("repo builds github", func(t *testing.T) {
		sf := selectorFor(t, "-repo", "octo/widget")
		s, err := sf.resolve()
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if _, ok := s.(*statestore.GitHubRefStore); !ok {
			t.Fatalf("expected *GitHubRefStore, got %T", s)
		}
	})
	t.Run("neither errors", func(t *testing.T) {
		sf := selectorFor(t)
		if _, err := sf.resolve(); err == nil {
			t.Fatalf("expected error when no store selected")
		}
	})
	t.Run("both errors", func(t *testing.T) {
		sf := selectorFor(t, "-git-dir", t.TempDir(), "-repo", "octo/widget")
		if _, err := sf.resolve(); err == nil {
			t.Fatalf("expected error when both stores selected")
		}
	})
	t.Run("bad repo errors", func(t *testing.T) {
		sf := selectorFor(t, "-repo", "no-slash")
		if _, err := sf.resolve(); err == nil {
			t.Fatalf("expected error for malformed -repo")
		}
	})
}

func TestStateShow_NoReportErrors(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command("git", "-C", dir, "init", "--bare", "-q")
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init bare: %v: %s", err, out)
	}
	// Empty ref → Read returns ErrNotFound → show surfaces an error (no panic).
	store := statestore.NewGitRefStore(statestore.Config{GitDir: dir})
	if err := runStateShowWithStore(store, t.TempDir(), true); err == nil {
		t.Fatalf("expected error for empty state ref")
	}
}

// --- test seams: run the operations against a constructed store without flags ---

func runStateShowWithStore(store statestore.StateStore, out string, noOpen bool) error {
	return showFromStore(store, out, noOpen)
}

func runStateExportWithStore(store statestore.StateStore, out string) error {
	return exportFromStore(store, out)
}

func selectorFor(t *testing.T, args ...string) *stateStoreFlags {
	t.Helper()
	fs := flag.NewFlagSet("state-test", flag.ContinueOnError)
	sf := registerStateStoreFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	return sf
}

func zipEntries(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer f.Close()
	info, _ := f.Stat()
	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		t.Fatalf("zip reader: %v", err)
	}
	out := map[string][]byte{}
	for _, e := range zr.File {
		rc, err := e.Open()
		if err != nil {
			t.Fatalf("open zip entry %s: %v", e.Name, err)
		}
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		out[e.Name] = b
	}
	return out
}

func keys(m map[string][]byte) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
