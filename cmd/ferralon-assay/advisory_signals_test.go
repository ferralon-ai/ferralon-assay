// advisory_signals_test.go
//
// The entrypoint half of tracker #64 (scanner): EPSS/KEV signals reach a run only as a provided
// input — -advisory-signals, its env channel, or a corpus tree's signals.json — and the run summary
// says which, how old, or that there were none.
package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const signalsDigest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"

// signalsDoc is a hand-written signals 1.x file whose newest EPSS value is from asOf.
func signalsDoc(asOf string) string {
	return `{"signals_version": "1.0.0", "record_count": 2, "signals_digest": "` + signalsDigest + `",
	  "records": [
	    {"identifier": "CVE-2021-38561", "epss": {"score": 0.0123, "percentile": 0.456, "as_of": "2026-09-01"}},
	    {"identifier": "CVE-2025-8110", "epss": {"score": 0.91, "percentile": 0.99, "as_of": "` + asOf + `"},
	     "kev": {"listed": true, "catalog_version": "2026.10.19", "date_released": "2026-10-19T18:00:00Z"}}]}`
}

func writeSignalsFile(t *testing.T, path string, body []byte) string {
	t.Helper()
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// corpusTreeCopy copies the pipeline's fixture corpus tree into a temp dir, so a test can add (or
// not) a signals.json at its root.
func corpusTreeCopy(t *testing.T) string {
	t.Helper()
	src := filepath.Join("..", "..", "pipeline", "testdata", "advisory_source")
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// resolvedFor parses args, resolves the corpus (as a run does first), then the signals.
func resolvedFor(t *testing.T, args ...string) (*runFlags, error) {
	t.Helper()
	f := runFlagsFor(t, args...)
	if _, err := f.advisoryCorpusOption(); err != nil {
		t.Fatalf("advisoryCorpusOption: %v", err)
	}
	return f, f.resolveSignals()
}

func clearSignalsEnv(t *testing.T) {
	t.Setenv(envAdvisorySignals, "")
	t.Setenv(envAdvisoryCorpusDir, "")
	t.Setenv(envAdvisoryCorpusPolicy, "")
	t.Setenv(envAdvisoryCorpusRequired, "")
}

// TestAdvisorySignals_LoadsFromFlagEnvAndCorpus covers each source of the signals file and their
// precedence, and that the Report's intel block names the file's digest once.
func TestAdvisorySignals_LoadsFromFlagEnvAndCorpus(t *testing.T) {
	dir := t.TempDir()
	plain := writeSignalsFile(t, filepath.Join(dir, "signals.json"), []byte(signalsDoc("2026-10-19")))
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(signalsDoc("2026-10-19")))
	zw.Close()
	packed := writeSignalsFile(t, filepath.Join(dir, "signals.json.gz"), gz.Bytes())

	t.Run("flag, json", func(t *testing.T) {
		clearSignalsEnv(t)
		f, err := resolvedFor(t, "-advisory-signals", plain)
		if err != nil || f.resolvedSignals == nil || f.signalsOrigin != plain {
			t.Fatalf("resolveSignals = %v, signals %v from %q", err, f.resolvedSignals, f.signalsOrigin)
		}
		if got := f.intelProvenance(workSet{}).SignalsDigest; got != signalsDigest {
			t.Errorf("intel provenance signals_digest = %q, want %q", got, signalsDigest)
		}
	})
	t.Run("flag, gz", func(t *testing.T) {
		clearSignalsEnv(t)
		f, err := resolvedFor(t, "-advisory-signals", packed)
		if err != nil || f.resolvedSignals.Records() != 2 {
			t.Fatalf("resolveSignals = %v, %d records", err, f.resolvedSignals.Records())
		}
	})
	t.Run("env", func(t *testing.T) {
		clearSignalsEnv(t)
		t.Setenv(envAdvisorySignals, packed)
		f, err := resolvedFor(t)
		if err != nil || f.signalsOrigin != packed {
			t.Fatalf("resolveSignals = %v, from %q; want %s", err, f.signalsOrigin, packed)
		}
	})
	t.Run("flag wins over env", func(t *testing.T) {
		clearSignalsEnv(t)
		t.Setenv(envAdvisorySignals, filepath.Join(dir, "absent.json"))
		f, err := resolvedFor(t, "-advisory-signals", plain)
		if err != nil || f.signalsOrigin != plain {
			t.Fatalf("resolveSignals = %v, from %q; want the flag's %s", err, f.signalsOrigin, plain)
		}
	})
	t.Run("corpus tree default", func(t *testing.T) {
		clearSignalsEnv(t)
		tree := corpusTreeCopy(t)
		want := writeSignalsFile(t, filepath.Join(tree, "signals.json"), []byte(signalsDoc("2026-10-19")))
		f, err := resolvedFor(t, "-advisory-corpus", tree)
		if err != nil || f.signalsOrigin != want || f.resolvedSignals == nil {
			t.Fatalf("resolveSignals = %v, from %q; want the corpus's %s", err, f.signalsOrigin, want)
		}
		// An explicit path still wins over the corpus default.
		f, err = resolvedFor(t, "-advisory-corpus", tree, "-advisory-signals", packed)
		if err != nil || f.signalsOrigin != packed {
			t.Fatalf("resolveSignals = %v, from %q; want the explicit %s", err, f.signalsOrigin, packed)
		}
	})
}

// TestAdvisorySignals_NoSourceMeansNoPriority: with no source the run loads nothing, the intel block
// names no digest, and the summary says so in one line — including when the corpus tree simply has
// no signals.json.
func TestAdvisorySignals_NoSourceMeansNoPriority(t *testing.T) {
	clearSignalsEnv(t)
	f, err := resolvedFor(t)
	if err != nil || f.resolvedSignals != nil {
		t.Fatalf("resolveSignals = %v, %v; want no signals and no error", err, f.resolvedSignals)
	}
	if got := f.intelProvenance(workSet{}).SignalsDigest; got != "" {
		t.Errorf("signals_digest = %q with no signals", got)
	}
	line := f.signalsSummary(time.Now())
	if !strings.HasPrefix(line, "none — no signals source was provided") || !strings.Contains(line, "no finding carries EPSS/KEV priority") || strings.Contains(line, "\n") {
		t.Errorf("summary line = %q", line)
	}

	tree := corpusTreeCopy(t)
	f, err = resolvedFor(t, "-advisory-corpus", tree)
	if err != nil || f.resolvedSignals != nil {
		t.Fatalf("corpus without signals.json: %v, %v", err, f.resolvedSignals)
	}
	if line := f.signalsSummary(time.Now()); !strings.Contains(line, "has no signals.json") || !strings.HasPrefix(line, "none — ") {
		t.Errorf("summary line = %q, want it to name the corpus tree's missing signals.json", line)
	}
}

// TestAdvisorySignals_BrokenFileFailsTheRun: a named file that is missing, malformed or of another
// signals_version fails the run — the corpus default included — and never degrades to no priority.
func TestAdvisorySignals_BrokenFileFailsTheRun(t *testing.T) {
	dir := t.TempDir()
	cases := map[string][]string{
		"missing":         {"-advisory-signals", filepath.Join(dir, "absent.json")},
		"malformed":       {"-advisory-signals", writeSignalsFile(t, filepath.Join(dir, "bad.json"), []byte(`{"signals_version": "1.0.0", "records": [`))},
		"unknown version": {"-advisory-signals", writeSignalsFile(t, filepath.Join(dir, "v2.json"), []byte(strings.Replace(signalsDoc("2026-10-19"), `"1.0.0"`, `"2.0.0"`, 1)))},
	}
	tree := corpusTreeCopy(t)
	writeSignalsFile(t, filepath.Join(tree, "signals.json"), []byte(`not json`))
	cases["corpus default malformed"] = []string{"-advisory-corpus", tree}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			clearSignalsEnv(t)
			f, err := resolvedFor(t, args...)
			if err == nil || f.resolvedSignals != nil {
				t.Fatalf("resolveSignals = %v, %v; want an error and no signals", err, f.resolvedSignals)
			}
			if !strings.Contains(err.Error(), "advisory signals") {
				t.Errorf("error %q does not say it is about the advisory signals", err)
			}
		})
	}
	t.Run("unknown version names it", func(t *testing.T) {
		clearSignalsEnv(t)
		_, err := resolvedFor(t, cases["unknown version"]...)
		if err == nil || !strings.Contains(err.Error(), `unsupported signals_version "2.0.0"`) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("non-positive max age", func(t *testing.T) {
		clearSignalsEnv(t)
		if _, err := resolvedFor(t, "-advisory-signals-max-age", "0s"); err == nil {
			t.Error("a zero -advisory-signals-max-age must be refused")
		}
	})
}

// TestAdvisorySignals_StaleWarnsButLoads: past the bound the file still loads and the summary names
// its age as a warning; under it there is no warning. The bound is the flag's.
func TestAdvisorySignals_StaleWarnsButLoads(t *testing.T) {
	clearSignalsEnv(t)
	path := writeSignalsFile(t, filepath.Join(t.TempDir(), "signals.json"), []byte(signalsDoc("2026-10-10")))
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC) // 10.5 days after the newest as_of

	f, err := resolvedFor(t, "-advisory-signals", path)
	if err != nil || f.resolvedSignals == nil {
		t.Fatalf("a stale file must still load: %v", err)
	}
	line := f.signalsSummary(now)
	for _, want := range []string{path, signalsDigest, "newest EPSS as_of 2026-10-10 (10 day(s) old)", "WARNING: stale"} {
		if !strings.Contains(line, want) {
			t.Errorf("summary %q lacks %q", line, want)
		}
	}

	f, _ = resolvedFor(t, "-advisory-signals", path, "-advisory-signals-max-age", "336h")
	if line := f.signalsSummary(now); strings.Contains(line, "WARNING") || !strings.Contains(line, "(10 day(s) old)") {
		t.Errorf("under a 14-day bound: summary %q; want the age and no warning", line)
	}
	if line := f.signalsSummary(time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)); strings.Contains(line, "WARNING") {
		t.Errorf("2 days old under the default bound: summary %q warns", line)
	}
}

// staleShareDoc is a signals 1.x file whose newest EPSS value is fresh and whose other values are
// from the as_of dates given, so the share of old values varies while the newest does not.
func staleShareDoc(older ...string) string {
	recs := `{"identifier": "CVE-2025-8110", "epss": {"score": 0.91, "as_of": "2026-10-19"}}`
	for i, asOf := range older {
		recs += fmt.Sprintf(`, {"identifier": "CVE-2026-%04d", "epss": {"score": 0.01, "as_of": %q}}`, i+1, asOf)
	}
	return fmt.Sprintf(`{"signals_version": "1.0.0", "record_count": %d, "signals_digest": %q, "records": [%s]}`,
		len(older)+1, signalsDigest, recs)
}

// TestAdvisorySignals_StaleShareWarns: the line counts the EPSS values older than the bound, and
// warns when over half of them are, even though the newest value is a day old; at half or under it
// counts them and does not warn.
func TestAdvisorySignals_StaleShareWarns(t *testing.T) {
	clearSignalsEnv(t)
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name  string
		older []string
		share string
		warn  bool
	}{
		{"most old", []string{"2026-08-02", "2026-08-02"}, "EPSS: 2/3 (67%) older than 7d", true},
		{"exactly half old", []string{"2026-08-02", "2026-08-02", "2026-10-18"}, "EPSS: 2/4 (50%) older than 7d", false},
		{"a third old", []string{"2026-08-02", "2026-10-18"}, "EPSS: 1/3 (33%) older than 7d", false},
		{"none old", []string{"2026-10-18"}, "EPSS: 0/2 (0%) older than 7d", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := writeSignalsFile(t, filepath.Join(t.TempDir(), "signals.json"), []byte(staleShareDoc(c.older...)))
			f, err := resolvedFor(t, "-advisory-signals", path)
			if err != nil {
				t.Fatal(err)
			}
			line := f.signalsSummary(now)
			if !strings.Contains(line, "newest EPSS as_of 2026-10-19 (1 day(s) old); "+c.share) {
				t.Errorf("summary %q lacks the newest date followed by %q", line, c.share)
			}
			if warned := strings.Contains(line, "WARNING: stale, over half the EPSS values are older than the 7d bound"); warned != c.warn {
				t.Errorf("summary %q: share warning = %v, want %v", line, warned, c.warn)
			}
		})
	}
}

// TestPercentOf pins the share's clamps: a non-zero share short of the whole rounds to 0% or 100%
// on a large total (1/300 and 299/300), and prints as 1% and 99% instead, while none and all stay
// 0% and 100%.
func TestPercentOf(t *testing.T) {
	for _, c := range []struct{ n, total, want int }{
		{1, 300, 1},
		{299, 300, 99},
		{0, 300, 0},
		{300, 300, 100},
		{150, 300, 50},
		{0, 0, 0},
	} {
		if got := percentOf(c.n, c.total); got != c.want {
			t.Errorf("percentOf(%d, %d) = %d%%, want %d%%", c.n, c.total, got, c.want)
		}
	}
}
