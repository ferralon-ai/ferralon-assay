package signals_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/intel"
	"github.com/ferralon-ai/ferralon-assay/signals"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// doc is sealed: its signals_digest is its own (intel.Digest).
const doc = `{
  "signals_version": "1.0.0",
  "record_count": 1,
  "signals_digest": "sha256:bd1a023081696cb237c7036d0799cb714801b5744397865b309f026be6159e07",
  "records": [{"identifier": "CVE-2025-8110", "epss": {"score": 0.91, "as_of": "2026-10-19"}}]
}`

// TestParseFeedsEveryTriggerRequest: a value parsed from outside the module reaches every trigger
// request's Signals field through Feed, carrying the file's values, and Feed with nil sets none.
func TestParseFeedsEveryTriggerRequest(t *testing.T) {
	s, err := signals.Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	var (
		baseline  trigger.BaselineRequest
		prInherit trigger.PRInheritRequest
		cveWatch  trigger.CVEWatchRequest
	)
	requests := map[string]struct {
		feed func(*signals.Signals)
		got  func() *intel.Signals
	}{
		"baseline":   {func(s *signals.Signals) { signals.Feed(&baseline, s) }, func() *intel.Signals { return baseline.Signals }},
		"pr-inherit": {func(s *signals.Signals) { signals.Feed(&prInherit, s) }, func() *intel.Signals { return prInherit.Signals }},
		"cve-watch":  {func(s *signals.Signals) { signals.Feed(&cveWatch, s) }, func() *intel.Signals { return cveWatch.Signals }},
	}
	for name, r := range requests {
		r.feed(s)
		e, ok := r.got().EPSS("CVE-2025-8110")
		if !ok || e.Score != 0.91 || e.AsOf != "2026-10-19" {
			t.Errorf("%s: fed request's EPSS(CVE-2025-8110) = %+v, %t; want score 0.91 as of 2026-10-19", name, e, ok)
		}
		if got := r.got().Digest; got != s.Digest() {
			t.Errorf("%s: fed request's digest = %q; want %q", name, got, s.Digest())
		}
		r.feed(nil)
		if got := r.got(); got != nil {
			t.Errorf("%s: Feed(nil) left Signals %p; want nil", name, got)
		}
	}
}

// TestSignalsMethods: the public method set reads the loaded file, and a nil *Signals holds nothing.
func TestSignalsMethods(t *testing.T) {
	s, err := signals.Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name              string
		s                 *signals.Signals
		records           int
		digest            string
		epss              signals.EPSS
		hasEPSS, hasKEV   bool
		stale, staleOfAll int
	}{
		{"loaded", s, 1, "sha256:bd1a023081696cb237c7036d0799cb714801b5744397865b309f026be6159e07",
			signals.EPSS{Identifier: "CVE-2025-8110", Score: 0.91, AsOf: "2026-10-19"}, true, false, 1, 1},
		{"nil", nil, 0, "", signals.EPSS{}, false, false, 0, 0},
	} {
		if got := c.s.Records(); got != c.records {
			t.Errorf("%s: Records = %d; want %d", c.name, got, c.records)
		}
		if got := c.s.Digest(); got != c.digest {
			t.Errorf("%s: Digest = %q; want %q", c.name, got, c.digest)
		}
		if got, ok := c.s.EPSS(" cve-2025-8110 "); got != c.epss || ok != c.hasEPSS {
			t.Errorf("%s: EPSS = %+v, %t; want %+v, %t", c.name, got, ok, c.epss, c.hasEPSS)
		}
		if got, ok := c.s.KEV("CVE-2025-8110"); ok != c.hasKEV || got != (signals.KEV{}) {
			t.Errorf("%s: KEV = %+v, %t; want none", c.name, got, ok)
		}
		if stale, total := c.s.StaleEPSS(now, 48*time.Hour); stale != c.stale || total != c.staleOfAll {
			t.Errorf("%s: StaleEPSS(48h) = %d of %d; want %d of %d", c.name, stale, total, c.stale, c.staleOfAll)
		}
	}
}

// TestParseRejectsOtherMajor: the public entry point keeps intel's version gate.
func TestParseRejectsOtherMajor(t *testing.T) {
	_, err := signals.Parse(strings.NewReader(strings.Replace(doc, `"1.0.0"`, `"2.0.0"`, 1)))
	if err == nil || !strings.Contains(err.Error(), "signals_version") {
		t.Fatalf("signals_version 2.0.0: err = %v; want a signals_version error", err)
	}
}

// TestLoadRejects: Load returns an error and no Signals for a file it cannot read, one of another
// signals_version major, and one whose payload does not hash to its signals_digest.
func TestLoadRejects(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, c := range []struct {
		name, path, want string
		notExist         bool
	}{
		{"missing path", filepath.Join(dir, "absent.json"), "absent.json", true},
		{"signals_version 2.x", write("v2.json", strings.Replace(doc, `"1.0.0"`, `"2.0.0"`, 1)), "signals_version", false},
		{"digest mismatch", write("tampered.json", strings.Replace(doc, "0.91", "0.99", 1)), "signals_digest mismatch", false},
	} {
		s, err := signals.Load(c.path)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v; want an error naming %q", c.name, err, c.want)
		}
		if c.notExist && !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: err = %v; want one that is fs.ErrNotExist", c.name, err)
		}
		if s != nil {
			t.Errorf("%s: Load returned Signals %p with its error; want nil", c.name, s)
		}
	}
}
