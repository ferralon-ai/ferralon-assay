package trigger

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/intel"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// TestWithSignals: the provenance a run hands its Builder names the signals file that ranked the
// run, and only when there is one. A Signals with no digest (never one Load or Parse returned) and a
// nil one both leave the provenance as it came, with no Intel block.
func TestWithSignals(t *testing.T) {
	base := report.Provenance{CommitSHA: "abc", AdvisoryCursor: "cur"}
	for _, c := range []struct {
		name string
		sig  *intel.Signals
		want *report.IntelProvenance
	}{
		{"nil signals", nil, nil},
		{"signals with no digest", &intel.Signals{}, nil},
		{"loaded signals", &intel.Signals{Digest: "sha256:" + strings.Repeat("a", 64)}, &report.IntelProvenance{SignalsDigest: "sha256:" + strings.Repeat("a", 64)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := withSignals(base, c.sig)
			if (got.Intel == nil) != (c.want == nil) || (c.want != nil && *got.Intel != *c.want) {
				t.Errorf("Intel = %+v, want %+v", got.Intel, c.want)
			}
			if got.CommitSHA != base.CommitSHA || got.AdvisoryCursor != base.AdvisoryCursor {
				t.Errorf("withSignals changed the rest of the provenance: %+v", got)
			}
		})
	}
	if base.Intel != nil {
		t.Errorf("withSignals wrote through to its argument: %+v", base.Intel)
	}
}

// TestEveryRunEntryPointRecordsTheSignalsDigest: each trigger.Run* path that returns a Report — the
// baseline, the PR-inherit fast path, the PR re-analysis and the CVE-watch earnest run, one
// WithProvenance block each — records the verified digest of the signals it was given as
// Provenance.Intel.SignalsDigest, and with none records no Intel block at all. The digest is the one
// Parse recomputed, not the placeholder the fixture's text claims. A path that stops stamping fails
// its rows below.
func TestEveryRunEntryPointRecordsTheSignalsDigest(t *testing.T) {
	ctx := context.Background()
	sig := prioritySignals(t)
	if sig.Digest == "" || sig.Digest == "sha256:"+strings.Repeat("1", 64) {
		t.Fatalf("fixture digest = %q; the test needs the recomputed one, not the placeholder", sig.Digest)
	}
	codebase := goFixtureModule(t)
	opts := []pipeline.AssessOption{
		pipeline.WithPlugin(fakeInventoryPlugin{lang: "go", inv: twoPackageInventory()}),
		pipeline.WithAdvisorySource(claimsScopeSource()),
	}
	subject := Subject{Repo: "example.com/app", ResolvedCommit: "sha"}
	workSet := []assessment.VulnRef{{ID: "GO-2021-0113", Source: "osv"}}

	baseline, err := buildBaselineReport(ctx, BaselineRequest{Subject: subject, Codebase: codebase, Advisories: workSet, AssessOptions: opts})
	if err != nil {
		t.Fatal(err)
	}
	if baseline.Provenance.Intel != nil {
		t.Fatalf("a baseline run with no signals recorded %+v", baseline.Provenance.Intel)
	}
	changed := baseline.SBOM
	changed.Packages = append([]report.Package{{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.8"}}, changed.Packages...)
	stored := func() *memStore {
		return &memStore{state: &statestore.State{Report: baseline, SBOM: baseline.SBOM, Cursor: "GO-2021-0113"}}
	}

	prInherit := func(head report.SBOM, wantInherited bool) func(*testing.T, *intel.Signals) *report.Report {
		return func(t *testing.T, s *intel.Signals) *report.Report {
			res, err := RunPRInherit(ctx, stored(), PRInheritRequest{
				Subject: subject, Codebase: codebase, PRSBOM: head, Advisories: workSet, AssessOptions: opts, Signals: s,
			})
			if err != nil {
				t.Fatal(err)
			}
			if res.Inherited != wantInherited {
				t.Fatalf("inherited = %v, want %v: the row would not exercise the path it is named for", res.Inherited, wantInherited)
			}
			return res.Report
		}
	}
	entries := []struct {
		name string
		run  func(*testing.T, *intel.Signals) *report.Report
	}{
		{"RunBaseline", func(t *testing.T, s *intel.Signals) *report.Report {
			rep, err := RunBaseline(ctx, &memStore{}, BaselineRequest{Subject: subject, Codebase: codebase, Advisories: workSet, AssessOptions: opts, Signals: s})
			if err != nil {
				t.Fatal(err)
			}
			return rep
		}},
		{"RunPRInherit, inherited", prInherit(baseline.SBOM, true)},
		{"RunPRInherit, re-analyzed", prInherit(changed, false)},
		{"RunCVEWatch, earnest", func(t *testing.T, s *intel.Signals) *report.Report {
			osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{
				{ID: "GO-2021-0113", Package: report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.6"}},
				{ID: "GO-2099-0002", Package: report.Package{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.17.0"}},
			}}}
			res, err := RunCVEWatch(ctx, stored(), osv, CVEWatchRequest{Subject: subject, Codebase: codebase, Advisories: workSet, AssessOptions: opts, Signals: s})
			if err != nil {
				t.Fatal(err)
			}
			if res.Heartbeat || res.Report == nil {
				t.Fatalf("CVE watch: heartbeat %v, report %v; the row needs an earnest run", res.Heartbeat, res.Report)
			}
			return res.Report
		}},
	}
	for _, e := range entries {
		t.Run(e.name+"/signals", func(t *testing.T) {
			got := e.run(t, sig).Provenance.Intel
			if got == nil || got.SignalsDigest != sig.Digest {
				t.Fatalf("Provenance.Intel = %+v, want SignalsDigest %q", got, sig.Digest)
			}
			if want := (report.IntelProvenance{SignalsDigest: sig.Digest}); *got != want {
				t.Errorf("Provenance.Intel = %+v; trigger records the signals digest and nothing else", *got)
			}
		})
		t.Run(e.name+"/no signals", func(t *testing.T) {
			if got := e.run(t, nil).Provenance.Intel; got != nil {
				t.Errorf("Provenance.Intel = %+v with no signals, want none", *got)
			}
		})
	}
}
