// range_dispute_test.go
//
// A version-axis disqualification stands only when no other source for the advisory places the
// version inside its affected range (tracker#887). The corpus serves the GO record and its GHSA alias
// separately, and they can disagree; govulncheck's own database is another source. A disagreement
// withdraws the disqualification and nothing more.
package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const disputeModule = "github.com/gorilla/websocket"

// disputeRecord is a record for disputeModule with the given ranges and aliases.
func disputeRecord(aliases []string, rngs ...Range) AdvisoryFacts {
	return AdvisoryFacts{
		Module: disputeModule, VersionScheme: "gomod", PURL: "pkg:golang/" + disputeModule,
		Aliases: aliases, AffectedRanges: rngs, Symbols: []string{disputeModule + ".Conn.ReadMessage"},
		Provenance: Provenance{Source: "synthetic", TrustTier: TrustFirstParty},
	}
}

// disputeSource serves records by id, so an advisory and its aliases can say different things.
type disputeSource map[string]AdvisoryFacts

func (s disputeSource) Lookup(id string) (AdvisoryFacts, bool) {
	f, ok := s[id]
	return f, ok
}

// The tracker#887 shape: the GHSA record says fixed in v1.5.3; the GO record says v1.5.3 is affected
// again until v1.5.4-0.20240701034025-d67f41855da4.
var (
	ghsaExcludes = disputeRecord([]string{"GO-2026-6278"}, Range{Fixed: "v1.5.3", FixedVersion: "v1.5.3"})
	goIncludes   = disputeRecord([]string{"GHSA-w67g-5rqw-f597"},
		Range{Fixed: "v1.5.1", FixedVersion: "v1.5.1"},
		Range{Introduced: "v1.5.3", Fixed: "v1.5.4-0.20240701034025-d67f41855da4", FixedVersion: "v1.5.4-0.20240701034025-d67f41855da4"})
	goExcludes = disputeRecord([]string{"GHSA-w67g-5rqw-f597"}, Range{Fixed: "v1.5.3", FixedVersion: "v1.5.3"})
)

// matchPlugin is the Go resolver with a Reachability that answers MatchOnly requests as set.
type matchPlugin struct {
	realResolverPlugin
	matched bool
	partial bool
	err     error
	reqs    *[]plugin.ReachabilityRequest
}

func (p matchPlugin) Reachability(_ context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	if p.reqs != nil {
		*p.reqs = append(*p.reqs, req)
	}
	if p.err != nil {
		return plugin.ReachabilityResult{}, p.err
	}
	res := plugin.ReachabilityResult{Partiality: plugin.Complete(), AnalyzerMatched: p.matched}
	if p.partial {
		res = plugin.ReachabilityResult{Partiality: plugin.Partial(plugin.PartialReasonToolFailure + ":govulncheck_partial_run")}
	}
	return res, nil
}

func runDisputeDisqual(t *testing.T, vulnID string, src AdvisorySource, p plugin.LanguagePlugin, version string) DisqualResult {
	t.Helper()
	buildDir := writeTreeFixture(t, map[string]string{
		"go.mod": "module example.com/target\n\ngo 1.21\n\nrequire " + disputeModule + " " + version + "\n",
	})
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-dispute", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: vulnID, Source: "corpus"},
		Codebase:      assessment.CodebaseRef{Repo: "example.com/target", Revision: "v1", Acquisition: assessment.Acquisition{Mode: "git"}},
	}}
	ctx := context.Background()
	if err := (advisoryIntake{src: src}).Run(ctx, c, store); err != nil {
		t.Fatalf("advisory_intake: %v", err)
	}
	inv := codebaseInventory{checkout: dirCheckout{dir: buildDir, lang: "go"}, plugin: realResolverPlugin{lang: "go"}, src: src}
	if err := inv.Run(ctx, c, store); err != nil {
		t.Fatalf("codebase_inventory: %v", err)
	}
	if err := (disqualificationDiscovery{src: src, plugin: p}).Run(ctx, c, store); err != nil {
		t.Fatalf("disqualification_discovery: %v", err)
	}
	return disqualRecordOf(t, store, c.ID)
}

func disqualRecordOf(t *testing.T, store *artifact.MemStore, caseID string) DisqualResult {
	t.Helper()
	arts, err := store.Query(caseID, artifact.TypeDiscovery)
	if err != nil || len(arts) != 1 {
		t.Fatalf("discovery artifacts = %d, %v", len(arts), err)
	}
	var res DisqualResult
	if err := json.Unmarshal(arts[0].Payload, &res); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	return res
}

// An alias record placing the version inside its range withdraws the disqualification, whichever
// record the row is keyed by; agreeing records, and alias records with nothing to say, leave it.
func TestRangeDispute_AliasRecord(t *testing.T) {
	for _, tc := range []struct {
		name     string
		vulnID   string
		src      disputeSource
		version  string
		disputed bool
	}{
		{"GHSA row, GO alias includes", "GHSA-w67g-5rqw-f597", disputeSource{"GHSA-w67g-5rqw-f597": ghsaExcludes, "GO-2026-6278": goIncludes}, "v1.5.3", true},
		{"GO row excludes, GHSA alias includes", "GO-2026-6278",
			disputeSource{"GO-2026-6278": disputeRecord([]string{"GHSA-w67g-5rqw-f597"}, Range{Fixed: "v1.5.3", FixedVersion: "v1.5.3"}),
				"GHSA-w67g-5rqw-f597": disputeRecord([]string{"GO-2026-6278"}, Range{Fixed: "v1.5.4", FixedVersion: "v1.5.4"})}, "v1.5.3", true},
		{"records agree", "GHSA-w67g-5rqw-f597", disputeSource{"GHSA-w67g-5rqw-f597": ghsaExcludes, "GO-2026-6278": goExcludes}, "v1.5.3", false},
		{"alias absent", "GHSA-w67g-5rqw-f597", disputeSource{"GHSA-w67g-5rqw-f597": ghsaExcludes}, "v1.5.3", false},
		{"alias rangeless", "GHSA-w67g-5rqw-f597", disputeSource{"GHSA-w67g-5rqw-f597": ghsaExcludes, "GO-2026-6278": disputeRecord(nil)}, "v1.5.3", false},
		{"alias names another module", "GHSA-w67g-5rqw-f597", disputeSource{"GHSA-w67g-5rqw-f597": ghsaExcludes,
			"GO-2026-6278": func() AdvisoryFacts {
				f := goIncludes
				f.Module, f.PURL = "example.com/other", "pkg:golang/example.com/other"
				return f
			}()}, "v1.5.3", false},
		{"version past both", "GHSA-w67g-5rqw-f597", disputeSource{"GHSA-w67g-5rqw-f597": ghsaExcludes, "GO-2026-6278": goIncludes}, "v1.5.4", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := runDisputeDisqual(t, tc.vulnID, tc.src, nil, tc.version)
			if tc.disputed {
				if res.Disqualified || res.Reason != ReasonInsufficient || res.RangeDisputed == "" || res.Source != nil {
					t.Fatalf("got %+v, want a proceeding row naming the dispute", res)
				}
				return
			}
			if !res.Disqualified || res.Reason != ReasonVersionNotInRange || res.RangeDisputed != "" {
				t.Fatalf("got %+v, want %s standing", res, ReasonVersionNotInRange)
			}
		})
	}
}

// govulncheck's database matching the advisory against the build withdraws the disqualification. A
// failed or partial run withdraws nothing: the clear stands and says it was not cross-checked.
func TestRangeDispute_AnalyzerDatabase(t *testing.T) {
	src := disputeSource{"GHSA-w67g-5rqw-f597": ghsaExcludes, "GO-2026-6278": goExcludes}
	for _, tc := range []struct {
		name      string
		p         matchPlugin
		disputed  bool
		wantCheck string
	}{
		{"matched", matchPlugin{matched: true}, true, ""},
		{"not matched", matchPlugin{}, false, ""},
		{"run failed", matchPlugin{matched: true, err: errors.New("govulncheck: build failed\nmore")}, false, "could not be consulted: govulncheck: build failed"},
		{"partial run", matchPlugin{matched: true, partial: true}, false, "over the whole build"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reqs []plugin.ReachabilityRequest
			tc.p.realResolverPlugin = realResolverPlugin{lang: "go"}
			tc.p.reqs = &reqs
			res := runDisputeDisqual(t, "GHSA-w67g-5rqw-f597", src, tc.p, "v1.5.3")
			if len(reqs) != 1 || !reqs[0].MatchOnly || reqs[0].VulnID != "GO-2026-6278" {
				t.Fatalf("Reachability requests = %+v, want one MatchOnly request for GO-2026-6278", reqs)
			}
			if tc.disputed {
				if res.Disqualified || res.Reason != ReasonInsufficient || !strings.Contains(res.RangeDisputed, "govulncheck") {
					t.Fatalf("got %+v, want a proceeding row naming govulncheck", res)
				}
				return
			}
			if !res.Disqualified || res.Reason != ReasonVersionNotInRange || res.RangeDisputed != "" {
				t.Fatalf("got %+v, want %s standing", res, ReasonVersionNotInRange)
			}
			if (tc.wantCheck == "") != (res.CrossCheck == "") || !strings.Contains(res.CrossCheck, tc.wantCheck) {
				t.Fatalf("CrossCheck = %q, want it to contain %q", res.CrossCheck, tc.wantCheck)
			}
		})
	}
}

// The analyzer is asked only about a version-axis disqualification: an in-range row and a non-Go
// lane never trigger the extra govulncheck read.
func TestRangeDispute_AnalyzerConsultedOnlyOnARangeClear(t *testing.T) {
	src := disputeSource{"GHSA-w67g-5rqw-f597": ghsaExcludes}
	for _, tc := range []struct {
		name    string
		lang    string
		version string
	}{
		{"in range", "go", "v1.5.2"},
		{"not a go lane", "js", "v1.5.3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reqs []plugin.ReachabilityRequest
			p := matchPlugin{realResolverPlugin: realResolverPlugin{lang: tc.lang}, matched: true, reqs: &reqs}
			runDisputeDisqual(t, "GHSA-w67g-5rqw-f597", src, p, tc.version)
			if len(reqs) != 0 {
				t.Fatalf("Reachability requests = %+v, want none", reqs)
			}
		})
	}
}
