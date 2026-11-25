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
		res.Partiality = plugin.Partial(plugin.PartialReasonToolFailure + ":govulncheck_partial_run")
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

// govulncheck's database matching the advisory against the build withdraws the disqualification, over
// a partial run too, and the dispute says the run was partial. A failed run, or a partial run with no
// match, withdraws nothing: the clear stands and says it was not cross-checked, in words that do not
// carry the run's error text.
func TestRangeDispute_AnalyzerDatabase(t *testing.T) {
	src := disputeSource{"GHSA-w67g-5rqw-f597": ghsaExcludes, "GO-2026-6278": goExcludes}
	for _, tc := range []struct {
		name      string
		p         matchPlugin
		disputed  bool
		wantText  string
		wantCheck string
	}{
		{"matched", matchPlugin{matched: true}, true, "govulncheck's database matches GO-2026-6278 against the build", ""},
		{"not matched", matchPlugin{}, false, "", ""},
		{"run failed", matchPlugin{matched: true, err: errors.New(`govulncheck failed ("/tmp/ferralon-assay-checkout-83412"): exit 1`)}, false, "",
			"govulncheck's database could not be consulted: govulncheck_failed"},
		{"partial run, matched", matchPlugin{matched: true, partial: true}, true, "over a partial run: tool_failure:govulncheck_partial_run", ""},
		{"partial run, not matched", matchPlugin{partial: true}, false, "", "over the whole build: tool_failure:govulncheck_partial_run"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reqs []plugin.ReachabilityRequest
			tc.p.realResolverPlugin = realResolverPlugin{lang: "go"}
			tc.p.reqs = &reqs
			res := runDisputeDisqual(t, "GHSA-w67g-5rqw-f597", src, tc.p, "v1.5.3")
			if len(reqs) != 1 || !reqs[0].MatchOnly || reqs[0].MatchOutsideToolchain || reqs[0].VulnID != "GO-2026-6278" {
				t.Fatalf("Reachability requests = %+v, want one MatchOnly request for GO-2026-6278 counting every match", reqs)
			}
			if tc.disputed {
				if res.Disqualified || res.Reason != ReasonInsufficient || !strings.Contains(res.RangeDisputed, tc.wantText) {
					t.Fatalf("got %+v, want a proceeding row whose dispute contains %q", res, tc.wantText)
				}
				if !tc.p.partial && strings.Contains(res.RangeDisputed, "partial") {
					t.Fatalf("RangeDisputed = %q names a partial run over a complete one", res.RangeDisputed)
				}
				return
			}
			if !res.Disqualified || res.Reason != ReasonVersionNotInRange || res.RangeDisputed != "" {
				t.Fatalf("got %+v, want %s standing", res, ReasonVersionNotInRange)
			}
			if strings.Contains(res.CrossCheck, "/tmp/") {
				t.Fatalf("CrossCheck = %q carries the run's error text", res.CrossCheck)
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

// A toolchain row asks the analyzer only when the version axis also judged another module, and then
// only about matches outside the toolchain, which the analyzer matches against its own.
func TestRangeDispute_AnalyzerOnAToolchainRow(t *testing.T) {
	const caseID = "case-dispute-toolchain"
	minimum := ToolchainFact{Version: "go1.21.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective}
	xnet := presentRanges{presentPackage: presentPackage{Module: "golang.org/x/net", Versions: []string{"v0.30.0"}, Complete: true}}
	stdlib := presentRanges{presentPackage: presentPackage{Coordinate: "stdlib", Versions: []string{"1.21.0"}, Complete: true}}
	for _, tc := range []struct {
		name     string
		others   []presentRanges
		matched  bool
		asked    bool
		disputed bool
	}{
		{"no other module", nil, true, false, false},
		{"only the toolchain beside it", []presentRanges{stdlib}, true, false, false},
		{"another module, matched", []presentRanges{xnet}, true, true, true},
		{"another module, not matched", []presentRanges{xnet}, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{"language": "go", "toolchain": minimum})
			putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{"coordinate": "stdlib", "purl": "pkg:golang/stdlib"})
			var reqs []plugin.ReachabilityRequest
			p := matchPlugin{realResolverPlugin: realResolverPlugin{lang: "go"}, matched: tc.matched, reqs: &reqs}
			c := &assessment.Assessment{ID: caseID, Request: assessment.Request{Vulnerability: assessment.VulnRef{ID: "GO-2099-0001"}}}
			s := disqualificationDiscovery{src: disputeSource{}, plugin: p}
			rngs := []affectedRange{{Scheme: "go-toolchain"}}
			dispute, _, _ := s.rangeDispute(context.Background(), c, store, "", "", versionAxis{Versions: []string{"1.21.0"}, Complete: true}, rngs, tc.others)
			if asked := len(reqs) == 1; asked != tc.asked {
				t.Fatalf("Reachability requests = %+v, want asked=%v", reqs, tc.asked)
			}
			if tc.asked && (!reqs[0].MatchOnly || !reqs[0].MatchOutsideToolchain) {
				t.Fatalf("request = %+v, want MatchOnly and MatchOutsideToolchain", reqs[0])
			}
			if (dispute != "") != tc.disputed {
				t.Fatalf("dispute = %q, want disputed=%v", dispute, tc.disputed)
			}
		})
	}
}

// An alias record's ranges pass through the projection the row's own did before they are compared,
// and are asked about every package the version axis judged, not only the adjudicated one.
func TestRangeDispute_AliasProjection(t *testing.T) {
	const caseID = "case-dispute-projection"
	minimum := ToolchainFact{Version: "go1.21.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective}
	exact := ToolchainFact{Version: "go1.21.0", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared}
	stdlibAlias := func(rngs ...Range) AdvisoryFacts {
		return AdvisoryFacts{Coordinate: "stdlib", PURL: "pkg:golang/stdlib", VersionScheme: "go-toolchain", AffectedRanges: rngs}
	}
	xnetAlias := func(fixed string) AdvisoryFacts {
		return AdvisoryFacts{Aliases: []string{"GO-2099-0001"}, AffectedPackages: []AffectedPackage{
			{Module: disputeModule, PURL: "pkg:golang/" + disputeModule, VersionScheme: "gomod", AffectedRanges: []Range{{Fixed: "v1.5.3"}}},
			{Module: "golang.org/x/net", PURL: "pkg:golang/golang.org/x/net", VersionScheme: "gomod", AffectedRanges: []Range{{Fixed: fixed}}},
		}}
	}
	for _, tc := range []struct {
		name     string
		inv      map[string]any
		adv      map[string]any
		alias    AdvisoryFacts
		axis     []string
		others   []presentRanges
		disputed bool
	}{
		{name: "stdlib floor inside the alias range once its lower bound drops",
			inv:   map[string]any{"language": "go", "toolchain": minimum},
			adv:   map[string]any{"coordinate": "stdlib", "purl": "pkg:golang/stdlib", "aliases": []string{"CVE-2099-0001"}},
			alias: stdlibAlias(Range{Introduced: "1.21.5", Fixed: "1.21.8"}), axis: []string{"1.21.0"}, disputed: true},
		{name: "stdlib exact version below the alias range",
			inv:   map[string]any{"language": "go", "toolchain": exact},
			adv:   map[string]any{"coordinate": "stdlib", "purl": "pkg:golang/stdlib", "aliases": []string{"CVE-2099-0001"}},
			alias: stdlibAlias(Range{Introduced: "1.21.5", Fixed: "1.21.8"}), axis: []string{"1.21.0"}},
		{name: "stdlib floor past the alias fix",
			inv:   map[string]any{"language": "go", "toolchain": minimum},
			adv:   map[string]any{"coordinate": "stdlib", "purl": "pkg:golang/stdlib", "aliases": []string{"CVE-2099-0001"}},
			alias: stdlibAlias(Range{Introduced: "1.20.0", Fixed: "1.20.9"}), axis: []string{"1.21.0"}},
		{name: "another present package inside the alias range",
			inv:   map[string]any{"language": "go"},
			adv:   map[string]any{"module": disputeModule, "purl": "pkg:golang/" + disputeModule, "aliases": []string{"CVE-2099-0001"}},
			alias: xnetAlias("v0.38.0"), axis: []string{"v1.5.3"},
			others: []presentRanges{{presentPackage: presentPackage{Module: "golang.org/x/net", Versions: []string{"v0.30.0"}, Complete: true}}}, disputed: true},
		{name: "another present package outside the alias range",
			inv:   map[string]any{"language": "go"},
			adv:   map[string]any{"module": disputeModule, "purl": "pkg:golang/" + disputeModule, "aliases": []string{"CVE-2099-0001"}},
			alias: xnetAlias("v0.20.0"), axis: []string{"v1.5.3"},
			others: []presentRanges{{presentPackage: presentPackage{Module: "golang.org/x/net", Versions: []string{"v0.30.0"}, Complete: true}}}},
		{name: "stdlib present beside the adjudicated package, floor inside once its lower bound drops",
			inv: map[string]any{"language": "go", "toolchain": minimum},
			adv: map[string]any{"module": disputeModule, "purl": "pkg:golang/" + disputeModule, "aliases": []string{"CVE-2099-0001"}},
			alias: AdvisoryFacts{AffectedPackages: []AffectedPackage{
				{Coordinate: "stdlib", PURL: "pkg:golang/stdlib", VersionScheme: "go-toolchain", AffectedRanges: []Range{{Introduced: "1.21.5", Fixed: "1.21.8"}}},
			}}, axis: []string{"v1.5.3"},
			others: []presentRanges{{presentPackage: presentPackage{Coordinate: "stdlib", Versions: []string{"1.21.0"}, Complete: true}}}, disputed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			putJSON(t, store, caseID, artifact.TypeInventory, tc.inv)
			putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, tc.adv)
			c := &assessment.Assessment{ID: caseID}
			s := disqualificationDiscovery{src: disputeSource{"CVE-2099-0001": tc.alias}}
			dispute, note, _ := s.rangeDispute(context.Background(), c, store, "", "", versionAxis{Versions: tc.axis, Complete: true}, nil, tc.others)
			if note != "" {
				t.Fatalf("note = %q, want none with no analyzer", note)
			}
			if (dispute != "") != tc.disputed {
				t.Fatalf("dispute = %q, want disputed=%v", dispute, tc.disputed)
			}
		})
	}
}

// An alias record that places the version outside only under the same assumption about a
// pseudo-version's ancestry agrees under it: the clear stands and states the assumption, whichever
// record it comes from. One that places the version inside still withdraws it.
func TestRangeDispute_AliasUnderAssumption(t *testing.T) {
	const bound = "v1.5.4-0.20240701034025-d67f41855da4"
	const installed = "v1.5.4-0.20240801000000-aaaaaaaaaaaa"
	pseudoFixed := Range{Introduced: "v1.5.3", Fixed: bound, FixedVersion: bound}
	for _, tc := range []struct {
		name     string
		row      AdvisoryFacts
		alias    AdvisoryFacts
		disputed bool
		// attributed: the line names the alias's bound, not one the row's own record carries.
		attributed bool
	}{
		{"alias identical", disputeRecord([]string{"GHSA-w67g-5rqw-f597"}, pseudoFixed), disputeRecord([]string{"GO-2026-6278"}, pseudoFixed), false, false},
		{"only the alias rests on the assumption", disputeRecord([]string{"GHSA-w67g-5rqw-f597"}, Range{Fixed: "v1.5.3", FixedVersion: "v1.5.3"}), disputeRecord([]string{"GO-2026-6278"}, pseudoFixed), false, true},
		{"alias includes", disputeRecord([]string{"GHSA-w67g-5rqw-f597"}, pseudoFixed), disputeRecord([]string{"GO-2026-6278"}, Range{Introduced: "v1.5.3", Fixed: "v1.5.5", FixedVersion: "v1.5.5"}), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := runDisputeDisqual(t, "GO-2026-6278", disputeSource{"GO-2026-6278": tc.row, "GHSA-w67g-5rqw-f597": tc.alias}, nil, installed)
			if tc.disputed {
				if res.Disqualified || res.RangeDisputed == "" || len(res.Assumptions) != 0 {
					t.Fatalf("got %+v, want a proceeding row naming the dispute and no assumption", res)
				}
				return
			}
			if !res.Disqualified || res.Reason != ReasonVersionNotInRange || res.RangeDisputed != "" || len(res.Assumptions) != 1 || !strings.Contains(res.Assumptions[0], "aaaaaaaaaaaa") {
				t.Fatalf("got %+v, want %s standing with one assumption about %s", res, ReasonVersionNotInRange, installed)
			}
			if got := strings.HasPrefix(res.Assumptions[0], "per GHSA-w67g-5rqw-f597: "); got != tc.attributed {
				t.Fatalf("assumption %q attributed to the alias = %v, want %v", res.Assumptions[0], got, tc.attributed)
			}
		})
	}
}
