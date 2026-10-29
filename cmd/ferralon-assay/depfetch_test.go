package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// The dependency-code hold is decided by fetches the re-assessments make, so cve-watch must read
// it when RunCVEWatch consults Hold, not when the request is built: a stuck registry observed after
// the request exists holds through Hold, and HoldCursor, fixed at construction, cannot see it. Hold
// judges the registry against the stored record it is handed.
func TestCVEWatchRequestHoldReadsTheFetchAfterAssessment(t *testing.T) {
	const npmjs = "https://registry.npmjs.org/"
	served := &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HasServed: true}}}
	for _, tc := range []struct {
		name    string
		outcome string
		stored  *statestore.DepFetch
		want    bool
	}{
		{"a transient error holds", pipeline.UnreadUnavailable, nil, true},
		{"not served by a registry that never served this repository falls back", pipeline.UnreadNotServed, nil, false},
		{"not served by a registry that has served this repository holds", pipeline.UnreadNotServed, served, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := &depCodeRun{source: report.DependencyCodeSourceFetch}
			req := cveWatchRequest(&runConfig{deps: run}, nil)
			if req.HoldCursor || req.Hold == nil || req.Hold(tc.stored) {
				t.Fatalf("before any fetch: HoldCursor %v, Hold set %v; want neither holding", req.HoldCursor, req.Hold != nil)
			}
			run.observe(pipeline.DependencyAcquisitionResult{
				Mode:     "fetch",
				Fallback: &pipeline.DependencyCodeCause{Kind: tc.outcome},
				Outcomes: []pipeline.DependencyOutcome{{PURL: "pkg:npm/a@1", Registry: npmjs, Outcome: tc.outcome}},
			})
			if got := req.Hold(tc.stored); got != tc.want {
				t.Fatalf("Hold() after the fetch = %v, want %v", got, tc.want)
			}
			if req.HoldCursor {
				t.Fatal("HoldCursor changed after construction")
			}
		})
	}
}

// A non-JS cve-watch has no acquisition to record: its request carries the stored depfetch.json.
func TestCVEWatchRequestDependencyFetchOnlyForJS(t *testing.T) {
	if cveWatchRequest(&runConfig{}, nil).DependencyFetch != nil {
		t.Error("non-JS request has a DependencyFetch hook")
	}
	if cveWatchRequest(&runConfig{deps: &depCodeRun{source: report.DependencyCodeSourceFetch}}, nil).DependencyFetch == nil {
		t.Error("JS request has no DependencyFetch hook")
	}
}

func TestDepCodeRunRecord(t *testing.T) {
	const npmjs, corp = "https://registry.npmjs.org/", "https://npm.corp.example/"
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	earlier := now.Add(-48 * time.Hour)
	out := func(purl, reg, outcome string) pipeline.DependencyOutcome {
		return pipeline.DependencyOutcome{PURL: purl, Registry: reg, Outcome: outcome}
	}
	fell := &pipeline.DependencyCodeCause{Kind: pipeline.UnreadNotServed}
	advs := func(ids ...string) []report.Advisory {
		var out []report.Advisory
		for _, id := range ids {
			out = append(out, report.Advisory{ID: id})
		}
		return out
	}
	watch := func(held bool, ids ...string) trigger.DependencyFetchRun {
		return trigger.DependencyFetchRun{Held: held, Assessed: advs(ids...)}
	}
	baseline := func(ids ...string) trigger.DependencyFetchRun {
		return trigger.DependencyFetchRun{Baseline: true, Assessed: advs(ids...)}
	}
	aliased := report.Advisory{ID: "CVE-2026-0001", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}}
	for _, tc := range []struct {
		name    string
		prior   *statestore.DepFetch
		results []pipeline.DependencyAcquisitionResult // nil: no acquisition observed
		run     trigger.DependencyFetchRun
		want    *statestore.DepFetch
	}{
		{
			name:  "nothing observed carries the stored record",
			prior: &statestore.DepFetch{Reassess: []string{"A"}, Registries: map[string]statestore.RegistryFetch{npmjs: {HeldRuns: 2, FirstHeldAt: earlier}}},
			run:   watch(true, "A"),
			want:  &statestore.DepFetch{Reassess: []string{"A"}, Registries: map[string]statestore.RegistryFetch{npmjs: {HeldRuns: 2, FirstHeldAt: earlier}}},
		},
		{
			name:    "a network fetch sets has_served",
			results: []pipeline.DependencyAcquisitionResult{{Outcomes: []pipeline.DependencyOutcome{out("pkg:npm/a@1", npmjs, pipeline.OutcomeReadNetwork)}}},
			run:     watch(false),
			want:    &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HasServed: true}}},
		},
		{
			name:    "a baseline network fetch sets has_served",
			results: []pipeline.DependencyAcquisitionResult{{Outcomes: []pipeline.DependencyOutcome{out("pkg:npm/a@1", npmjs, pipeline.OutcomeReadNetwork)}}},
			run:     baseline(),
			want:    &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HasServed: true}}},
		},
		{
			name:    "a cache read does not set has_served",
			results: []pipeline.DependencyAcquisitionResult{{Outcomes: []pipeline.DependencyOutcome{out("pkg:npm/a@1", npmjs, pipeline.OutcomeReadCache)}}},
			run:     watch(false),
			want:    &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {}}},
		},
		{
			name:  "a cache read resets the held count but keeps has_served",
			prior: &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HasServed: true, HeldRuns: 2, FirstHeldAt: earlier}}},
			results: []pipeline.DependencyAcquisitionResult{{Outcomes: []pipeline.DependencyOutcome{
				out("pkg:npm/a@1", npmjs, pipeline.OutcomeReadCache), out("pkg:npm/b@1", npmjs, pipeline.UnreadNotServed),
			}}},
			run:  watch(true),
			want: &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HasServed: true}}},
		},
		{
			name:    "a held run against a registry answering a transient error counts and stamps the first",
			results: []pipeline.DependencyAcquisitionResult{{Fallback: fell, Outcomes: []pipeline.DependencyOutcome{out("pkg:npm/a@1", npmjs, pipeline.UnreadUnavailable)}}},
			run:     watch(true),
			want:    &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HeldRuns: 1, FirstHeldAt: now}}},
		},
		{
			name:    "a later held run, unreachable where the registry has served, counts and keeps the first time",
			prior:   &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HasServed: true, HeldRuns: 1, FirstHeldAt: earlier}}},
			results: []pipeline.DependencyAcquisitionResult{{Fallback: fell, Outcomes: []pipeline.DependencyOutcome{out("pkg:npm/a@1", npmjs, pipeline.UnreadUnreachable)}}},
			run:     watch(true),
			want:    &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HasServed: true, HeldRuns: 2, FirstHeldAt: earlier}}},
		},
		{
			name:    "a held cursor counts nothing against a registry that does not hold it",
			prior:   &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HeldRuns: 1, FirstHeldAt: earlier}}},
			results: []pipeline.DependencyAcquisitionResult{{Fallback: fell, Outcomes: []pipeline.DependencyOutcome{out("pkg:npm/a@1", npmjs, pipeline.UnreadNotServed)}}},
			run:     watch(true),
			want:    &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HeldRuns: 1, FirstHeldAt: earlier}}},
		},
		{
			name:  "a deadline-cancelled fetch is not a registry failure",
			prior: &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HeldRuns: 1, FirstHeldAt: earlier}}},
			results: []pipeline.DependencyAcquisitionResult{{
				Fallback: &pipeline.DependencyCodeCause{Kind: pipeline.UnreadCancelled},
				Outcomes: []pipeline.DependencyOutcome{out("pkg:npm/a@1", npmjs, pipeline.UnreadCancelled), out("pkg:npm/b@1", npmjs, pipeline.UnreadCancelled)},
			}},
			run:  watch(true),
			want: &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HeldRuns: 1, FirstHeldAt: earlier}}},
		},
		{
			name:    "a run whose cursor advanced does not count",
			prior:   &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HeldRuns: 1, FirstHeldAt: earlier}}},
			results: []pipeline.DependencyAcquisitionResult{{Fallback: fell, Outcomes: []pipeline.DependencyOutcome{out("pkg:npm/a@1", npmjs, pipeline.UnreadUnavailable)}}},
			run:     watch(false),
			want:    &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HeldRuns: 1, FirstHeldAt: earlier}}},
		},
		{
			name:    "a baseline never touches the held count",
			prior:   &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HeldRuns: 1, FirstHeldAt: earlier}, corp: {HeldRuns: 3, FirstHeldAt: earlier}}},
			results: []pipeline.DependencyAcquisitionResult{{Outcomes: []pipeline.DependencyOutcome{out("pkg:npm/a@1", npmjs, pipeline.OutcomeReadCache), out("pkg:npm/b@1", corp, pipeline.UnreadNotServed)}}},
			run:     baseline(),
			want:    &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HeldRuns: 1, FirstHeldAt: earlier}, corp: {HeldRuns: 3, FirstHeldAt: earlier}}},
		},
		{
			name: "registries are judged apart, and a limit that is not a fetch failure is neither",
			results: []pipeline.DependencyAcquisitionResult{{Fallback: fell, Outcomes: []pipeline.DependencyOutcome{
				out("pkg:npm/a@1", npmjs, pipeline.OutcomeReadNetwork),
				out("pkg:npm/b@1", corp, pipeline.UnreadUnavailable),
				out("pkg:npm/c@1", "", pipeline.UnreadNoIntegrity),
				out("pkg:npm/d@1", "https://other.example/", pipeline.UnreadNoIntegrity),
			}}},
			run: watch(true),
			want: &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{
				npmjs: {HasServed: true}, corp: {HeldRuns: 1, FirstHeldAt: now}, "https://other.example/": {},
			}},
		},
		{
			name:    "a registry that has served and now serves nothing counts",
			prior:   &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HasServed: true}}},
			results: []pipeline.DependencyAcquisitionResult{{Fallback: fell, Outcomes: []pipeline.DependencyOutcome{out("pkg:npm/a@1", npmjs, pipeline.UnreadNotServed), out("pkg:npm/b@1", npmjs, pipeline.UnreadNotServed)}}},
			run:     watch(true),
			want:    &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HasServed: true, HeldRuns: 1, FirstHeldAt: now}}},
		},
		{
			name:  "a registry that has served but now gets no token counts nothing",
			prior: &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{corp: {HasServed: true, HeldRuns: 1, FirstHeldAt: earlier}}},
			results: []pipeline.DependencyAcquisitionResult{{Fallback: fell, Outcomes: []pipeline.DependencyOutcome{
				{PURL: "pkg:npm/a@1", Registry: corp, Outcome: pipeline.UnreadPolicyRefused, Detail: artifactcache.PolicyMissingCredential, UnsetEnv: "NODE_AUTH_TOKEN"},
			}}},
			run:  watch(true),
			want: &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{corp: {HasServed: true, HeldRuns: 1, FirstHeldAt: earlier}}},
		},
		{
			name:  "a partial read resets the count and adds what it assessed",
			prior: &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HasServed: true, HeldRuns: 2, FirstHeldAt: earlier}}},
			results: []pipeline.DependencyAcquisitionResult{{Outcomes: []pipeline.DependencyOutcome{
				out("pkg:npm/a@1", npmjs, pipeline.OutcomeReadNetwork), out("pkg:npm/b@1", npmjs, pipeline.UnreadUnavailable),
			}}},
			run:  watch(true, "A"),
			want: &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HasServed: true}}, Reassess: []string{"A"}},
		},
		{
			name:  "a baseline partial read neither adds nor clears",
			prior: &statestore.DepFetch{Reassess: []string{"A"}},
			results: []pipeline.DependencyAcquisitionResult{{Outcomes: []pipeline.DependencyOutcome{
				out("pkg:npm/a@1", npmjs, pipeline.OutcomeReadCache), out("pkg:npm/b@1", npmjs, pipeline.UnreadNotServed),
			}}},
			run:  baseline("A", "B"),
			want: &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {}}, Reassess: []string{"A"}},
		},
		{
			name:  "a registry whose every fetch the deadline cancelled counts nothing even where it has served",
			prior: &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HasServed: true, HeldRuns: 1, FirstHeldAt: earlier}}},
			results: []pipeline.DependencyAcquisitionResult{{
				Fallback: &pipeline.DependencyCodeCause{Kind: pipeline.UnreadCancelled},
				Outcomes: []pipeline.DependencyOutcome{out("pkg:npm/a@1", npmjs, pipeline.UnreadCancelled)},
			}},
			run:  watch(true),
			want: &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HasServed: true, HeldRuns: 1, FirstHeldAt: earlier}}},
		},
		{
			name:  "outcomes accumulate across acquisitions",
			prior: &statestore.DepFetch{Reassess: []string{"Z"}},
			results: []pipeline.DependencyAcquisitionResult{
				{Fallback: fell, Outcomes: []pipeline.DependencyOutcome{out("pkg:npm/a@1", npmjs, pipeline.UnreadNotServed)}},
				{Outcomes: []pipeline.DependencyOutcome{out("pkg:npm/a@1", npmjs, pipeline.OutcomeReadNetwork)}},
			},
			run:  watch(true, "A"),
			want: &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HasServed: true}}, Reassess: []string{"Z", "A"}},
		},
		{
			name:    "a cve-watch run that fell back adds what it assessed",
			prior:   &statestore.DepFetch{Reassess: []string{"Z"}},
			results: []pipeline.DependencyAcquisitionResult{{Fallback: fell}},
			run:     watch(false, "A", "B"),
			want:    &statestore.DepFetch{Reassess: []string{"Z", "A", "B"}},
		},
		{
			name:    "a baseline that fell back adds nothing",
			prior:   &statestore.DepFetch{Reassess: []string{"A"}},
			results: []pipeline.DependencyAcquisitionResult{{Fallback: fell}},
			run:     baseline("A", "B"),
			want:    &statestore.DepFetch{Reassess: []string{"A"}},
		},
		{
			name:    "a baseline that read clears what it assessed",
			prior:   &statestore.DepFetch{Reassess: []string{"A", "Z"}},
			results: []pipeline.DependencyAcquisitionResult{{Outcomes: []pipeline.DependencyOutcome{out("pkg:npm/a@1", npmjs, pipeline.OutcomeReadCache)}}},
			run:     baseline("A", "B"),
			want:    &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {}}, Reassess: []string{"Z"}},
		},
		{
			name:    "a cve-watch run that read clears what it assessed",
			prior:   &statestore.DepFetch{Reassess: []string{"A", "Z"}},
			results: []pipeline.DependencyAcquisitionResult{{}},
			run:     watch(false, "A"),
			want:    &statestore.DepFetch{Reassess: []string{"Z"}},
		},
		{
			name:    "a cve-watch run that fell back adds the advisory's ID",
			results: []pipeline.DependencyAcquisitionResult{{Fallback: fell}},
			run:     trigger.DependencyFetchRun{Assessed: []report.Advisory{aliased}},
			want:    &statestore.DepFetch{Reassess: []string{"CVE-2026-0001"}},
		},
		{
			name:    "a cve-watch run that read keeps an entry naming only an alias of what it assessed",
			prior:   &statestore.DepFetch{Reassess: []string{"GHSA-aaaa-bbbb-cccc", "Z"}},
			results: []pipeline.DependencyAcquisitionResult{{}},
			run:     trigger.DependencyFetchRun{Assessed: []report.Advisory{aliased}},
			want:    &statestore.DepFetch{Reassess: []string{"GHSA-aaaa-bbbb-cccc", "Z"}},
		},
		{
			name:    "a baseline that read clears an entry naming an alias of what it assessed",
			prior:   &statestore.DepFetch{Reassess: []string{"GHSA-aaaa-bbbb-cccc", "Z"}},
			results: []pipeline.DependencyAcquisitionResult{{}},
			run:     trigger.DependencyFetchRun{Baseline: true, Assessed: []report.Advisory{aliased}},
			want:    &statestore.DepFetch{Reassess: []string{"Z"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := &depCodeRun{source: report.DependencyCodeSourceFetch}
			for _, r := range tc.results {
				run.observe(r)
			}
			var before *statestore.DepFetch
			if tc.prior != nil {
				before = deepCopyDepFetch(tc.prior)
			}
			got := run.record(tc.prior, tc.run, now)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("record =\n %+v\nwant\n %+v", got, tc.want)
			}
			if !reflect.DeepEqual(tc.prior, before) {
				t.Fatalf("record modified prior: %+v, was %+v", tc.prior, before)
			}
		})
	}
}

// A nil run (not JS) records nothing: its hook is nil and the stored record is carried.
func TestDepCodeRunFetchUpdateNilForNonJS(t *testing.T) {
	var run *depCodeRun
	if run.fetchUpdate() != nil {
		t.Fatal("nil run has a DependencyFetch hook")
	}
}

func deepCopyDepFetch(d *statestore.DepFetch) *statestore.DepFetch {
	cp := &statestore.DepFetch{ReportSHA256: d.ReportSHA256}
	if d.Registries != nil {
		cp.Registries = map[string]statestore.RegistryFetch{}
		for k, v := range d.Registries {
			cp.Registries[k] = v
		}
	}
	if d.Reassess != nil {
		cp.Reassess = append([]string{}, d.Reassess...)
	}
	return cp
}

// Each cause maps to one action. A refused token is red however much the registry served; a
// registry that served some packages is partial; one that served none holds on a transient error,
// or where it has served this repository before and failed for a reason other than a missing
// credential; anything else falls back.
func TestClassifyRegistry(t *testing.T) {
	const reg = "https://npm.corp.example/"
	o := func(outcome, detail string) pipeline.DependencyOutcome {
		return pipeline.DependencyOutcome{PURL: "pkg:npm/a@1", Registry: reg, Outcome: outcome, Detail: detail}
	}
	read := o(pipeline.OutcomeReadNetwork, "")
	cached := o(pipeline.OutcomeReadCache, "")
	rejected := o(pipeline.UnreadPolicyRefused, artifactcache.PolicyCredentialRejected)
	missing := o(pipeline.UnreadPolicyRefused, artifactcache.PolicyMissingCredential)
	refused := o(pipeline.UnreadPolicyRefused, artifactcache.PolicyRedirectOffAllowlist)
	unavailable := o(pipeline.UnreadUnavailable, "")
	unreachable := o(pipeline.UnreadUnreachable, "")
	notServed := o(pipeline.UnreadNotServed, "")
	mismatch := o(pipeline.UnreadIntegrityMismatch, "")
	failed := o(pipeline.UnreadFetchFailed, "")
	cancelled := o(pipeline.UnreadCancelled, "")
	noIntegrity := o(pipeline.UnreadNoIntegrity, "")
	served := statestore.RegistryFetch{HasServed: true}
	for _, tc := range []struct {
		name     string
		outcomes []pipeline.DependencyOutcome
		prior    statestore.RegistryFetch
		want     registryAction
	}{
		{"everything read", []pipeline.DependencyOutcome{read, cached}, statestore.RegistryFetch{}, actionRead},
		{"a limit that is not a fetch failure", []pipeline.DependencyOutcome{noIntegrity}, statestore.RegistryFetch{}, actionRead},
		{"token refused on every package", []pipeline.DependencyOutcome{rejected}, statestore.RegistryFetch{}, actionRed},
		{"token refused on one package of many read", []pipeline.DependencyOutcome{read, read, rejected}, served, actionRed},
		{"token refused beside a missing credential", []pipeline.DependencyOutcome{missing, rejected}, served, actionRed},
		{"missing credential, never served", []pipeline.DependencyOutcome{missing}, statestore.RegistryFetch{}, actionFallback},
		{"missing credential, has served", []pipeline.DependencyOutcome{missing, missing}, served, actionFallback},
		{"missing credential on one package of many read", []pipeline.DependencyOutcome{read, missing}, served, actionPartial},
		{"transient, never served", []pipeline.DependencyOutcome{unavailable}, statestore.RegistryFetch{}, actionHold},
		{"transient beside a missing credential", []pipeline.DependencyOutcome{missing, unavailable}, statestore.RegistryFetch{}, actionHold},
		{"transient on one package of many read", []pipeline.DependencyOutcome{read, unavailable}, served, actionPartial},
		{"unreachable, never served", []pipeline.DependencyOutcome{unreachable}, statestore.RegistryFetch{}, actionFallback},
		{"unreachable, has served", []pipeline.DependencyOutcome{unreachable}, served, actionHold},
		{"not served, never served", []pipeline.DependencyOutcome{notServed}, statestore.RegistryFetch{}, actionFallback},
		{"not served, has served", []pipeline.DependencyOutcome{notServed}, served, actionHold},
		{"not served on one package of many read", []pipeline.DependencyOutcome{cached, notServed}, statestore.RegistryFetch{}, actionPartial},
		{"other policy refusal, never served", []pipeline.DependencyOutcome{refused}, statestore.RegistryFetch{}, actionFallback},
		{"other policy refusal, has served", []pipeline.DependencyOutcome{refused}, served, actionHold},
		{"integrity mismatch, has served", []pipeline.DependencyOutcome{mismatch}, served, actionHold},
		{"fetch failed, never served", []pipeline.DependencyOutcome{failed}, statestore.RegistryFetch{}, actionFallback},
		{"has served, a missing credential beside a real failure", []pipeline.DependencyOutcome{missing, notServed}, served, actionHold},
		{"every fetch cancelled, has served", []pipeline.DependencyOutcome{cancelled, cancelled}, served, actionFallback},
		{"cancelled beside packages read", []pipeline.DependencyOutcome{read, cancelled}, served, actionPartial},
		{"cancelled beside a transient error", []pipeline.DependencyOutcome{cancelled, unavailable}, statestore.RegistryFetch{}, actionHold},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tally registryTally
			for _, o := range tc.outcomes {
				tally.add(o)
			}
			if got := classifyRegistry(tally, tc.prior); got != tc.want {
				t.Fatalf("classifyRegistry = %v, want %v (tally %+v)", got, tc.want, tally)
			}
		})
	}
}

// One rule holds the cursor and counts the run: for every outcome set, a cve-watch earnest run
// whose cursor held counts the registry exactly when Hold, handed the same stored record, held.
func TestDepCodeRunHoldAndCountAgree(t *testing.T) {
	const reg = "https://npm.corp.example/"
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	o := func(outcome, detail string) pipeline.DependencyOutcome {
		return pipeline.DependencyOutcome{PURL: "pkg:npm/a@1", Registry: reg, Outcome: outcome, Detail: detail}
	}
	sets := map[string][]pipeline.DependencyOutcome{
		"read":            {o(pipeline.OutcomeReadCache, "")},
		"transient":       {o(pipeline.UnreadUnavailable, "")},
		"unreachable":     {o(pipeline.UnreadUnreachable, "")},
		"not served":      {o(pipeline.UnreadNotServed, "")},
		"missing":         {o(pipeline.UnreadPolicyRefused, artifactcache.PolicyMissingCredential)},
		"rejected":        {o(pipeline.UnreadPolicyRefused, artifactcache.PolicyCredentialRejected)},
		"all cancelled":   {o(pipeline.UnreadCancelled, ""), o(pipeline.UnreadCancelled, "")},
		"partial":         {o(pipeline.OutcomeReadNetwork, ""), o(pipeline.UnreadUnavailable, "")},
		"cancelled+stuck": {o(pipeline.UnreadCancelled, ""), o(pipeline.UnreadNotServed, "")},
	}
	priors := map[string]*statestore.DepFetch{
		"no record":  nil,
		"never":      {Registries: map[string]statestore.RegistryFetch{reg: {}}},
		"has served": {Registries: map[string]statestore.RegistryFetch{reg: {HasServed: true}}},
	}
	for sname, outcomes := range sets {
		for pname, prior := range priors {
			t.Run(sname+"/"+pname, func(t *testing.T) {
				run := &depCodeRun{source: report.DependencyCodeSourceFetch}
				run.observe(pipeline.DependencyAcquisitionResult{Outcomes: outcomes})
				held := run.holds(prior)
				got := run.record(prior, trigger.DependencyFetchRun{Held: true}, now)
				if counted := got.Registries[reg].HeldRuns == 1; counted != held {
					t.Fatalf("holds = %v but counted = %v", held, counted)
				}
			})
		}
	}
}

// The stall cap needs both legs: stallRuns held runs and stallAge since the first. A run at the
// cap still holds its cursor; it also fails.
func TestDepCodeRunStallCap(t *testing.T) {
	const reg = "https://registry.npmjs.org/"
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		priorRuns int           // held runs before this one
		since     time.Duration // first_held_at, before now
		held      bool          // the cursor held
		baseline  bool
		wantRed   bool
	}{
		{name: "2 runs over 25h holds", priorRuns: 1, since: 25 * time.Hour, held: true},
		{name: "3 runs over 23h holds", priorRuns: 2, since: 23 * time.Hour, held: true},
		{name: "3 runs one instant short of 24h holds", priorRuns: 2, since: 24*time.Hour - time.Nanosecond, held: true},
		{name: "3 runs over 24h fails", priorRuns: 2, since: 24 * time.Hour, held: true, wantRed: true},
		{name: "5 runs over 72h fails", priorRuns: 4, since: 72 * time.Hour, held: true, wantRed: true},
		{name: "a run whose cursor advanced does not fail", priorRuns: 4, since: 72 * time.Hour},
		{name: "a baseline does not fail", priorRuns: 4, since: 72 * time.Hour, baseline: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := now.Add(-tc.since)
			prior := &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{reg: {HasServed: true, HeldRuns: tc.priorRuns, FirstHeldAt: first}}}
			run := &depCodeRun{source: report.DependencyCodeSourceFetch}
			run.observe(pipeline.DependencyAcquisitionResult{
				Mode:     "fetch",
				Fallback: &pipeline.DependencyCodeCause{Kind: pipeline.UnreadUnreachable},
				Outcomes: []pipeline.DependencyOutcome{{PURL: "pkg:npm/a@1", Registry: reg, Outcome: pipeline.UnreadUnreachable}},
			})
			if !tc.baseline && !run.holds(prior) {
				t.Fatal("the registry does not hold")
			}
			run.record(prior, trigger.DependencyFetchRun{Held: tc.held, Baseline: tc.baseline}, now)
			err := run.err()
			var de *depFetchError
			if got := errors.As(err, &de) && de.Kind == kindFetchStalled; got != tc.wantRed {
				t.Fatalf("err = %v, want stalled %v", err, tc.wantRed)
			}
			if tc.wantRed && (de.Registry != reg || de.HeldRuns != tc.priorRuns+1 || !de.Since.Equal(first)) {
				t.Fatalf("stalled = %+v", de)
			}
		})
	}
}

// A refused token fails the run whatever the run kind: err does not depend on record, which only
// a writing run calls, and a pr-inherit run never does. The message names a curation proxy beside
// an expired or wrong token.
func TestDepCodeRunCredentialRejectedIsRed(t *testing.T) {
	const reg = "https://npm.corp.example/"
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	res := pipeline.DependencyAcquisitionResult{
		Mode:     "fetch",
		Fallback: &pipeline.DependencyCodeCause{Kind: pipeline.UnreadPolicyRefused, Detail: "pkg:npm/@corp/b@1: " + artifactcache.PolicyCredentialRejected},
		Outcomes: []pipeline.DependencyOutcome{
			{PURL: "pkg:npm/@corp/a@1", Registry: reg, Outcome: pipeline.OutcomeReadNetwork},
			{PURL: "pkg:npm/@corp/b@1", Registry: reg, Outcome: pipeline.UnreadPolicyRefused, Detail: artifactcache.PolicyCredentialRejected},
		},
	}
	for _, tc := range []struct {
		name string
		run  *trigger.DependencyFetchRun // nil: the run writes no state
	}{
		{"pr-inherit", nil},
		{"baseline", &trigger.DependencyFetchRun{Baseline: true}},
		{"cve-watch, cursor advanced", &trigger.DependencyFetchRun{}},
		{"cve-watch, cursor held", &trigger.DependencyFetchRun{Held: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := &depCodeRun{source: report.DependencyCodeSourceFetch}
			run.observe(res)
			if run.holds(nil) {
				t.Fatal("a refused token holds the cursor")
			}
			if tc.run != nil {
				run.record(nil, *tc.run, now)
			}
			err := runExit(nil, run)
			var de *depFetchError
			if !errors.As(err, &de) || de.Kind != kindCredentialRejected || de.Registry != reg || de.Detail != "pkg:npm/@corp/b@1" {
				t.Fatalf("err = %v, want credential_rejected for %s", err, reg)
			}
			for _, want := range []string{"credential_rejected", reg, "expired or wrong", "curation proxy", "Artifactory curation", "Nexus firewall"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("message lacks %q: %s", want, err)
				}
			}
		})
	}
}

// No other cause fails the run, and a nil run (not JS) never does.
func TestDepCodeRunOnlyRejectedAndStalledFail(t *testing.T) {
	var none *depCodeRun
	if err := none.err(); err != nil {
		t.Fatalf("nil run err = %v", err)
	}
	for _, outcome := range []pipeline.DependencyOutcome{
		{Outcome: pipeline.UnreadUnavailable},
		{Outcome: pipeline.UnreadUnreachable},
		{Outcome: pipeline.UnreadNotServed},
		{Outcome: pipeline.UnreadIntegrityMismatch},
		{Outcome: pipeline.UnreadCancelled},
		{Outcome: pipeline.UnreadPolicyRefused, Detail: artifactcache.PolicyMissingCredential, UnsetEnv: "NODE_AUTH_TOKEN"},
		{Outcome: pipeline.UnreadPolicyRefused, Detail: artifactcache.PolicyRedirectOffAllowlist},
	} {
		outcome.PURL, outcome.Registry = "pkg:npm/a@1", "https://registry.npmjs.org/"
		run := &depCodeRun{source: report.DependencyCodeSourceFetch}
		run.observe(pipeline.DependencyAcquisitionResult{Mode: "fetch", Fallback: &pipeline.DependencyCodeCause{Kind: outcome.Outcome}, Outcomes: []pipeline.DependencyOutcome{outcome}})
		if err := run.err(); err != nil {
			t.Errorf("%s %s: err = %v, want none", outcome.Outcome, outcome.Detail, err)
		}
	}
}
