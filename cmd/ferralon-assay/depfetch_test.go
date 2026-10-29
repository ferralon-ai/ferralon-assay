package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// The dependency-code hold is decided by fetches the re-assessments make, so cve-watch must read
// it when RunCVEWatch consults Hold, not when the request is built: a fallback observed after the
// request exists holds through Hold, and HoldCursor, fixed at construction, cannot see it. With
// today's policy a fallback holds nothing.
func TestCVEWatchRequestHoldReadsTheFetchAfterAssessment(t *testing.T) {
	fell := pipeline.DependencyAcquisitionResult{Mode: "fetch", Fallback: &pipeline.DependencyCodeCause{Kind: pipeline.UnreadNotServed}}
	for _, tc := range []struct {
		name     string
		failsRun bool
		want     bool
	}{
		{"policy fails the run", true, true},
		{"policy today", fetchFailureFailsRun, fetchFailureFailsRun},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := &depCodeRun{source: report.DependencyCodeSourceFetch, failsRun: tc.failsRun}
			req := cveWatchRequest(&runConfig{deps: run}, nil)
			if req.HoldCursor || req.Hold == nil || req.Hold() {
				t.Fatalf("before any fetch: HoldCursor %v, Hold set %v; want neither holding", req.HoldCursor, req.Hold != nil)
			}
			run.observe(fell)
			if got := req.Hold(); got != tc.want {
				t.Fatalf("Hold() after a fallback = %v, want %v", got, tc.want)
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
	watch := func(held bool, ids ...string) trigger.DependencyFetchRun {
		return trigger.DependencyFetchRun{Held: held, Assessed: ids}
	}
	baseline := func(ids ...string) trigger.DependencyFetchRun {
		return trigger.DependencyFetchRun{Baseline: true, Assessed: ids}
	}
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
			name:    "a held run with every fetch failing counts and stamps the first",
			results: []pipeline.DependencyAcquisitionResult{{Fallback: fell, Outcomes: []pipeline.DependencyOutcome{out("pkg:npm/a@1", npmjs, pipeline.UnreadNotServed)}}},
			run:     watch(true),
			want:    &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HeldRuns: 1, FirstHeldAt: now}}},
		},
		{
			name:    "a later held run counts and keeps the first time",
			prior:   &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HasServed: true, HeldRuns: 1, FirstHeldAt: earlier}}},
			results: []pipeline.DependencyAcquisitionResult{{Fallback: fell, Outcomes: []pipeline.DependencyOutcome{out("pkg:npm/a@1", npmjs, pipeline.UnreadUnreachable)}}},
			run:     watch(true),
			want:    &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HasServed: true, HeldRuns: 2, FirstHeldAt: earlier}}},
		},
		{
			name:    "a run that advanced does not count",
			prior:   &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{npmjs: {HeldRuns: 1, FirstHeldAt: earlier}}},
			results: []pipeline.DependencyAcquisitionResult{{Fallback: fell, Outcomes: []pipeline.DependencyOutcome{out("pkg:npm/a@1", npmjs, pipeline.UnreadNotServed)}}},
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
				out("pkg:npm/b@1", corp, pipeline.UnreadPolicyRefused),
				out("pkg:npm/c@1", "", pipeline.UnreadNoIntegrity),
				out("pkg:npm/d@1", "https://other.example/", pipeline.UnreadNoIntegrity),
			}}},
			run: watch(true),
			want: &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{
				npmjs: {HasServed: true}, corp: {HeldRuns: 1, FirstHeldAt: now}, "https://other.example/": {},
			}},
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
