package pipeline

import (
	"context"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// laneStubPlugin is the capturing stub plugin of a chosen language.
type laneStubPlugin struct {
	multiSinkPlugin
	lang string
}

func (p laneStubPlugin) Language() string { return p.lang }

// laneRequest runs reachability_ingress for a plugin of language lang under opts and returns the
// request the plugin saw.
func laneRequest(t *testing.T, lang string, opts ...AssessOption) plugin.ReachabilityRequest {
	t.Helper()
	var seen plugin.ReachabilityRequest
	p := laneStubPlugin{multiSinkPlugin: multiSinkPlugin{seen: &seen}, lang: lang}
	var reach Stage
	for _, s := range AssessStages(append([]AssessOption{WithPlugin(p)}, opts...)...) {
		if s.Name() == "reachability_ingress" {
			reach = s
		}
	}
	if reach == nil {
		t.Fatal("no reachability_ingress stage")
	}
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-entry-override"}
	c.Request.Vulnerability = assessment.VulnRef{ID: "FERRALON-APP-SSRF-0001", Source: "osv"}
	putJSON(t, store, c.ID, artifact.TypeInventory, map[string]any{"build_dir": "/checkout/svc", "checkout_root": "/checkout"})
	if err := (symbolMapping{plugin: p}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("symbol_mapping: %v", err)
	}
	if err := reach.Run(context.Background(), c, store); err != nil {
		t.Fatalf("reachability_ingress: %v", err)
	}
	return seen
}

// TestReachability_HandsTheJSEntryOverrideToTheLane: the js lane's request carries the routed
// override of a removing input, and no other plugin's request does.
func TestReachability_HandsTheJSEntryOverrideToTheLane(t *testing.T) {
	removing := mustOverrides(t, "!js:bin=bin:storybook")
	cases := []struct {
		name string
		lang string
		in   map[string]plugin.EntryOverride
		want *plugin.EntryOverride
	}{
		{name: "js lane, removing input", lang: "js", in: removing, want: JSEntryOverride(removing)},
		{name: "js lane, auto", lang: "js", in: mustOverrides(t, "auto")},
		{name: "js lane, nothing stated", lang: "js"},
		{name: "js lane, go-only input", lang: "js", in: mustOverrides(t, "go:library=pkg/api")},
		{name: "go lane, removing input", lang: "go", in: removing},
		{name: "java lane, removing input", lang: "java", in: removing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := laneRequest(t, tc.lang, WithEntrypoints(tc.in)).EntryOverride
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("request EntryOverride = %+v, want %+v", got, tc.want)
			}
		})
	}
	if JSEntryOverride(removing) == nil {
		t.Fatal("the removing input routes to no js override")
	}
}
