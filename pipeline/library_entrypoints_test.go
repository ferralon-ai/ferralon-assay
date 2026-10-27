package pipeline

import (
	"context"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestReachability_HandsTheLaneLibraryEntrypoints: the caller's library-entrypoints statement
// reaches the lane's ReachabilityRequest through AssessStages, based at the recorded checkout root,
// and nothing stated sends nil (auto).
func TestReachability_HandsTheLaneLibraryEntrypoints(t *testing.T) {
	declared := plugin.LibraryEntrypoints{Mode: plugin.LibraryEntrypointsPaths, Include: []string{"pkg/api"}}
	based := declared
	based.Base = "/checkout"
	for _, tc := range []struct {
		name string
		opts []AssessOption
		root string
		want *plugin.LibraryEntrypoints
	}{
		{"nothing stated", nil, "/checkout", nil},
		{"declared, no checkout root recorded", []AssessOption{WithLibraryEntrypoints(declared)}, "", &declared},
		{"declared, based at the checkout root", []AssessOption{WithLibraryEntrypoints(declared)}, "/checkout", &based},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var seen plugin.ReachabilityRequest
			p := multiSinkPlugin{seen: &seen}
			var reach Stage
			for _, s := range AssessStages(append([]AssessOption{WithPlugin(p)}, tc.opts...)...) {
				if s.Name() == "reachability_ingress" {
					reach = s
				}
			}
			if reach == nil {
				t.Fatal("no reachability_ingress stage")
			}
			store := artifact.NewMemStore()
			c := &assessment.Assessment{ID: "case-entry"}
			c.Request.Vulnerability = assessment.VulnRef{ID: "FERRALON-APP-SSRF-0001", Source: "osv"}
			if tc.root != "" {
				putJSON(t, store, c.ID, artifact.TypeInventory, map[string]any{"build_dir": "/checkout/svc", "checkout_root": tc.root})
			}
			if err := (symbolMapping{plugin: p}).Run(context.Background(), c, store); err != nil {
				t.Fatalf("symbol_mapping: %v", err)
			}
			if err := reach.Run(context.Background(), c, store); err != nil {
				t.Fatalf("reachability_ingress: %v", err)
			}
			if !reflect.DeepEqual(seen.LibraryEntrypoints, tc.want) {
				t.Errorf("ReachabilityRequest.LibraryEntrypoints = %+v, want %+v", seen.LibraryEntrypoints, tc.want)
			}
		})
	}
}
