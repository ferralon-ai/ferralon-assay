package pipeline

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// targetEnvRecorder is a java LanguagePlugin that records the inventory request it receives.
type targetEnvRecorder struct {
	plugin.StubPlugin
	got *plugin.ResolveInventoryRequest
}

func (targetEnvRecorder) Language() string { return "java" }

func (r targetEnvRecorder) ResolveInventory(_ context.Context, req plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	*r.got = req
	return plugin.DependencyInventory{Partiality: plugin.Complete()}, nil
}

func TestResolveCodebaseInventory_SubjectJavaVersionReachesTargetEnv(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"pom.xml":                  `<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>`,
		"src/main/java/g/App.java": "package g; class App {}",
	} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	codebase := assessment.CodebaseRef{Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: dir}}

	tests := []struct {
		name string
		opts []AssessOption
		want map[string]string
	}{
		{"not provided", nil, nil},
		{"provided", []AssessOption{WithSubjectJavaVersion("17.0.12")}, map[string]string{"java.version": "17.0.12"}},
		{"profiles only", []AssessOption{WithSubjectMavenProfiles("release,!docs")}, map[string]string{"maven.profiles": "release,!docs"}},
		{"both", []AssessOption{WithSubjectJavaVersion("17"), WithSubjectMavenProfiles(",")}, map[string]string{"java.version": "17", "maven.profiles": ","}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got plugin.ResolveInventoryRequest
			opts := append([]AssessOption{WithPlugin(targetEnvRecorder{got: &got})}, tt.opts...)
			if _, lang, _, err := ResolveCodebaseInventory(context.Background(), codebase, "", opts...); err != nil || lang != "java" {
				t.Fatalf("ResolveCodebaseInventory: lang %q err %v", lang, err)
			}
			if len(got.TargetEnv) != len(tt.want) || got.TargetEnv["java.version"] != tt.want["java.version"] || got.TargetEnv["maven.profiles"] != tt.want["maven.profiles"] {
				t.Errorf("TargetEnv = %v, want %v", got.TargetEnv, tt.want)
			}
		})
	}
}

// runConditionRecorder records the symbol and reachability requests it receives.
type runConditionRecorder struct {
	firstPartyStubPlugin
	sym   *plugin.ResolveSymbolsRequest
	reach *plugin.ReachabilityRequest
}

func (r runConditionRecorder) ResolveDependencySymbols(ctx context.Context, req plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	*r.sym = req
	return r.firstPartyStubPlugin.ResolveDependencySymbols(ctx, req)
}

func (r runConditionRecorder) Reachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	*r.reach = req
	return r.firstPartyStubPlugin.Reachability(ctx, req)
}

// The stages that resolve the inventory again to build their search space are handed the same
// stated conditions as codebase_inventory, so one run never answers under two.
func TestAssessStages_SubjectConditionsReachAnalysisRequests(t *testing.T) {
	tests := []struct {
		name string
		opts []AssessOption
		want map[string]string
	}{
		{"not provided", nil, nil},
		{"java version only", []AssessOption{WithSubjectJavaVersion("17")}, map[string]string{"java.version": "17"}},
		{"both", []AssessOption{WithSubjectJavaVersion("17"), WithSubjectMavenProfiles(",")}, map[string]string{"java.version": "17", "maven.profiles": ","}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sym plugin.ResolveSymbolsRequest
			var reach plugin.ReachabilityRequest
			rec := runConditionRecorder{
				firstPartyStubPlugin: firstPartyStubPlugin{sink: "scip:app#sink", ingress: "scip:app#sink"},
				sym:                  &sym,
				reach:                &reach,
			}
			store := artifact.NewMemStore()
			c := &assessment.Assessment{ID: "case-env"}
			c.Request.Vulnerability = assessment.VulnRef{ID: "FERRALON-APP-SSRF-0001", Source: "osv"}
			ran := 0
			for _, st := range AssessStages(append([]AssessOption{WithPlugin(rec)}, tt.opts...)...) {
				switch st.(type) {
				case symbolMapping, reachabilityIngress:
					if err := st.Run(context.Background(), c, store); err != nil {
						t.Fatalf("%s: %v", st.Name(), err)
					}
					ran++
				}
			}
			if ran != 2 {
				t.Fatalf("ran %d analysis stages, want 2", ran)
			}
			if !maps.Equal(sym.TargetEnv, tt.want) || (sym.TargetEnv == nil) != (tt.want == nil) {
				t.Errorf("symbol request TargetEnv = %v, want %v", sym.TargetEnv, tt.want)
			}
			if !maps.Equal(reach.TargetEnv, tt.want) || (reach.TargetEnv == nil) != (tt.want == nil) {
				t.Errorf("reachability request TargetEnv = %v, want %v", reach.TargetEnv, tt.want)
			}
		})
	}
}
