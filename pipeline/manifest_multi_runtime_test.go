// manifest_multi_runtime_test.go
//
// Table-driven proof that codebase_inventory's build-manifest fold goes through PrimaryRuntime/
// PrimaryResolver, not an arbitrary element: a manifest with more than one runtime (a C-family-shaped
// manifest with no privileged element) must leave go_version/build_command empty, while the live
// single-runtime Go path (exactly what goanalysis.BuildManifest emits from a go.mod) is unaffected
// and still flows the ToolchainFact.
package pipeline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// multiRuntimePlugin's BuildManifest returns two runtimes and two resolvers with none privileged,
// so PrimaryRuntime/PrimaryResolver must report false.
type multiRuntimePlugin struct{ plugin.StubPlugin }

func (multiRuntimePlugin) Language() string { return "go" }

func (multiRuntimePlugin) BuildManifest(_ context.Context, _ plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	return plugin.BuildManifestResult{
		Partiality: plugin.Complete(),
		Runtimes: []plugin.RuntimeSpec{
			{Name: "c", Lang: "c", Target: "x86_64-linux-gnu", Source: plugin.RuntimeSourceCompileDB},
			{Name: "c", Lang: "c++", Target: "arm64-apple-darwin", Source: plugin.RuntimeSourceCompileDB},
		},
		Resolvers: []plugin.ResolverSpec{
			{Name: "cmake", Command: "cmake --build build", Source: plugin.RuntimeSourceDeclared},
			{Name: "make", Command: "make", Source: plugin.RuntimeSourceDeclared},
		},
	}, nil
}

func TestCodebaseInventory_BuildManifestFoldsOnPrimaryOnly(t *testing.T) {
	cases := []struct {
		name          string
		buildStage    func(t *testing.T) codebaseInventory
		wantGoVersion bool
		wantBuildCmd  bool
	}{
		{
			name: "multi-runtime manifest leaves go_version/build_command empty",
			buildStage: func(t *testing.T) codebaseInventory {
				return codebaseInventory{checkout: dirCheckout{dir: writeEmptyGoMod(t), lang: "go"}, plugin: multiRuntimePlugin{}}
			},
			wantGoVersion: false,
			wantBuildCmd:  false,
		},
		{
			name: "single Go runtime still folds go_version/build_command",
			buildStage: func(t *testing.T) codebaseInventory {
				dir := writeGoModFixture(t, "module example.com/target\n\ngo 1.21.0\n")
				return codebaseInventory{checkout: dirCheckout{dir: dir, lang: "go"}, plugin: goManifestPlugin{}}
			},
			wantGoVersion: true,
			wantBuildCmd:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			c := &assessment.Assessment{ID: "case-multi-runtime", Request: assessment.Request{
				Codebase: assessment.CodebaseRef{
					Repo: "example.com/target", Revision: "v1",
					Acquisition: assessment.Acquisition{Mode: "git"},
				},
			}}
			stage := tc.buildStage(t)
			if err := stage.Run(context.Background(), c, store); err != nil {
				t.Fatalf("codebase_inventory.Run: %v", err)
			}
			arts, err := store.Query(c.ID, artifact.TypeInventory)
			if err != nil || len(arts) == 0 {
				t.Fatalf("no inventory artifact: %v", err)
			}
			var inv struct {
				GoVersion    string        `json:"go_version"`
				BuildCommand string        `json:"build_command"`
				Toolchain    ToolchainFact `json:"toolchain"`
			}
			if jerr := json.Unmarshal(arts[0].Payload, &inv); jerr != nil {
				t.Fatalf("decode inventory: %v", jerr)
			}
			if gotSet := inv.GoVersion != ""; gotSet != tc.wantGoVersion {
				t.Errorf("go_version set = %v (%q), want %v", gotSet, inv.GoVersion, tc.wantGoVersion)
			}
			if gotSet := inv.BuildCommand != ""; gotSet != tc.wantBuildCmd {
				t.Errorf("build_command set = %v (%q), want %v", gotSet, inv.BuildCommand, tc.wantBuildCmd)
			}
			if tc.wantGoVersion && inv.Toolchain.Bound != ToolchainBoundMinimum {
				t.Errorf("single-runtime Go case: ToolchainFact must still resolve from the go.mod directive, got Bound=%q", inv.Toolchain.Bound)
			}
		})
	}
}
