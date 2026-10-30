package pipeline

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// workspaceManifestPlugin records the GOWORK each BuildManifest request carried.
type workspaceManifestPlugin struct {
	plugin.StubPlugin
	mu     sync.Mutex
	goWork []string
}

func (*workspaceManifestPlugin) Language() string { return "go" }

func (p *workspaceManifestPlugin) BuildManifest(ctx context.Context, req plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	p.mu.Lock()
	p.goWork = append(p.goWork, req.GoWork)
	p.mu.Unlock()
	return plugin.BuildManifestResult{}, nil
}

// TestCodebaseInventory_GoWorkspace: codebase_inventory records the go.work the build runs under and
// hands that same file to the analyzer; a declared go.work it cannot establish fails the stage, so
// the advisory is withheld rather than assessed under a guessed workspace.
func TestCodebaseInventory_GoWorkspace(t *testing.T) {
	const modA = "module example.com/mono/a\n\ngo 1.22\n"
	const modB = "module example.com/mono/b\n\ngo 1.22\n"
	cases := []struct {
		name     string
		work     string
		declared string
		want     string // go.work relative to the tree, "" for off
		wantErr  bool
	}{
		{"a go.work using the module", "go 1.22\n\nuse (\n\t./a\n\t./b\n)\n", "", "go.work", false},
		{"a go.work not using the module", "go 1.22\n\nuse ./b\n", "", "", false},
		{"declared off over a go.work using the module", "go 1.22\n\nuse (\n\t./a\n\t./b\n)\n", "off", "", false},
		{"declared and missing", "", "/no/such/go.work", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"a/go.mod": modA, "b/go.mod": modB}
			if tc.work != "" {
				files["go.work"] = tc.work
			}
			tree, _ := filepath.EvalSymlinks(writeTree(t, files))
			gitTree(t, tree)
			p := &workspaceManifestPlugin{}
			store := artifact.NewMemStore()
			c := &assessment.Assessment{ID: "case-go-workspace", Request: assessment.Request{
				Vulnerability: assessment.VulnRef{ID: "CVE-TEST-NO-SUCH-ADVISORY", Source: "corpus"},
				Codebase:      assessment.CodebaseRef{Repo: "example.com/mono", Revision: "v1"},
			}}
			stage := codebaseInventory{checkout: dirCheckout{dir: filepath.Join(tree, "a"), lang: "go"}, plugin: p, subjectGoWork: tc.declared}
			err := stage.Run(context.Background(), c, store)
			if tc.wantErr {
				if err == nil {
					t.Fatal("codebase_inventory.Run succeeded under a go.work it cannot establish")
				}
				if arts, _ := store.Query(c.ID, artifact.TypeInventory); len(arts) != 0 {
					t.Fatal("an inventory was recorded under a go.work that could not be established")
				}
				return
			}
			if err != nil {
				t.Fatalf("codebase_inventory.Run: %v", err)
			}
			want := GoWorkspace{}
			if tc.want != "" {
				want.File = filepath.Join(tree, tc.want)
			}
			got, err := InventoryGoWorkspace(store, c.ID)
			if err != nil || got != want {
				t.Fatalf("InventoryGoWorkspace = %+v, %v; want %+v", got, err, want)
			}
			if len(p.goWork) != 1 || p.goWork[0] != want.File {
				t.Fatalf("BuildManifest ran under GOWORK %q, want %q", p.goWork, want.File)
			}
		})
	}
}

// TestCodebaseInventory_GoWorkspaceToolchainFloor: a workspace build runs under the go.work's go and
// toolchain lines and ignores its modules' toolchain lines, so the toolchain floor is the go.work's.
// A member's `toolchain go1.23.4` under a go.work at go 1.22.5 is no floor: that build runs go1.22.5.
func TestCodebaseInventory_GoWorkspaceToolchainFloor(t *testing.T) {
	const modA = "module example.com/mono/a\n\ngo 1.22\n\ntoolchain go1.23.4\n"
	cases := []struct {
		name     string
		work     string
		declared string
		want     ToolchainFact
	}{
		{"the go.work's go line", "go 1.22.5\n\nuse ./a\n", "", ToolchainFact{Version: "go1.22.5", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective}},
		{"the go.work's toolchain line", "go 1.22.5\n\ntoolchain go1.24.1\n\nuse ./a\n", "", ToolchainFact{Version: "go1.24.1", Bound: ToolchainBoundMinimum, Source: ToolchainSourceToolchainDirective}},
		{"a go.work with a go line that does not bind", "go 1.22\n\nuse ./a\n", "", ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved}},
		{"off reads the module's own lines", "go 1.22.5\n\nuse ./a\n", "off", ToolchainFact{Version: "go1.23.4", Bound: ToolchainBoundMinimum, Source: ToolchainSourceToolchainDirective}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, _ := filepath.EvalSymlinks(writeTree(t, map[string]string{"go.work": tc.work, "a/go.mod": modA}))
			gitTree(t, tree)
			stage := codebaseInventory{
				checkout:      dirCheckout{dir: filepath.Join(tree, "a"), lang: "go"},
				plugin:        goManifestPlugin{pinBuildToolchain: true},
				subjectGoWork: tc.declared,
			}
			if got := runRealInventory(t, stage).Toolchain; !toolchainFactEqual(got, tc.want) {
				t.Fatalf("toolchain = %+v, want %+v", got, tc.want)
			}
		})
	}
}
