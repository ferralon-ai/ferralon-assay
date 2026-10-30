// toolchain_bazel_test.go
//
// Inside a Bazel workspace rules_go compiles with the SDK the workspace declares, so go.mod's
// directives floor nothing there.
package pipeline

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveToolchainFact_Bazel: inside a Bazel workspace neither directive floors the SDK.
func TestResolveToolchainFact_Bazel(t *testing.T) {
	tests := []struct {
		name string
		in   toolchainInputs
		want ToolchainFact
	}{
		{
			// tracker#610: go_sdk.download(version = "1.21.13") beside `go 1.22.0`.
			name: "a workspace takes no floor",
			in:   toolchainInputs{goDirective: "1.22.0", bazelWorkspace: true},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "a workspace drops the toolchain line too",
			in:   toolchainInputs{goDirective: "1.22.0", toolchainDirective: "go1.22.4", bazelWorkspace: true},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "a workspace refutes no exact claim",
			in:   toolchainInputs{subjectDeclared: "go1.21.13", goDirective: "1.22.0", bazelWorkspace: true},
			want: ToolchainFact{Version: "go1.21.13", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
		},
		{
			name: "a workspace takes no exact bound from the host go command",
			in:   toolchainInputs{goDirective: "1.22", buildResolved: "go1.23.4", trustCIObserved: true, bazelWorkspace: true},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveToolchainFact(tc.in); !toolchainFactEqual(got, tc.want) {
				t.Errorf("resolveToolchainFact(%+v) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

// TestCodebaseInventory_BazelWorkspaceFloor runs tracker#610's scenario through the real stage: a
// go.mod beside a MODULE.bazel resolves no floor, whichever SDK declaration the module makes, and
// so does one whose checkout is a subdirectory of the workspace (an Action `target:` in a monorepo).
func TestCodebaseInventory_BazelWorkspaceFloor(t *testing.T) {
	tests := []struct {
		name   string
		module string
		above  bool // MODULE.bazel sits in the directory above the checkout
		want   ToolchainFact
	}{
		{
			name: "go_sdk.download",
			module: `go_sdk = use_extension("@rules_go//go:extensions.bzl", "go_sdk")
go_sdk.download(version = "1.21.13")
`,
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "go_sdk.from_file",
			module: `go_sdk = use_extension("@rules_go//go:extensions.bzl", "go_sdk")
go_sdk.from_file(go_mod = "//:go.mod")
`,
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "workspace above the checkout",
			module: `go_sdk = use_extension("@rules_go//go:extensions.bzl", "go_sdk")
go_sdk.download(version = "1.21.13")
`,
			above: true,
			want:  ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buildDir := writeGoModFixture(t, "module example.com/target\n\ngo 1.22.0\n")
			workspace := buildDir
			if tc.above {
				workspace = filepath.Dir(buildDir)
			}
			if err := os.WriteFile(filepath.Join(workspace, "MODULE.bazel"), []byte(tc.module), 0o644); err != nil {
				t.Fatal(err)
			}
			inv := runRealInventory(t, codebaseInventory{
				checkout: dirCheckout{dir: buildDir, lang: "go"},
				plugin:   goManifestPlugin{},
			})
			if !toolchainFactEqual(inv.Toolchain, tc.want) {
				t.Errorf("toolchain = %+v, want %+v", inv.Toolchain, tc.want)
			}
		})
	}
}
