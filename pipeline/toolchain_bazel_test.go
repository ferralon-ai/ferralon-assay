// toolchain_bazel_test.go
//
// Inside a Bazel workspace rules_go compiles with the SDK the workspace declares, so go.mod's
// directives floor nothing there.
package pipeline

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/gittest"
)

// gitInitRepo makes dir a git repository with one empty commit, the top-level BazelWorkspaceAbove
// bounds its search at; the commit keeps a checkout that resolves HEAD working.
func gitInitRepo(t *testing.T, dir string) {
	t.Helper()
	for _, args := range [][]string{
		{"init", "-q"},
		{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "init"},
	} {
		cmd := gittest.Command(args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

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
			name: "a workspace with a toolchain line takes no floor",
			in:   toolchainInputs{goDirective: "1.21.0", toolchainDirective: "go1.22.4", bazelWorkspace: true},
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

// TestResolveToolchainFloor_BazelIsNoBindingGoLine: a Bazel workspace yields exactly what a go line
// that does not bind yields, in all three results, so no caller can read a bound into it.
func TestResolveToolchainFloor_BazelIsNoBindingGoLine(t *testing.T) {
	tests := []struct {
		name  string
		bazel toolchainInputs
	}{
		{"go line only", toolchainInputs{goDirective: "1.22.0", bazelWorkspace: true}},
		{"go line and toolchain line", toolchainInputs{goDirective: "1.22.0", toolchainDirective: "go1.22.4", bazelWorkspace: true}},
		{"toolchain line only", toolchainInputs{toolchainDirective: "go1.22.4", bazelWorkspace: true}},
	}
	// "1.22" is a bare go line with no toolchain line: it does not bind (directivesBindToolchain).
	unbound := toolchainInputs{goDirective: "1.22"}
	wantFact, wantParsed, wantOK := resolveToolchainFloor(unbound)
	if wantOK {
		t.Fatalf("fixture: %+v unexpectedly resolves a floor", unbound)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fact, parsed, ok := resolveToolchainFloor(tc.bazel)
			if !reflect.DeepEqual(fact, wantFact) || !reflect.DeepEqual(parsed, wantParsed) || ok != wantOK {
				t.Errorf("resolveToolchainFloor(%+v) = (%+v, %+v, %v), want (%+v, %+v, %v)",
					tc.bazel, fact, parsed, ok, wantFact, wantParsed, wantOK)
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
			// The search stops at the git top-level: the workspace is inside it, or is it.
			gitInitRepo(t, workspace)
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

// TestCodebaseInventory_BazelMarkerAboveTopLevel: a marker above the repository's top-level is no
// workspace of the subject, so the go line stays a floor and the contradiction guard still refutes
// an exact claim below it.
func TestCodebaseInventory_BazelMarkerAboveTopLevel(t *testing.T) {
	buildDir := writeGoModFixture(t, "module example.com/target\n\ngo 1.22.0\n")
	gitInitRepo(t, buildDir)
	if err := os.WriteFile(filepath.Join(filepath.Dir(buildDir), "MODULE.bazel"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	inv := runRealInventory(t, codebaseInventory{
		checkout:         dirCheckout{dir: buildDir, lang: "go"},
		plugin:           goManifestPlugin{},
		subjectGoVersion: "go1.21.13",
	})
	if inv.Toolchain.Bound == ToolchainBoundExact {
		t.Errorf("toolchain = %+v, want the claim below the go line refuted, not exact", inv.Toolchain)
	}
	if inv.Toolchain.Contradiction == nil {
		t.Errorf("toolchain = %+v, want a recorded contradiction", inv.Toolchain)
	}
	if inv.GoFloor == "" {
		t.Errorf("go_floor empty, want the go line's floor")
	}
}
