// bazel_sdk_test.go
//
// The Bazel SDK binding: only a root MODULE.bazel whose one SDK declaration is
// go_sdk.from_file(go_mod = <this module's go.mod>) keeps a go.mod floor; every other workspace,
// and every spelling this does not read, takes none.
package pipeline

import (
	"os"
	"path/filepath"
	"testing"
)

const fromFileModule = `bazel_dep(name = "rules_go", version = "0.65.0")

go_sdk = use_extension("@rules_go//go:extensions.bzl", "go_sdk")
go_sdk.from_file(go_mod = "//svc:go.mod")
`

func TestResolveBazelSDK(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string // path relative to the checkout root → content
		want  bazelSDKBinding
	}{
		{"no workspace", nil, bazelSDKNone},
		{"marker above the checkout root is not ours", map[string]string{"../MODULE.bazel": fromFileModule}, bazelSDKNone},
		{"from_file naming this go.mod", map[string]string{"MODULE.bazel": fromFileModule}, bazelSDKFromGoMod},
		{"from_file in the module root's own workspace", map[string]string{"svc/MODULE.bazel": `go_sdk = use_extension("@rules_go//go:extensions.bzl", "go_sdk")
go_sdk.from_file(go_mod = "//:go.mod")
`}, bazelSDKFromGoMod},
		{"from_file with a name, @@ label, io_bazel_rules_go, nogo, a comment", map[string]string{"MODULE.bazel": `# go_sdk.download(version = "1.21.13")
sdk = use_extension("@io_bazel_rules_go//go:extensions.bzl", "go_sdk", dev_dependency = True)
sdk.from_file(name = "go_sdk", go_mod = "@@//svc:go.mod")  # pinned to go.mod
sdk.nogo(nogo = "//:nogo")
use_repo(sdk, "go_toolchains")
`}, bazelSDKFromGoMod},
		{"an empty WORKSPACE beside it", map[string]string{"MODULE.bazel": fromFileModule, "WORKSPACE": "# bzlmod only\n"}, bazelSDKFromGoMod},

		{"go_sdk.download", map[string]string{"MODULE.bazel": `go_sdk = use_extension("@rules_go//go:extensions.bzl", "go_sdk")
go_sdk.download(version = "1.21.13")
`}, bazelSDKUnbound},
		{"from_file plus a download", map[string]string{"MODULE.bazel": fromFileModule + `go_sdk.download(version = "1.21.13")
`}, bazelSDKUnbound},
		{"go_sdk.host", map[string]string{"MODULE.bazel": `go_sdk = use_extension("@rules_go//go:extensions.bzl", "go_sdk")
go_sdk.host()
`}, bazelSDKUnbound},
		{"from_file naming another go.mod", map[string]string{"MODULE.bazel": `go_sdk = use_extension("@rules_go//go:extensions.bzl", "go_sdk")
go_sdk.from_file(go_mod = "//tools:go.mod")
`}, bazelSDKUnbound},
		{"from_file on go.work", map[string]string{"MODULE.bazel": `go_sdk = use_extension("@rules_go//go:extensions.bzl", "go_sdk")
go_sdk.from_file(go_work = "//:go.work")
`}, bazelSDKUnbound},
		{"from_file for one platform", map[string]string{"MODULE.bazel": `go_sdk = use_extension("@rules_go//go:extensions.bzl", "go_sdk")
go_sdk.from_file(go_mod = "//svc:go.mod", goos = "linux", goarch = "amd64")
`}, bazelSDKUnbound},
		{"from_file label not a literal", map[string]string{"MODULE.bazel": `go_sdk = use_extension("@rules_go//go:extensions.bzl", "go_sdk")
go_sdk.from_file(go_mod = Label("//svc:go.mod"))
`}, bazelSDKUnbound},
		{"a second go_sdk binding with a download", map[string]string{"MODULE.bazel": fromFileModule + `dev = use_extension("@rules_go//go:extensions.bzl", "go_sdk", dev_dependency = True)
dev.download(version = "1.21.13")
`}, bazelSDKUnbound},
		{"a go_sdk binding split over lines", map[string]string{"MODULE.bazel": `go_sdk = use_extension(
    "@rules_go//go:extensions.bzl",
    "go_sdk",
)
go_sdk.from_file(go_mod = "//svc:go.mod")
`}, bazelSDKFromGoMod},
		{"a go_sdk binding not recognized", map[string]string{"MODULE.bazel": fromFileModule + `ext = use_extension(RULES_GO + "//go:extensions.bzl", "go_sdk")
ext.download(version = "1.21.13")
`}, bazelSDKUnbound},
		{"a go_sdk binding through a variable label", map[string]string{"MODULE.bazel": fromFileModule + `ext = use_extension(GO_EXTENSIONS, "go_sdk")
ext.download(version = "1.21.13")
`}, bazelSDKUnbound},
		{"rules_go's extensions.bzl bound to another name", map[string]string{"MODULE.bazel": fromFileModule + `ext = use_extension("@rules_go//go:extensions.bzl", SDK)
ext.download(version = "1.21.13")
`}, bazelSDKUnbound},
		{"include()", map[string]string{"MODULE.bazel": fromFileModule + `include("//:go.MODULE.bazel")
`}, bazelSDKUnbound},
		{"no SDK declaration takes rules_go's default", map[string]string{"MODULE.bazel": `bazel_dep(name = "rules_go", version = "0.65.0")
`}, bazelSDKUnbound},
		{"a WORKSPACE with content beside it", map[string]string{"MODULE.bazel": fromFileModule, "WORKSPACE": `go_register_toolchains(version = "1.21.13")
`}, bazelSDKUnbound},
		{"a WORKSPACE.bzlmod with content beside it", map[string]string{"MODULE.bazel": fromFileModule, "WORKSPACE.bzlmod": `load("//:deps.bzl", "deps")
`}, bazelSDKUnbound},
		{"WORKSPACE only", map[string]string{"WORKSPACE": ""}, bazelSDKUnbound},
		{"WORKSPACE.bazel only", map[string]string{"WORKSPACE.bazel": ""}, bazelSDKUnbound},
		{"two workspaces", map[string]string{"MODULE.bazel": fromFileModule, "svc/MODULE.bazel": `go_sdk = use_extension("@rules_go//go:extensions.bzl", "go_sdk")
go_sdk.from_file(go_mod = "//:go.mod")
`}, bazelSDKUnbound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkoutRoot := filepath.Join(t.TempDir(), "checkout")
			moduleRoot := filepath.Join(checkoutRoot, "svc")
			if err := os.MkdirAll(moduleRoot, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(moduleRoot, "go.mod"), []byte("module example.com/svc\n\ngo 1.22.0\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			for path, content := range tc.files {
				if err := os.WriteFile(filepath.Join(checkoutRoot, path), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got := resolveBazelSDK(moduleRoot, checkoutRoot); got != tc.want {
				t.Errorf("resolveBazelSDK = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestResolveToolchainFact_Bazel: inside a Bazel workspace the directives floor the SDK only through
// from_file, and then as rules_go reads them (the toolchain line, else the go line), not by maximum.
func TestResolveToolchainFact_Bazel(t *testing.T) {
	tests := []struct {
		name string
		in   toolchainInputs
		want ToolchainFact
	}{
		{
			// tracker#610: go_sdk.download(version = "1.21.13") beside `go 1.22.0`.
			name: "unbound workspace takes no floor",
			in:   toolchainInputs{goDirective: "1.22.0", bazel: bazelSDKUnbound},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "unbound workspace drops the toolchain line too",
			in:   toolchainInputs{goDirective: "1.22.0", toolchainDirective: "go1.22.4", bazel: bazelSDKUnbound},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "unbound workspace refutes no exact claim",
			in:   toolchainInputs{subjectDeclared: "go1.21.13", goDirective: "1.22.0", bazel: bazelSDKUnbound},
			want: ToolchainFact{Version: "go1.21.13", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
		},
		{
			name: "from_file floors at the go line",
			in:   toolchainInputs{goDirective: "1.22.0", bazel: bazelSDKFromGoMod},
			want: ToolchainFact{Version: "go1.22.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
		},
		{
			name: "from_file floors at the toolchain line when there is one",
			in:   toolchainInputs{goDirective: "1.22.0", toolchainDirective: "go1.22.4", bazel: bazelSDKFromGoMod},
			want: ToolchainFact{Version: "go1.22.4", Bound: ToolchainBoundMinimum, Source: ToolchainSourceToolchainDirective},
		},
		{
			name: "from_file takes a toolchain line below the go line, not the maximum",
			in:   toolchainInputs{goDirective: "1.23.0", toolchainDirective: "go1.22.4", bazel: bazelSDKFromGoMod},
			want: ToolchainFact{Version: "go1.22.4", Bound: ToolchainBoundMinimum, Source: ToolchainSourceToolchainDirective},
		},
		{
			name: "from_file reads a two-part go line",
			in:   toolchainInputs{goDirective: "1.22", bazel: bazelSDKFromGoMod},
			want: ToolchainFact{Version: "go1.22.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
		},
		{
			name: "from_file with no directive resolves nothing",
			in:   toolchainInputs{bazel: bazelSDKFromGoMod},
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

// TestCodebaseInventory_BazelWorkspaceFloor runs tracker#610's scenario through the real stage: the
// same go.mod floors the version axis beside a from_file MODULE.bazel and resolves nothing beside a
// download one.
func TestCodebaseInventory_BazelWorkspaceFloor(t *testing.T) {
	tests := []struct {
		name   string
		module string
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
			want: ToolchainFact{Version: "go1.22.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buildDir := writeGoModFixture(t, "module example.com/target\n\ngo 1.22.0\n")
			if err := os.WriteFile(filepath.Join(buildDir, "MODULE.bazel"), []byte(tc.module), 0o644); err != nil {
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
