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
		{"from_file with a name, @@ label, io_bazel_rules_go, nogo, use_repo, go_toolchains", map[string]string{"MODULE.bazel": `sdk = use_extension("@io_bazel_rules_go//go:extensions.bzl", "go_sdk")
sdk.from_file(name = "go_sdk", go_mod = "@@//svc:go.mod")  # pinned to go.mod
sdk.nogo(nogo = "//:nogo")
use_repo(sdk, "go_toolchains")
register_toolchains("@go_toolchains//:all")
`}, bazelSDKFromGoMod},
		{"the binding's name inside a string", map[string]string{"MODULE.bazel": `go_sdk = use_extension("@rules_go//go:extensions.bzl", "go_sdk")
go_sdk.from_file(name = "go_sdk", go_mod = "//svc:go.mod")
`}, bazelSDKFromGoMod},
		{"a commented-out download", map[string]string{"MODULE.bazel": fromFileModule + `# go_sdk.download(version = "1.21.13")
`}, bazelSDKFromGoMod},
		{"an empty WORKSPACE beside it", map[string]string{"MODULE.bazel": fromFileModule, "WORKSPACE": "# bzlmod only\n"}, bazelSDKFromGoMod},
		{"a .bazelrc with other flags and a missing try-import", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": `# CI
build --jobs=8
try-import %workspace%/user.bazelrc
`}, bazelSDKFromGoMod},
		{"a .bazelrc setting an Apple SDK version", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": `build --macos_sdk_version=14.0
`}, bazelSDKFromGoMod},
		{"a .bazelrc word that is not an import verb", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": `future-import %workspace%/ci.bazelrc
`, "ci.bazelrc": `build --extra_toolchains=//toolchains:go
`}, bazelSDKFromGoMod},
		{"a .bazelrc import with a trailing comment", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": `import %workspace%/ci.bazelrc # CI only
`, "ci.bazelrc": `build --jobs=8
`}, bazelSDKFromGoMod},
		{"a .bazelrc tab-separated try-import of a missing file", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": "try-import\t%workspace%/user.bazelrc\n"}, bazelSDKFromGoMod},
		{"a .bazelrc setting rules_go and dependency build settings", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": `build --@rules_go//go/config:pure --@aspect_rules_lint//lint:fail_on_violation
`}, bazelSDKFromGoMod},
		{"a .bazeliskrc without a wrapper directory", map[string]string{"MODULE.bazel": fromFileModule, ".bazeliskrc": "USE_BAZEL_VERSION=9.3.1\n"}, bazelSDKFromGoMod},
		{"a docstring with a quote in it", map[string]string{"MODULE.bazel": `"""Module for svc; "go_sdk" pins the "SDK"."""
` + fromFileModule}, bazelSDKFromGoMod},

		{"a dev_dependency binding", map[string]string{"MODULE.bazel": `go_sdk = use_extension("@rules_go//go:extensions.bzl", "go_sdk", dev_dependency = True)
go_sdk.from_file(go_mod = "//svc:go.mod")
`}, bazelSDKUnbound},
		{"an isolated binding", map[string]string{"MODULE.bazel": `go_sdk = use_extension("@rules_go//go:extensions.bzl", "go_sdk", isolate = True)
go_sdk.from_file(go_mod = "//svc:go.mod")
use_repo(go_sdk, "go_toolchains")
`}, bazelSDKUnbound},
		{"an alias carrying a second from_file", map[string]string{"MODULE.bazel": fromFileModule + `pinned = go_sdk
pinned.from_file(name = "pinned_sdk", go_mod = "//tools:go.mod")
`}, bazelSDKUnbound},
		{"a tag this cannot read", map[string]string{"MODULE.bazel": fromFileModule + `go_sdk.wrap(root_file = Label("@local_go//:ROOT"))
`}, bazelSDKUnbound},
		{"another register_toolchains", map[string]string{"MODULE.bazel": fromFileModule + `register_toolchains("//toolchains:all")
`}, bazelSDKUnbound},
		{"a .bazelrc selecting an sdk_version", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": `build --@rules_go//go/toolchain:sdk_version=1.26.7
`}, bazelSDKUnbound},
		{"a .bazelrc importing extra_toolchains", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": `import %workspace%/tools/ci.bazelrc
`, "tools/ci.bazelrc": `build:ci --extra_toolchains=//toolchains:go
`}, bazelSDKUnbound},
		{"a .bazelrc selecting an sdk_name", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": `build --@rules_go//go/toolchain:sdk_name=go_default_sdk
`}, bazelSDKUnbound},
		{"a .bazelrc flag continued over lines", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": "build --@rules_go//go/toolchain:sdk_\\\nversion=1.26.7\n"}, bazelSDKUnbound},
		{"a .bazelrc try-import-if-bazel-version", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": `try-import-if-bazel-version >=8.0.0 %workspace%/ci.bazelrc
`, "ci.bazelrc": `build --@rules_go//go/toolchain:sdk_version=1.26.7
`}, bazelSDKUnbound},
		{"a .bazelrc import after a tab", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": "import\t%workspace%/ci.bazelrc\n", "ci.bazelrc": `build --extra_toolchains=//toolchains:go
`}, bazelSDKUnbound},
		{"a tools/bazel wrapper", map[string]string{"MODULE.bazel": fromFileModule, "tools/bazel": "#!/bin/sh\nexec \"$BAZEL_REAL\" \"$@\"\n"}, bazelSDKUnbound},
		{"register_toolchains with a space", map[string]string{"MODULE.bazel": fromFileModule + `register_toolchains ("//toolchains:all")
`}, bazelSDKUnbound},
		{"include with a space", map[string]string{"MODULE.bazel": fromFileModule + `include ("//:go.MODULE.bazel")
`}, bazelSDKUnbound},
		{"an alias after a docstring with an odd quote", map[string]string{"MODULE.bazel": fromFileModule + `DOC = """a "quote"""
pinned = go_sdk
pinned.from_file(name = "pinned_sdk", go_mod = "//tools:go.mod")
`}, bazelSDKUnbound},
		{"a .bazelrc importing a file outside the workspace", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": `try-import /etc/ci.bazelrc
`}, bazelSDKUnbound},
		{"a .bazelrc setting a main-repository build setting", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": `build --//:gosdk=1.26.7
`}, bazelSDKUnbound},
		{"a .bazelrc setting a main-repository build setting by @//", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": `build --@//:gosdk=1.26.7
`}, bazelSDKUnbound},
		{"a .bazelrc clearing a main-repository build setting", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": `build --no@@//:pure
`}, bazelSDKUnbound},
		{"a .bazelrc setting a build setting by the module's name", map[string]string{"MODULE.bazel": `module(name = "svc", version = "1.0")
` + fromFileModule, ".bazelrc": `build --@svc//:gosdk=1.26.7
`}, bazelSDKUnbound},
		{"a .bazelrc setting a build setting by the module's repo_name", map[string]string{"MODULE.bazel": `module(name = "svc", repo_name = "me")
` + fromFileModule, ".bazelrc": `build --@me//:gosdk=1.26.7
`}, bazelSDKUnbound},
		{"a module name this cannot read", map[string]string{"MODULE.bazel": `NAME = "svc"
module(name = NAME)
` + fromFileModule}, bazelSDKUnbound},
		{"a .bazelrc import whose comment names another file", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": `import %workspace%/a.bazelrc # %workspace%/b.bazelrc
`, "a.bazelrc": `build --@rules_go//go/toolchain:sdk_version=1.26.7
`, "b.bazelrc": `build --jobs=8
`}, bazelSDKUnbound},
		{"a .bazelrc flag with a quoted part", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": `build --@rules_go//go/toolchain:"sdk_version"=1.26.7
`}, bazelSDKUnbound},
		{"a .bazelrc flag with an escaped byte", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": `build --extra\_toolchains=//toolchains:go
`}, bazelSDKUnbound},
		{"a .bazelrc flag continued before the match", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": "build --extra_tool\\\nchains=//toolchains:go\n"}, bazelSDKUnbound},
		{"an indented .bazelrc import", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": "  import %workspace%/ci.bazelrc\n", "ci.bazelrc": `build --extra_toolchains=//toolchains:go
`}, bazelSDKUnbound},
		{"an import with an extra word", map[string]string{"MODULE.bazel": fromFileModule, ".bazelrc": `import %workspace%/a.bazelrc %workspace%/b.bazelrc
`, "a.bazelrc": "build --jobs=8\n", "b.bazelrc": "build --jobs=8\n"}, bazelSDKUnbound},
		{"a .bazeliskrc moving the wrapper directory", map[string]string{"MODULE.bazel": fromFileModule, ".bazeliskrc": "BAZELISK_WRAPPER_DIRECTORY=scripts\n", "scripts/bazel": "#!/bin/sh\n"}, bazelSDKUnbound},
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
				if err := os.MkdirAll(filepath.Dir(filepath.Join(checkoutRoot, path)), 0o755); err != nil {
					t.Fatal(err)
				}
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
// from_file, and then at the lower of what rules_go reads (the toolchain line, else the go line) and
// the binding go line a go command in the same repository enforces.
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
			name: "from_file floors at the go line below the toolchain line",
			in:   toolchainInputs{goDirective: "1.22.0", toolchainDirective: "go1.22.4", bazel: bazelSDKFromGoMod},
			want: ToolchainFact{Version: "go1.22.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
		},
		{
			name: "from_file takes a toolchain line below the go line, not the maximum",
			in:   toolchainInputs{goDirective: "1.23.0", toolchainDirective: "go1.22.4", bazel: bazelSDKFromGoMod},
			want: ToolchainFact{Version: "go1.22.4", Bound: ToolchainBoundMinimum, Source: ToolchainSourceToolchainDirective},
		},
		{
			name: "from_file with a two-part go line takes no floor",
			in:   toolchainInputs{goDirective: "1.22", bazel: bazelSDKFromGoMod},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "from_file with a go line before 1.21 takes no floor",
			in:   toolchainInputs{goDirective: "1.20.14", bazel: bazelSDKFromGoMod},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "from_file with a toolchain line it cannot order takes no floor",
			in:   toolchainInputs{goDirective: "1.22.0", toolchainDirective: "default", bazel: bazelSDKFromGoMod},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
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
