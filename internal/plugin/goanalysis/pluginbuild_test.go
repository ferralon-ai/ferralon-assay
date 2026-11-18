package goanalysis

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestPluginBuildOf: a load that compiled the plugin stub reads as cgo off unless the go command
// resolves a target whose build compiles the stub with cgo on too. Neither the files the load
// ignored nor the name of the file that loads plugins decides it.
func TestPluginBuildOf(t *testing.T) {
	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(strings.TrimSpace(string(out)), "src", "plugin")
	stub, real := filepath.Join(src, "plugin_stubs.go"), filepath.Join(src, "plugin.go")
	if _, err := os.Stat(stub); err != nil {
		t.Skipf("this Go release names the plugin stub otherwise: %v", err)
	}
	std := func(files ...string) []*packages.Package {
		return []*packages.Package{{PkgPath: "plugin", GoFiles: files}}
	}
	env := func(kv ...string) []string { return append(os.Environ(), kv...) }
	stopped, stop := context.WithCancel(context.Background())
	stop()
	cases := []struct {
		name string
		pkgs []*packages.Package
		env  []string
		ctx  context.Context
		want pluginBuild
	}{
		{"the stub on a GOOS with plugins, nothing ignored", std(real, stub), env("GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0"), nil, pluginCgoOff},
		{"the stub on a GOOS with plugins, the loader under another name", func() []*packages.Package {
			p := std(real, stub)
			p[0].IgnoredFiles = []string{filepath.Join(src, "plugin_unix.go")}
			return p
		}(), env("GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0"), nil, pluginCgoOff},
		{"the stub on a GOOS without plugins", std(real, stub), env("GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0"), nil, pluginNoPlatform},
		{"the stub, the go command not answering", std(real, stub), env("GOOS=windows", "GOARCH=amd64"), stopped, pluginCgoOff},
		{"the stub, its file unreadable", std(real, filepath.Join(t.TempDir(), "plugin_stubs.go")), env("GOOS=windows", "GOARCH=amd64"), nil, pluginCgoOff},
		{"the loader compiled", std(real, filepath.Join(src, "plugin_dlopen.go")), env("GOOS=linux", "GOARCH=amd64"), nil, pluginLoads},
		{"no package plugin", []*packages.Package{{PkgPath: "os"}}, env(), nil, pluginLoads},
		{"a module's own package named plugin", []*packages.Package{{PkgPath: "plugin", GoFiles: []string{stub}, Module: &packages.Module{Path: "plugin"}}}, env("GOOS=windows"), nil, pluginLoads},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := tc.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			if got := pluginBuildOf(ctx, t.TempDir(), tc.pkgs, tc.env); got != tc.want {
				t.Errorf("pluginBuildOf = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestReconciledResult_PluginLoadCgoOff: with cgo off, a build that reaches plugin.Open and no
// vulnerable symbol keeps its refutation, declares plugin_load:cgo_off beside it, and says in the
// refutation's detail that it holds for CGO_ENABLED=0.
func TestReconciledResult_PluginLoadCgoOff(t *testing.T) {
	if !slices.Contains([]string{"linux", "darwin", "freebsd"}, runtime.GOOS) {
		t.Skip("the host's GOOS has no plugins")
	}
	t.Setenv("CGO_ENABLED", "0")
	main := "package main\n\nimport (\n\t\"plugin\"\n\n\t\"example.com/vulnmod\"\n)\n\nfunc main() {\n\tvulnmod.Safe()\n\t_, _ = plugin.Open(\"x.so\")\n}\n"
	_, res := reconcileFor(t, map[string]string{"main.go": main}, vulnmodFinding, plugin.LibraryEntrypoints{})
	if !slices.Contains(res.Partiality.Reasons, plugin.PartialReasonPluginLoadCgoOff) || slices.Contains(res.Partiality.Reasons, plugin.PartialReasonPluginLoad) {
		t.Errorf("reasons = %v, want %s and not %s", res.Partiality.Reasons, plugin.PartialReasonPluginLoadCgoOff, plugin.PartialReasonPluginLoad)
	}
	if res.Refutation == nil || !strings.Contains(res.Refutation.Detail, pluginScopeDetail) {
		t.Fatalf("refutation = %+v, want one whose detail states %q", res.Refutation, pluginScopeDetail)
	}
}
