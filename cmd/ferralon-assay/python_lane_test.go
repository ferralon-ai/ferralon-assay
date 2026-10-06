package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// fakeAnalyzer writes an executable named name into dir that answers any request with a
// capability manifest whose Language is tag, so a test can tell which binary was driven.
func fakeAnalyzer(t *testing.T, dir, name, tag string) {
	t.Helper()
	script := "#!/bin/sh\nread line\necho '{\"protocol\":\"" + plugin.ProtocolVersion + "\",\"manifest\":{\"version\":\"\",\"language\":\"" + tag + "\",\"supported\":false}}'\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestSelectPlugin_PythonLaneSwitch pins the Python lane switch: only the exact (case- and
// space-insensitive) value "cgx" selects assay-plugin-python-cgx; anything else keeps the
// lexical analyzer; an explicit binary path wins over the switch.
func TestSelectPlugin_PythonLaneSwitch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake analyzers")
	}
	path := t.TempDir()
	fakeAnalyzer(t, path, plugin.BinaryName("python"), "lexical")
	fakeAnalyzer(t, path, plugin.BinaryName("python-cgx"), "cgx")
	explicit := filepath.Join(t.TempDir(), "explicit")
	fakeAnalyzer(t, filepath.Dir(explicit), "explicit", "explicit")
	t.Setenv("PATH", path)

	cases := []struct {
		env, bin, want string
	}{
		{"", "", "lexical"},
		{"cgx", "", "cgx"},
		{" CGX ", "", "cgx"},
		{"cgxx", "", "lexical"},
		{"1", "", "lexical"},
		{"cgx", explicit, "explicit"},
	}
	for _, tc := range cases {
		t.Run(tc.env+"|"+tc.bin, func(t *testing.T) {
			t.Setenv(envPythonLane, tc.env)
			p, err := selectPlugin(checkout.LangPython, tc.bin)
			if err != nil {
				t.Fatalf("selectPlugin: %v", err)
			}
			if p.Language() != "python" {
				t.Fatalf("Language() = %q, want python", p.Language())
			}
			m, err := p.CapabilityManifest(context.Background(), plugin.CapabilityManifestRequest{})
			if err != nil {
				t.Fatalf("CapabilityManifest: %v", err)
			}
			if m.Language != tc.want {
				t.Errorf("%s=%q bin=%q drove the %q analyzer, want %q", envPythonLane, tc.env, tc.bin, m.Language, tc.want)
			}
		})
	}
}

func TestSelectPlugin_PythonLaneCgxMissingBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv(envPythonLane, "cgx")
	_, err := selectPlugin(checkout.LangPython, "")
	if err == nil || !strings.Contains(err.Error(), plugin.BinaryName("python-cgx")) {
		t.Fatalf("selectPlugin with the cgx lane and no binary: err = %v, want it to name %s", err, plugin.BinaryName("python-cgx"))
	}
}
