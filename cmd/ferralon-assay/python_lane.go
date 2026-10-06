package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// envPythonLane selects the analyzer behind the Python lane. Only the value "cgx" changes
// anything: it selects the cgx-backed analyzer (assay-plugin-python-cgx), which answers the
// call-graph operations from a cgx index and delegates the rest to the lexical analyzer.
// Empty, a typo, or any other value keeps the lexical analyzer, because a switch that changes
// verdict evidence must never be flipped by a typo. An explicit -plugin-go path wins over it.
const envPythonLane = brand.EnvPrefix + "_PYTHON_LANE"

// pythonLaneCgx is the value of envPythonLane that selects the cgx-backed analyzer.
const pythonLaneCgx = "cgx"

// pythonCgxPluginName is the executable the cgx-backed Python analyzer is discovered as on PATH.
var pythonCgxPluginName = plugin.BinaryName("python-cgx")

func pythonLaneIsCgx() bool {
	return strings.ToLower(strings.TrimSpace(os.Getenv(envPythonLane))) == pythonLaneCgx
}

// newPythonCgxPlugin discovers assay-plugin-python-cgx on PATH and drives it through the
// ordinary Python client: it speaks the same protocol and reports Language() "python".
func newPythonCgxPlugin() (plugin.LanguagePlugin, error) {
	bin, err := exec.LookPath(pythonCgxPluginName)
	if err != nil {
		return nil, fmt.Errorf("%s=%s: discover %s: %w", envPythonLane, pythonLaneCgx, pythonCgxPluginName, err)
	}
	return plugin.NewPythonPlugin(plugin.WithPythonBinaryPath(bin))
}
