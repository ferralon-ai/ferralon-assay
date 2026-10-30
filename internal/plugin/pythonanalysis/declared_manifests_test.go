package pythonanalysis

import (
	"slices"
	"testing"
)

// A lone CR ends a line for CPython, so a comment in a CR-only setup.py or hatch_build.py
// ends there too rather than running on over the declarations after it.
func TestDeclaredManifests_LoneCRLineBreaks(t *testing.T) {
	setupPy := "from setuptools import setup\rsetup(\r    name='svc',\r    install_requires=[  # runtime\r        'six==1.16.0',\r        'pyjwt==2.8.0',\r    ],\r)\r"
	specs, complete := scanSetupPy(setupPy)
	if !complete || !slices.Equal(specs, []string{"six==1.16.0", "pyjwt==2.8.0"}) {
		t.Errorf("setup.py: specs=%q complete=%v, want both requirements read in full", specs, complete)
	}

	hatch := "# hook\rfrom hatchling.builders.hooks.plugin.interface import BuildHookInterface\rclass H(BuildHookInterface):\r    deps = ['pyjwt==2.8.0']\r"
	deps, _ := parseHatchBuild([]byte(hatch))
	if len(deps) != 1 || deps[0].Coordinate != "pyjwt" {
		t.Errorf("hatch_build.py: deps=%+v, want pyjwt", deps)
	}
}
