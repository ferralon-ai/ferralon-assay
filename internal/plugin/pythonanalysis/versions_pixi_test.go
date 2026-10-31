package pythonanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Pixi's PyPI tables are read for the projects they name, each unresolved, under every feature
// and target. Conda dependencies and local path installs are not PyPI projects. The result stays
// partial, since pixi's tables are not resolved.
func TestResolveVersions_PixiPyPINames(t *testing.T) {
	const pixi = "[pypi-dependencies]\npyjwt = \"==2.10.0\"\nlocal_pkg = { path = \"./lib\", editable = true }\n" +
		"gitpkg = { git = \"https://example.com/gitpkg.git\" }\n\n" +
		"[dependencies]\nnumpy = \"1.26.*\"\n\n" +
		"[target.linux-64.pypi-dependencies]\nuvloop = \"*\"\n\n" +
		"[feature.dev.pypi-dependencies]\npytest = { version = \"==8.0.0\" }\n\n" +
		"[feature.dev.target.win-64.pypi-dependencies]\npywin32 = \"*\"\n"
	want := []string{"gitpkg", "pyjwt", "pytest", "pywin32", "uvloop"}
	for name, files := range map[string]map[string]string{
		"pixi.toml": {"pixi.toml": "[workspace]\nchannels = [\"conda-forge\"]\nplatforms = [\"linux-64\"]\n\n" + pixi},
		"pyproject": {"pyproject.toml": "[project]\nname = \"app\"\n\n" + prefixPixiTables(pixi)},
		"nested pixi.toml": {
			"requirements.txt":   "flask==3.0.0\n",
			"services/pixi.toml": pixi,
		},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: writeTree(t, files)})
			if err != nil {
				t.Fatal(err)
			}
			if res.Partiality.Complete || res.Exhaustive {
				t.Fatalf("partiality %+v Exhaustive=%v, want partial and non-exhaustive", res.Partiality, res.Exhaustive)
			}
			got := map[string]plugin.ResolvedDependency{}
			for _, d := range res.All {
				got[d.Coordinate] = d
			}
			for _, n := range want {
				d, ok := got[n]
				if !ok || d.Resolved || d.Version != "" {
					t.Errorf("%s: %+v (found %v), want an unresolved entry", n, d, ok)
				}
			}
			for _, n := range []string{"numpy", "local_pkg"} {
				if _, ok := got[n]; ok {
					t.Errorf("%s is in All: %+v", n, res.All)
				}
			}
		})
	}
}

// A name pixi declares, also pinned in requirements.txt, is found and withheld.
func TestResolveVersions_PixiNameWithholdsPin(t *testing.T) {
	res := resolveVersion(t, writeTree(t, map[string]string{
		"requirements.txt": "pyjwt==2.8.0\n",
		"pixi.toml":        "[pypi-dependencies]\npyjwt = \"==2.10.0\"\n",
	}), "pyjwt")
	if !res.Found || res.Match.Resolved || res.Partiality.Complete {
		t.Fatalf("Found=%v Match=%+v partiality %+v, want found, unresolved and partial", res.Found, res.Match, res.Partiality)
	}
}

// A pixi.toml that does not decode leaves the result partial and adds nothing.
func TestResolveVersions_PixiUndecodable(t *testing.T) {
	res, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: writeTree(t, map[string]string{
		"requirements.txt": "flask==3.0.0\n",
		"pixi.toml":        "[pypi-dependencies\npyjwt = \"==2.10.0\"\n",
	})})
	if err != nil || res.Partiality.Complete || len(res.All) != 1 {
		t.Fatalf("err=%v partiality %+v All=%+v, want partial with flask alone", err, res.Partiality, res.All)
	}
}

// prefixPixiTables moves a pixi.toml's table headers under [tool.pixi].
func prefixPixiTables(src string) string {
	out := []byte{}
	for i := 0; i < len(src); i++ {
		if src[i] == '[' && (i == 0 || src[i-1] == '\n') {
			out = append(out, "[tool.pixi."...)
			continue
		}
		out = append(out, src[i])
	}
	return string(out)
}
