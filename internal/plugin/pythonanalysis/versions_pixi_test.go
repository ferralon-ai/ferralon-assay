package pythonanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Pixi's PyPI tables are read for the projects they name, each unresolved, under every feature,
// inline environment and target. Conda dependencies are not PyPI projects, and an in-tree source
// directory is read through its own manifest. A wheel, an sdist, an out-of-tree or Windows-form
// path, and a source directory the walk reads no manifest in stay entries. The
// result stays partial, since pixi's tables are not resolved.
func TestResolveVersions_PixiPyPINames(t *testing.T) {
	const pixi = "[pypi-dependencies]\npyjwt = \"==2.10.0\"\nlocal_pkg = { path = \"./lib\", editable = true }\n" +
		"gitpkg = { git = \"https://example.com/gitpkg.git\" }\n\n" +
		"[dependencies]\nnumpy = \"1.26.*\"\n\n" +
		"[target.linux-64.pypi-dependencies]\nuvloop = \"*\"\n\n" +
		"[feature.dev.pypi-dependencies]\npytest = { version = \"==8.0.0\" }\n\n" +
		"[feature.dev.target.win-64.pypi-dependencies]\npywin32 = \"*\"\n\n" +
		"[environments]\ndefault = [\"dev\"]\n\n" +
		"[environments.ci.pypi-dependencies]\ncoverage = \"*\"\n" +
		"wheelpkg = { path = \"./wheels/wheelpkg-1.0-py3-none-any.whl\" }\n" +
		"outpkg = { path = \"../vendor/outpkg\" }\n" +
		"barepkg = { path = \"./bare\" }\n" +
		"hiddenpkg = { path = \".pixi/src/hiddenpkg\" }\n" +
		"winpkg = { path = \"lib\\\\win\" }\n" +
		"sdistpkg = { path = \"./dist-in/SdistPkg-1.0.TAR.GZ\" }\n\n" +
		"[environments.ci.target.osx-arm64.pypi-dependencies]\nmlx = \"*\"\n"
	want := []string{"barepkg", "coverage", "gitpkg", "hiddenpkg", "mlx", "outpkg", "pyjwt", "pytest", "pywin32", "sdistpkg",
		"uvloop", "wheelpkg", "winpkg"}
	// local_pkg's source holds a manifest the walk reads; bare's holds none, and .pixi is skipped.
	srcs := map[string]string{
		"lib/pyproject.toml":                 "[project]\nname = \"local_pkg\"\n",
		"bare/local.py":                      "x = 1\n",
		".pixi/src/hiddenpkg/pyproject.toml": "[project]\nname = \"hiddenpkg\"\n",
	}
	for name, files := range map[string]map[string]string{
		"pixi.toml": {"pixi.toml": "[workspace]\nchannels = [\"conda-forge\"]\nplatforms = [\"linux-64\"]\n\n" + pixi},
		"pyproject": {"pyproject.toml": "[project]\nname = \"app\"\n\n" + prefixPixiTables(pixi)},
		"nested pixi.toml": {
			"requirements.txt":   "flask==3.0.0\n",
			"services/pixi.toml": pixi,
		},
	} {
		t.Run(name, func(t *testing.T) {
			base := ""
			for f := range files {
				if strings.HasSuffix(f, "pixi.toml") || strings.HasSuffix(f, "pyproject.toml") {
					base = strings.TrimSuffix(strings.TrimSuffix(f, "pixi.toml"), "pyproject.toml")
				}
			}
			for f, body := range srcs {
				files[base+f] = body
			}
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

// A name only pixi declares, beside a uv.lock and pyproject that would otherwise prove it
// absent, is found, unresolved, and the answer is not exhaustive.
func TestResolveVersions_PixiNameBesideCoveringLock(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"pixi.toml": {"pixi.toml": "[pypi-dependencies]\npyjwt = \">=2\"\n"},
		"pyproject": {"pyproject.toml": exPyproject + "[tool.pixi.pypi-dependencies]\npyjwt = \">=2\"\n"},
	} {
		t.Run(name, func(t *testing.T) {
			tree := map[string]string{"uv.lock": exUVLock, "pyproject.toml": exPyproject}
			for k, v := range files {
				tree[k] = v
			}
			r := resolveVersion(t, writeTree(t, tree), "PyJWT")
			if !r.Found || r.Match.Resolved || r.Exhaustive {
				t.Fatalf("Found=%v Match=%+v Exhaustive=%v, want found, unresolved and not exhaustive", r.Found, r.Match, r.Exhaustive)
			}
		})
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
