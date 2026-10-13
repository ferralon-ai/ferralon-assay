package pythonanalysis

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	exUVLock = `version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "flask" }]

[[package]]
name = "flask"
version = "3.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "jinja2" }]

[[package]]
name = "jinja2"
version = "3.1.4"
source = { registry = "https://pypi.org/simple" }
`
	exPyproject = "[project]\nname = \"app\"\ndependencies = [\"flask>=3\"]\n"
)

// Exhaustive covers the whole build dir: a manifest the resolver skipped or never parses, an
// include it did not follow, a pyproject group its lock does not hold, or an installed copy of
// the coordinate each withholds it. Every row keeps a uv.lock that would otherwise prove PyJWT
// absent.
func TestResolveVersions_ExhaustiveInstallSurface(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"baseline: lock and pyproject", map[string]string{}, true},

		// Manifests and installed trees under directories the analyzer skips.
		{"requirements under build/", map[string]string{"build/tool/requirements.txt": "pyjwt==2.8.0\n"}, false},
		{"requirements under env/", map[string]string{"env/requirements.txt": "pyjwt==2.8.0\n"}, false},
		{"pyproject under a dot-dir", map[string]string{".github/tool/pyproject.toml": "[project]\nname = \"tool\"\ndependencies = [\"pyjwt\"]\n"}, false},
		{"site-packages dist-info", map[string]string{"venv/lib/python3.12/site-packages/PyJWT-2.8.0.dist-info/METADATA": "Name: PyJWT\n"}, false},
		{"dist-packages egg-info", map[string]string{"lib/dist-packages/PyJWT-2.8.0-py3.12.egg-info/PKG-INFO": "Name: PyJWT\n"}, false},
		{"site-packages holding only locked names", map[string]string{".venv/lib/python3.12/site-packages/flask-3.0.0.dist-info/METADATA": "Name: flask\n"}, true},
		{"stray egg-info", map[string]string{"src/PyJWT.egg-info/PKG-INFO": "Name: PyJWT\n"}, false},
		{"vendored wheel", map[string]string{"wheels/PyJWT-2.8.0-py3-none-any.whl": "x"}, false},
		{"vendored sdist", map[string]string{"vendor/pyjwt-2.8.0.tar.gz": "x"}, false},
		{"egg-link", map[string]string{"PyJWT.egg-link": "/src/pyjwt\n"}, false},
		{"wheel for another name", map[string]string{"wheels/flask-3.0.0-py3-none-any.whl": "x"}, true},

		// Install manifests the resolver never parses.
		{"requirements/ directory", map[string]string{"requirements/prod.txt": "pyjwt==2.8.0\n"}, false},
		{"dev-requirements.txt", map[string]string{"dev-requirements.txt": "pyjwt==2.8.0\n"}, false},
		{"requirements.in", map[string]string{"requirements.in": "pyjwt\n"}, false},
		{"Pipfile without a lock", map[string]string{"Pipfile": "[packages]\npyjwt = \"*\"\n"}, false},
		{"environment.yml", map[string]string{"environment.yml": "dependencies:\n  - pip:\n    - pyjwt\n"}, false},
		{"tox.ini with deps", map[string]string{"tox.ini": "[testenv]\ndeps = pyjwt\n"}, false},
		{"tox.ini without deps", map[string]string{"tox.ini": "[tox]\nenvlist = py312\n"}, true},
		{"noxfile.py installing", map[string]string{"noxfile.py": "def tests(session):\n    session.install(\"pyjwt\")\n"}, false},
		{"MANIFEST.in", map[string]string{"MANIFEST.in": "include README.md\n"}, true},

		// Requirements includes.
		{"-r include not parsed", map[string]string{"requirements.txt": "-r base.txt\nflask==3.0.0\n", "base.txt": "pyjwt==2.8.0\n"}, false},
		{"-r include glued", map[string]string{"requirements.txt": "-rbase.txt\n", "base.txt": "pyjwt==2.8.0\n"}, false},
		{"--requirement= include", map[string]string{"requirements.txt": "--requirement=base.txt\n", "base.txt": "pyjwt==2.8.0\n"}, false},
		{"-c include missing", map[string]string{"requirements.txt": "-c pins.txt\nflask==3.0.0\n"}, false},
		{"-r include of a parsed manifest", map[string]string{"requirements.txt": "-r requirements-dev.txt\nflask==3.0.0\n", "requirements-dev.txt": "jinja2==3.1.4\n"}, true},

		// pyproject declarations outside [project].
		{"[dependency-groups] unlocked", map[string]string{"pyproject.toml": exPyproject + "[dependency-groups]\ndev = [\"pyjwt>=2\"]\n"}, false},
		{"[dependency-groups] locked, with include-group", map[string]string{"pyproject.toml": exPyproject + "[dependency-groups]\ndev = [\"jinja2\", {include-group = \"base\"}]\nbase = [\"flask\"]\n"}, true},
		{"[dependency-groups] unreadable entry", map[string]string{"pyproject.toml": exPyproject + "[dependency-groups]\ndev = [\"=bad\"]\n"}, false},
		{"[tool.uv] dev-dependencies unlocked", map[string]string{"pyproject.toml": exPyproject + "[tool.uv]\ndev-dependencies = [\"pyjwt\"]\n"}, false},
		{"[tool.poetry.dependencies] unlocked", map[string]string{"pyproject.toml": exPyproject + "[tool.poetry.dependencies]\npython = \"^3.12\"\npyjwt = \"^2\"\n"}, false},
		{"[tool.poetry.dependencies] locked", map[string]string{"pyproject.toml": exPyproject + "[tool.poetry.dependencies]\npython = \"^3.12\"\nflask = { version = \"^3\" }\n"}, true},
		{"[tool.poetry.group] unlocked", map[string]string{"pyproject.toml": exPyproject + "[tool.poetry.group.dev.dependencies]\npyjwt = \"^2\"\n"}, false},
		{"[tool.poetry.dev-dependencies] unlocked", map[string]string{"pyproject.toml": exPyproject + "[tool.poetry.dev-dependencies]\npyjwt = \"^2\"\n"}, false},
		{"[tool.pdm.dev-dependencies] unlocked", map[string]string{"pyproject.toml": exPyproject + "[tool.pdm.dev-dependencies]\ntest = [\"pyjwt\"]\n"}, false},
		{"[tool.hatch.envs] unlocked", map[string]string{"pyproject.toml": exPyproject + "[tool.hatch.envs.default]\ndependencies = [\"pyjwt\"]\n"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"uv.lock": exUVLock, "pyproject.toml": exPyproject}
			for k, v := range tt.files {
				files[k] = v
			}
			r := resolveVersion(t, writeTree(t, files), "PyJWT")
			if r.Found {
				t.Fatalf("PyJWT unexpectedly found: %+v", r.Match)
			}
			if r.Exhaustive != tt.want {
				t.Fatalf("Exhaustive = %v, want %v (partiality %+v)", r.Exhaustive, tt.want, r.Partiality)
			}
		})
	}
}

// A symlinked directory is not followed by the walk, so what it holds goes unread.
func TestResolveVersions_ExhaustiveSymlinkedDir(t *testing.T) {
	root := writeTree(t, map[string]string{"uv.lock": exUVLock, "pyproject.toml": exPyproject})
	elsewhere := writeTree(t, map[string]string{"requirements.txt": "pyjwt==2.8.0\n"})
	if r := resolveVersion(t, root, "PyJWT"); !r.Exhaustive {
		t.Fatalf("baseline not exhaustive")
	}
	if err := os.Symlink(elsewhere, filepath.Join(root, "tools")); err != nil {
		t.Fatal(err)
	}
	if r := resolveVersion(t, root, "PyJWT"); r.Exhaustive {
		t.Fatalf("Exhaustive with a symlinked directory")
	}
}
