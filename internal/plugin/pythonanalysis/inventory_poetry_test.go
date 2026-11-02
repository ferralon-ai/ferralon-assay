package pythonanalysis

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// A poetry.lock package that every recorded poetry install leaves out stays in the inventory at
// its lock version, marked not installed; one an install may put in place is never marked, and
// every marked one is a package version resolution leaves unresolved.
func TestInventory_PoetryInstallGroups(t *testing.T) {
	const (
		pyproject = "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"jinja2==3.1.4\"]\n" +
			"[tool.poetry.group.dev.dependencies]\npytest = \"8.3.2\"\n" +
			"[tool.poetry.group.docs]\noptional = true\n[tool.poetry.group.docs.dependencies]\nsphinx = \"7.4.7\"\n"
		lock = "[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\ngroups = [\"main\"]\n\n" +
			"[[package]]\nname = \"pytest\"\nversion = \"8.3.2\"\ngroups = [\"dev\"]\n\n" +
			"[[package]]\nname = \"sphinx\"\nversion = \"7.4.7\"\ngroups = [\"docs\"]\n\n" +
			"[[package]]\nname = \"colorama\"\nversion = \"0.4.6\"\ngroups = [\"main\", \"dev\"]\n"
		mainOnlyProject = "[tool.poetry]\nname = \"app\"\nversion = \"0.1.0\"\n[tool.poetry.dependencies]\njinja2 = \"3.1.4\"\n"
		legacyProject   = mainOnlyProject + "[tool.poetry.dev-dependencies]\npytest = \"8.3.2\"\n"
		categoryLock    = "[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\ncategory = \"main\"\noptional = false\n\n" +
			"[[package]]\nname = \"pytest\"\nversion = \"8.3.2\"\ncategory = \"dev\"\noptional = false\n"
		bareLock = "[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\n\n[[package]]\nname = \"pytest\"\nversion = \"8.3.2\"\n"
	)
	versions := map[string]string{"jinja2": "3.1.4", "pytest": "8.3.2", "sphinx": "7.4.7", "colorama": "0.4.6"}
	tests := []struct {
		name         string
		files        map[string]string // over pyproject.toml and poetry.lock
		notInstalled []string
	}{
		{"--only main", map[string]string{"install.sh": "poetry install --only main\n"}, []string{"pytest", "sphinx"}},
		{"--without dev", map[string]string{"install.sh": "poetry install --without dev\n"}, []string{"pytest", "sphinx"}},
		{"--with an optional group", map[string]string{"install.sh": "poetry install --with docs --without dev\n"}, []string{"pytest"}},
		{"a recorded bare install leaves an optional group out", map[string]string{"install.sh": "poetry install\n"}, []string{"sphinx"}},
		{"--with a group under another spelling may install it", map[string]string{"install.sh": "poetry install --with Docs\n"}, nil},
		{"--without a group under another spelling may keep it", map[string]string{"install.sh": "poetry install --without Dev\n"}, []string{"sphinx"}},
		{"--only a group under another spelling may install it", map[string]string{"install.sh": "poetry install --only Main\n"}, []string{"pytest", "sphinx"}},
		{"every surface's install must leave it out", map[string]string{"install.sh": "poetry install --only main\n", "ci.sh": "poetry install\n"}, []string{"sphinx"}},
		{"surfaces that each leave it out", map[string]string{"install.sh": "poetry install --only main\n", "ci.sh": "poetry install --without dev\n"}, []string{"pytest", "sphinx"}},
		{"a package only an extra pulls in", map[string]string{"install.sh": "poetry install --with docs\n",
			"poetry.lock": strings.Replace(lock, `groups = ["docs"]`, "groups = [\"docs\"]\noptional = true", 1)}, []string{"sphinx"}},
		{"every same-name entry must be left out", map[string]string{"install.sh": "poetry install --only main\n",
			"poetry.lock": lock + "\n" + "[[package]]\nname = \"sphinx\"\nversion = \"7.4.7\"\ngroups = [\"main\"]\n"}, []string{"pytest"}},
		{"every same-name entry must be left out, listed first", map[string]string{"install.sh": "poetry install --only main\n",
			"poetry.lock": "[[package]]\nname = \"sphinx\"\nversion = \"7.4.7\"\ngroups = [\"main\"]\n\n" + lock}, []string{"pytest"}},
		{"an optional key that is not a bool", map[string]string{"install.sh": "poetry install --only main\n",
			"poetry.lock": strings.Replace(lock, `groups = ["docs"]`, "groups = [\"docs\"]\noptional = \"yes\"", 1)}, []string{"pytest"}},
		{"a groups element that is not a string", map[string]string{"install.sh": "poetry install --only main\n",
			"poetry.lock": strings.Replace(lock, `groups = ["dev"]`, `groups = ["dev", 1]`, 1)}, []string{"sphinx"}},
		{"a groups value that is not a list", map[string]string{"install.sh": "poetry install --only main\n",
			"poetry.lock": strings.Replace(lock, `groups = ["dev"]`, `groups = "dev"`, 1)}, []string{"sphinx"}},
		{"an empty groups list", map[string]string{"install.sh": "poetry install --only main\n",
			"poetry.lock": strings.Replace(lock, `groups = ["docs"]`, `groups = []`, 1)}, []string{"pytest"}},
		{"a lock group the manifest does not declare", map[string]string{"install.sh": "poetry install --only main\n",
			"poetry.lock": strings.Replace(lock, `groups = ["dev"]`, `groups = ["dev", "ghost"]`, 1)}, []string{"sphinx"}},
		{"poetry 1.x category, --only main", map[string]string{"install.sh": "poetry install --only main\n", "pyproject.toml": legacyProject, "poetry.lock": categoryLock}, []string{"pytest"}},
		{"poetry 1.x category main may be a dev dependency too", map[string]string{"install.sh": "poetry install --only dev\n", "pyproject.toml": legacyProject, "poetry.lock": categoryLock}, nil},
		{"poetry 1.x category, no group selected", map[string]string{"install.sh": "poetry install --without main --without dev\n", "pyproject.toml": legacyProject, "poetry.lock": categoryLock}, []string{"jinja2", "pytest"}},
		{"poetry 1.x unknown category", map[string]string{"install.sh": "poetry install --only main\n", "pyproject.toml": legacyProject,
			"poetry.lock": strings.Replace(categoryLock, `category = "dev"`, `category = "test"`, 1)}, nil},
		{"no membership keys, no group selected", map[string]string{"install.sh": "poetry install --without main --without dev\n", "pyproject.toml": legacyProject, "poetry.lock": bareLock}, []string{"jinja2", "pytest"}},
		{"poetry 1.x category dev with no dev group declared", map[string]string{"install.sh": "poetry install --only main\n",
			"pyproject.toml": mainOnlyProject, "poetry.lock": categoryLock}, nil},
		{"no membership keys under a group flag", map[string]string{"install.sh": "poetry install --only main\n", "pyproject.toml": legacyProject, "poetry.lock": bareLock}, nil},
		{"no install recorded", nil, nil},
		{"a withheld script surface", map[string]string{"install.sh": "poetry install --only main\npip install pytest\n"}, nil},
		{"a pip self-upgrade", map[string]string{"install.sh": "pip install -U pip\npoetry install --only main\n"}, nil},
		{"an allowed pip install -r", map[string]string{"install.sh": "poetry install --only main\npip install -r requirements-dev.txt\n",
			"requirements-dev.txt": "pytest==8.3.2\n"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"pyproject.toml": pyproject, "poetry.lock": lock}
			for k, v := range tt.files {
				files[k] = v
			}
			dir := writeTree(t, files)
			inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			for name, version := range versions {
				if !strings.Contains(files["poetry.lock"], "\""+name+"\"") {
					continue
				}
				n, ok := nodeByPURL(inv, "pkg:pypi/"+name+"@"+version)
				if !ok || n.Provenance.Lockfile != "poetry.lock" {
					t.Errorf("%s@%s: no poetry.lock node, want one", name, version)
					continue
				}
				want := slices.Contains(tt.notInstalled, name)
				if n.NotInstalled != want {
					t.Errorf("%s NotInstalled = %v, want %v", name, n.NotInstalled, want)
				}
				if r := resolveVersion(t, dir, name); want && (!r.Found || r.Match.Resolved) {
					t.Errorf("%s is marked not installed but version resolution gives %+v found %v", name, r.Match, r.Found)
				}
			}
		})
	}
}
