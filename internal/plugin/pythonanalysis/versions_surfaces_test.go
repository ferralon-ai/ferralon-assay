package pythonanalysis

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Every install surface the resolver does not parse vetoes the root pin, wherever the shared
// walk finds it and whatever case its name is in, and so does a file that only its content
// marks as one.
func TestResolveVersions_UnreadInstallSurfaceVetoes(t *testing.T) {
	const pin = "pyjwt==2.10.0\n"
	for name, tc := range map[string]struct{ file, body string }{
		"pylock":                {"pylock.toml", "lock-version = \"1.0\"\n[[packages]]\nname = \"pyjwt\"\nversion = \"2.10.0\"\n"},
		"named pylock":          {"pylock.dev.toml", "lock-version = \"1.0\"\n[[packages]]\nname = \"pyjwt\"\nversion = \"2.10.0\"\n"},
		"rye lock":              {"requirements.lock", pin},
		"rye dev lock":          {"requirements-dev.lock", pin},
		"pixi manifest":         {"pixi.toml", "[pypi-dependencies]\npyjwt = \"==2.10.0\"\n"},
		"pixi lock":             {"pixi.lock", "version: 5\n"},
		"build dir":             {"build/requirements.txt", pin},
		"ci dir":                {".ci/requirements.txt", pin},
		"dist dir":              {"dist/requirements.txt", pin},
		"venv dir":              {".venv/requirements.txt", pin},
		"tox":                   {"tox.ini", "[testenv]\ndeps = pyjwt==2.10.0\n"},
		"nox":                   {"noxfile.py", "import nox\n\n@nox.session\ndef t(s):\n    s.install(\"pyjwt==2.10.0\")\n"},
		"constraints":           {"constraints.txt", pin},
		"conda env":             {"conda-env.yml", "dependencies:\n  - pip:\n    - pyjwt==2.10.0\n"},
		"conda lock":            {"conda-lock.yml", "version: 1\n"},
		"environment":           {"environment.yaml", "dependencies:\n  - pip:\n    - pyjwt==2.10.0\n"},
		"lowercase pipfile":     {"svc/pipfile", "[packages]\npyjwt = \"==2.10.0\"\n"},
		"Pipfile.dev":           {"svc/Pipfile.dev", "[packages]\npyjwt = \"==2.10.0\"\n"},
		"lowercase lock":        {"svc/pipfile.lock", "{}\n"},
		"Poetry.lock":           {"svc/Poetry.lock", "[[package]]\nname = \"pyjwt\"\nversion = \"2.10.0\"\n"},
		"UV.lock":               {"svc/UV.lock", "version = 1\n"},
		"PYPROJECT.toml":        {"svc/PYPROJECT.toml", "[project]\nname = \"svc\"\ndependencies = [\"pyjwt==2.10.0\"]\n"},
		"Requirements.txt":      {"svc/Requirements.txt", pin},
		"other lock":            {"svc/deps.lock", pin},
		"templated":             {"svc/requirements.txt.j2", pin},
		"requirements dir":      {"requirements/prod.pip", pin},
		"input file":            {"deps/base.in", "pyjwt\n"},
		"content only":          {"deps/pins", pin},
		"toml content":          {"svc/project.toml", "[project]\nname = \"svc\"\ndependencies = [\"pyjwt==2.10.0\"]\n"},
		"lock content":          {"svc/frozen", "[[package]]\nname = \"pyjwt\"\nversion = \"2.10.0\"\nrequires-python = \">=3.8\"\n"},
		"conda content":         {"svc/env.yml", "channels:\n  - conda-forge\ndependencies:\n  - pyjwt=2.10.0\n"},
		"setup() content":       {"tools/make_dist.py", "import setuptools\nsetuptools.setup(install_requires=[\"pyjwt==2.10.0\"])\n"},
		"metadata unreadable":   {".venv/lib/python3.12/site-packages/PyJWT-2.10.0.dist-info/RECORD", ""},
		"egg-info unreadable":   {"lib/site-packages/PyJWT-2.10.0.egg-info/top_level.txt", "jwt\n"},
		"git dir is walked":     {".git/requirements.txt", pin},
		"hatch hook":            {"hatch_build.py", "class H:\n    def update(self, m):\n        m['dependencies'] = ['pyjwt==2.10.0']\n"},
		"conda nonstandard yml": {"conda.yml", "dependencies:\n  - pyjwt=2.10.0\n"},
		"TOX.INI case":          {"svc/TOX.INI", "[testenv]\ndeps = pyjwt\n"},
		"Requirements.txt bare": {"svc/Requirements.txt", "pyjwt\n"},
		"PYPROJECT.TOML case":   {"svc/PYPROJECT.TOML", "[tool.ruff]\nline-length = 100\n"},
		"build dir pyproject":   {"build/pyproject.toml", "[tool.ruff]\nline-length = 100\n"},
		"requirements dir bare": {"requirements/prod.pip", "pyjwt\n"},
		"templated tox":         {"svc/tox.ini.j2", "[testenv]\ndeps = {{ deps }}\n"},
		"templated TOX.INI":     {"svc/TOX.INI.j2", "[testenv]\ndeps = {{ deps }}\n"},
		"Pipfile tables":        {"svc/deps.toml", "[packages]\npyjwt = \"==2.10.0\"\n"},
		"empty marker":          {"svc/deps.pins", "pyjwt==2.10.0;\n"},
	} {
		t.Run(name, func(t *testing.T) {
			mustVetoedPy(t, writeTree(t, map[string]string{
				"requirements.txt": "pyjwt==2.8.0\n",
				tc.file:            tc.body,
			}), "pyjwt")
		})
	}
}

// A file only the ManifestCandidates classifier (pyCandidate) recognises is an install surface
// too: a lock name in another case than the ecosystem that owns it writes, a MANIFEST.in in
// another case, and requirement lines pip's parser accepts. Each vetoes the root pin.
func TestResolveVersions_ManifestCandidateVetoes(t *testing.T) {
	for name, tc := range map[string]struct{ file, body string }{
		"lowercase cargo.lock": {"svc/cargo.lock", "version = 3\n"},
		"Yarn.lock case":       {"svc/Yarn.lock", "x\n"},
		"Manifest.in case":     {"svc/Manifest.in", "include README.md\n"},
		"requirement lines":    {"svc/deps", "foo= =1\n"},
	} {
		t.Run(name, func(t *testing.T) {
			mustVetoedPy(t, writeTree(t, map[string]string{
				"requirements.txt": "pyjwt==2.8.0\n",
				tc.file:            tc.body,
			}), "pyjwt")
		})
	}
}

// Surfaces the resolver reads in full do not veto: the root pin resolves, complete, beside a
// pyproject.toml, a setup.py and setup.cfg with no *_require keyword, an empty Pipfile, a conda
// environment of only the interpreter and pip, tox.ini without deps, a noxfile that never
// installs, documentation quoting another pin, VCS metadata, and an installed copy at the
// same version.
func TestResolveVersions_FullyReadSurfacesResolve(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"requirements.txt": "pyjwt==2.8.0\n",
		"pyproject.toml":   "[build-system]\nrequires = [\"setuptools>=61\"]\n\n[project]\nname = \"app\"\ndependencies = [\"pyjwt==2.8.0\"]\n",
		"setup.py":         "from setuptools import setup\nsetup(name=\"app\")\n",
		"setup.cfg":        "[metadata]\nname = app\n",
		"Pipfile":          "[packages]\n\n[requires]\npython_version = \"3.12\"\n",
		"environment.yml":  "dependencies:\n  - python=3.12\n  - pip\n",
		"tox.ini":          "[testenv]\ncommands = pytest\n",
		"noxfile.py":       "import nox\n\n@nox.session\ndef t(s):\n    s.run(\"pytest\")\n",
		"docs/install.md":  "# Install\n\nRun `pip install pyjwt==2.10.0` for the new API.\n",
		"docs/notes.txt":   "Install flask 2.0 or later.\n",
		".git/HEAD":        "ref: refs/heads/main\n",
		".git/config":      "[core]\n\tbare = false\n",
		".venv/lib/python3.12/site-packages/PyJWT-2.8.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: PyJWT\nVersion: 2.8.0\n\nbody\n",
		"lib/site-packages/PyJWT-2.8.0.egg-info/PKG-INFO":                   "Metadata-Version: 1.0\nName: PyJWT\nVersion: 2.8.0\n",
		"app.py": "import jwt\n",
	})
	mustResolvedCompletePy(t, dir, "pyjwt", "2.8.0")
}

// [build-system].requires is read as a declaration no lock covers, and a copy installed in a
// site-packages directory under the build dir is another copy of its project: either one at
// another version leaves the pin unresolved.
func TestResolveVersions_BuildRequiresAndInstalledCopiesRead(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"build-system requires": {
			"pyproject.toml": "[build-system]\nrequires = [\"pyjwt==2.10.0\"]\n\n[project]\nname = \"app\"\ndependencies = [\"pyjwt==2.8.0\"]\n",
		},
		"build-system range beside a lock": {
			"pyproject.toml": "[build-system]\nrequires = [\"pyjwt>=2\"]\n\n[project]\nname = \"app\"\ndependencies = [\"pyjwt>=2\"]\n",
			"uv.lock":        "version = 1\n\n[[package]]\nname = \"pyjwt\"\nversion = \"2.8.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n",
		},
		"dist-info": {
			".venv/lib/python3.12/site-packages/PyJWT-2.10.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: PyJWT\nVersion: 2.10.0\n",
		},
		"egg-info dir": {
			"lib/site-packages/PyJWT-2.10.0.egg-info/PKG-INFO": "Metadata-Version: 1.0\nName: PyJWT\nVersion: 2.10.0\n",
		},
		"egg-info file": {
			"lib/site-packages/PyJWT-2.10.0.egg-info": "Metadata-Version: 1.0\nName: PyJWT\nVersion: 2.10.0\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			tree := map[string]string{"requirements.txt": "pyjwt==2.8.0\n"}
			for k, v := range files {
				tree[k] = v
			}
			mustUnresolvedPy(t, resolveVersion(t, writeTree(t, tree), "pyjwt"))
		})
	}
}

// A symlinked site-packages that leaves the build dir is an unread surface.
func TestResolveVersions_SitePackagesLinkOutsideVetoes(t *testing.T) {
	outside := writeTree(t, map[string]string{
		"PyJWT-2.10.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: PyJWT\nVersion: 2.10.0\n",
	})
	dir := writeTree(t, map[string]string{"requirements.txt": "pyjwt==2.8.0\n"})
	if err := os.MkdirAll(filepath.Join(dir, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "lib", "site-packages")); err != nil {
		t.Fatal(err)
	}
	mustVetoedPy(t, dir, "pyjwt")
}

// A package link inside site-packages that leaves the build dir is an unread copy; one that
// stays inside it is read at its target, once.
func TestResolveVersions_SitePackagesEntryLink(t *testing.T) {
	const meta = "Metadata-Version: 2.1\nName: PyJWT\nVersion: 2.8.0\n"
	outside := writeTree(t, map[string]string{"PyJWT-2.10.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: PyJWT\nVersion: 2.10.0\n"})
	escaping := writeTree(t, map[string]string{
		"requirements.txt": "pyjwt==2.8.0\n",
		"lib/site-packages/PyJWT-2.8.0.dist-info/METADATA": meta,
	})
	if err := os.Symlink(filepath.Join(outside, "PyJWT-2.10.0.dist-info"), filepath.Join(escaping, "lib", "site-packages", "PyJWT-2.10.0.dist-info")); err != nil {
		t.Fatal(err)
	}
	mustVetoedPy(t, escaping, "pyjwt")

	inside := writeTree(t, map[string]string{
		"requirements.txt": "pyjwt==2.8.0\n",
		"lib/site-packages/PyJWT-2.8.0.dist-info/METADATA": meta,
	})
	if err := os.Symlink(filepath.Join(inside, "lib", "site-packages", "PyJWT-2.8.0.dist-info"), filepath.Join(inside, "lib", "site-packages", "linked.dist-info")); err != nil {
		t.Fatal(err)
	}
	mustResolvedCompletePy(t, inside, "pyjwt", "2.8.0")
}

// An import of a project only an unread surface declares carries tool_failure in the call
// graph, wherever the shared walk finds that surface.
func TestCallGraph_UnreadInstallSurfaceIsToolFailure(t *testing.T) {
	const app = "import othermod\n\ndef f():\n    return othermod.go()\n"
	for name, tc := range map[string]struct {
		file, body  string
		toolFailure bool
	}{
		"pylock":    {"pylock.toml", "lock-version = \"1.0\"\n[[packages]]\nname = \"othermod\"\nversion = \"1.0\"\n", true},
		"rye lock":  {"requirements.lock", "othermod==1.0\n", true},
		"tox":       {"tox.ini", "[testenv]\ndeps = othermod\n", true},
		"conda":     {"conda-env.yml", "dependencies:\n  - pip:\n    - othermod==1.0\n", true},
		"build dir": {"build/requirements.txt", "othermod==1.0\n", true},
		"lowercase": {"pipfile", "[packages]\nothermod = \"*\"\n", true},
		"docs only": {"docs/usage.md", "# Usage\n\nRun `pip install othermod`.\n", false},
		"empty tox": {"tox.ini", "[testenv]\ncommands = pytest\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: writeTree(t, map[string]string{
				"requirements.txt": "flask==3.0.0\n",
				tc.file:            tc.body,
				"app.py":           app,
			})})
			if err != nil {
				t.Fatalf("CallGraph: %v", err)
			}
			if got := hasReason(res.Partiality, plugin.PartialReasonToolFailure); got != tc.toolFailure {
				t.Fatalf("tool_failure = %v, want %v (%+v)", got, tc.toolFailure, res.Partiality)
			}
		})
	}
}

// The content rule takes a file for a requirements file only when every line is one and one
// line carries a version clause, a direct reference or an option.
func TestRequirementLinesContent(t *testing.T) {
	for src, want := range map[string]bool{
		"pyjwt==2.10.0\n":                             true,
		"flask>=2.0\n# comment\nrequests\n":           true,
		"pkg @ https://example.com/p.whl\n":           true,
		"--index-url https://x\nflask\n":              true,
		"flask[async] (>=2.0) ; python_version>'3'\n": true,
		"flask\nrequests\n":                           false,
		"1.2.3\n":                                     false,
		"ref: refs/heads/main\n":                      false,
		"Install flask 2.0 or later.\n":               false,
		"registry=https://example.com\n":              false,
		"":                                            false,
	} {
		if got := requirementLinesContent(src); got != want {
			t.Errorf("requirementLinesContent(%q) = %v, want %v", src, got, want)
		}
	}
}

// A NUL in a file's head makes buildtree.Head report it binary, but pip reads past one in a
// comment, so a surface only its content marks is judged with the NUL removed or made a
// newline (buildtree.NULHeadMatch), and vetoes the root pin. A binary file that holds no
// surface does not.
func TestResolveVersions_NULHeadSurfaceVetoes(t *testing.T) {
	for name, tc := range map[string]struct{ file, body string }{
		"Pipfile tables":    {"svc/deps.toml", "# pinned deps for the worker svc...\n#\x00\n[packages]\npyjwt = \"==2.10.0\"\n"},
		"requirement lines": {"svc/deps.pins", "# pinned deps for the worker svc...\n#\x00\npyjwt==2.10.0\n"},
	} {
		t.Run(name, func(t *testing.T) {
			mustVetoedPy(t, writeTree(t, map[string]string{
				"requirements.txt": "pyjwt==2.8.0\n",
				tc.file:            tc.body,
			}), "pyjwt")
		})
	}
	t.Run("binary control", func(t *testing.T) {
		res := resolveVersion(t, writeTree(t, map[string]string{
			"requirements.txt": "pyjwt==2.8.0\n",
			"svc/blob.bin":     "\x00\x01\x02\x03",
		}), "pyjwt")
		if !res.Match.Resolved || res.Match.Version != "2.8.0" || !res.Partiality.Complete {
			t.Fatalf("got %+v, %+v; want 2.8.0, complete", res.Match, res.Partiality)
		}
	})
}

// A manifest in UTF-16 or UTF-32 behind its byte-order mark, which pip decodes, is not read by
// readers that take its bytes as UTF-8, so it vetoes the pin another manifest records rather
// than leave that pin standing.
func TestResolveVersions_WideMarkedManifestVetoes(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"UTF-16LE requirements.txt beside uv.lock": {"uv.lock": exUVLock, "pyproject.toml": exPyproject, "requirements.txt": encodeBOM("UTF-16LE", "flask==2.0.0\r\n")},
		"UTF-16BE requirements.txt beside uv.lock": {"uv.lock": exUVLock, "pyproject.toml": exPyproject, "requirements.txt": encodeBOM("UTF-16BE", "flask==2.0.0\n")},
		"UTF-32BE requirements.txt beside uv.lock": {"uv.lock": exUVLock, "pyproject.toml": exPyproject, "requirements.txt": encodeBOM("UTF-32BE", "flask==2.0.0\n")},
		"UTF-16LE tox.ini":                         {"uv.lock": exUVLock, "pyproject.toml": exPyproject, "tox.ini": encodeBOM("UTF-16LE", "[testenv]\ndeps = flask==2.0.0\n")},
	} {
		t.Run(name, func(t *testing.T) { mustVetoedPy(t, writeTree(t, files), "flask") })
	}
}

// A pyproject.toml that configures pixi is unread on the version path, as a pixi.toml is: pixi
// installs from its own dependency tables, which can name another version of a [project]
// dependency, and this reader does not read them. The declared pin is unresolved.
func TestResolveVersions_PyprojectPixiUnread(t *testing.T) {
	const project = "[project]\nname = \"app\"\ndependencies = [\"pyjwt==2.8.0\"]\n"
	for name, pixi := range map[string]string{
		"pypi-dependencies":         "[tool.pixi.pypi-dependencies]\npyjwt = \"==2.10.0\"\n",
		"conda dependencies":        "[tool.pixi.dependencies]\npyjwt = \"2.10.0.*\"\n",
		"feature pypi-dependencies": "[tool.pixi.feature.dev.pypi-dependencies]\npyjwt = \"==2.10.0\"\n",
		"workspace only":            "[tool.pixi.workspace]\nchannels = [\"conda-forge\"]\nplatforms = [\"linux-64\"]\n",
	} {
		t.Run(name, func(t *testing.T) {
			mustVetoedPy(t, writeTree(t, map[string]string{"pyproject.toml": project + pixi}), "pyjwt")
		})
	}
	t.Run("another tool table still resolves", func(t *testing.T) {
		mustResolvedCompletePy(t, writeTree(t, map[string]string{
			"pyproject.toml": project + "[tool.ruff]\nline-length = 100\n",
		}), "pyjwt", "2.8.0")
	})
}
