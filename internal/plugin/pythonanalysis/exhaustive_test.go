package pythonanalysis

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
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
	exPyproject    = "[project]\nname = \"app\"\ndependencies = [\"flask>=3\"]\n"
	exDynPyproject = "[project]\nname = \"app\"\ndynamic = [\"dependencies\"]\n"
	exSetupCfgFile = "[metadata]\nname = app\n[options]\ninstall_requires = file: deps.txt\n"
)

// Exhaustive covers the whole build dir: a manifest the resolver skipped or never parses, an
// include it did not follow, a pyproject group its lock does not hold, or an installed copy of
// the coordinate each withholds it. Every row keeps a uv.lock that would otherwise prove PyJWT
// absent.
func TestResolveVersions_ExhaustiveInstallSurface(t *testing.T) {
	// nulAt pads a comment so a NUL lands at byte off, then puts rest on the next line.
	nulAt := func(off int, rest string) string { return "# " + strings.Repeat("x", off-2) + "\x00\n" + rest }
	// utf16 encodes ASCII s as UTF-16 behind its byte-order mark.
	utf16 := func(bigEndian bool, s string) string {
		var b strings.Builder
		if bigEndian {
			b.WriteString("\xfe\xff")
		} else {
			b.WriteString("\xff\xfe")
		}
		for _, c := range []byte(s) {
			if bigEndian {
				b.WriteByte(0)
				b.WriteByte(c)
			} else {
				b.WriteByte(c)
				b.WriteByte(0)
			}
		}
		return b.String()
	}
	// utf32LE encodes ASCII s as UTF-32LE behind its byte-order mark.
	utf32LE := func(s string) string {
		b := []byte("\xff\xfe\x00\x00")
		for _, c := range []byte(s) {
			b = append(b, c, 0, 0, 0)
		}
		return string(b)
	}
	// commentsTo is comment lines filling n characters.
	commentsTo := func(n int) string {
		line := "# " + strings.Repeat("x", 61) + "\r\n"
		return strings.Repeat(line, n/len(line)) + "#" + strings.Repeat("x", n%len(line)-2) + "\r\n"
	}
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

		// Requirement files named by setup.cfg "file:" and pyproject dynamic metadata.
		{"setup.cfg file: locked names", map[string]string{"setup.cfg": exSetupCfgFile, "deps.txt": "flask>=3\n"}, true},
		{"setup.cfg file: unlocked name", map[string]string{"setup.cfg": exSetupCfgFile, "deps.txt": "flask>=3\nrequests\n"}, false},
		{"setup.cfg file: missing", map[string]string{"setup.cfg": exSetupCfgFile}, false},
		{"dynamic dependencies from setuptools file, locked", map[string]string{"pyproject.toml": exDynPyproject + "[tool.setuptools.dynamic]\ndependencies = {file = [\"deps.txt\"]}\n", "deps.txt": "flask>=3\n"}, true},
		{"dynamic dependencies from setuptools file, unlocked", map[string]string{"pyproject.toml": exDynPyproject + "[tool.setuptools.dynamic]\ndependencies = {file = [\"deps.txt\"]}\n", "deps.txt": "requests\n"}, false},
		{"dynamic dependencies from setup.cfg beside it", map[string]string{"pyproject.toml": exDynPyproject, "setup.cfg": "[metadata]\nname = app\n[options]\ninstall_requires = flask>=3\n"}, true},
		{"dynamic dependencies from an unread hatchling hook", map[string]string{"pyproject.toml": "[build-system]\nbuild-backend = \"hatchling.build\"\n" + exDynPyproject, "setup.cfg": "[flake8]\nmax-line-length = 100\n"}, false},
		{"dynamic dependencies with no source", map[string]string{"pyproject.toml": exDynPyproject}, false},

		// setup.py and hatch_build.py are read only when their dependencies are literal.
		{"setup.py literal install_requires", map[string]string{"setup.py": "from setuptools import setup\nsetup(name=\"app\", install_requires=[\"flask>=3\"])\n"}, true},
		{"setup.py computed install_requires", map[string]string{"setup.py": "from setuptools import setup\nREQS = open(\"deps.txt\").read().split()\nsetup(name=\"app\", install_requires=REQS)\n"}, false},
		{"setup.py install_requires extended", map[string]string{"setup.py": "from setuptools import setup\ninstall_requires = [\"flask>=3\"]\ninstall_requires.append(\"pyjwt\")\nsetup(name=\"app\", install_requires=install_requires)\n"}, false},
		{"setup.py splatted options", map[string]string{"setup.py": "from setuptools import setup\nsetup(name=\"app\", **load_options())\n"}, false},
		{"setup.py literal extras_require, unlocked", map[string]string{"setup.py": "from setuptools import setup\nsetup(name=\"app\", extras_require={\"http\": [\"requests\"]})\n"}, false},
		{"setup.py literal extras_require, locked", map[string]string{"setup.py": "from setuptools import setup\nsetup(name=\"app\", extras_require={\"web\": [\"jinja2\"], \"all\": [\"flask\", \"jinja2\"]})\n"}, true},
		{"setup.py computed extras_require", map[string]string{"setup.py": "from setuptools import setup\nsetup(name=\"app\", extras_require=EXTRAS)\n"}, false},
		{"hatch_build.py", map[string]string{"hatch_build.py": "from hatchling.metadata.plugin.interface import MetadataHookInterface\n"}, false},

		// A NUL makes buildtree.Head report a file binary, but pip reads past one in a comment, so
		// requirement lines found by content are judged with the NUL removed or made a newline.
		{"requirement lines by content", map[string]string{"deps.pins": "pyjwt==2.8.0\n"}, false},
		{"requirement lines by content, NUL at byte 40", map[string]string{"deps.pins": nulAt(40, "pyjwt==2.8.0\n")}, false},
		{"requirement lines by content, NUL past byte 8000", map[string]string{"deps.pins": nulAt(8100, "pyjwt==2.8.0\n")}, false},
		{"requirement lines by content, NUL splitting the requirement", map[string]string{"deps.pins": "pyjwt\x00==2.8.0\n"}, false},
		{"requirement lines by content, NUL ending a comment", map[string]string{"deps.pins": "# pins\x00pyjwt==2.8.0\n"}, false},
		// pip decodes a requirements file by its byte-order mark; Windows PowerShell 5 writes
		// `pip freeze >` as UTF-16LE with one.
		{"requirement lines by content, UTF-16LE with a BOM", map[string]string{"deps.pins": utf16(false, "# pins\r\npyjwt==2.8.0\r\n")}, false},
		{"requirement lines by content, UTF-16BE with a BOM", map[string]string{"deps.pins": utf16(true, "pyjwt==2.8.0\n")}, false},
		{"requirement lines by content, UTF-8 BOM", map[string]string{"deps.pins": "\xef\xbb\xbfpyjwt==2.8.0\n"}, false},
		{"UTF-16LE text file without requirement lines", map[string]string{"notes": utf16(false, "pyjwt is not used here\n")}, true},
		// pip's UTF-16 decoder consumes a second byte-order mark.
		{"requirement lines by content, UTF-16LE with a doubled BOM", map[string]string{"deps.pins": "\xff\xfe" + utf16(false, "pyjwt==2.8.0\n")}, false},
		// A marked file is judged over its UTF-8 twin's head: HeadSize bytes of UTF-8 text, which
		// UTF-16 and UTF-32 spend more raw bytes on.
		{"requirement lines by content, UTF-16LE, first requirement at character 40000", map[string]string{"deps.pins": utf16(false, commentsTo(40000)+"pyjwt==2.8.0\r\n")}, false},
		{"requirement lines by content, UTF-32LE, first requirement at character 40000", map[string]string{"deps.pins": utf32LE(commentsTo(40000) + "pyjwt==2.8.0\r\n")}, false},
		{"UTF-8 BOM text file without requirement lines", map[string]string{"notes": "\xef\xbb\xbfpyjwt is not used here\n"}, true},
		{"binary file without requirement lines", map[string]string{"assets/logo.png": "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00"}, true},
		{"text file without requirement lines", map[string]string{"notes": "pyjwt is not used here\n"}, true},
		{"empty file", map[string]string{"deps.pins": ""}, true},
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

// A symlinked directory leaving the build dir is not followed by the walk, so what it holds goes
// unread.
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

// Pipfile.lock sections are walked in sorted key order, so All and Match are identical across
// runs. Go randomizes map iteration, so an unsorted walk fails this within a few of the 64 runs.
func TestResolveVersions_PipfileLockWalkOrderDeterministic(t *testing.T) {
	const lock = `{"default": {"zeta": {"version": "==1.0.0"}, "requests": {"version": "==2.31.0"}, "alpha": {"version": "==1.0.0"}, "mid": {"version": "==2.0.0"}},
"develop": {"requests": {"version": "==2.32.3"}, "beta": {"version": "==3.0.0"}, "gamma": {"version": "==4.0.0"}}}`
	want := []string{"alpha@1.0.0", "mid@2.0.0", "requests@2.31.0", "zeta@1.0.0", "beta@3.0.0", "gamma@4.0.0", "requests@2.32.3"}
	dir := writeTree(t, map[string]string{"Pipfile.lock": lock})
	first := resolveVersion(t, dir, "requests").Match
	for i := 0; i < 64; i++ {
		r := resolveVersion(t, dir, "requests")
		got := make([]string, 0, len(r.All))
		for _, d := range r.All {
			got = append(got, d.Coordinate+"@"+d.Version)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("run %d: All = %v, want %v", i, got, want)
		}
		if !reflect.DeepEqual(r.Match, first) {
			t.Fatalf("run %d: Match = %+v, first run %+v", i, r.Match, first)
		}
	}
}
