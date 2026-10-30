package pythonanalysis

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	// covUVLock locks requests with its socks extra recorded and that extra's package locked.
	covUVLock = `version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "requests", extra = ["socks"] }]

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }

[package.optional-dependencies]
socks = [{ name = "pysocks" }]

[[package]]
name = "pysocks"
version = "1.7.1"
source = { registry = "https://pypi.org/simple" }
`
	// covUVLockNoExtra locks requests without recording any extra.
	covUVLockNoExtra = `version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "requests" }]

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }
`
	// covUVLockExtraUnlocked records the socks extra but not the package it pulls in.
	covUVLockExtraUnlocked = `version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }

[package.optional-dependencies]
socks = [{ name = "pysocks" }]
`
	// covUVLockForked locks two requests versions, one per environment.
	covUVLockForked = `version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }
`
	// covUVLockMember also locks the svc/ workspace member.
	covUVLockMember = covUVLockNoExtra + `
[[package]]
name = "svc"
version = "0.1.0"
source = { editable = "svc" }
`
	covPoetryLock = `[[package]]
name = "requests"
version = "2.32.3"

[package.extras]
socks = ["PySocks (>=1.5.6,!=1.5.7)"]

[[package]]
name = "pysocks"
version = "1.7.1"

[metadata]
lock-version = "2.0"
`
	covPoetryLockNoPySocks = `[[package]]
name = "requests"
version = "2.32.3"

[package.extras]
socks = ["PySocks (>=1.5.6,!=1.5.7)"]

[metadata]
lock-version = "2.0"
`
	covPDMLock = `[[package]]
name = "requests"
version = "2.32.3"

[[package]]
name = "requests"
version = "2.32.3"
extras = ["socks"]
dependencies = ["requests==2.32.3", "PySocks!=1.5.7,>=1.5.6"]

[[package]]
name = "pysocks"
version = "1.7.1"
`
)

func covPyproject(deps ...string) string {
	s := "[project]\nname = \"app\"\ndependencies = ["
	for i, d := range deps {
		if i > 0 {
			s += ", "
		}
		s += "'" + d + "'"
	}
	return s + "]\n"
}

// TestResolveVersions_ExhaustiveCoverage: each governing lockfile must hold every declaration on
// its own, at a version the declared range admits, with every extra asked for recorded and its
// packages locked, and a nested project definition must be one the lock resolves. PyJWT is
// absent from every lock, so each row's Exhaustive is decided by coverage alone.
func TestResolveVersions_ExhaustiveCoverage(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		// Extras.
		{"pyproject extra recorded, its package locked", map[string]string{"uv.lock": covUVLock, "pyproject.toml": covPyproject("requests[socks]>=2.31")}, true},
		{"pyproject extra the lock does not record", map[string]string{"uv.lock": covUVLockNoExtra, "pyproject.toml": covPyproject("requests[socks]>=2.31")}, false},
		{"pyproject extra recorded, its package unlocked", map[string]string{"uv.lock": covUVLockExtraUnlocked, "pyproject.toml": covPyproject("requests[socks]>=2.31")}, false},
		{"requirements extra the lock does not record", map[string]string{"uv.lock": covUVLockNoExtra, "pyproject.toml": covPyproject("requests"), "requirements.txt": "requests[socks]==2.32.3\n"}, false},
		{"requirements extra recorded", map[string]string{"uv.lock": covUVLock, "pyproject.toml": covPyproject("requests"), "requirements.txt": "requests[socks]==2.32.3\n"}, false},
		{"requirements extra recorded, hashed", map[string]string{"uv.lock": covUVLock, "pyproject.toml": covPyproject("requests"), "requirements.txt": "requests[socks]==2.32.3 --hash=sha256:aaa\n"}, true},
		{"requirements extra recorded, hashed with a space", map[string]string{"uv.lock": covUVLock, "pyproject.toml": covPyproject("requests"), "requirements.txt": "requests[socks]==2.32.3 --hash sha256:aaa\n"}, true},
		{"requirements extra recorded, hash after another option", map[string]string{"uv.lock": covUVLock, "pyproject.toml": covPyproject("requests"), "requirements.txt": "requests[socks]==2.32.3 --no-binary=:all: --hash=sha256:aaa\n"}, true},
		{"poetry extra recorded, its package locked", map[string]string{"poetry.lock": covPoetryLock, "pyproject.toml": "[tool.poetry.dependencies]\npython = \"^3.12\"\nrequests = { version = \"^2.31\", extras = [\"socks\"] }\n"}, true},
		{"poetry extra recorded, its package unlocked", map[string]string{"poetry.lock": covPoetryLockNoPySocks, "pyproject.toml": "[tool.poetry.dependencies]\npython = \"^3.12\"\nrequests = { version = \"^2.31\", extras = [\"socks\"] }\n"}, false},
		{"pdm extra recorded", map[string]string{"pdm.lock": covPDMLock, "pyproject.toml": covPyproject("requests[socks]>=2.31")}, true},
		{"pdm extra not recorded", map[string]string{"pdm.lock": covPDMLock, "pyproject.toml": covPyproject("requests[security]>=2.31")}, false},

		// Range drift.
		{"pyproject range admits the locked version", map[string]string{"uv.lock": covUVLockNoExtra, "pyproject.toml": covPyproject("requests>=2.31,<3")}, true},
		{"pyproject range excludes the locked version", map[string]string{"uv.lock": covUVLockNoExtra, "pyproject.toml": covPyproject("requests>=2.40")}, false},
		{"requirements pin disagrees", map[string]string{"uv.lock": covUVLockNoExtra, "pyproject.toml": covPyproject("requests"), "requirements.txt": "requests==2.31.0\n"}, false},
		{"requirements compatible-release admits", map[string]string{"uv.lock": covUVLockNoExtra, "pyproject.toml": covPyproject("requests"), "requirements.txt": "requests~=2.32.0\n"}, false},
		{"requirements compatible-release admits, hashed", map[string]string{"uv.lock": covUVLockNoExtra, "pyproject.toml": covPyproject("requests"), "requirements.txt": "requests~=2.32.0 --hash=sha256:aaa\n"}, true},
		{"poetry caret admits", map[string]string{"poetry.lock": covPoetryLock, "pyproject.toml": "[tool.poetry.dependencies]\nrequests = \"^2.31\"\n"}, true},
		{"poetry caret excludes", map[string]string{"poetry.lock": covPoetryLock, "pyproject.toml": "[tool.poetry.dependencies]\nrequests = \"^3.0\"\n"}, false},
		{"poetry alternation is not read", map[string]string{"poetry.lock": covPoetryLock, "pyproject.toml": "[tool.poetry.dependencies]\nrequests = \"^2.31 || ^3.0\"\n"}, false},
		{"unmarked range must admit every locked version", map[string]string{"uv.lock": covUVLockForked, "pyproject.toml": covPyproject("requests>=2.32")}, false},
		{"marked range needs one locked version", map[string]string{"uv.lock": covUVLockForked, "pyproject.toml": covPyproject(`requests>=2.32; python_version >= "3.12"`)}, true},

		// Nested project definitions.
		{"nested pyproject the lock does not resolve", map[string]string{"uv.lock": covUVLockNoExtra, "pyproject.toml": covPyproject("requests"), "svc/pyproject.toml": "[project]\nname = \"svc\"\ndependencies = [\"requests\"]\n"}, false},
		{"nested pyproject that is a workspace member", map[string]string{"uv.lock": covUVLockMember, "pyproject.toml": covPyproject("requests"), "svc/pyproject.toml": "[project]\nname = \"svc\"\ndependencies = [\"requests\"]\n"}, true},
		{"nested requirements file", map[string]string{"uv.lock": covUVLockNoExtra, "pyproject.toml": covPyproject("requests"), "svc/requirements.txt": "requests>=2\n"}, false},
		{"nested requirements file, closed under the lock", map[string]string{"uv.lock": covUVLockNoExtra, "pyproject.toml": covPyproject("requests"), "svc/requirements.txt": "requests==2.32.3\n"}, true},
		{"nested requirements file, hashed", map[string]string{"uv.lock": covUVLockNoExtra, "pyproject.toml": covPyproject("requests"), "svc/requirements.txt": "requests==2.32.3 --hash=sha256:aaa\n"}, true},
		{"nested setup.py the lock does not resolve", map[string]string{"uv.lock": covUVLockNoExtra, "pyproject.toml": covPyproject("requests"), "svc/setup.py": "from setuptools import setup\nsetup(name=\"svc\", install_requires=[\"requests\"])\n"}, false},
		{"nested project with its own lock", map[string]string{"uv.lock": covUVLockNoExtra, "pyproject.toml": covPyproject("requests"), "svc/pyproject.toml": "[project]\nname = \"svc\"\ndependencies = [\"requests\"]\n", "svc/uv.lock": covUVLockNoExtra}, true},

		// Per lock, never a union.
		{"two locks, only one holds the name", map[string]string{"uv.lock": exUVLock, "poetry.lock": covPoetryLock, "pyproject.toml": covPyproject("flask", "requests")}, false},
		{"two locks, both hold every name", map[string]string{"uv.lock": covUVLockNoExtra, "poetry.lock": covPoetryLock, "pyproject.toml": covPyproject("requests")}, true},
		{"nested poetry.lock inconsistent", map[string]string{"uv.lock": covUVLockNoExtra, "pyproject.toml": covPyproject("requests"), "svc/poetry.lock": "[[package]]\nname = \"flask\"\nversion = \"3.0.0\"\n\n[[package]]\nname=\"jinja2\"\nversion=\"3.1.4\"\n"}, false},

		// Build-time requirements install into an isolated build environment, not the runtime
		// one, and no lockfile records them.
		{"build-system requires unlocked", map[string]string{"uv.lock": covUVLockNoExtra, "pyproject.toml": "[build-system]\nrequires = [\"hatchling>=1.20\"]\nbuild-backend = \"hatchling.build\"\n" + covPyproject("requests")}, true},
		{"setup_requires unlocked", map[string]string{"uv.lock": covUVLockNoExtra, "pyproject.toml": covPyproject("requests"), "setup.py": "from setuptools import setup\nsetup(name=\"app\", setup_requires=[\"setuptools_scm\"], install_requires=[\"requests\"])\n"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveVersion(t, writeTree(t, tt.files), "PyJWT")
			if r.Found {
				t.Fatalf("PyJWT unexpectedly found: %+v", r.Match)
			}
			if r.Exhaustive != tt.want {
				t.Fatalf("Exhaustive = %v, want %v (partiality %+v)", r.Exhaustive, tt.want, r.Partiality)
			}
		})
	}
}

// TestResolveVersions_ExhaustiveUnreadSurfaces: install formats the resolver never parses,
// symlinks, and installed copies each withhold Exhaustive. Every row keeps the uv.lock and
// pyproject that would otherwise prove PyJWT absent.
func TestResolveVersions_ExhaustiveUnreadSurfaces(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"pylock.toml", map[string]string{"pylock.toml": "lock-version = \"1.0\"\n[[packages]]\nname = \"pyjwt\"\nversion = \"2.8.0\"\n"}, false},
		{"pylock.<name>.toml", map[string]string{"pylock.dev.toml": "lock-version = \"1.0\"\n[[packages]]\nname = \"pyjwt\"\nversion = \"2.8.0\"\n"}, false},
		{"rye requirements.lock", map[string]string{"requirements.lock": "pyjwt==2.8.0\n"}, false},
		{"rye requirements-dev.lock", map[string]string{"requirements-dev.lock": "pyjwt==2.8.0\n"}, false},
		{"pixi.toml pypi-dependencies", map[string]string{"pixi.toml": "[project]\nname = \"app\"\n[pypi-dependencies]\npyjwt = \">=2\"\n"}, false},
		{"pyproject configuring pixi", map[string]string{"pyproject.toml": exPyproject + "[tool.pixi.pypi-dependencies]\npyjwt = \">=2\"\n"}, false},
		{"conda-lock.yml", map[string]string{"conda-lock.yml": "package:\n- name: pyjwt\n  manager: pip\n"}, false},
		{"requirement file under any name", map[string]string{"deploy/prod.pins": "pyjwt==2.8.0 --hash=sha256:abc\n"}, false},
		{"requirement file template", map[string]string{"requirements.txt.j2": "flask=={{ flask_version }}\npyjwt>=2\n"}, false},
		{"Python TOML table under another name", map[string]string{"tools/lint.toml": "[project]\nname = \"lint\"\ndependencies = [\"pyjwt\"]\n"}, false},
		{"setup() under another name", map[string]string{"tools/setup_lint.py": "from setuptools import setup\nsetup(name=\"lint\", install_requires=[\"pyjwt\"])\n"}, false},
		{"unknown *.lock", map[string]string{"deps.lock": "pyjwt 2.8.0\n"}, false},

		{"Cargo.lock is not Python", map[string]string{"Cargo.lock": "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"}, true},
		{"a TOML snippet in docs is not a manifest", map[string]string{"docs/install.md": "```toml\n[project]\ndependencies = [\"pyjwt\"]\n```\n"}, true},
		{"a word list is not a requirement file", map[string]string{"words.txt": "apple\nbanana\ncherry\n"}, true},
		{"build-system requires is not coverage", map[string]string{"pyproject.toml": "[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n" + exPyproject}, true},

		// A build backend that vendors a dependency into the built wheel leaves its metadata on
		// the normal installed-copy path.
		{"vendored dist-info in a build tree", map[string]string{"build/lib/app/_vendor/PyJWT-2.8.0.dist-info/METADATA": "Name: PyJWT\n"}, false},
		{"vendored dist-info in the source tree", map[string]string{"src/app/_vendor/pyjwt-2.8.0.dist-info/METADATA": "Name: PyJWT\n"}, false},
		{"built wheel in dist/", map[string]string{"dist/PyJWT-2.8.0-py3-none-any.whl": "x"}, false},
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

// TestResolveVersions_ExhaustiveSymlinks: a symlinked manifest is not fully read even when its
// target is, and a symlink leaving the build dir is a surface the walk cannot read: the
// .venv/bin/python link uv sync leaves to an interpreter outside the build dir included. A
// symlinked directory inside it is read through its target when the walk reads that target
// itself (the .venv/lib64 link to lib), and not when the target is under a skipped directory.
func TestResolveVersions_ExhaustiveSymlinks(t *testing.T) {
	outside := writeTree(t, map[string]string{"python3.12": "#!binary\n"})
	tests := []struct {
		name, target, link string
		want               bool
	}{
		{"symlinked requirements file inside root", "requirements-base.txt", "requirements-dev.txt", false},
		{"symlink leaving root", filepath.Join(outside, "python3.12"), ".venv/bin/python", false},
		{"venv lib64 linked to lib", "lib", ".venv/lib64", true},
		{"directory linked into site-packages", filepath.Join(".venv", "lib", "python3.12", "site-packages"), "pkgs", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTree(t, map[string]string{
				"uv.lock": exUVLock, "pyproject.toml": exPyproject, "requirements-base.txt": "flask==3.0.0 --hash=sha256:aaa\n",
				".venv/lib/python3.12/site-packages/flask-3.0.0.dist-info/METADATA": "Name: flask\n",
			})
			if r := resolveVersion(t, root, "PyJWT"); !r.Exhaustive {
				t.Fatalf("baseline not exhaustive")
			}
			link := filepath.Join(root, tt.link)
			if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(tt.target, link); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if r := resolveVersion(t, root, "PyJWT"); r.Exhaustive != tt.want {
				t.Fatalf("Exhaustive = %v with %s, want %v (partiality %+v)", r.Exhaustive, tt.link, tt.want, r.Partiality)
			}
		})
	}
}

// Build-time requirements are declarations: found on the advisory path with their range, though
// coverage does not ask a lockfile to hold them.
func TestResolveVersions_BuildRequiresFound(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
	}{
		{"pyproject build-system requires", map[string]string{"pyproject.toml": "[build-system]\nrequires = [\"setuptools>=61\", \"PyJWT>=2.4\"]\n[project]\nname = \"app\"\n"}},
		{"setup.py setup_requires", map[string]string{"setup.py": "from setuptools import setup\nsetup(name=\"app\", setup_requires=[\"PyJWT>=2.4\"])\n"}},
		{"setup.cfg setup_requires", map[string]string{"setup.cfg": "[metadata]\nname = app\n[options]\nsetup_requires =\n    PyJWT>=2.4\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveVersion(t, writeTree(t, tt.files), "pyjwt")
			if !r.Found {
				t.Fatalf("PyJWT not found among build requirements")
			}
			if r.Match.Resolved || r.Match.Constraint != ">=2.4" {
				t.Fatalf("match = %+v, want unresolved with constraint >=2.4", r.Match)
			}
		})
	}
}

func TestPoetrySpecifier(t *testing.T) {
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"", "", true},
		{"*", "", true},
		{"^1.2.3", ">=1.2.3,<2", true},
		{"^0.2.3", ">=0.2.3,<0.3", true},
		{"^0.0.3", ">=0.0.3,<0.0.4", true},
		{"^0", ">=0,<1", true},
		{"~1.2.3", ">=1.2.3,<1.3", true},
		{"~1.2", ">=1.2,<1.3", true},
		{"~1", ">=1,<2", true},
		{"~=1.2", "~=1.2", true},
		{"1.2.3", "==1.2.3", true},
		{"1.2.*", "==1.2.*", true},
		{"=1.2.3", "==1.2.3", true},
		{">=1.2,<2.0", ">=1.2,<2.0", true},
		{">= 1.2, < 2.0", ">=1.2,<2.0", true},
		{">=1.2 <2.0", ">=1.2,<2.0", true},
		{"^1.0 || ^2.0", "", false},
		{"^1.0b1", "", false},
		{"latest", "", false},
	}
	for _, tt := range tests {
		got, ok := poetrySpecifier(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Errorf("poetrySpecifier(%q) = %q, %v; want %q, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}
