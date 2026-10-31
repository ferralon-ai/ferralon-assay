package pythonanalysis

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func scriptNodes(t *testing.T, dir string) ([]string, plugin.Partiality) {
	t.Helper()
	inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, n := range inv.Nodes {
		if !strings.HasPrefix(n.ID, "requirements.txt#") {
			got = append(got, n.ID+" "+n.PURL)
		}
	}
	slices.Sort(got)
	if _, ok := nodeByPURL(inv, "pkg:pypi/flask@3.0.0"); !ok {
		t.Error("the requirements.txt node is missing")
	}
	return got, inv.Partiality
}

// A package a build script's pip install names joins the inventory, scoped to the script or to
// the -r file it names. The inventory's partiality is what the manifests alone give it.
func TestInventory_ScriptInstalls(t *testing.T) {
	const pyprojectFileDirective = "[project]\nname = \"x\"\nversion = \"1\"\ndynamic = [\"dependencies\"]\n" +
		"[tool.setuptools.dynamic]\ndependencies = {file = [\"reqs/base.txt\"]}\n"
	tests := []struct {
		name  string
		files map[string]string // beside requirements.txt flask==3.0.0
		want  []string          // script node ID PURL pairs, sorted
	}{
		{"a bare pip install", map[string]string{"install.sh": "pip install pyjwt==1.5.0\n"},
			[]string{"install.sh#pyjwt pkg:pypi/pyjwt@1.5.0"}},
		{"a range stays unversioned", map[string]string{"install.sh": "pip install pyjwt\n"},
			[]string{"install.sh#pyjwt pkg:pypi/pyjwt"}},
		{"a -r file no manifest reads", map[string]string{"install.sh": "pip install -r deps/extra.in\n", "deps/extra.in": "pyjwt==1.5.0\n"},
			[]string{"deps/extra.in#pyjwt pkg:pypi/pyjwt@1.5.0"}},
		{"an attached -r", map[string]string{"install.sh": "pip install -rdeps/extra.in\n", "deps/extra.in": "pyjwt==1.5.0\n"},
			[]string{"deps/extra.in#pyjwt pkg:pypi/pyjwt@1.5.0"}},
		{"uv's --requirements", map[string]string{"install.sh": "uv pip install --requirements deps/extra.in\n", "deps/extra.in": "pyjwt==1.5.0\n"},
			[]string{"deps/extra.in#pyjwt pkg:pypi/pyjwt@1.5.0"}},
		{"a script's -r resolves from the directory it runs in", map[string]string{"ci/install.sh": "pip install --requirement=extra.in\n",
			"ci/extra.in": "pyjwt==1.5.0\n", "extra.in": "decoy==9.9\n"},
			[]string{"ci/extra.in#pyjwt pkg:pypi/pyjwt@1.5.0"}},
		{"a -r resolves after cd", map[string]string{"install.sh": "cd deps && pip install -r extra.in\n",
			"deps/extra.in": "pyjwt==1.5.0\n", "extra.in": "decoy==9.9\n"},
			[]string{"deps/extra.in#pyjwt pkg:pypi/pyjwt@1.5.0"}},
		{"a workflow -r resolves from the workspace", map[string]string{
			".github/workflows/ci.yml": "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pip install -r dev.in\n",
			"dev.in":                   "pyjwt==1.5.0\n", ".github/workflows/dev.in": "decoy==9.9\n"},
			[]string{"dev.in#pyjwt pkg:pypi/pyjwt@1.5.0"}},
		{"a -r from a step that may run in two directories names nothing", map[string]string{
			".github/workflows/ci.yml": "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n" +
				"      - run: pip install -r dev.in\n        working-directory: svc\n      - run: pip install -r dev.in\n",
			"svc/dev.in": "pyjwt==1.5.0\n", "dev.in": "decoy==9.9\n"}, nil},
		{"a -r after a cd on an earlier recipe line names nothing", map[string]string{
			"Makefile": "deps:\n\tcd deps\n\tpip install -r extra.in\n", "deps/extra.in": "pyjwt==1.5.0\n", "extra.in": "decoy==9.9\n"}, nil},
		{"a -r pylock.toml is read as a lock", map[string]string{"install.sh": "uv pip install -r deps/pylock.toml\n",
			"deps/pylock.toml": "lock-version = \"1.0\"\ncreated-by = \"uv\"\n[[packages]]\nname = \"PyJWT\"\nversion = \"1.5.0\"\n" +
				"[[packages]]\nname = \"pywin32\"\nversion = \"306\"\nmarker = \"sys_platform == 'win32'\"\n"},
			[]string{"deps/pylock.toml#pyjwt pkg:pypi/pyjwt@1.5.0", "deps/pylock.toml#pywin32 pkg:pypi/pywin32@306"}}, // an unbound marker keeps it
		{"a pylock.toml's sources, extras and groups", map[string]string{"install.sh": "uv pip install --extra-index-url https://x -r pylock.toml --extra docs\n",
			"pylock.toml": "lock-version = \"1.0\"\nextras = [\"docs\", \"test\"]\ndefault-groups = [\"dev\"]\n" +
				"[[packages]]\nname = \"myproj\"\ndirectory = { path = \".\", editable = true }\n" +
				"[[packages]]\nname = \"forked\"\nversion = \"1.0\"\nvcs = { type = \"git\", url = \"https://x/forked\", commit-id = \"abc\" }\n" +
				"[[packages]]\nname = \"sphinx\"\nversion = \"7.0\"\nmarker = \"'docs' in extras\"\n" +
				"[[packages]]\nname = \"pytest\"\nversion = \"8.0\"\nmarker = \"'test' in extras\"\n" +
				"[[packages]]\nname = \"ruff\"\nversion = \"0.5\"\nmarker = \"'dev' in dependency_groups\"\n" +
				"[[packages]]\nname = \"mypy\"\nversion = \"1.0\"\nmarker = \"'lint' in dependency_groups\"\n"},
			[]string{"pylock.toml#forked pkg:pypi/forked", "pylock.toml#ruff pkg:pypi/ruff@0.5", "pylock.toml#sphinx pkg:pypi/sphinx@7.0"}},
		{"pip cannot install a -r pylock.toml", map[string]string{"install.sh": "pip install -r pylock.toml\n",
			"pylock.toml": "lock-version = \"1.0\"\n[[packages]]\nname = \"pyjwt\"\nversion = \"1.5.0\"\n"}, nil},
		{"a -r of project metadata names nothing", map[string]string{"install.sh": "uv pip install -r deps/setup.cfg -r deps/other.toml\n",
			"deps/setup.cfg": "[metadata]\nname = x\n", "deps/other.toml": "[tool]\nx = 1\n"}, nil},
		{"a -r file outside the tree", map[string]string{"Dockerfile": "FROM python:3.12\nRUN pip install -r /app/extra.in\n"}, nil},
		{"a -r file two surfaces install is read once", map[string]string{"a.sh": "pip install -r deps/extra.in\n", "b.sh": "pip install -r deps/extra.in -r deps/extra.in\n",
			"deps/extra.in": "pyjwt==1.5.0\n"},
			[]string{"deps/extra.in#pyjwt pkg:pypi/pyjwt@1.5.0"}},
		{"a -r file a manifest already reads", map[string]string{"a.sh": "pip install -r reqs/base.txt --index-url https://x\n",
			"reqs/base.txt": "pyjwt==1.5.0\n", "pyproject.toml": pyprojectFileDirective},
			[]string{"pyproject.toml#pyjwt pkg:pypi/pyjwt@1.5.0"}}, // the manifest's own node
		{"a Dockerfile RUN", map[string]string{"Dockerfile": "FROM python:3.12\nRUN pip install pyjwt==1.5.0\n"},
			[]string{"Dockerfile#pyjwt pkg:pypi/pyjwt@1.5.0"}},
		{"python -m pip and uv pip", map[string]string{"ci.sh": "uv pip install pyjwt\npython3 -m pip install 'requests[socks]==2.0'\n"},
			[]string{"ci.sh#pyjwt pkg:pypi/pyjwt", "ci.sh#requests pkg:pypi/requests@2.0"}},
		{"every install in a surface, one name twice", map[string]string{"install.sh": "pip install a==1\npip install a==2\npip install a==2\n"},
			[]string{"install.sh#a pkg:pypi/a@1", "install.sh#a#2 pkg:pypi/a@2"}},
		{"installs past a command withheld for another reason", map[string]string{"install.sh": "pip install a==1\napt-get install -y python3-dev\npip install pyjwt==1.5.0\n"},
			[]string{"install.sh#a pkg:pypi/a@1", "install.sh#pyjwt pkg:pypi/pyjwt@1.5.0"}},
		{"options and their values are not requirements", map[string]string{"install.sh": "pip install -i https://x/simple --no-deps -c c.txt " +
			"--resume-retries 3 --build-constraint bc.txt --uploaded-prior-to 2025-01-01 --only-final :all: --install-option=--x -qU pyjwt==1.5.0\n"},
			[]string{"install.sh#pyjwt pkg:pypi/pyjwt@1.5.0"}},
		{"uv option values are not requirements", map[string]string{"install.sh": "uv pip install -P requests --reinstall-package flask --system pyjwt==1.5.0\n"},
			[]string{"install.sh#pyjwt pkg:pypi/pyjwt@1.5.0"}},
		{"value-less options and --", map[string]string{"install.sh": "uv pip install --system --no-cache --use-pep517 --verify-hashes a==1 -- b==2\n"},
			[]string{"install.sh#a pkg:pypi/a@1", "install.sh#b pkg:pypi/b@2"}},
		{"paths, archives, URLs and editables name nothing", map[string]string{"install.sh": "pip install . -e ./lib ./dist/a-1.0-py3-none-any.whl a-1.0.tar.gz git+https://x/y\n"}, nil},
		{"a wildcard version is a requirement", map[string]string{"install.sh": "pip install 'transformers==4.51.*'\n"},
			[]string{"install.sh#transformers pkg:pypi/transformers"}},
		{"more archives and globs name nothing", map[string]string{"install.sh": "pip install a-1.0.tar.xz b-2.0.tbz c-1.txz d-1.tar.lzma pyjwt* e?\n"}, nil},
		{"an expansion names nothing", map[string]string{"install.sh": "pip install $PKG\n"}, nil},
		{"a sample hook git never runs", map[string]string{".git/hooks/pre-commit.sample": "#!/bin/sh\npip install evil==1\n"}, nil},
		{"a self-upgrade in a sample hook", map[string]string{".git/hooks/pre-commit.sample": "#!/bin/sh\npip install -U pip==24.0\n"}, nil},
		{"a pip self-upgrade", map[string]string{"install.sh": "pip install -U pip==24.0\n"},
			[]string{"install.sh#pip pkg:pypi/pip@24.0"}},
		{"a self-upgrade beside a script naming pip config", map[string]string{"install.sh": "pip install -U pip==24.0\n", "ci.sh": "export PIP_CONFIG_FILE=x\n"},
			[]string{"install.sh#pip pkg:pypi/pip@24.0"}},
		{"an allowed -r of a read manifest adds nothing", map[string]string{"install.sh": "pip install -r requirements.txt\n"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"requirements.txt": "flask==3.0.0\n"}
			for k, v := range tt.files {
				files[k] = v
			}
			dir := writeTree(t, files)
			got, partiality := scriptNodes(t, dir)
			if !slices.Equal(got, tt.want) {
				t.Errorf("script nodes = %q, want %q", got, tt.want)
			}
			if !partiality.Complete {
				t.Errorf("partiality = %+v, want complete: the manifests are read in full", partiality)
			}
			if again, _ := scriptNodes(t, dir); !slices.Equal(again, got) {
				t.Errorf("second run = %q, want %q", again, got)
			}
		})
	}
}

// A -r file that is a symlink out of the build tree names nothing.
func TestInventory_ScriptInstallSymlinkEscape(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "host.in")
	if err := os.WriteFile(outside, []byte("hostonly==6.6.6\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := writeTree(t, map[string]string{"requirements.txt": "flask==3.0.0\n", "install.sh": "pip install -r deps/extra.in\n"})
	if err := os.MkdirAll(filepath.Join(dir, "deps"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "deps", "extra.in")); err != nil {
		t.Fatal(err)
	}
	if got, _ := scriptNodes(t, dir); len(got) != 0 {
		t.Errorf("script nodes = %q, want none", got)
	}
}

// Recording the runs changes nothing version resolution reads from the script surfaces.
func TestScanSurfaces_RecordingLeavesVersionSurfaces(t *testing.T) {
	trees := []map[string]string{
		{"install.sh": "pip install pyjwt==1.5.0\npip install -r deps/extra.in\n", "deps/extra.in": "a==1\n"},
		{"install.sh": "pip install -U pip==24.0\npip install -r requirements.txt\n"},
		{"install.sh": "pip install -U pip\n", "ci.sh": "export PIP_CONFIG_FILE=x\n"},
		{"Dockerfile": "FROM python:3.12\nRUN pip install pyjwt==1.5.0\n", ".git/hooks/pre-commit.sample": "pip install -U pip\n"},
		{"install.sh": "sed -i s/a/b/ requirements.txt\npip install -r requirements.txt\ncd deps && pip install -r extra.in\n"},
	}
	for i, files := range trees {
		files["requirements.txt"] = "flask==3.0.0\n"
		dir := writeTree(t, files)
		m1, u1, w1, i1, t1 := versionSurfaces(dir)
		var runs []scriptRun
		m2, u2, w2, i2, t2 := scanSurfaces(dir, &runs)
		if !reflect.DeepEqual([]any{m1, u1, w1, i1, t1}, []any{m2, u2, w2, i2, t2}) {
			t.Errorf("tree %d: recording changed versionSurfaces: %v %v %v %v %v, want %v %v %v %v %v", i, m2, u2, w2, i2, t2, m1, u1, w1, i1, t1)
		}
	}
}

// A wide-marked manifest a script names with -r is the manifest's own, not a second read.
func TestInventory_ScriptInstallWideManifest(t *testing.T) {
	wide := []byte{0xFF, 0xFE}
	for _, c := range "flask==3.0.0\n" {
		wide = append(wide, byte(c), 0)
	}
	count := func(files map[string]string) int {
		dir := writeTree(t, files)
		if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), wide, 0o644); err != nil {
			t.Fatal(err)
		}
		inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
		if err != nil {
			t.Fatal(err)
		}
		return len(inv.Nodes)
	}
	if without, with := count(map[string]string{"a.txt": ""}), count(map[string]string{"install.sh": "pip install -r requirements.txt\n"}); with != without {
		t.Errorf("nodes = %d with the -r, want %d", with, without)
	}
}
