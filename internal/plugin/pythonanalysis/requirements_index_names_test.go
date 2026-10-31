package pythonanalysis

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"unicode/utf16"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func sortedPURLs(inv plugin.DependencyInventory) []string {
	var out []string
	for _, n := range inv.Nodes {
		out = append(out, n.PURL)
	}
	sort.Strings(out)
	return out
}

// TestRequirementsLineShapes pins which requirements lines name a PyPI node and which are
// recorded as an include, a local install, or an unnamed install (ferralon-ai/tracker#697).
func TestRequirementsLineShapes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		line     string
		wantNode string // the node's Name, "" for none
		wantKind reqKind
		includes []string
		locals   []string
		unnamed  bool
	}{
		{name: "pinned", line: "requests==2.31.0", wantNode: "requests", wantKind: reqNormal},
		{name: "parenthesized", line: "requests (>=2)", wantNode: "requests", wantKind: reqNormal},
		{name: "extras", line: "requests[socks]>=2", wantNode: "requests", wantKind: reqNormal},
		{name: "per-line option", line: "psycopg2 --no-binary psycopg2", wantNode: "psycopg2", wantKind: reqNormal},
		{name: "per-line option after pin", line: "foo==1.0 --config-settings=x=y", wantNode: "foo", wantKind: reqNormal},
		{name: "local dir with option", line: "./libs/core --config-settings=x=y", locals: []string{"./libs/core"}},
		{name: "single equals", line: "torchtext=0.3.1"},
		{name: "toml key", line: `name = "demo"`},
		{name: "toml table", line: "[project]"},
		{name: "quoted", line: `"requests"`},
		{name: "build root", line: ".", locals: []string{"."}},
		{name: "build root extras", line: ".[user]", locals: []string{"."}},
		{name: "editable root", line: "-e .", locals: []string{"."}},
		{name: "relative dir", line: "./libs/core", locals: []string{"./libs/core"}},
		{name: "editable dir", line: "--editable=libs/core", locals: []string{"libs/core"}},
		{name: "local wheel", line: "dist/My_Pkg-1.0-py3-none-any.whl", wantNode: "my-pkg", wantKind: reqURL},
		{name: "bare wheel", line: "My_Pkg-1.0-py3-none-any.whl", wantNode: "my-pkg", wantKind: reqURL},
		{name: "local sdist", line: "dist/mypkg-1.0.tar.gz", unnamed: true},
		{name: "archive url", line: "https://example.com/a/master.zip", unnamed: true},
		{name: "wheel url", line: "https://example.com/w/Foo-2.0-py3-none-any.whl", wantNode: "foo", wantKind: reqURL},
		{name: "vcs no egg", line: "git+https://github.com/o/r.git@main", unnamed: true},
		{name: "vcs egg", line: "git+https://github.com/o/r.git#egg=Foo_Bar", wantNode: "foo-bar", wantKind: reqVCS},
		{name: "editable vcs egg", line: "-e git+https://github.com/o/r.git#egg=foo", wantNode: "foo", wantKind: reqEditable},
		{name: "editable vcs no egg", line: "-e git+https://github.com/o/r.git", unnamed: true},
		{name: "direct ref vcs", line: "auto-gpt-plugin-template @ git+https://github.com/o/r@0.1", wantNode: "auto-gpt-plugin-template", wantKind: reqVCS},
		{name: "direct ref url", line: "en_core_web_sm[x] @ https://h/en_core_web_sm-3.7.1.tar.gz", wantNode: "en-core-web-sm", wantKind: reqURL},
		{name: "include", line: "-r base.txt", includes: []string{"base.txt"}},
		{name: "include long", line: "--requirement=base.txt", includes: []string{"base.txt"}},
		{name: "include attached", line: "-rbase.txt", includes: []string{"base.txt"}},
		{name: "editable attached", line: "-e.", locals: []string{"."}},
		{name: "file link", line: "file:libs/core", locals: []string{"file:libs/core"}},
		{name: "egg after another fragment param", line: "git+https://github.com/o/r#subdirectory=x&egg=r", wantNode: "r", wantKind: reqVCS},
		{name: "constraint", line: "-c constraints.txt"},
		{name: "marker false local", line: `. ; sys_platform == "nope"`},
		{name: "marker false include", line: `-r base.txt ; sys_platform == "nope"`},
		{name: "marker false unnamed", line: `https://h/a.zip ; sys_platform == "nope"`},
		{name: "marker unresolved local", line: `. ; extra_var == "x"`, locals: []string{"."}},
		{name: "index option", line: "--index-url https://example.com/simple"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rf := parseRequirementsFile([]byte(tc.line+"\n"), map[string]string{"sys_platform": "linux"}, nil)
			var got []pyReq
			for _, r := range rf.reqs {
				if r.Selected || r.Unresolved {
					got = append(got, r)
				}
			}
			switch {
			case tc.wantNode == "" && len(got) != 0:
				t.Errorf("nodes = %+v, want none", got)
			case tc.wantNode != "" && (len(got) != 1 || got[0].Name != tc.wantNode || got[0].Kind != tc.wantKind):
				t.Errorf("nodes = %+v, want one %q of kind %d", got, tc.wantNode, tc.wantKind)
			case tc.wantNode != "" && tc.wantKind != reqNormal && !containsString(got[0].Partial, plugin.PartialReasonSourceUnpinned):
				t.Errorf("%q: partial = %v, want source_unpinned", tc.wantNode, got[0].Partial)
			}
			if !reflect.DeepEqual(rf.includes, tc.includes) {
				t.Errorf("includes = %q, want %q", rf.includes, tc.includes)
			}
			if !reflect.DeepEqual(rf.locals, tc.locals) {
				t.Errorf("locals = %q, want %q", rf.locals, tc.locals)
			}
			if rf.unnamed != tc.unnamed {
				t.Errorf("unnamed = %v, want %v", rf.unnamed, tc.unnamed)
			}
		})
	}
}

// TestRequirementsByteOrderMark decodes a requirements file the way pip does: a UTF-16 file
// with a byte-order mark lists its packages rather than NUL-riddled junk.
func TestRequirementsByteOrderMark(t *testing.T) {
	enc := func(s string, le bool) []byte {
		u := utf16.Encode([]rune(s))
		out := []byte{0xFE, 0xFF}
		if le {
			out = []byte{0xFF, 0xFE}
		}
		for _, c := range u {
			if le {
				out = append(out, byte(c), byte(c>>8))
			} else {
				out = append(out, byte(c>>8), byte(c))
			}
		}
		return out
	}
	for name, data := range map[string][]byte{
		"utf-16le": enc("aiohttp==3.13.3\r\nPyYAML>=6\r\n", true),
		"utf-16be": enc("aiohttp==3.13.3\nPyYAML>=6\n", false),
		"utf-8":    append([]byte{0xEF, 0xBB, 0xBF}, "aiohttp==3.13.3\nPyYAML>=6\n"...),
	} {
		t.Run(name, func(t *testing.T) {
			var got []string
			for _, r := range resolveRequirements(data, nil, nil) {
				got = append(got, r.Name+"@"+r.Version)
			}
			if want := []string{"aiohttp@3.13.3", "PyYAML@"}; !reflect.DeepEqual(got, want) {
				t.Errorf("reqs = %q, want %q", got, want)
			}
		})
	}
}

// TestInventoryIndexNames covers the assembled inventory for ferralon-ai/tracker#697: PURLs
// carry the PEP 503 name, a line that names no project becomes no node, and the graph is
// partial (source_unpinned) only when such a line installs something the inventory does not
// otherwise enumerate.
func TestInventoryIndexNames(t *testing.T) {
	const project = "[project]\nname = \"app\"\ndependencies = [\"click==8.1.7\"]\n"
	for _, tc := range []struct {
		name         string
		files        map[string]string
		wantPURLs    []string
		wantUnpinned bool
	}{
		{
			name:      "pep 503 name",
			files:     map[string]string{"requirements.txt": "types-PyYAML==6.0.12\nZope.Interface\n"},
			wantPURLs: []string{"pkg:pypi/types-pyyaml@6.0.12", "pkg:pypi/zope-interface"},
		},
		{
			name:      "toml lines name nothing",
			files:     map[string]string{"requirements.txt": "[tool.x]\nname = \"demo\"\nrequests==2.31.0\n"},
			wantPURLs: []string{"pkg:pypi/requests@2.31.0"},
		},
		{
			name: "root self-install read",
			files: map[string]string{
				"pyproject.toml":   project,
				"requirements.txt": "-e .\n",
			},
			wantPURLs: []string{"pkg:pypi/click@8.1.7"},
		},
		{
			name: "root self-install from a subdirectory file",
			files: map[string]string{
				"pyproject.toml":        project,
				"docs/requirements.txt": ".[docs]\n",
			},
			wantPURLs: []string{"pkg:pypi/click@8.1.7"},
		},
		{
			name: "root self-install with computed setup.py deps",
			files: map[string]string{
				"setup.py":         "from setuptools import setup\nsetup(install_requires=open('r').read().split())\n",
				"requirements.txt": ".\n",
			},
			wantUnpinned: true,
		},
		{
			name: "working directory is ambiguous and one candidate is an unread project",
			files: map[string]string{
				"pyproject.toml":         project,
				"requirements.txt":       "-r build/requirements.txt\n",
				"build/requirements.txt": ".\n",
				"build/pyproject.toml":   project,
			},
			wantPURLs:    []string{"pkg:pypi/click@8.1.7"},
			wantUnpinned: true,
		},
		{
			name: "working directory is ambiguous and the other candidate is not a project",
			files: map[string]string{
				"pyproject.toml":         project,
				"requirements.txt":       "-r build/requirements.txt\n",
				"build/requirements.txt": ".\n",
			},
			wantPURLs: []string{"pkg:pypi/click@8.1.7"},
		},
		{
			name:         "self-install with no manifest",
			files:        map[string]string{"requirements.txt": ".\n"},
			wantUnpinned: true,
		},
		{
			name:         "missing local dir",
			files:        map[string]string{"pyproject.toml": project, "requirements.txt": "-e path/to/project\n"},
			wantPURLs:    []string{"pkg:pypi/click@8.1.7"},
			wantUnpinned: true,
		},
		{
			name:         "unnamed archive url",
			files:        map[string]string{"requirements.txt": "https://github.com/o/r/archive/master.zip\n"},
			wantUnpinned: true,
		},
		{
			name:      "named direct reference",
			files:     map[string]string{"requirements.txt": "IfxPy @ git+https://github.com/o/r\n"},
			wantPURLs: []string{"pkg:pypi/ifxpy"},
		},
		{
			name: "include already walked",
			files: map[string]string{
				"requirements.txt":      "-r requirements-base.txt\n",
				"requirements-base.txt": "requests==2.31.0\n",
			},
			wantPURLs: []string{"pkg:pypi/requests@2.31.0"},
		},
		{
			// pip reads an include relative to the including file only; a same-named root file
			// is not the one it reads.
			name: "include named from the build root is not read",
			files: map[string]string{
				"a/b/requirements.txt": "-r a/c/requirements.txt\n",
				"a/c/requirements.txt": "requests==2.31.0\n",
			},
			wantPURLs:    []string{"pkg:pypi/requests@2.31.0"},
			wantUnpinned: true,
		},
		{
			name: "nested include read beside its file, not the root's",
			files: map[string]string{
				"requirements.txt":     "requests==2.31.0\n-r .ci/dev.in\n",
				".ci/dev.in":           "-r requirements.txt\n",
				".ci/requirements.txt": "django==5.0\n",
			},
			wantPURLs: []string{"pkg:pypi/django@5.0", "pkg:pypi/requests@2.31.0"},
		},
		{
			name: "attached include flag",
			files: map[string]string{
				"requirements.txt": "-rinc.txt\n",
				"inc.txt":          "six==1.16.0\n",
			},
			wantPURLs: []string{"pkg:pypi/six@1.16.0"},
		},
		{
			name:         "attached editable flag",
			files:        map[string]string{"requirements.txt": "-e.\n"},
			wantUnpinned: true,
		},
		{
			name:         "file link without slashes",
			files:        map[string]string{"requirements.txt": "file:sub\n"},
			wantUnpinned: true,
		},
		{
			name: "file link to the read build root",
			files: map[string]string{
				"pyproject.toml":   project,
				"requirements.txt": "file:.\n",
			},
			wantPURLs: []string{"pkg:pypi/click@8.1.7"},
		},
		{
			// [tool.poetry] dependencies with no lock put nothing in the inventory.
			name: "root self-install of an unlocked poetry project",
			files: map[string]string{
				"pyproject.toml":   "[tool.poetry]\nname = \"app\"\n[tool.poetry.dependencies]\npython = \"^3.10\"\nrequests = \"^2.31\"\n",
				"requirements.txt": "-e .\n",
			},
			wantUnpinned: true,
		},
		{
			name: "root self-install of a locked poetry project",
			files: map[string]string{
				"pyproject.toml":   "[tool.poetry]\nname = \"app\"\n[tool.poetry.dependencies]\npython = \"^3.10\"\nRequests = \"^2.31\"\n",
				"poetry.lock":      "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n",
				"requirements.txt": "-e .\n",
			},
			wantPURLs: []string{"pkg:pypi/requests@2.31.0"},
		},
		{
			// pip installs [project].dependencies; a [tool.poetry] table beside them is not
			// what it reads.
			name: "root self-install of a poetry project with project dependencies",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"app\"\ndependencies = [\"six==1.16.0\"]\n[tool.poetry.dependencies]\nrequests = \"^2.31\"\n",
				"requirements.txt": "-e .\n",
			},
			wantPURLs: []string{"pkg:pypi/six@1.16.0"},
		},
		{
			name: "root self-install of a poetry project locked elsewhere",
			files: map[string]string{
				"pyproject.toml":   "[tool.poetry]\nname = \"app\"\n[tool.poetry.dependencies]\nrequests = \"^2.31\"\n",
				"sub/poetry.lock":  "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n",
				"requirements.txt": "-e .\n",
			},
			wantPURLs:    []string{"pkg:pypi/requests@2.31.0"},
			wantUnpinned: true,
		},
		{
			name: "attached constraint flags add nothing",
			files: map[string]string{
				"requirements.txt": "-cc.txt\n--constraint=c.txt\nsix==1.16.0\n",
				"c.txt":            "django==5.0\n",
			},
			wantPURLs: []string{"pkg:pypi/six@1.16.0"},
		},
		{
			name: "abbreviated include flag",
			files: map[string]string{
				"requirements.txt": "--requirem inc.txt\nsix==1.16.0\n",
				"inc.txt":          "django==5.0\n",
			},
			wantPURLs:    []string{"pkg:pypi/six@1.16.0"},
			wantUnpinned: true,
		},
		{
			name:         "abbreviated editable flag",
			files:        map[string]string{"requirements.txt": "--edit ./pkg\n"},
			wantUnpinned: true,
		},
		{
			// pip reads the value of "-r=inc.txt" as "=inc.txt".
			name: "short include flag with an equals sign",
			files: map[string]string{
				"requirements.txt": "-r=inc.txt\n",
				"inc.txt":          "django==5.0\n",
			},
			wantUnpinned: true,
		},
		{
			name: "include after another option",
			files: map[string]string{
				"requirements.txt": "--pre -r inc.txt\nsix==1.16.0\n",
				"inc.txt":          "django==5.0\n",
			},
			wantPURLs:    []string{"pkg:pypi/six@1.16.0"},
			wantUnpinned: true,
		},
		{
			name:         "editable after another option",
			files:        map[string]string{"requirements.txt": "--index-url https://example.com/simple -e ./pkg\n"},
			wantUnpinned: true,
		},
		{
			name: "abbreviated include after another option",
			files: map[string]string{
				"requirements.txt": "--pre --requirem inc.txt\nsix==1.16.0\n",
				"inc.txt":          "django==5.0\n",
			},
			wantPURLs:    []string{"pkg:pypi/six@1.16.0"},
			wantUnpinned: true,
		},
		{
			name: "quoted include after another option",
			files: map[string]string{
				"requirements.txt": "--pre '-rinc.txt'\nsix==1.16.0\n",
				"inc.txt":          "django==5.0\n",
			},
			wantPURLs:    []string{"pkg:pypi/six@1.16.0"},
			wantUnpinned: true,
		},
		{
			name:      "constraint after another option adds nothing",
			files:     map[string]string{"requirements.txt": "--pre -c c.txt\nsix==1.16.0\n"},
			wantPURLs: []string{"pkg:pypi/six@1.16.0"},
		},
		{
			name:      "plain options",
			files:     map[string]string{"requirements.txt": "--extra-index-url https://example.com/simple --prefer-binary\nsix==1.16.0\n"},
			wantPURLs: []string{"pkg:pypi/six@1.16.0"},
		},
		{
			name: "include followed",
			files: map[string]string{
				"requirements.txt":           "-r requirements/framework.txt\n",
				"requirements/framework.txt": "-r more.in\nPyYAML==6.0.1\n",
				"requirements/more.in":       "-r framework.txt\nrequests==2.31.0\n",
			},
			wantPURLs: []string{"pkg:pypi/pyyaml@6.0.1", "pkg:pypi/requests@2.31.0"},
		},
		{
			name:         "include missing",
			files:        map[string]string{"requirements.txt": "-r requirements/framework.txt\nrequests==2.31.0\n"},
			wantPURLs:    []string{"pkg:pypi/requests@2.31.0"},
			wantUnpinned: true,
		},
		{
			name:         "include url",
			files:        map[string]string{"requirements.txt": "-r https://example.com/req.txt\n"},
			wantUnpinned: true,
		},
		{
			name:         "include outside the build dir",
			files:        map[string]string{"requirements.txt": "-r ../outside.txt\n"},
			wantUnpinned: true,
		},
		{
			name:      "constraint is not an install",
			files:     map[string]string{"requirements.txt": "-c missing-constraints.txt\nrequests==2.31.0\n"},
			wantPURLs: []string{"pkg:pypi/requests@2.31.0"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, tc.files)
			inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			if got := sortedPURLs(inv); !reflect.DeepEqual(got, tc.wantPURLs) {
				t.Errorf("PURLs = %q, want %q", got, tc.wantPURLs)
			}
			if got := containsString(inv.Partiality.Reasons, plugin.PartialReasonSourceUnpinned); got != tc.wantUnpinned {
				t.Errorf("graph partiality = %+v, want source_unpinned=%v", inv.Partiality, tc.wantUnpinned)
			}
			if !tc.wantUnpinned && !inv.Partiality.Complete {
				t.Errorf("graph partiality = %+v, want complete", inv.Partiality)
			}
		})
	}
}

// A symlinked directory that leads back to an include's own directory does not re-include it.
func TestInventoryIncludeSymlinkLoop(t *testing.T) {
	dir := writeTree(t, map[string]string{"requirements.txt": "-r loop/requirements.txt\nrequests==2.31.0\n"})
	if err := os.Symlink(".", filepath.Join(dir, "loop")); err != nil {
		t.Skip(err)
	}
	inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sortedPURLs(inv), []string{"pkg:pypi/requests@2.31.0"}; !reflect.DeepEqual(got, want) {
		t.Errorf("PURLs = %q, want %q", got, want)
	}
	if !inv.Partiality.Complete {
		t.Errorf("graph partiality = %+v, want complete", inv.Partiality)
	}
}

// A ".." after a symlinked directory is collapsed as text, as pip's os.path.abspath does,
// so it steps back out of the link's own directory, not out of its target.
func TestInventoryIncludeDotDotAfterSymlink(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"requirements.txt":    "requests==2.31.0\n-r .link/dev.txt\n",
		".reqs/inner/dev.txt": "-r ../other.txt\n",
		".reqs/other.txt":     "django==5.0\n",
		"other.txt":           "flask==3.0\n",
	})
	if err := os.Symlink(filepath.Join(".reqs", "inner"), filepath.Join(dir, ".link")); err != nil {
		t.Skip(err)
	}
	inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sortedPURLs(inv), []string{"pkg:pypi/flask@3.0", "pkg:pypi/requests@2.31.0"}; !reflect.DeepEqual(got, want) {
		t.Errorf("PURLs = %q, want %q", got, want)
	}
	if !inv.Partiality.Complete {
		t.Errorf("graph partiality = %+v, want complete", inv.Partiality)
	}
}

// An include is read by where it leads: a symlink out of the build dir is not read, an
// absolute path into it is.
func TestInventoryIncludeResolvedPath(t *testing.T) {
	outside := writeTree(t, map[string]string{"dev.txt": "django==5.0\n"})
	for _, tc := range []struct {
		name         string
		include      func(dir string) string
		wantPURLs    []string
		wantUnpinned bool
	}{
		{
			name: "symlink to a file outside",
			include: func(dir string) string {
				if err := os.Symlink(filepath.Join(outside, "dev.txt"), filepath.Join(dir, "dev.txt")); err != nil {
					t.Skip(err)
				}
				return "dev.txt"
			},
			wantPURLs:    []string{"pkg:pypi/requests@2.31.0"},
			wantUnpinned: true,
		},
		{
			name: "absolute path inside",
			include: func(dir string) string {
				if err := os.WriteFile(filepath.Join(dir, "dev.txt"), []byte("django==5.0\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(dir, "dev.txt")
			},
			wantPURLs: []string{"pkg:pypi/django@5.0", "pkg:pypi/requests@2.31.0"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			req := "requests==2.31.0\n-r " + tc.include(dir) + "\n"
			if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(req), 0o644); err != nil {
				t.Fatal(err)
			}
			inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			if got := sortedPURLs(inv); !reflect.DeepEqual(got, tc.wantPURLs) {
				t.Errorf("PURLs = %q, want %q", got, tc.wantPURLs)
			}
			if got := containsString(inv.Partiality.Reasons, plugin.PartialReasonSourceUnpinned); got != tc.wantUnpinned {
				t.Errorf("graph partiality = %+v, want source_unpinned=%v", inv.Partiality, tc.wantUnpinned)
			}
		})
	}
}
