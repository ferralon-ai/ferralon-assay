package goanalysis

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/module"
	modzip "golang.org/x/mod/zip"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// srcModule is one module@version, with its source files, served by a file GOPROXY.
type srcModule struct {
	path, version string
	files         map[string]string // go.mod is added
}

// newSourceProxy writes srcModules to a file GOPROXY and points the go command at it and at an
// empty module cache, with go.sum checked as a CI build checks it (no -mod=mod).
func newSourceProxy(t *testing.T, mods []srcModule) string {
	t.Helper()
	proxy := t.TempDir()
	for _, m := range mods {
		esc, err := module.EscapePath(m.path)
		if err != nil {
			t.Fatal(err)
		}
		base := filepath.Join(proxy, esc, "@v")
		gomod := "module " + m.path + "\n\ngo 1.21\n"
		writeDir(t, base, map[string]string{
			m.version + ".info": `{"Version":"` + m.version + `","Time":"2020-01-01T00:00:00Z"}`,
			m.version + ".mod":  gomod,
			"list":              m.version + "\n",
		})
		src := t.TempDir()
		writeDir(t, src, m.files)
		writeDir(t, src, map[string]string{"go.mod": gomod})
		zf, err := os.Create(filepath.Join(base, m.version+".zip"))
		if err != nil {
			t.Fatal(err)
		}
		if err := modzip.CreateFromDir(zf, module.Version{Path: m.path, Version: m.version}, src); err != nil {
			t.Fatalf("zip %s@%s: %v", m.path, m.version, err)
		}
		zf.Close()
	}
	t.Setenv("GOPROXY", "file://"+proxy)
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOMODCACHE", writableTempDir(t))
	t.Setenv("GOPATH", writableTempDir(t))
	return proxy
}

// newApp writes example.com/app importing each of imports, with the given go.mod tail, and runs
// go mod tidy so go.mod and go.sum are complete. The module cache is left warm.
func newApp(t *testing.T, imports []string, gomodTail string, extra map[string]string) string {
	t.Helper()
	root := t.TempDir()
	app := filepath.Join(root, "app")
	var b strings.Builder
	b.WriteString("package main\n\nimport (\n")
	for _, p := range imports {
		b.WriteString("\t_ \"" + p + "\"\n")
	}
	b.WriteString(")\n\nfunc main() {}\n")
	writeDir(t, app, map[string]string{"go.mod": "module example.com/app\n\ngo 1.21\n" + gomodTail, "main.go": b.String()})
	writeDir(t, root, extra)
	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = app
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go mod tidy: %v\n%s", err, out)
	}
	return app
}

// coldCache points the go command at an empty module cache.
func coldCache(t *testing.T) { t.Setenv("GOMODCACHE", writableTempDir(t)) }

var (
	modA = srcModule{"example.com/a", "v1.0.0", map[string]string{"a.go": "package a\n\nfunc Other() {}\n"}}
	modB = srcModule{"example.com/b", "v1.0.0", map[string]string{
		"b.go":             "package b\n\nvar X = 1\n",
		"b_test.go":        "package b\n\nfunc UpdateRepoFile() {}\n",
		"testdata/x.go":    "package x\n\nfunc UpdateRepoFile() {}\n",
		"_skip/x.go":       "package x\n\nfunc UpdateRepoFile() {}\n",
		"internal/b/in.go": "package b\n\nfunc inner() {}\n",
	}}
	modFork = srcModule{"example.com/fork", "v1.0.0", map[string]string{
		"db/repo.go": "package db\n\ntype Repo struct{}\n\nfunc (*Repo) UpdateRepoFile() error { return nil }\n",
	}}
)

const gogsDB = "gogs.io/gogs/internal/db"

var gogsSymbols = []string{"UpdateRepoFile"}

func search(t *testing.T, app, pkgPath string, symbols []string) *plugin.ModuleSearch {
	t.Helper()
	return searchBuildModules(context.Background(), app, pkgPath, symbols)
}

func wantSearch(t *testing.T, got *plugin.ModuleSearch, searched, declaring []string) {
	t.Helper()
	if got == nil {
		t.Fatalf("searchBuildModules = nil, want Searched %v Declaring %v", searched, declaring)
	}
	if !slices.Equal(got.Searched, searched) || !slices.Equal(got.Declaring, declaring) {
		t.Fatalf("searchBuildModules = Searched %v Declaring %v, want Searched %v Declaring %v",
			got.Searched, got.Declaring, searched, declaring)
	}
}

func TestSearchBuildModules(t *testing.T) {
	t.Run("no module declares the symbol", func(t *testing.T) {
		newSourceProxy(t, []srcModule{modA, modB})
		app := newApp(t, []string{"example.com/a", "example.com/b"}, "", nil)
		wantSearch(t, search(t, app, gogsDB, gogsSymbols), []string{"example.com/a", "example.com/app", "example.com/b"}, nil)
	})
	t.Run("a renamed fork declares the symbol as a method", func(t *testing.T) {
		newSourceProxy(t, []srcModule{modA, modFork})
		app := newApp(t, []string{"example.com/a", "example.com/fork/db"}, "", nil)
		wantSearch(t, search(t, app, gogsDB, []string{"gogs.io/gogs/internal/db.(*Repo).UpdateRepoFile"}),
			[]string{"example.com/a", "example.com/app", "example.com/fork"}, []string{"example.com/fork"})
	})
	t.Run("the scanned module declares the symbol", func(t *testing.T) {
		newSourceProxy(t, []srcModule{modA})
		app := newApp(t, []string{"example.com/a"}, "", map[string]string{"app/repo.go": "package main\n\nconst UpdateRepoFile = 1\n"})
		wantSearch(t, search(t, app, gogsDB, gogsSymbols), []string{"example.com/a", "example.com/app"}, []string{"example.com/app"})
	})
	t.Run("cold cache downloads without touching go.mod or go.sum", func(t *testing.T) {
		newSourceProxy(t, []srcModule{modA, modFork})
		app := newApp(t, []string{"example.com/a", "example.com/fork/db"}, "", nil)
		// A module in the graph whose packages the build does not compile has only its go.mod
		// hash in go.sum; downloading it records its zip hash, which must not land here.
		rewriteZipSum(t, app, "example.com/a", "")
		before := readFiles(t, app, "go.mod", "go.sum")
		coldCache(t)
		wantSearch(t, search(t, app, gogsDB, gogsSymbols),
			[]string{"example.com/a", "example.com/app", "example.com/fork"}, []string{"example.com/fork"})
		if after := readFiles(t, app, "go.mod", "go.sum"); after != before {
			t.Errorf("the search changed the checkout's go.mod or go.sum:\nbefore:\n%s\nafter:\n%s", before, after)
		}
	})
	t.Run("a module that fails verification is not searched, nor any it was downloaded with", func(t *testing.T) {
		newSourceProxy(t, []srcModule{modA, modFork})
		app := newApp(t, []string{"example.com/a", "example.com/fork/db"}, "", nil)
		corruptZipSum(t, app, "example.com/fork")
		coldCache(t)
		// The mismatch stops the whole download, so example.com/a is left unread too.
		wantSearch(t, search(t, app, gogsDB, gogsSymbols), []string{"example.com/app"}, nil)
	})
	t.Run("a module the proxy no longer serves is not searched", func(t *testing.T) {
		proxy := newSourceProxy(t, []srcModule{modA, modFork})
		app := newApp(t, []string{"example.com/a", "example.com/fork/db"}, "", nil)
		coldCache(t)
		listAll(t, app) // the module graph resolves; only the zip is missing
		if err := os.Remove(filepath.Join(proxy, "example.com", "fork", "@v", "v1.0.0.zip")); err != nil {
			t.Fatal(err)
		}
		wantSearch(t, search(t, app, gogsDB, gogsSymbols), []string{"example.com/a", "example.com/app"}, nil)
	})
	t.Run("GOPROXY=off with a cold cache searches only what is on disk", func(t *testing.T) {
		newSourceProxy(t, []srcModule{modA, modFork})
		app := newApp(t, []string{"example.com/a", "example.com/fork/db"}, "", nil)
		coldCache(t)
		listAll(t, app)
		t.Setenv("GOPROXY", "off")
		wantSearch(t, search(t, app, gogsDB, gogsSymbols), []string{"example.com/app"}, nil)
	})
	t.Run("a module replace searches the replacement under both paths", func(t *testing.T) {
		newSourceProxy(t, []srcModule{modA, modFork})
		app := newApp(t, []string{"example.com/a/db"},
			"\nreplace example.com/a v1.0.0 => example.com/fork v1.0.0\n", nil)
		coldCache(t)
		got := search(t, app, gogsDB, gogsSymbols)
		wantSearch(t, got, []string{"example.com/a", "example.com/app", "example.com/fork"}, []string{"example.com/a"})
	})
	localA := func(extra map[string]string) map[string]string {
		files := map[string]string{"locala/go.mod": "module example.com/a\n\ngo 1.21\n", "locala/a.go": "package a\n\nfunc Other() {}\n"}
		for k, v := range extra {
			files[k] = v
		}
		return files
	}
	t.Run("a local-path replace without the symbol", func(t *testing.T) {
		newSourceProxy(t, nil)
		app := newApp(t, []string{"example.com/a"}, "\nrequire example.com/a v1.0.0\n\nreplace example.com/a => ../locala\n", localA(nil))
		wantSearch(t, search(t, app, gogsDB, gogsSymbols), []string{"example.com/a", "example.com/app"}, nil)
	})
	t.Run("a local-path replace declaring the symbol", func(t *testing.T) {
		newSourceProxy(t, nil)
		app := newApp(t, []string{"example.com/a"}, "\nrequire example.com/a v1.0.0\n\nreplace example.com/a => ../locala\n",
			localA(map[string]string{"locala/db/db.go": "package db\n\nfunc UpdateRepoFile() {}\n"}))
		wantSearch(t, search(t, app, gogsDB, gogsSymbols), []string{"example.com/a", "example.com/app"}, []string{"example.com/a"})
	})
	t.Run("a nested module's declaration is not the module's", func(t *testing.T) {
		newSourceProxy(t, nil)
		app := newApp(t, []string{"example.com/a"}, "\nrequire example.com/a v1.0.0\n\nreplace example.com/a => ../locala\n",
			localA(map[string]string{
				"locala/nested/go.mod": "module example.com/a/nested\n\ngo 1.21\n",
				"locala/nested/n.go":   "package nested\n\nfunc UpdateRepoFile() {}\n",
			}))
		wantSearch(t, search(t, app, gogsDB, gogsSymbols), []string{"example.com/a", "example.com/app"}, nil)
	})
	t.Run("a local-path replace with a file that does not parse is not searched", func(t *testing.T) {
		newSourceProxy(t, nil)
		app := newApp(t, []string{"example.com/a"}, "\nrequire example.com/a v1.0.0\n\nreplace example.com/a => ../locala\n",
			localA(map[string]string{"locala/broken/b.go": "package broken\n\nfunc {\n"}))
		wantSearch(t, search(t, app, gogsDB, gogsSymbols), []string{"example.com/app"}, nil)
	})
	t.Run("a module of the build holds the advisory's package", func(t *testing.T) {
		newSourceProxy(t, []srcModule{modA, modB})
		app := newApp(t, []string{"example.com/a", "example.com/b"}, "", nil)
		if got := search(t, app, "example.com/B/internal/b", gogsSymbols); got != nil {
			t.Fatalf("searchBuildModules = %+v, want nil", got)
		}
	})
	t.Run("a replacement module holds the advisory's package", func(t *testing.T) {
		newSourceProxy(t, []srcModule{modA, modFork})
		app := newApp(t, []string{"example.com/a/db"}, "\nreplace example.com/a v1.0.0 => example.com/fork v1.0.0\n", nil)
		if got := search(t, app, "example.com/fork/db", gogsSymbols); got != nil {
			t.Fatalf("searchBuildModules = %+v, want nil", got)
		}
	})
	t.Run("no symbols", func(t *testing.T) {
		newSourceProxy(t, []srcModule{modA})
		app := newApp(t, []string{"example.com/a"}, "", nil)
		if got := search(t, app, gogsDB, []string{"(*)"}); got != nil {
			t.Fatalf("searchBuildModules = %+v, want nil", got)
		}
	})
	t.Run("a vendored build", func(t *testing.T) {
		newSourceProxy(t, []srcModule{modA})
		app := newApp(t, []string{"example.com/a"}, "", nil)
		t.Setenv("GOFLAGS", "-mod=vendor")
		if got := search(t, app, gogsDB, gogsSymbols); got != nil {
			t.Fatalf("searchBuildModules = %+v, want nil", got)
		}
	})
	t.Run("GOFLAGS names a modfile", func(t *testing.T) {
		newSourceProxy(t, []srcModule{modA})
		app := newApp(t, []string{"example.com/a"}, "", nil)
		t.Setenv("GOFLAGS", "-modfile="+filepath.Join(app, "go.mod"))
		if got := search(t, app, gogsDB, gogsSymbols); got != nil {
			t.Fatalf("searchBuildModules = %+v, want nil", got)
		}
	})
	t.Run("the go env file's GOFLAGS names a modfile", func(t *testing.T) {
		newSourceProxy(t, []srcModule{modA})
		app := newApp(t, []string{"example.com/a"}, "", nil)
		goenv := filepath.Join(t.TempDir(), "env")
		if err := os.WriteFile(goenv, []byte("GOFLAGS=-modfile="+filepath.Join(app, "go.mod")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("GOENV", goenv)
		if got := search(t, app, gogsDB, gogsSymbols); got != nil {
			t.Fatalf("searchBuildModules = %+v, want nil", got)
		}
	})
}

// TestSearchBuildModules_Timeout: a download still running at moduleSearchTimeout leaves its
// module unsearched.
func TestSearchBuildModules_Timeout(t *testing.T) {
	proxy := newSourceProxy(t, []srcModule{modA, modFork})
	app := newApp(t, []string{"example.com/a", "example.com/fork/db"}, "", nil)
	coldCache(t)
	files := http.FileServer(http.Dir(proxy))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".zip") {
			<-r.Context().Done()
			return
		}
		files.ServeHTTP(w, r)
	}))
	defer srv.Close()
	t.Setenv("GOPROXY", srv.URL)
	listAll(t, app)
	defer func(d time.Duration) { moduleSearchTimeout = d }(moduleSearchTimeout)
	moduleSearchTimeout = 3 * time.Second
	start := time.Now()
	got := search(t, app, gogsDB, gogsSymbols)
	if d := time.Since(start); d > time.Minute {
		t.Errorf("search took %v, want it bounded by moduleSearchTimeout", d)
	}
	if got == nil {
		t.Fatal("searchBuildModules = nil")
	}
	if slices.Contains(got.Searched, "example.com/a") || slices.Contains(got.Searched, "example.com/fork") {
		t.Fatalf("Searched = %v, want neither downloaded module", got.Searched)
	}
}

func TestResolveDependencySymbols_ModuleSearch(t *testing.T) {
	res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir:        firstPartyFixtureDir,
		PURL:            "pkg:golang/" + gogsDB,
		AdvisorySymbols: gogsSymbols,
		VulnID:          "CVE-2024-55947",
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	if res.ModuleSearch == nil || len(res.ModuleSearch.Searched) == 0 || len(res.ModuleSearch.Declaring) != 0 {
		t.Fatalf("ModuleSearch = %+v, want the fixture's modules searched and none declaring", res.ModuleSearch)
	}
}

func TestDeclaresName(t *testing.T) {
	names := map[string]bool{"UpdateRepoFile": true}
	cases := []struct {
		name    string
		files   map[string]string
		links   map[string]string // link -> target, relative to the module root
		want    bool
		wantErr bool
	}{
		{"function", map[string]string{"x.go": "package x\n\nfunc UpdateRepoFile() {}\n"}, nil, true, false},
		{"method", map[string]string{"x.go": "package x\n\ntype T struct{}\n\nfunc (T) UpdateRepoFile() {}\n"}, nil, true, false},
		{"variable", map[string]string{"x.go": "package x\n\nvar UpdateRepoFile = func() {}\n"}, nil, true, false},
		{"constant in a group", map[string]string{"x.go": "package x\n\nconst (\n\tA = 1\n\tUpdateRepoFile = 2\n)\n"}, nil, true, false},
		{"a type of the name", map[string]string{"x.go": "package x\n\ntype UpdateRepoFile struct{}\n"}, nil, false, false},
		{"a call of the name", map[string]string{"x.go": "package x\n\nfunc f() { UpdateRepoFile() }\n"}, nil, false, false},
		{"under a build constraint", map[string]string{"x_windows.go": "//go:build windows\n\npackage x\n\nfunc UpdateRepoFile() {}\n"}, nil, true, false},
		{"test file", map[string]string{"x_test.go": "package x\n\nfunc UpdateRepoFile() {}\n"}, nil, false, false},
		{"testdata", map[string]string{"testdata/x.go": "package x\n\nfunc UpdateRepoFile() {}\n"}, nil, false, false},
		{"vendor", map[string]string{"vendor/x.go": "package x\n\nfunc UpdateRepoFile() {}\n"}, nil, false, false},
		{"dot directory", map[string]string{".x/x.go": "package x\n\nfunc UpdateRepoFile() {}\n"}, nil, false, false},
		{"underscore directory", map[string]string{"_x/x.go": "package x\n\nfunc UpdateRepoFile() {}\n"}, nil, false, false},
		{"nested module", map[string]string{"n/go.mod": "module n\n", "n/x.go": "package x\n\nfunc UpdateRepoFile() {}\n"}, nil, false, false},
		{"subdirectory", map[string]string{"a/b/x.go": "package b\n\nfunc UpdateRepoFile() {}\n"}, nil, true, false},
		{"a file that does not parse", map[string]string{"x.go": "package x\n\nfunc {\n"}, nil, false, true},
		{"a symbolic link to a .go file", map[string]string{"real/x.txt": "x"}, map[string]string{"x.go": "real/x.txt"}, false, true},
		{"a symbolic link to a directory", map[string]string{"real/x.go": "package x\n"}, map[string]string{"link": "real"}, false, true},
		{"a dangling symbolic link", nil, map[string]string{"link": "missing"}, false, true},
		{"a symbolic link to another file", map[string]string{"real/x.txt": "x"}, map[string]string{"LICENSE": "real/x.txt"}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeDir(t, dir, tc.files)
			for link, target := range tc.links {
				if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
					t.Fatal(err)
				}
			}
			got, err := declaresName(context.Background(), dir, names)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("declaresName = %v, %v; want %v, error %v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestSymbolNames(t *testing.T) {
	got := symbolNames([]string{"UpdateRepoFile", "db.Repo.Save", "gogs.io/gogs/internal/db.(*Repo).Load", "(*)", ""})
	want := map[string]bool{"UpdateRepoFile": true, "Save": true, "Load": true}
	if len(got) != len(want) {
		t.Fatalf("symbolNames = %v, want %v", got, want)
	}
	for n := range want {
		if !got[n] {
			t.Fatalf("symbolNames = %v, want %v", got, want)
		}
	}
}

func readFiles(t *testing.T, dir string, names ...string) string {
	t.Helper()
	var b bytes.Buffer
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		b.Write(data)
	}
	return b.String()
}

// corruptZipSum rewrites the go.sum hash of a module's zip, leaving its go.mod hash, so the
// module graph still resolves and only the download fails verification.
func corruptZipSum(t *testing.T, app, path string) {
	t.Helper()
	rewriteZipSum(t, app, path, "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
}

// rewriteZipSum replaces the go.sum hash of a module's zip with hash, or drops the line when
// hash is empty.
func rewriteZipSum(t *testing.T, app, path, hash string) {
	t.Helper()
	sum := filepath.Join(app, "go.sum")
	data, err := os.ReadFile(sum)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) == 3 && f[0] == path && !strings.HasSuffix(f[1], "/go.mod") {
			if hash == "" {
				continue
			}
			line = f[0] + " " + f[1] + " " + hash
		}
		out = append(out, line)
	}
	if err := os.WriteFile(sum, []byte(strings.Join(out, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
}

func listAll(t *testing.T, app string) {
	t.Helper()
	cmd := exec.Command("go", "list", "-m", "all")
	cmd.Dir = app
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go list -m all: %v\n%s", err, out)
	}
}

// vendor vendors app's dependencies, so that go list -m all no longer lists its build.
func vendor(t *testing.T, app string) {
	t.Helper()
	cmd := exec.Command("go", "mod", "vendor")
	cmd.Dir = app
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go mod vendor: %v\n%s", err, out)
	}
	if _, err := listModules(context.Background(), app); err == nil {
		t.Fatal("go list -m all listed a vendored build; the vendor fallback is untested")
	}
}

func TestDependencyHolds_UnreadableBuildList(t *testing.T) {
	if dependencyHolds(context.Background(), t.TempDir(), "example.com/a") {
		t.Fatal("a build list that cannot be read holds a dependency path; the advisory would resolve nothing")
	}
}

// TestSameDir_Unresolvable: a main module whose directory cannot be resolved is not buildDir's own, so
// a path it holds is measured as a dependency's rather than resolved name-wide as first-party.
func TestSameDir_Unresolvable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone")
	if sameDir(missing, missing) {
		t.Fatal("sameDir counts a directory it cannot resolve as buildDir's own module")
	}
}

func TestResolveDependencySymbols_DependencyScope(t *testing.T) {
	reader := map[string]string{"app/reader.go": "package main\n\ntype Reader struct{}\n\nfunc (*Reader) Verify() error { return nil }\n\nfunc Verify() bool { return true }\n"}
	modSub := srcModule{"example.com/app/sub", "v1.0.0", map[string]string{"sub.go": "package sub\n\nvar X = 1\n"}}
	resolve := func(t *testing.T, app, purl string, symbols []string) plugin.SymbolResolutionResult {
		t.Helper()
		res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{BuildDir: app, PURL: purl, AdvisorySymbols: symbols})
		if err != nil {
			t.Fatalf("ResolveDependencySymbols: %v", err)
		}
		return res
	}
	wantNone := func(t *testing.T, res plugin.SymbolResolutionResult) {
		t.Helper()
		if len(res.Resolved) != 0 || res.ModuleSearch != nil {
			t.Fatalf("Resolved %v, ModuleSearch %+v; want neither: a first-party symbol is not a dependency's", res.Resolved, res.ModuleSearch)
		}
	}
	wantFirstParty := func(t *testing.T, res plugin.SymbolResolutionResult) {
		t.Helper()
		if len(res.Resolved) != 2 {
			t.Fatalf("Resolved %v, want the app's (*Reader).Verify and Verify", res.Resolved)
		}
		for _, s := range res.Resolved {
			if s.Package != "example.com/app" {
				t.Fatalf("Resolved %v, want only example.com/app symbols", res.Resolved)
			}
		}
	}

	t.Run("dependency advisories resolve nothing in first-party code", func(t *testing.T) {
		newSourceProxy(t, []srcModule{modA})
		app := newApp(t, []string{"example.com/a"}, "", reader)
		for _, purl := range []string{"pkg:golang/example.com/a", "pkg:golang/example.com/a/ssh@v1.0.0",
			"pkg:golang/example.com/a?type=module", "pkg:golang/example.com/a#ssh", "pkg:golang/example.com/a/ssh@v1.0.0?type=module#sub",
			"pkg:Golang/example.com/a"} {
			t.Run(purl, func(t *testing.T) {
				wantNone(t, resolve(t, app, purl, []string{"example.com/a/ssh.Certificate.Verify"}))
			})
		}
		t.Run("a path no module holds still resolves by name and searches the modules", func(t *testing.T) {
			res := resolve(t, app, "pkg:golang/tegron/corpus/x", []string{"main.Verify"})
			wantFirstParty(t, res)
			wantSearch(t, res.ModuleSearch, []string{"example.com/a", "example.com/app"}, []string{"example.com/app"})
		})
		t.Run("an unloaded path of the scanned module still resolves by name", func(t *testing.T) {
			wantFirstParty(t, resolve(t, app, "pkg:golang/example.com/app/missing", []string{"main.Verify"}))
		})
	})
	t.Run("a module nested under the scanned module's path is a dependency", func(t *testing.T) {
		newSourceProxy(t, []srcModule{modSub})
		app := newApp(t, []string{"example.com/app/sub"}, "", reader)
		wantNone(t, resolve(t, app, "pkg:golang/example.com/app/sub/x", []string{"Verify"}))
	})
	t.Run("a dependency held under its replacement's path", func(t *testing.T) {
		newSourceProxy(t, []srcModule{modA})
		app := newApp(t, []string{"example.com/old"}, "\nrequire example.com/old v1.0.0\n\nreplace example.com/old v1.0.0 => example.com/a v1.0.0\n", reader)
		wantNone(t, resolve(t, app, "pkg:golang/example.com/a", []string{"example.com/a.Verify"}))
	})
	t.Run("a standard-library advisory", func(t *testing.T) {
		newSourceProxy(t, []srcModule{modA})
		app := newApp(t, []string{"example.com/a"}, "", reader)
		wantNone(t, resolve(t, app, "pkg:golang/stdlib", []string{"crypto/x509.Certificate.Verify"}))
	})
	t.Run("a standard-library or toolchain advisory resolves nothing in first-party code", func(t *testing.T) {
		newSourceProxy(t, []srcModule{modA})
		app := newApp(t, []string{"example.com/a"}, "", reader)
		for _, purl := range []string{
			"pkg:golang/stdlib@go1.22.1", "pkg:golang/stdlib?type=module", "pkg:golang/stdlib#net/http",
			"pkg:golang/stdlib@go1.22.1?os=linux#net/http", "pkg:golang/StdLib",
			"pkg:golang/toolchain", "pkg:golang/toolchain@go1.22.1", "pkg:golang/toolchain?os=linux#cmd/go",
			"pkg:golang/cmd/go", "pkg:golang/cmd/go/internal/modfetch@go1.22.1", "pkg:GOLANG/stdlib", "pkg:golang/Toolchain",
		} {
			t.Run(purl, func(t *testing.T) {
				wantNone(t, resolve(t, app, purl, []string{"Verify"}))
			})
		}
	})
	t.Run("the scanned module nested under a dependency's path holds its own paths", func(t *testing.T) {
		parent := srcModule{"example.com", "v1.0.0", map[string]string{"root.go": "package root\n\nvar X = 1\n"}}
		newSourceProxy(t, []srcModule{parent})
		app := newApp(t, []string{"example.com"}, "", reader)
		purl := "pkg:golang/example.com/app/missing"
		wantFirstParty(t, resolve(t, app, purl, []string{"main.Verify"}))
		vendor(t, app)
		wantFirstParty(t, resolve(t, app, purl, []string{"main.Verify"}))
		wantNone(t, resolve(t, app, "pkg:golang/example.com/x", []string{"example.com/x.Verify"}))
	})
	t.Run("a vendored build", func(t *testing.T) {
		newSourceProxy(t, []srcModule{modA})
		app := newApp(t, []string{"example.com/a"}, "", reader)
		vendor(t, app)
		wantNone(t, resolve(t, app, "pkg:golang/example.com/a/ssh", []string{"example.com/a/ssh.Certificate.Verify"}))
		wantFirstParty(t, resolve(t, app, "pkg:golang/example.com/app/missing", []string{"main.Verify"}))
	})
}

func TestPackageFromPURL(t *testing.T) {
	for _, tc := range []struct{ purl, want string }{
		{"pkg:golang/example.com/a/ssh", "example.com/a/ssh"},
		{"pkg:golang/example.com/a/ssh@v1.0.0", "example.com/a/ssh"},
		{"pkg:golang/example.com/a/ssh?type=module", "example.com/a/ssh"},
		{"pkg:golang/example.com/a/ssh#sub/dir", "example.com/a/ssh"},
		{"pkg:golang/example.com/a/ssh@v1.0.0?type=module#sub/dir", "example.com/a/ssh"},
		{"pkg:golang/stdlib", "stdlib"},
		{"pkg:golang/toolchain@go1.22.1", "toolchain"},
		{"pkg:Golang/example.com/a?q=1@x", "example.com/a"},
		{"pkg:golang/example.com/a#s@x", "example.com/a"},
		{"pkg:npm/left-pad@1.0.0", ""},
		{"", ""},
	} {
		if got := packageFromPURL(tc.purl); got != tc.want {
			t.Errorf("packageFromPURL(%q) = %q, want %q", tc.purl, got, tc.want)
		}
	}
}
