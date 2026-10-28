package goanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/mod/modfile"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// moduleSearchTimeout bounds a module search, downloads included. A module not read by then is
// left out of the result, as unreadable.
var moduleSearchTimeout = 5 * time.Minute

// listedModule is one module of `go list -m -json all`.
type listedModule struct {
	Path    string
	Version string
	Main    bool
	Dir     string
	Replace *struct {
		Path    string
		Version string
		Dir     string
	}
}

// searchBuildModules searches the source of every module in buildDir's build list for a
// declaration named like one of symbols, for an advisory on pkgPath. It returns nil when the
// search does not apply or cannot start: no symbols, a module in the build holds pkgPath, or the
// build list cannot be listed (a vendored build, for one).
//
// A module whose source is not in the module cache is downloaded the way the go command would,
// honoring the caller's GOPROXY, GOPRIVATE, GONOSUMDB and GOFLAGS, and verified against go.sum
// and the checksum database. A module that fails to download, verify or parse, or that is not
// read before moduleSearchTimeout, is left out of Searched.
func searchBuildModules(ctx context.Context, buildDir, pkgPath string, symbols []string) *plugin.ModuleSearch {
	names := symbolNames(symbols)
	if pkgPath == "" || len(names) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, moduleSearchTimeout)
	defer cancel()
	if modfileFlagSet(ctx, buildDir) {
		return nil
	}
	mods, err := listModules(ctx, buildDir)
	if err != nil {
		return nil
	}
	for _, m := range mods {
		if pathHolds(m.Path, pkgPath) || m.Replace != nil && pathHolds(m.Replace.Path, pkgPath) {
			return nil
		}
	}
	downloaded := downloadModules(ctx, buildDir, mods)

	res := &plugin.ModuleSearch{Searched: []string{}}
	for _, m := range mods {
		dir := sourceDir(m, downloaded)
		if dir == "" {
			continue
		}
		declares, err := declaresName(ctx, dir, names)
		if err != nil {
			continue
		}
		res.Searched = append(res.Searched, m.Path)
		if m.Replace != nil && m.Replace.Version != "" {
			res.Searched = append(res.Searched, m.Replace.Path)
		}
		if declares {
			res.Declaring = append(res.Declaring, m.Path)
		}
	}
	slices.Sort(res.Searched)
	res.Searched = slices.Compact(res.Searched)
	slices.Sort(res.Declaring)
	return res
}

// symbolNames returns the bare names advisory symbols declare: "Func", "Type.Method",
// "(*Type).Method" and "pkg.Func" all name their last element.
func symbolNames(symbols []string) map[string]bool {
	names := make(map[string]bool, len(symbols))
	for _, s := range symbols {
		if i := strings.LastIndexByte(s, '.'); i >= 0 {
			s = s[i+1:]
		}
		if s = strings.Trim(s, "(*)"); s != "" {
			names[s] = true
		}
	}
	return names
}

// modfileFlagSet reports whether the GOFLAGS the go command uses in buildDir, from the
// environment or the go env file, names a -modfile, which the download below replaces with its
// own copy and so would not honor. GOFLAGS that cannot be read counts as naming one.
func modfileFlagSet(ctx context.Context, buildDir string) bool {
	cmd := exec.CommandContext(ctx, "go", "env", "GOFLAGS")
	cmd.Dir = buildDir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.Output()
	if err != nil {
		return true
	}
	for _, f := range strings.Fields(string(out)) {
		if strings.HasPrefix(strings.TrimLeft(f, "-"), "modfile") {
			return true
		}
	}
	return false
}

// dependencyHolds reports whether a module of buildDir's build list other than the main module
// holds import path p: the module holding it with the longest path, by its own path or its
// replacement's, is not the main module. A vendored build, whose build list the go command does not
// list, is read from vendor/modules.txt. A build list that cannot be read holds nothing.
func dependencyHolds(ctx context.Context, buildDir, p string) bool {
	ctx, cancel := context.WithTimeout(ctx, moduleSearchTimeout)
	defer cancel()
	mods, err := listModules(ctx, buildDir)
	if err != nil {
		if mods, err = vendoredModules(buildDir); err != nil {
			return false
		}
	}
	held, main := 0, false
	for _, m := range mods {
		paths := []string{m.Path}
		if m.Replace != nil {
			paths = append(paths, m.Replace.Path)
		}
		for _, path := range paths {
			if len(path) > held && pathHolds(path, p) {
				held, main = len(path), m.Main
			}
		}
	}
	return held > 0 && !main
}

// vendoredModules reads a vendored build's module list: the main module from go.mod, and every
// module vendor/modules.txt records, with its replacement.
func vendoredModules(buildDir string) ([]listedModule, error) {
	data, err := os.ReadFile(filepath.Join(buildDir, "go.mod"))
	if err != nil {
		return nil, err
	}
	main := modfile.ModulePath(data)
	if main == "" {
		return nil, fmt.Errorf("%s/go.mod declares no module", buildDir)
	}
	txt, err := os.ReadFile(filepath.Join(buildDir, "vendor", "modules.txt"))
	if err != nil {
		return nil, err
	}
	mods := []listedModule{{Path: main, Main: true}}
	for _, line := range strings.Split(string(txt), "\n") {
		// "# path [version] [=> replacement [version]]"; "##" lines annotate the module above.
		rest, ok := strings.CutPrefix(line, "# ")
		if !ok {
			continue
		}
		mod, repl, replaced := strings.Cut(rest, " => ")
		f := strings.Fields(mod)
		if len(f) == 0 {
			continue
		}
		m := listedModule{Path: f[0]}
		if rf := strings.Fields(repl); replaced && len(rf) > 0 {
			m.Replace = &struct {
				Path    string
				Version string
				Dir     string
			}{Path: rf[0]}
		}
		mods = append(mods, m)
	}
	return mods, nil
}

// pathHolds reports whether module path mod holds import path p, ignoring case.
func pathHolds(mod, p string) bool {
	return len(p) >= len(mod) && strings.EqualFold(p[:len(mod)], mod) && (len(p) == len(mod) || p[len(mod)] == '/')
}

func listModules(ctx context.Context, buildDir string) ([]listedModule, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-json", "all")
	cmd.Dir = buildDir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var mods []listedModule
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var m listedModule
		if err := dec.Decode(&m); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		mods = append(mods, m)
	}
	return mods, nil
}

// downloadTarget is the path@version a module's source is downloaded as: its replacement's when a
// replace by another module substitutes one, "" when there is nothing to download.
func downloadTarget(m listedModule) string {
	switch {
	case m.Main:
		return ""
	case m.Replace != nil && m.Replace.Version != "":
		return m.Replace.Path + "@" + m.Replace.Version
	case m.Replace != nil:
		return "" // a directory replace: its source is on disk or nowhere
	case m.Version != "":
		return m.Path + "@" + m.Version
	}
	return ""
}

func sourceDir(m listedModule, downloaded map[string]string) string {
	if m.Replace != nil {
		if m.Replace.Dir != "" {
			return m.Replace.Dir
		}
	} else if m.Dir != "" {
		return m.Dir
	}
	return downloaded[downloadTarget(m)]
}

// downloadModules downloads the modules whose source is not on disk and returns the directory of
// each one that downloaded and verified, keyed by path@version. It runs against a copy of go.mod
// and go.sum, so the checksums a download records never land in the checkout.
func downloadModules(ctx context.Context, buildDir string, mods []listedModule) map[string]string {
	var args []string
	for _, m := range mods {
		if mv := downloadTarget(m); mv != "" && sourceDir(m, nil) == "" {
			args = append(args, mv)
		}
	}
	if len(args) == 0 {
		return nil
	}
	tmp, err := os.MkdirTemp("", "assay-modsearch")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(tmp)
	modfile := filepath.Join(tmp, "build.mod")
	if err := copyFile(filepath.Join(buildDir, "go.mod"), modfile); err != nil {
		return nil
	}
	if err := copyFile(filepath.Join(buildDir, "go.sum"), filepath.Join(tmp, "build.sum")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	cmd := exec.CommandContext(ctx, "go", append([]string{"mod", "download", "-json", "-modfile=" + modfile}, args...)...)
	cmd.Dir = buildDir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	// A module that fails to download is reported in its own JSON entry and makes the command
	// exit non-zero, so the output is read whatever the exit status. A checksum mismatch stops the
	// command before it reports any module, which leaves every module it was to download unread.
	out, _ := cmd.Output()
	dirs := make(map[string]string, len(args))
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var m struct {
			Path, Version, Dir, Error string
		}
		if dec.Decode(&m) != nil {
			break
		}
		if m.Error == "" && m.Dir != "" {
			dirs[m.Path+"@"+m.Version] = m.Dir
		}
	}
	return dirs
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}

// declaresName reports whether a module's source rooted at dir declares a function, method,
// variable or constant with one of names. It reads every .go file the module's packages can
// compile, whatever its build constraints: test files, testdata, vendor, directories the go
// command ignores (leading '.' or '_') and nested modules are not part of the module. A file that
// does not parse, or a symbolic link to a .go file or a directory, is an error, since what it
// declares is unknown.
func declaresName(ctx context.Context, dir string, names map[string]bool) (bool, error) {
	found := false
	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.Type()&fs.ModeSymlink != 0 {
			if fi, err := os.Stat(path); strings.HasSuffix(path, ".go") || err != nil || fi.IsDir() {
				return fmt.Errorf("symbolic link %s", path)
			}
			return nil
		}
		if d.IsDir() {
			if path == dir {
				return nil
			}
			if n := d.Name(); n == "testdata" || n == "vendor" || strings.HasPrefix(n, ".") || strings.HasPrefix(n, "_") {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		if declares(f, names) {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found, err
}

func declares(f *ast.File, names map[string]bool) bool {
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if names[d.Name.Name] {
				return true
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					for _, n := range vs.Names {
						if names[n.Name] {
							return true
						}
					}
				}
			}
		}
	}
	return false
}
