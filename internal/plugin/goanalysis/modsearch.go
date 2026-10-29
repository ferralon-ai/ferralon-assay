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

// modsearchGo runs a go command and returns its standard output. Tests replace it to observe the
// commands a module search issues.
var modsearchGo = func(cmd *exec.Cmd) ([]byte, error) { return cmd.Output() }

// goCommand is a go command run in buildDir under the environment the program load runs under
// (programEnv), so the build list it reads is the one the resolution index was loaded from.
func goCommand(ctx context.Context, buildDir string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = buildDir
	cmd.Env, _, _ = programEnv(ctx, buildDir)
	return cmd
}

// buildKey is the run cache key of a go command's answer for buildDir, which depends on the
// build and the environment programEnv derives from the process's.
func buildKey(buildDir string, extra ...string) []string {
	return append(append([]string{buildDir}, extra...), os.Environ()...)
}

// modfileFlagSet reports whether the GOFLAGS the go command uses in buildDir, from the
// environment or the go env file, names a -modfile, which the download below replaces with its
// own copy and so would not honor. GOFLAGS that cannot be read counts as naming one. It is read
// once per build per scan.
func modfileFlagSet(ctx context.Context, buildDir string) bool {
	b, err := runCached(ctx, "modfileflag", buildKey(buildDir), func() ([]byte, error) {
		out, err := modsearchGo(goCommand(ctx, buildDir, "env", "GOFLAGS"))
		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			return []byte("true"), nil
		}
		for _, f := range strings.Fields(string(out)) {
			if strings.HasPrefix(strings.TrimLeft(f, "-"), "modfile") {
				return []byte("true"), nil
			}
		}
		return []byte("false"), nil
	})
	return err != nil || string(b) != "false"
}

// dependencyHolds reports whether a module of buildDir's build list other than the main module
// holds import path p: the module holding it with the longest path, by its own path or its
// replacement's, is not the main module. A build the go command reads from vendor/, whose build
// list it does not list, is read from vendor/modules.txt; a vendor/ the go command does not read
// is not. A build list that cannot be read holds nothing.
func dependencyHolds(ctx context.Context, buildDir, p string) bool {
	ctx, cancel := context.WithTimeout(ctx, moduleSearchTimeout)
	defer cancel()
	mods, err := listModules(ctx, buildDir)
	vendored := errors.Is(err, errVendorMode)
	if vendored {
		mods, err = vendoredModules(buildDir)
	}
	if err != nil {
		return false
	}
	held, main, mainPath := 0, false, ""
	for _, m := range mods {
		if m.Main {
			mainPath = m.Path
		}
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
	// The go command does not check every vendor/modules.txt entry against go.mod, so a stale one
	// can name a module whose path the main module has since absorbed. In vendor mode the go
	// command still loads such a path from the main module's own tree.
	return held > 0 && !main && !(vendored && mainTreeHolds(buildDir, mainPath, p))
}

// mainTreeHolds reports whether the main module mainPath, rooted at buildDir, has a directory for
// import path p with no go.mod between them, as the go command requires of a path it loads from the
// main module.
func mainTreeHolds(buildDir, mainPath, p string) bool {
	if mainPath == "" || !pathHolds(mainPath, p) {
		return false
	}
	dir := filepath.Join(buildDir, filepath.FromSlash(strings.TrimPrefix(p[len(mainPath):], "/")))
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return false
	}
	for d := dir; len(d) > len(buildDir); d = filepath.Dir(d) {
		if fi, err := os.Stat(filepath.Join(d, "go.mod")); err == nil && !fi.IsDir() {
			return false
		}
	}
	return true
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

// moduleListing is what `go list -m -json all` answered for a build: its modules, or why it
// listed none, and whether that was the go command's vendor-mode refusal.
type moduleListing struct {
	Modules []listedModule
	Err     string
	Vendor  bool
}

// errVendorMode is listModules' answer for a build the go command reads from vendor/: in vendor
// mode it knows only the modules vendor/modules.txt records, so it refuses to compute 'all'.
var errVendorMode = errors.New("go list -m all: the go command reads the build from vendor/")

// vendorRefusal reports whether err is the go command refusing `go list -m all` because it is in
// vendor mode, as it resolved that from -mod in GOFLAGS, the go.mod go version and vendor/
// itself. Releases print the refusal prefixed "go list -m: " or "go: ".
func vendorRefusal(err error) bool {
	var ee *exec.ExitError
	return errors.As(err, &ee) && bytes.Contains(ee.Stderr, []byte("can't compute 'all' using the vendor directory"))
}

// listModules lists buildDir's build list once per build per scan, through the run cache: every
// advisory resolved against the build reads the same list. A listing the go command refused is
// kept as that refusal, errVendorMode when it refused because it is in vendor mode; one cut short
// by ctx is not kept, so a later advisory lists again.
func listModules(ctx context.Context, buildDir string) ([]listedModule, error) {
	b, err := runCached(ctx, "modlist", buildKey(buildDir), func() ([]byte, error) {
		var l moduleListing
		out, err := modsearchGo(goCommand(ctx, buildDir, "list", "-m", "-json", "all"))
		if err == nil {
			l.Modules, err = decodeModules(out)
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			l.Err, l.Vendor = err.Error(), vendorRefusal(err)
		}
		return json.Marshal(l)
	})
	if err != nil {
		return nil, err
	}
	var l moduleListing
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("decode cached module list: %w", err)
	}
	if l.Vendor {
		return nil, errVendorMode
	}
	if l.Err != "" {
		return nil, errors.New(l.Err)
	}
	return l.Modules, nil
}

func decodeModules(out []byte) ([]listedModule, error) {
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
// each one that downloaded and verified, keyed by path@version. The answer is kept once per build
// per scan, unless the download could not start or ctx cut it short: a later search then downloads
// again.
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
	var unfinished map[string]string
	b, err := runCached(ctx, "moddownload", buildKey(buildDir, args...), func() ([]byte, error) {
		dirs, err := download(ctx, buildDir, args)
		if err != nil {
			unfinished = dirs
			return nil, err
		}
		return json.Marshal(dirs)
	})
	if err != nil {
		return unfinished
	}
	var dirs map[string]string
	if json.Unmarshal(b, &dirs) != nil {
		return nil
	}
	return dirs
}

// download runs `go mod download` for args against a copy of buildDir's go.mod and go.sum, so the
// checksums it records never land in the checkout. It returns the modules it read, and an error
// when it could not start or ctx cut it short.
func download(ctx context.Context, buildDir string, args []string) (map[string]string, error) {
	tmp, err := os.MkdirTemp("", "assay-modsearch")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	modfile := filepath.Join(tmp, "build.mod")
	if err := copyFile(filepath.Join(buildDir, "go.mod"), modfile); err != nil {
		return nil, err
	}
	if err := copyFile(filepath.Join(buildDir, "go.sum"), filepath.Join(tmp, "build.sum")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	// A module that fails to download is reported in its own JSON entry and makes the command
	// exit non-zero, so the output is read whatever the exit status. A checksum mismatch stops the
	// command before it reports any module, which leaves every module it was to download unread.
	out, _ := modsearchGo(goCommand(ctx, buildDir, append([]string{"mod", "download", "-json", "-modfile=" + modfile}, args...)...))
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
	return dirs, ctx.Err()
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
