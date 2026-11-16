package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

// hopName is a path hop split into the package it names and the function in it. Recv is the receiver
// type of a method, empty for a function.
type hopName struct {
	Pkg, Recv, Func string
}

// symbol is the name as pkg.go.dev anchors it: Func or Type.Method.
func (n hopName) symbol() string {
	if n.Recv != "" {
		return n.Recv + "." + n.Func
	}
	return n.Func
}

// splitHop splits "pkg/path.Func" or "pkg/path.Type.Method" (qualifiedHop's form). The last path
// element may itself hold dots ("yaml.v3", "v9"), so the split is ambiguous; exists says whether a
// candidate package is real, and the first candidate that is wins, a plain function before a method.
// With no exists, a package whose last element has a dot in it ("zstd.Encoder") is not one, unless
// the dot is a gopkg-style version ("yaml.v3").
func splitHop(hop string, exists func(pkg string) bool) (hopName, bool) {
	slash := strings.LastIndex(hop, "/")
	head, tail := hop[:slash+1], hop[slash+1:]
	parts := strings.Split(tail, ".")
	var cands []hopName
	for _, rest := range []int{1, 2} {
		if len(parts) <= rest || hasEmpty(parts[len(parts)-rest:]) {
			continue
		}
		n := hopName{Pkg: head + strings.Join(parts[:len(parts)-rest], "."), Func: parts[len(parts)-1]}
		if rest == 2 {
			n.Recv = parts[len(parts)-2]
		}
		cands = append(cands, n)
	}
	if exists == nil {
		exists = plausiblePackage
	}
	for _, c := range cands {
		if exists(c.Pkg) {
			return c, true
		}
	}
	return hopName{}, false
}

var gopkgVersion = regexp.MustCompile(`\.v[0-9]+$`)

// plausiblePackage is the reading of a package path when no source says which candidate is real.
func plausiblePackage(pkg string) bool {
	last := pkg[strings.LastIndex(pkg, "/")+1:]
	return !strings.Contains(last, ".") || gopkgVersion.MatchString(last)
}

// hasEmpty reports an empty name among parts.
func hasEmpty(parts []string) bool {
	for _, p := range parts {
		if p == "" {
			return true
		}
	}
	return false
}

// moduleSet maps module paths to the version a build uses.
type moduleSet map[string]string

// add records a module's version unless one is already recorded: earlier sources outrank later ones.
func (m moduleSet) add(path, version string) {
	if path == "" || version == "" || m[path] != "" {
		return
	}
	m[path] = version
}

// readGoMod adds the requirements of a go.mod, with its replace directives applied, and returns the
// main module's path.
func (m moduleSet) readGoMod(data []byte) (string, error) {
	f, err := modfile.ParseLax("go.mod", data, nil)
	if err != nil {
		return "", err
	}
	replaced := map[string]module.Version{}
	for _, r := range f.Replace {
		if r.Old.Version == "" {
			replaced[r.Old.Path] = r.New
		}
	}
	for _, r := range f.Require {
		if n, ok := replaced[r.Mod.Path]; ok {
			if modfile.IsDirectoryPath(n.Path) {
				continue // a local directory: no version to read
			}
			m.add(n.Path, n.Version)
			continue
		}
		m.add(r.Mod.Path, r.Mod.Version)
	}
	mod := ""
	if f.Module != nil {
		mod = f.Module.Mod.Path
	}
	return mod, nil
}

// owner is the module whose path is the longest prefix of pkg.
func (m moduleSet) owner(pkg string) (path, version string, ok bool) {
	for p, v := range m {
		if (pkg == p || strings.HasPrefix(pkg, p+"/")) && len(p) > len(path) {
			path, version, ok = p, v, true
		}
	}
	return path, version, ok
}

// stdlibPackage reports a package of the Go standard library: no dot in its first path element.
func stdlibPackage(pkg string) bool {
	first, _, _ := strings.Cut(pkg, "/")
	return !strings.Contains(first, ".")
}

// sources says where the code of each hop lives on this machine; any field may be empty.
type sources struct {
	// Repo is a checkout of the target at the pinned commit; Modcache is a Go module cache; GOROOT is
	// the pinned toolchain's root.
	Repo, Modcache, GOROOT string
	// MainModule is the target's module path.
	MainModule string
	Context    build.Context
	// fset is shared by every parse, so a position resolves in whatever file it came from.
	fset  *token.FileSet
	cache map[string]map[string][]declPos
}

// declPos is where a function or method is declared: file relative to the package's root, and line.
type declPos struct {
	File string
	Line int
}

// packageDir is the directory of a package on this machine and the root its file paths are relative
// to, or "" when the code is not here.
func (s *sources) packageDir(pkg string, mods moduleSet) (dir, root string) {
	switch {
	case s.MainModule != "" && (pkg == s.MainModule || strings.HasPrefix(pkg, s.MainModule+"/")):
		if s.Repo == "" {
			return "", ""
		}
		return filepath.Join(s.Repo, strings.TrimPrefix(strings.TrimPrefix(pkg, s.MainModule), "/")), s.Repo
	case stdlibPackage(pkg):
		if s.GOROOT == "" {
			return "", ""
		}
		return filepath.Join(s.GOROOT, "src", pkg), filepath.Join(s.GOROOT, "src")
	}
	path, version, ok := mods.owner(pkg)
	if !ok || s.Modcache == "" {
		return "", ""
	}
	ep, err1 := module.EscapePath(path)
	ev, err2 := module.EscapeVersion(version)
	if err1 != nil || err2 != nil {
		return "", ""
	}
	root = filepath.Join(s.Modcache, ep+"@"+ev)
	return filepath.Join(root, strings.TrimPrefix(strings.TrimPrefix(pkg, path), "/")), root
}

// packageExists reports whether pkg's directory holds Go files here.
func (s *sources) packageExists(pkg string, mods moduleSet) bool {
	dir, _ := s.packageDir(pkg, mods)
	if dir == "" {
		return false
	}
	m, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	return len(m) > 0
}

// locate finds where a hop's function is declared, among the files the pinned build selects (GOOS,
// GOARCH, build tags, cgo; test files excluded). A name declared more than once in that build is not
// resolved: the reason says so. The file is relative to the repository, the module or src/.
func (s *sources) locate(n hopName, mods moduleSet) (declPos, string) {
	dir, root := s.packageDir(n.Pkg, mods)
	if dir == "" {
		return declPos{}, "source not available here"
	}
	decls, err := s.declarations(dir, root)
	if err != nil {
		return declPos{}, err.Error()
	}
	found := decls[n.symbol()]
	switch len(found) {
	case 0:
		return declPos{}, "no declaration of " + n.symbol() + " in the pinned build"
	case 1:
		return found[0], ""
	}
	return declPos{}, fmt.Sprintf("%s is declared %d times in the pinned build", n.symbol(), len(found))
}

// declarations parses the package's files for the pinned build and indexes every function and method.
func (s *sources) declarations(dir, root string) (map[string][]declPos, error) {
	if d, ok := s.cache[dir]; ok {
		return d, nil
	}
	if s.cache == nil {
		s.cache = map[string]map[string][]declPos{}
		s.fset = token.NewFileSet()
	}
	pkg, err := s.Context.ImportDir(dir, 0)
	var noGo *build.NoGoError
	var multi *build.MultiplePackageError
	if err != nil && !errors.As(err, &noGo) && !errors.As(err, &multi) {
		return nil, fmt.Errorf("reading %s: %v", dir, err)
	}
	out := map[string][]declPos{}
	files := append(append([]string{}, pkg.GoFiles...), pkg.CgoFiles...)
	sort.Strings(files)
	for _, name := range files {
		path := filepath.Join(dir, name)
		f, err := parser.ParseFile(s.fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %v", path, err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil, err
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			key := fd.Name.Name
			if fd.Recv != nil && len(fd.Recv.List) == 1 {
				key = receiverName(fd.Recv.List[0].Type) + "." + key
			}
			out[key] = append(out[key], declPos{File: filepath.ToSlash(rel), Line: s.fset.Position(fd.Name.Pos()).Line})
		}
	}
	s.cache[dir] = out
	return out, nil
}

// receiverName is the type name of a method receiver, through a pointer and type parameters.
func receiverName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return receiverName(t.X)
	case *ast.ParenExpr:
		return receiverName(t.X)
	case *ast.IndexExpr:
		return receiverName(t.X)
	case *ast.IndexListExpr:
		return receiverName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return ""
}

// pseudoVersion matches the commit suffix of a pseudo-version (vX.Y.Z-0.<time>-<commit> too).
var pseudoVersion = regexp.MustCompile(`[-.]\d{14}-([0-9a-f]{12})$`)

var majorSuffix = regexp.MustCompile(`^v[2-9][0-9]*$`)

// sourceLink is where a hop's file and line can be read, and the source host's name for the check.
type sourceLink struct {
	// URL is the line permalink; empty when no host with a stable line link is known for the module.
	URL string
	// RawURL is the same file's raw bytes, for the link check.
	RawURL string
}

// depLink builds the line permalink of a dependency's file at the exact version. GitHub-hosted modules
// and golang.org/x modules (mirrored at github.com/golang) get one; a module at any other host gets
// none, never a guessed one. file is relative to the module root.
func depLink(modPath, version, file string, line int) sourceLink {
	elems := strings.Split(modPath, "/")
	var repo string
	var sub []string
	switch {
	case elems[0] == "github.com" && len(elems) >= 3:
		repo, sub = elems[1]+"/"+elems[2], elems[3:]
	case elems[0] == "golang.org" && len(elems) >= 3 && elems[1] == "x":
		repo, sub = "golang/"+elems[2], elems[3:]
	default:
		return sourceLink{}
	}
	if n := len(sub); n > 0 && majorSuffix.MatchString(sub[n-1]) {
		sub = sub[:n-1]
	}
	ref := version
	if m := pseudoVersion.FindStringSubmatch(version); m != nil {
		ref = m[1]
	} else if len(sub) > 0 {
		ref = strings.Join(sub, "/") + "/" + version
	}
	path := file
	if len(sub) > 0 {
		path = strings.Join(sub, "/") + "/" + file
	}
	return githubLink(repo, ref, path, line)
}

// githubLink is the blob permalink of path at ref in an owner/name repository, and its raw twin.
func githubLink(repo, ref, path string, line int) sourceLink {
	return sourceLink{
		URL:    fmt.Sprintf("https://github.com/%s/blob/%s/%s#L%d", repo, ref, path, line),
		RawURL: fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s", repo, ref, path),
	}
}

// stdlibLink is the permalink of a standard-library file at the pinned toolchain's release tag.
func stdlibLink(goVersion, file string, line int) sourceLink {
	return githubLink("golang/go", "go"+strings.TrimPrefix(goVersion, "go"), "src/"+file, line)
}

// readFileOrEmpty reads a file, or returns nil.
func readFileOrEmpty(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}
