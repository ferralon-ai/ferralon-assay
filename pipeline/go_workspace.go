package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/mod/modfile"
)

// GoWorkspace is the go.work a Go build of one module runs under: none (GOWORK=off), or one go.work
// that uses the module. codebase_inventory resolves it once per assessment and records it; the
// analyzer loads under it and every ownership, presence and version read here reads the same file,
// so no fact rests on a different build from the one analyzed.
type GoWorkspace struct {
	// File is the absolute path of the go.work, or "" when the build runs with GOWORK=off.
	File string `json:"file,omitempty"`
}

// GOWORK is the value of GOWORK the build's go command runs under.
func (w GoWorkspace) GOWORK() string {
	if w.File == "" {
		return "off"
	}
	return w.File
}

// ResolveGoWorkspace resolves the go.work the build of the Go module at buildDir runs under.
//
// declared is the caller's statement of the build's GOWORK: "off", a path to the go.work (relative
// to checkoutRoot unless absolute), or "" for none. The scanner's own GOWORK is never read; run
// conditions are handed in, not resolved from the analyzer's environment. With nothing declared the
// go.work is the one the go command finds, the nearest at or above buildDir, searched no higher than
// the git work tree holding buildDir (else checkoutRoot when it holds buildDir, else buildDir): a
// go.work above the repository is a developer's, not the build's. A found go.work that does not use
// buildDir's module is not one the build ran under, since the go command refuses to build a module
// outside the workspace, so the build ran with it off.
//
// An error means the build's workspace cannot be established: a declared go.work that does not
// exist, does not parse or does not use buildDir's module, or a found one that does not parse.
func ResolveGoWorkspace(ctx context.Context, buildDir, checkoutRoot, declared string) (GoWorkspace, error) {
	own, err := filepath.EvalSymlinks(buildDir)
	if err != nil {
		return GoWorkspace{}, err
	}
	switch declared {
	case "off":
		return GoWorkspace{}, nil
	case "":
		file, found, err := findGoWork(ctx, own, checkoutRoot)
		if err != nil || !found {
			return GoWorkspace{}, err
		}
		member, err := goWorkUsesDir(file, own)
		if err != nil || !member {
			return GoWorkspace{}, err
		}
		return GoWorkspace{File: file}, nil
	}
	file := declared
	if !filepath.IsAbs(file) {
		file = filepath.Join(checkoutRoot, file)
	}
	file, err = filepath.EvalSymlinks(file)
	if err != nil {
		return GoWorkspace{}, fmt.Errorf("subject go.work %q: %w", declared, err)
	}
	member, err := goWorkUsesDir(file, own)
	if err != nil {
		return GoWorkspace{}, err
	}
	if !member {
		return GoWorkspace{}, fmt.Errorf("subject go.work %q does not use the module at %s", declared, buildDir)
	}
	return GoWorkspace{File: file}, nil
}

// findGoWork returns the nearest go.work at or above own, searched no higher than its repository.
func findGoWork(ctx context.Context, own, checkoutRoot string) (string, bool, error) {
	top := own
	if t, err := gitOutput(ctx, own, "rev-parse", "--show-toplevel"); err == nil && t != "" {
		top = t
	} else if root, err := filepath.EvalSymlinks(checkoutRoot); err == nil && within(own, root) {
		top = root
	}
	for dir := own; ; dir = filepath.Dir(dir) {
		file := filepath.Join(dir, "go.work")
		fi, err := os.Stat(file)
		switch {
		case err == nil && !fi.IsDir():
			return file, true, nil
		case err != nil && !os.IsNotExist(err):
			return "", false, err
		}
		if dir == top || filepath.Dir(dir) == dir {
			return "", false, nil
		}
	}
}

// within reports whether dir is root or lies below it.
func within(dir, root string) bool {
	return strings.HasPrefix(dir+string(filepath.Separator), root+string(filepath.Separator))
}

// uses returns the directory of every module the workspace uses and the module path of everything
// its go.work replaces; ok is false when the go.work cannot be read or does not parse.
func (w GoWorkspace) uses() (uses, replaced []string, ok bool) {
	if w.File == "" {
		return nil, nil, true
	}
	uses, replaced, err := parseGoWork(w.File)
	return uses, replaced, err == nil
}

// goWorkUsesDir reports whether the go.work at file uses the module directory own.
func goWorkUsesDir(file, own string) (bool, error) {
	uses, _, err := parseGoWork(file)
	if err != nil {
		return false, err
	}
	for _, use := range uses {
		if d, err := filepath.EvalSymlinks(use); err == nil && d == own {
			return true, nil
		}
	}
	return false, nil
}

// parseGoWork returns the directory of every module the go.work at file uses, and the module path
// of everything it replaces.
func parseGoWork(file string) (uses, replaced []string, err error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, err
	}
	wf, err := modfile.ParseWork(file, data, nil)
	if err != nil {
		return nil, nil, err
	}
	dir := filepath.Dir(file)
	for _, r := range wf.Replace {
		replaced = append(replaced, r.Old.Path)
	}
	for _, u := range wf.Use {
		use := filepath.FromSlash(u.Path)
		if !filepath.IsAbs(use) {
			use = filepath.Join(dir, use)
		}
		uses = append(uses, use)
	}
	return uses, replaced, nil
}

// moduleVersionFromBuild is moduleVersionFromGoMod for the build of buildDir under the workspace ws.
// With no go.work in force it is moduleVersionFromGoMod. Under one, the go.mod files state neither
// the selected version nor what is in the build: the workspace runs one MVS over every module it
// uses, and a dependency's own requirements can raise a module past the highest version any go.mod
// there lists, or bring in one none lists. So the version is read off the build list the go command
// computes (workspaceBuildList): pinned at the listed version, absent when the list holds no such
// module, and unpinned when the go command cannot say. It is unpinned too, as for a replaced
// module, when the module is one the workspace uses or one a go.work, a go.mod there or the list
// replaces: none of those builds compile code a required version describes. manifestRead is false
// when the go.work or a go.mod of a module it uses is unreadable.
func moduleVersionFromBuild(ctx context.Context, buildDir string, ws GoWorkspace, module string) (v string, pinned, manifestRead bool) {
	if ws.File == "" {
		return moduleVersionFromGoMod(buildDir, module)
	}
	unpinned, ok := workspaceUnpinned(ws)
	if !ok {
		return "", false, false
	}
	if unpinned[module] {
		return "", false, true
	}
	mods, err := workspaceBuildList(ctx, buildDir, ws)
	if err != nil {
		return "", false, true
	}
	for _, m := range mods {
		if m.Path != module {
			continue
		}
		if !m.pinned() {
			return "", false, true
		}
		return m.Version, true, true
	}
	return "", true, true
}

// workspaceUnpinned returns the modules the workspace ws uses or replaces, in its go.work or in a
// go.mod of a module it uses: a build of any of them compiles code no required version describes.
// ok is false when the go.work or one of those go.mod files is unreadable.
func workspaceUnpinned(ws GoWorkspace) (unpinned map[string]bool, ok bool) {
	data, err := os.ReadFile(ws.File)
	if err != nil {
		return nil, false
	}
	wf, err := modfile.ParseWork(ws.File, data, nil)
	if err != nil {
		return nil, false
	}
	unpinned = make(map[string]bool)
	for _, r := range wf.Replace {
		unpinned[r.Old.Path] = true
	}
	uses, _, _ := parseGoWork(ws.File)
	for _, use := range uses {
		data, err := os.ReadFile(filepath.Join(use, "go.mod"))
		if err != nil {
			return nil, false
		}
		mf, err := modfile.Parse("go.mod", data, nil)
		if err != nil || mf.Module == nil {
			return nil, false
		}
		unpinned[mf.Module.Mod.Path] = true
		for _, r := range mf.Replace {
			unpinned[r.Old.Path] = true
		}
	}
	return unpinned, true
}

// GoWorkspaceModules returns every module the build of the Go module at buildDir holds under the
// workspace ws, other than buildDir's own, read as moduleVersionFromBuild reads each: pinned maps a
// module to the version the build selects, and unpinned lists, sorted, the modules it holds at no
// version a required release describes (one the workspace uses or replaces, or one the build list
// reports replaced or versionless).
//
// When the go command cannot compute the build list, the modules are those the workspace uses and
// those its go.mod files require, all unpinned: a go.mod's require is a lower bound under a
// workspace's MVS, not the version built. An error means the go.work or a go.mod of buildDir or a
// module the workspace uses cannot be read.
func GoWorkspaceModules(ctx context.Context, buildDir string, ws GoWorkspace) (pinned map[string]string, unpinned []string, err error) {
	own := goModFileModule(filepath.Join(buildDir, "go.mod"))
	structural, ok := workspaceUnpinned(ws)
	if !ok || own == "" {
		return nil, nil, fmt.Errorf("pipeline: the workspace %s cannot be read", ws.File)
	}
	set := make(map[string]bool)
	pinned = make(map[string]string)
	mods, listErr := workspaceBuildList(ctx, buildDir, ws)
	if listErr != nil {
		for m := range structural {
			set[m] = true
		}
		uses, _, _ := parseGoWork(ws.File)
		for _, use := range uses {
			data, err := os.ReadFile(filepath.Join(use, "go.mod"))
			if err != nil {
				return nil, nil, fmt.Errorf("pipeline: the workspace %s cannot be read: %w", ws.File, err)
			}
			mf, err := modfile.Parse("go.mod", data, nil)
			if err != nil {
				return nil, nil, fmt.Errorf("pipeline: the workspace %s cannot be read: %w", ws.File, err)
			}
			for _, r := range mf.Require {
				set[r.Mod.Path] = true
			}
		}
	} else {
		for _, m := range mods {
			switch {
			case m.Path == own:
			case structural[m.Path] || !m.pinned():
				set[m.Path] = true
			default:
				pinned[m.Path] = m.Version
			}
		}
	}
	delete(set, own)
	for m := range set {
		unpinned = append(unpinned, m)
	}
	sort.Strings(unpinned)
	return pinned, unpinned, nil
}

// listedModule is the part of `go list -m -json` output the pipeline reads.
type listedModule struct {
	Path    string
	Version string
	Main    bool
	Replace *struct{ Path, Version string }
}

// pinned reports whether the build compiles the module at a released version: not a main module,
// not replaced, and listed with a version.
func (m listedModule) pinned() bool {
	return !m.Main && m.Replace == nil && m.Version != ""
}

// buildLists memoizes workspaceBuildList by the build directory and the content of the go.work, every
// go.mod it uses and every go.mod a replace there points at, which with the checksummed go.mod files
// of the module cache fix the list.
var buildLists sync.Map

// workspaceBuildList returns every module in the build list of buildDir under the workspace ws, as
// `go list -m -json all` reports it: a superset of the modules the build compiles, each at the
// version it selects. An error means the go command could not compute it.
func workspaceBuildList(ctx context.Context, buildDir string, ws GoWorkspace) ([]listedModule, error) {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00", buildDir, ws.File)
	data, err := os.ReadFile(ws.File)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	wf, err := modfile.ParseWork(ws.File, data, nil)
	if err != nil {
		return nil, err
	}
	hashReplaced(h, filepath.Dir(ws.File), wf.Replace)
	uses, _, err := parseGoWork(ws.File)
	if err != nil {
		return nil, err
	}
	for _, use := range uses {
		data, err := os.ReadFile(filepath.Join(use, "go.mod"))
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(h, "\x00%s\x00", use)
		h.Write(data)
		mf, err := modfile.Parse("go.mod", data, nil)
		if err != nil {
			return nil, err
		}
		hashReplaced(h, use, mf.Replace)
	}
	key := string(h.Sum(nil))
	if mods, ok := buildLists.Load(key); ok {
		return mods.([]listedModule), nil
	}
	mods, err := goListBuild(ctx, buildDir, ws)
	if err != nil {
		return nil, err
	}
	buildLists.Store(key, mods)
	return mods, nil
}

// hashReplaced adds to h the go.mod of every directory a replace in a manifest under dir points at:
// the build reads its requirements as the replaced module's. One that cannot be read hashes as such,
// and the go command decides what that means.
func hashReplaced(h io.Writer, dir string, replaces []*modfile.Replace) {
	for _, r := range replaces {
		if !modfile.IsDirectoryPath(r.New.Path) {
			continue
		}
		target := r.New.Path
		if !filepath.IsAbs(target) {
			target = filepath.Join(dir, target)
		}
		data, err := os.ReadFile(filepath.Join(target, "go.mod"))
		fmt.Fprintf(h, "\x00%s\x00%v\x00", target, err != nil)
		h.Write(data)
	}
}

// goListBuild runs `go list -m -json all` for the build of buildDir under ws. It runs offline
// (GOPROXY=off) and read-only, so it answers from the module cache or fails; it executes no code of
// the subject.
var goListBuild = func(ctx context.Context, buildDir string, ws GoWorkspace) ([]listedModule, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-json", "all")
	cmd.Dir = buildDir
	cmd.Env = append(os.Environ(), "GOWORK="+ws.GOWORK(), "GOPROXY=off", "GOFLAGS=-mod=readonly")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var mods []listedModule
	for dec := json.NewDecoder(bytes.NewReader(out)); dec.More(); {
		var m listedModule
		if err := dec.Decode(&m); err != nil {
			return nil, err
		}
		mods = append(mods, m)
	}
	return mods, nil
}

// Directives returns the go and toolchain lines of the go.work, which a workspace build runs under in
// place of its modules' own: "" for a line it does not declare, and both "" when it cannot be read.
func (w GoWorkspace) Directives() (goLine, toolchain string) {
	data, err := os.ReadFile(w.File)
	if err != nil {
		return "", ""
	}
	wf, err := modfile.ParseWork(w.File, data, nil)
	if err != nil {
		return "", ""
	}
	if wf.Go != nil {
		goLine = wf.Go.Version
	}
	if wf.Toolchain != nil {
		toolchain = wf.Toolchain.Name
	}
	return goLine, toolchain
}
