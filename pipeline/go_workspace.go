package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
	gomodule "golang.org/x/mod/module"
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
// With no go.work in force it is moduleVersionFromGoMod. Under one, the go.mod files do not state the
// selected version: the workspace runs one MVS over every module it uses, and a dependency's own
// requirements can raise a module past the highest version any go.mod there lists. So the version is
// pinned only at the one the go command selects (goListModule); when it cannot say, the version is
// left unpinned. It is unpinned too, as for a replaced module, when the module is one the workspace
// uses or one a go.work or go.mod there replaces: none of those builds compile code a required
// version describes. A module no go.mod there requires reads as moduleVersionFromGoMod reads it.
// manifestRead is false when the go.work or a go.mod of a module it uses is unreadable.
func moduleVersionFromBuild(ctx context.Context, buildDir string, ws GoWorkspace, module string) (v string, pinned, manifestRead bool) {
	if ws.File == "" {
		return moduleVersionFromGoMod(buildDir, module)
	}
	data, err := os.ReadFile(ws.File)
	if err != nil {
		return "", false, false
	}
	wf, err := modfile.ParseWork(ws.File, data, nil)
	if err != nil {
		return "", false, false
	}
	replaced, required := false, false
	for _, r := range wf.Replace {
		replaced = replaced || r.Old.Path == module
	}
	uses, _, _ := parseGoWork(ws.File)
	for _, use := range uses {
		data, err := os.ReadFile(filepath.Join(use, "go.mod"))
		if err != nil {
			return "", false, false
		}
		mf, err := modfile.Parse("go.mod", data, nil)
		if err != nil || mf.Module == nil {
			return "", false, false
		}
		replaced = replaced || mf.Module.Mod.Path == module
		for _, r := range mf.Replace {
			replaced = replaced || r.Old.Path == module
		}
		for _, r := range mf.Require {
			required = required || r.Mod.Path == module
		}
	}
	switch {
	case replaced:
		return "", false, true
	case !required:
		return "", true, true
	}
	m, err := goListModule(ctx, buildDir, ws, module)
	if err != nil || m.Path != module || m.Main || m.Replace != nil || m.Version == "" {
		return "", false, true
	}
	return m.Version, true, true
}

// listedModule is the part of `go list -m -json` output the version axis reads.
type listedModule struct {
	Path    string
	Version string
	Main    bool
	Replace *struct{ Path, Version string }
}

// goListModule asks the go command which version of module the build of buildDir under ws selects.
// It runs offline (GOPROXY=off) and read-only, so it answers from the module cache or fails; it
// executes no code of the subject.
var goListModule = func(ctx context.Context, buildDir string, ws GoWorkspace, module string) (listedModule, error) {
	if err := gomodule.CheckPath(module); err != nil {
		return listedModule{}, err
	}
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-json", module)
	cmd.Dir = buildDir
	cmd.Env = append(os.Environ(), "GOWORK="+ws.GOWORK(), "GOPROXY=off", "GOFLAGS=-mod=readonly")
	out, err := cmd.Output()
	if err != nil {
		return listedModule{}, err
	}
	var m listedModule
	if err := json.Unmarshal(out, &m); err != nil {
		return listedModule{}, err
	}
	return m, nil
}

// directives returns the go and toolchain lines of the go.work, which a workspace build runs under in
// place of its modules' own: "" for a line it does not declare, and both "" when it cannot be read.
func (w GoWorkspace) directives() (goLine, toolchain string) {
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
