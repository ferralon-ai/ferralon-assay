package buildgraph

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// runner runs one tool's steps in the repository and records each as a Command.
type runner struct {
	dir      string   // repository root, the working directory of every step
	tool     string   // the executable as found: an absolute wrapper path or a PATH lookup
	shown    string   // the executable as recorded: "./mvnw" or "mvn"
	env      []string // the job's environment with the stated overlays
	work     string   // the directory step outputs are written to
	commands []Command
}

// run executes one step and returns its combined output. A nonzero exit is a classified
// Failure; the command is recorded either way.
func (r *runner) run(ctx context.Context, step string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, r.tool, args...)
	cmd.Dir = r.dir
	cmd.Env = r.env
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	exit := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return nil, &Failure{Kind: KindToolFailed, Detail: step, Log: err.Error()}
		}
		exit = ee.ExitCode()
	}
	r.commands = append(r.commands, Command{Step: step, Argv: r.recorded(args), Exit: exit})
	if exit != 0 {
		return out.Bytes(), classify(step, out.Bytes())
	}
	return out.Bytes(), nil
}

// recorded is a step's argv as the graph records it: the tool as shown, and output paths under
// the work directory written relative to it, so the same resolution records the same argv.
func (r *runner) recorded(args []string) []string {
	argv := []string{r.shown}
	for _, a := range args {
		argv = append(argv, strings.ReplaceAll(a, r.work, "$OUT"))
	}
	return argv
}

// findTool prefers the repository's executable wrapper, then the tool on PATH. Neither is
// toolchain_absent.
func findTool(dir, wrapper, onPath string, env []string) (path, shown string, isWrapper bool, err error) {
	w := filepath.Join(dir, wrapper)
	if fi, statErr := os.Stat(w); statErr == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
		return w, "./" + wrapper, true, nil
	}
	if p, lookErr := lookPath(onPath, env); lookErr == nil {
		return p, onPath, false, nil
	}
	return "", "", false, &Failure{Kind: KindToolchainAbsent, Detail: "", Log: "no ./" + wrapper + " and no " + onPath + " on PATH"}
}

// lookPath resolves name against the PATH the tool will run with, not the producer's own.
func lookPath(name string, env []string) (string, error) {
	path := ""
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			path = v
		}
	}
	for _, d := range filepath.SplitList(path) {
		if d == "" {
			continue
		}
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	return "", exec.ErrNotFound
}

// environ is the job's environment with the stated env overlaid, sorted by key.
func environ(base []string, overlay map[string]string) []string {
	m := map[string]string{}
	for _, kv := range base {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	for k, v := range overlay {
		m[k] = v
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+m[k])
	}
	return out
}

// sha256File is the hex sha256 of a regular file's contents.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// skipDirs are never walked for build inputs: VCS metadata, build output and tool caches.
var skipDirs = map[string]bool{".git": true, "target": true, "build": true, ".gradle": true, ".kotlin": true, "node_modules": true}

// collectInputs digests every regular file under dir that match accepts, by slash path from dir.
// Symlinks are not followed. Listing more files than the tool read only tightens the binding.
func collectInputs(dir string, match func(rel, name string) bool) ([]Input, error) {
	var inputs []Input
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != dir && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !match(rel, d.Name()) {
			return nil
		}
		sum, err := sha256File(p)
		if err != nil {
			return err
		}
		inputs = append(inputs, Input{Path: rel, SHA256: sum})
		return nil
	})
	if err != nil {
		return nil, &Failure{Kind: KindToolFailed, Detail: "inputs", Log: err.Error()}
	}
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].Path < inputs[j].Path })
	return inputs, nil
}

// treeSkipDirs are never walked inside an included build, wherever they sit: VCS metadata and
// tool caches, none a source package name can take. IDE state (.idea) is skipped only outside a
// src directory, since a resource directory inside one can take the name; build output only
// where it lives.
var treeSkipDirs = map[string]bool{".git": true, ".gradle": true, ".kotlin": true, "node_modules": true}

// collectTree digests every file under root/sub, an included build, by slash path from root. It
// walks from sub itself, so no ancestor's name keeps it out, and skips only a build directory that
// is a project's output (see buildOutput), so a source package named build is still read. A
// symlinked file is hashed under its own path when its target is in the checkout; any other
// symlink fails, since what it points to could change unseen. A required build must hold a file:
// one that holds none was recorded under some other name than the walk can find.
func collectTree(root, sub string, required bool) ([]Input, error) {
	fail := func(log string) error { return &Failure{Kind: KindToolFailed, Detail: "inputs", Log: log} }
	base := filepath.Join(root, filepath.FromSlash(sub))
	var inputs []Input
	err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != base && (treeSkipDirs[d.Name()] || d.Name() == ".idea" && !inSource(base, filepath.Dir(p)) || d.Name() == "build" && buildOutput(base, filepath.Dir(p))) {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(base, p)
		if err != nil {
			return err
		}
		rel = sub + "/" + filepath.ToSlash(rel)
		file := p
		switch {
		case d.Name() == ".DS_Store":
			return nil
		case d.Type().IsRegular():
		case d.Type()&fs.ModeSymlink != 0:
			target, ok := realRel(root, p)
			if !ok {
				return fail("symlink " + rel + " in an included build points outside the checkout")
			}
			file = filepath.Join(root, filepath.FromSlash(target))
			if fi, err := os.Stat(file); err != nil || !fi.Mode().IsRegular() {
				return fail("symlink " + rel + " in an included build is not to a file")
			}
		default:
			return nil
		}
		sum, err := sha256File(file)
		if err != nil {
			return err
		}
		inputs = append(inputs, Input{Path: rel, SHA256: sum})
		return nil
	})
	if err != nil {
		var f *Failure
		if errors.As(err, &f) {
			return nil, f
		}
		return nil, fail(err.Error())
	}
	if len(inputs) == 0 && required {
		return nil, fail("included build " + sub + " holds no build input")
	}
	return inputs, nil
}

// buildOutput reports whether a build directory in dir, under the included build at base, is a
// project's output: dir is base itself, which is a Gradle build whether or not it has a script
// (a script-less buildSrc still builds), or a directory holding a Gradle build or settings file.
// Nothing under a src directory is a project, so a script file there never hides a sibling
// source package named build.
func buildOutput(base, dir string) bool {
	if dir == base {
		return true
	}
	return !inSource(base, dir) && gradleProjectDir(dir)
}

// inSource reports whether dir, under the included build at base, lies in a src directory, or
// can't be placed relative to base.
func inSource(base, dir string) bool {
	rel, err := filepath.Rel(base, dir)
	return err != nil || slices.Contains(strings.Split(filepath.ToSlash(rel), "/"), "src")
}

// gradleProjectDir reports whether dir holds a Gradle build or settings file.
func gradleProjectDir(dir string) bool {
	for _, n := range []string{"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"} {
		if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
			return true
		}
	}
	return false
}

// gitSubject reads the checkout's commit and tree when dir is the top of a git work tree. In a
// subdirectory of one, or outside one, both are empty and the inputs alone bind the graph.
func gitSubject(ctx context.Context, dir string) (commit, tree string) {
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "--show-toplevel", "HEAD", "HEAD^{tree}").Output()
	if err != nil {
		return "", ""
	}
	f := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(f) != 3 {
		return "", ""
	}
	top, err1 := filepath.EvalSymlinks(f[0])
	abs, err2 := filepath.EvalSymlinks(dir)
	if err1 != nil || err2 != nil || top != abs {
		return "", ""
	}
	return f[1], f[2]
}

// relPath is p relative to root, slash-separated; false when p is outside root.
func relPath(root, p string) (string, bool) {
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// sameDir reports whether a and b name the same directory once symlinks are resolved.
func sameDir(a, b string) bool {
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	return err1 == nil && err2 == nil && ra == rb
}

// within reports whether p is root or under it once symlinks are resolved.
func within(root, p string) bool {
	_, ok := realRel(root, p)
	return ok
}

// realRel is p relative to root once symlinks in both are resolved; false when p is outside root
// or root is missing. A p that does not exist yet resolves through its nearest existing parent.
func realRel(root, p string) (string, bool) {
	rr, err1 := filepath.EvalSymlinks(root)
	rp, err2 := evalExisting(p)
	if err1 != nil || err2 != nil {
		return "", false
	}
	return relPath(rr, rp)
}

// evalExisting resolves symlinks in the longest existing prefix of the absolute path p and
// appends the rest.
func evalExisting(p string) (string, error) {
	p = filepath.Clean(p)
	var rest []string
	for {
		r, err := filepath.EvalSymlinks(p)
		if err == nil {
			for i := len(rest) - 1; i >= 0; i-- {
				r = filepath.Join(r, rest[i])
			}
			return r, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(p)
		if parent == p {
			return "", err
		}
		rest = append(rest, filepath.Base(p))
		p = parent
	}
}

// withInputs adds each of files, by slash path from dir, to inputs when collectInputs passed it
// over: a reactor POM under a skipped directory is still an input. A missing file fails.
func withInputs(dir string, inputs []Input, files []string) ([]Input, error) {
	have := map[string]bool{}
	for _, in := range inputs {
		have[in.Path] = true
	}
	for _, f := range files {
		if have[f] {
			continue
		}
		sum, err := sha256File(filepath.Join(dir, filepath.FromSlash(f)))
		if err != nil {
			return nil, &Failure{Kind: KindToolFailed, Detail: "inputs", Log: err.Error()}
		}
		have[f] = true
		inputs = append(inputs, Input{Path: f, SHA256: sum})
	}
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].Path < inputs[j].Path })
	return inputs, nil
}
