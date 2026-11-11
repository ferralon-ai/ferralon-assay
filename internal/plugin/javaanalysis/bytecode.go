package javaanalysis

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/depreach"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// bytecode.go — the build's own compiled classes. Java first-party code is parsed from source
// for the lexical graph, but a whole-program search has to run over what the build compiled:
// the bytecode carries the real call targets (descriptor-exact, through the class hierarchy),
// and it is the same representation the dependency JARs are read in, so one engine spans
// first-party and dependency code.
//
// The class output is trusted only when it covers the sources: every top-level type declared
// in a main source file must have a class file, and none may be older than its source. A gap
// is a scoped first_party_bytecode_absent reason (unbounded: Package "", Targets nil), and the
// search over that output is never reported as Searched.

const reasonFirstPartyBytecodeAbsent = "first_party_bytecode_absent"

// firstPartyBytecode is the compiled main output found under a build dir.
type firstPartyBytecode struct {
	classes []classfile.Class
	roots   []string // class output directories that were read
	// cp lists the packages each class output directory defines; one that cannot be listed,
	// or holds a nested archive, leaves it unlisted.
	cp depreach.Classpath
	// gaps lists, one line each, why the output does not stand for the sources: a main
	// source type with no class file, a class file older than its source, or an unreadable
	// class file. Empty when the output covers every main source.
	gaps []string
	// unit is the unit module's own output when this is one reactor unit's view, else nil: the
	// launch entry is read from it alone.
	unit *unitOutput
}

// complete reports whether the class output was found and covers every main source.
func (b *firstPartyBytecode) complete() bool { return len(b.roots) > 0 && len(b.gaps) == 0 }

// scoped returns the partiality reasons the gaps incur, nil when there are none.
func (b *firstPartyBytecode) scoped() []plugin.ScopedReason {
	if len(b.roots) == 0 {
		return []plugin.ScopedReason{{Reason: reasonFirstPartyBytecodeAbsent, Path: "no compiled main classes under the build dir"}}
	}
	if len(b.gaps) == 0 {
		return nil
	}
	return []plugin.ScopedReason{{Reason: reasonFirstPartyBytecodeAbsent, Path: b.gaps[0]}}
}

// projectDirs returns the distinct project directories the class output roots belong to: the
// directory holding target/classes (Maven) or build/classes/<lang>/main (Gradle). Java and
// Kotlin output of one Gradle project count once.
func (b *firstPartyBytecode) projectDirs() []string {
	return classOutputProjects(b.roots)
}

// classOutputProjects returns the distinct project directories of class output roots, sorted.
func classOutputProjects(roots []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range roots {
		d := classOutputProject(r)
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

// classOutputProject is the project directory of one class output root.
func classOutputProject(root string) string {
	d := filepath.Dir(root) // .../target or .../build/classes/<lang>
	if filepath.Base(d) != "target" {
		d = filepath.Dir(filepath.Dir(d)) // .../build
	}
	return filepath.Dir(d)
}

// isClassOutputDir reports whether rel (slash-separated, relative to the build dir) is a
// main class output directory: Maven's target/classes or Gradle's build/classes/<lang>/main.
func isClassOutputDir(rel string) bool {
	segs := strings.Split(rel, "/")
	n := len(segs)
	if n >= 2 && segs[n-2] == "target" && segs[n-1] == "classes" {
		return true
	}
	return n >= 4 && segs[n-4] == "build" && segs[n-3] == "classes" && segs[n-1] == "main"
}

// classOutputRoots returns every main class output directory under buildDir, in walk order.
func classOutputRoots(buildDir string) []string {
	var roots []string
	_ = filepath.WalkDir(buildDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if path == buildDir {
				return err
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		name := d.Name()
		if path != buildDir && (strings.HasPrefix(name, ".") || name == "node_modules") {
			return filepath.SkipDir
		}
		rel, err := filepath.Rel(buildDir, path)
		if err != nil || !isClassOutputDir(filepath.ToSlash(rel)) {
			return nil
		}
		roots = append(roots, path)
		return filepath.SkipDir
	})
	return roots
}

// classOutput is one class output directory as read.
type classOutput struct {
	root    string
	pkgs    map[string]bool
	listed  bool // every package listed and the directory closed
	classes []classfile.Class
	times   map[string]time.Time // binary name -> class file modification time
	failed  []string
}

// readClassOutputs reads every main class output directory under buildDir.
func readClassOutputs(buildDir string) []classOutput {
	roots := classOutputRoots(buildDir)
	out := make([]classOutput, 0, len(roots))
	for _, root := range roots {
		pkgs, listed, closed := classfile.ClasspathPackages(root, buildDir)
		classes, times, failed := loadClassTree(root)
		out = append(out, classOutput{root: root, pkgs: pkgs, listed: listed && closed, classes: classes, times: times, failed: failed})
	}
	return out
}

// loadFirstPartyBytecode reads every main class output directory under buildDir and checks
// it against the main sources prog parsed.
func loadFirstPartyBytecode(buildDir string, prog *program) *firstPartyBytecode {
	return assembleFirstParty(buildDir, readClassOutputs(buildDir), prog.files)
}

// assembleFirstParty builds the first-party view over outputs, checked against the main sources
// in files.
func assembleFirstParty(buildDir string, outputs []classOutput, files []fileParse) *firstPartyBytecode {
	out := &firstPartyBytecode{}
	classTime := map[string]time.Time{}
	for _, o := range outputs {
		out.roots = append(out.roots, o.root)
		out.cp.Add(o.pkgs, o.listed)
		out.classes = append(out.classes, o.classes...)
		for k, v := range o.times {
			classTime[k] = v
		}
		out.gaps = append(out.gaps, o.failed...)
	}
	if len(out.roots) == 0 {
		return out
	}

	for _, f := range files {
		if !isMainSource(buildDir, f.path) {
			continue
		}
		info, err := os.Stat(f.path)
		if err != nil {
			out.gaps = append(out.gaps, f.path+": "+err.Error())
			continue
		}
		pkgPath := strings.ReplaceAll(f.pkg, ".", "/")
		for _, d := range f.decls {
			if d.kind != kindType || len(d.enclosing) != 0 {
				continue
			}
			bin := d.name
			if pkgPath != "" {
				bin = pkgPath + "/" + d.name
			}
			mod, ok := classTime[bin]
			switch {
			case !ok:
				out.gaps = append(out.gaps, f.path+": no class file for "+bin)
			case mod.Before(info.ModTime()):
				out.gaps = append(out.gaps, f.path+": class file for "+bin+" is older than its source")
			}
		}
	}
	sort.Strings(out.gaps)
	return out
}

// isMainSource reports whether a source file belongs to the production code the class output
// must cover: not a test source set (src/test, src/integrationTest, src/it, ...) and not a
// package-info or module-info file, which declare no type.
func isMainSource(buildDir, path string) bool {
	base := filepath.Base(path)
	if base == "package-info.java" || base == "module-info.java" {
		return false
	}
	rel, err := filepath.Rel(buildDir, path)
	if err != nil {
		return true
	}
	segs := strings.Split(filepath.ToSlash(rel), "/")
	for i := 0; i+1 < len(segs); i++ {
		if segs[i] != "src" {
			continue
		}
		set := strings.ToLower(segs[i+1])
		if set == "it" || strings.Contains(set, "test") {
			return false
		}
	}
	return true
}

// loadClassTree parses every .class file under root. failed lists files that could not be
// read or parsed; a file that is not a class file at all (bad magic) is skipped quietly. A
// multi-release override under META-INF/versions/ is listed in failed rather than read: a
// JDK at its release runs it in place of the base class, and the output is not merged.
func loadClassTree(root string) (classes []classfile.Class, times map[string]time.Time, failed []string) {
	times = map[string]time.Time{}
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			failed = append(failed, path+": "+err.Error())
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".class") || d.Name() == "module-info.class" {
			return nil
		}
		if rel, err := filepath.Rel(root, path); err == nil && strings.HasPrefix(filepath.ToSlash(rel), "META-INF/versions/") {
			failed = append(failed, path+": multi-release override not read")
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			failed = append(failed, path+": read: "+err.Error())
			return nil
		}
		c, err := classfile.ParseClass(data)
		if err != nil {
			if !errors.Is(err, classfile.ErrBadMagic) {
				failed = append(failed, path+": parse: "+err.Error())
			}
			return nil
		}
		if info, err := d.Info(); err == nil {
			times[c.Name] = info.ModTime()
		}
		classes = append(classes, c)
		return nil
	})
	return classes, times, failed
}
