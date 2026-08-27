package kotlinanalysis

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

// buildoutput.go — first-party compiled-.class discovery and loading. Per A4, Kotlin
// first-party code is analyzed as its compiled BUILD OUTPUT, not its source. When no
// build output is present the analyzer cannot see the code at all — this is a
// tool-unavailable condition the caller declares as partiality (honest-absent, §3.6),
// never a confident "the project has no code".

// firstPartyClassRoots are the conventional compiled-output directories a Kotlin/JVM
// build populates, in the order they are searched. Gradle emits per-language class dirs
// (build/classes/kotlin/main, and build/classes/java/main for interop .java); Maven emits
// target/classes; IntelliJ emits out/production/classes. build/libs holds packaged JARs.
var firstPartyClassRoots = []string{
	filepath.Join("build", "classes", "kotlin", "main"),
	filepath.Join("build", "classes", "java", "main"),
	filepath.Join("target", "classes"),
	filepath.Join("out", "production", "classes"),
}

// firstPartyJarDir is the Gradle packaged-artifact directory; any .jar here is treated as
// first-party build output.
var firstPartyJarDir = filepath.Join("build", "libs")

// firstPartyLoad discovers and parses the first-party compiled classes under buildDir.
// found reports whether ANY build-output root existed (regardless of how many classes it
// held): found=false is the tool-unavailable signal the caller turns into partiality.
// failed collects per-class parse hazards (a class the analyzer could not read is a place
// an edge could hide — declared, never silently dropped). classes is sorted by binary name
// for deterministic downstream ordering.
func firstPartyLoad(buildDir string) (classes []classfile.Class, found bool, failed []string) {
	seen := map[string]bool{}
	add := func(cs []classfile.Class) {
		for _, c := range cs {
			if seen[c.Name] {
				continue
			}
			seen[c.Name] = true
			classes = append(classes, c)
		}
	}

	for _, rel := range firstPartyClassRoots {
		root := filepath.Join(buildDir, rel)
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		found = true
		cs, fs := loadClassTree(root)
		add(cs)
		failed = append(failed, fs...)
	}

	jarDir := filepath.Join(buildDir, firstPartyJarDir)
	if entries, err := os.ReadDir(jarDir); err == nil {
		found = true
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".jar") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			res, err := classfile.LoadJar(filepath.Join(jarDir, n))
			if err != nil {
				failed = append(failed, filepath.Join(firstPartyJarDir, n)+": "+err.Error())
				continue
			}
			add(res.Classes)
			failed = append(failed, res.Failed...)
		}
	}

	sort.Slice(classes, func(i, j int) bool { return classes[i].Name < classes[j].Name })
	return classes, found, failed
}

// loadClassTree walks a compiled-class directory, parsing every .class file. A file that
// cannot be read or parsed is recorded in failed (a completeness hazard), never aborting
// the walk — one hostile class must not blind the analysis to the rest.
func loadClassTree(root string) (classes []classfile.Class, failed []string) {
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			failed = append(failed, path+": "+err.Error())
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".class") {
			return nil
		}
		if d.Name() == "module-info.class" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			failed = append(failed, path+": read: "+err.Error())
			return nil
		}
		c, err := classfile.ParseClass(data)
		if err != nil {
			// A non-class .class entry is a quiet skip; a real parse failure is a hazard.
			if !errors.Is(err, classfile.ErrBadMagic) {
				failed = append(failed, path+": parse: "+err.Error())
			}
			return nil
		}
		classes = append(classes, c)
		return nil
	})
	return classes, failed
}
