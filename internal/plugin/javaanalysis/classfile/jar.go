package classfile

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"strings"
)

// JarResult is the outcome of parsing every class in a JAR. Failed records entries
// that could not be parsed: these are completeness hazards — a dependency class the
// analysis could not read is a place a call edge could hide — and the caller must
// declare them, never treat the shortfall as "nothing there".
type JarResult struct {
	Classes []Class
	Entries int      // .class entries considered (excludes META-INF/ and module-info)
	Failed  []string // "<entry>: <reason>" per class that failed to parse
	// Resources holds the raw bytes of the named non-.class zip entries a caller
	// requested via LoadJarWithResources (e.g. META-INF/spring.factories,
	// META-INF/spring/*.AutoConfiguration.imports for auto-config bean-existence).
	// nil when no resource predicate was supplied — the .class parse is unaffected.
	Resources map[string][]byte
}

// LoadJar opens a JAR (a zip of .class files) and parses every application class in
// it. A zip that cannot be opened is a hard error (the artifact is unreadable);
// individual class parse failures are collected in JarResult.Failed rather than
// aborting, so one hostile class does not blind the analysis to the rest.
func LoadJar(path string) (JarResult, error) {
	return LoadJarWithResources(path, nil)
}

// LoadJarWithResources is LoadJar plus the ability to also read named non-.class zip
// entries: every entry whose name satisfies wantResource is read into
// JarResult.Resources keyed by its full zip path. It is purely additive — the .class
// selection (isApplicationClass) and Entries accounting are byte-identical to LoadJar,
// so a nil wantResource yields exactly LoadJar's result. A resource that cannot be read
// is recorded in Failed as a completeness hazard, never a silent drop.
func LoadJarWithResources(path string, wantResource func(name string) bool) (JarResult, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return JarResult{}, fmt.Errorf("classfile: open jar %q: %w", path, err)
	}
	defer zr.Close()
	return loadZip(&zr.Reader, wantResource)
}

// loadZip parses classes from an already-open zip.Reader — the shared core of
// LoadJar and the in-memory path used by tests. When wantResource is non-nil, a
// non-.class entry it selects is read into res.Resources; .class handling is unchanged.
func loadZip(zr *zip.Reader, wantResource func(name string) bool) (JarResult, error) {
	var res JarResult
	for _, f := range zr.File {
		if !isApplicationClass(f.Name) {
			if wantResource != nil && wantResource(f.Name) {
				data, err := readZipEntry(f)
				if err != nil {
					res.Failed = append(res.Failed, fmt.Sprintf("%s: read: %v", f.Name, err))
					continue
				}
				if res.Resources == nil {
					res.Resources = map[string][]byte{}
				}
				res.Resources[f.Name] = data
			}
			continue
		}
		res.Entries++
		data, err := readZipEntry(f)
		if err != nil {
			res.Failed = append(res.Failed, fmt.Sprintf("%s: read: %v", f.Name, err))
			continue
		}
		c, err := ParseClass(data)
		if err != nil {
			if errors.Is(err, ErrBadMagic) {
				// A .class-named entry that is not a class — skip quietly, not a hazard.
				res.Entries--
				continue
			}
			res.Failed = append(res.Failed, fmt.Sprintf("%s: parse: %v", f.Name, err))
			continue
		}
		res.Classes = append(res.Classes, c)
	}
	return res, nil
}

// isApplicationClass reports whether a zip entry is a class we analyze. It excludes
// META-INF/ (signatures, and multi-release version overrides under
// META-INF/versions/N/ — selecting the right release is a documented precision
// refinement, not a core-soundness concern) and module-info.class (no methods).
func isApplicationClass(name string) bool {
	if !strings.HasSuffix(name, ".class") {
		return false
	}
	if strings.HasPrefix(name, "META-INF/") {
		return false
	}
	if name == "module-info.class" || strings.HasSuffix(name, "/module-info.class") {
		return false
	}
	return true
}

func readZipEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}
