package classfile

import (
	"archive/zip"
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ClasspathPackages lists the packages the classpath entry at path defines a class in, read
// from a JAR's zip central directory or a class directory's file names; no class is parsed.
// A multi-release JAR's META-INF/versions/<n>/ entries count under their unversioned package.
//
// ok is false when the entry cannot be listed in full, and the caller must then assume it may
// define any package: it is missing or unreadable, is not a zip, is neither a regular file nor
// a directory (a FIFO, device or socket, which is never opened), is a directory symlink that
// resolves outside root, or is a class directory holding a symlink or a non-regular file.
//
// closed is true only when the listing is everything the entry can put on the classpath. It is
// false when the entry holds a nested archive (a .jar, .war or .zip at any depth, which a
// nested-JAR launcher such as Spring Boot's loads classes from), a class under a directory that
// is not a package name (BOOT-INF/classes/, WEB-INF/classes/: a loader roots it elsewhere), or
// the JAR's manifest names further JARs in a non-empty Class-Path. The caller still reads the
// entry's own classes, but must assume the classpath may define any package.
func ClasspathPackages(path, root string) (pkgs map[string]bool, ok, closed bool) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, false, false
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, false, false
		}
		if fi, err = os.Stat(target); err != nil {
			return nil, false, false
		}
		if fi.IsDir() && !within(target, root) {
			return nil, false, false
		}
		path = target
	}
	switch {
	case fi.Mode().IsRegular():
		return jarPackages(path)
	case fi.IsDir():
		return dirPackages(path)
	}
	return nil, false, false
}

// within reports whether the resolved path lies inside root once root's own symlinks resolve.
func within(path, root string) bool {
	r, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(r, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// JarBytesPackages is ClasspathPackages for a JAR already read into memory, so the caller lists
// the same bytes it parses.
func JarBytesPackages(data []byte) (pkgs map[string]bool, ok, closed bool) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, false, false
	}
	return zipPackages(zr.File)
}

func jarPackages(path string) (map[string]bool, bool, bool) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, false, false
	}
	defer zr.Close()
	return zipPackages(zr.File)
}

func zipPackages(files []*zip.File) (map[string]bool, bool, bool) {
	pkgs, closed := map[string]bool{}, true
	for _, f := range files {
		closed = addClassPackage(pkgs, f.Name) && closed && !nestedArchive(f.Name)
		if strings.EqualFold(f.Name, "META-INF/MANIFEST.MF") {
			cp, ok := manifestClassPath(f)
			if !ok {
				return nil, false, false
			}
			closed = closed && !cp
		}
	}
	return pkgs, true, closed
}

func nestedArchive(name string) bool {
	n := strings.ToLower(name)
	return strings.HasSuffix(n, ".jar") || strings.HasSuffix(n, ".war") || strings.HasSuffix(n, ".zip")
}

// manifestClassPath reports whether the manifest's main section has a non-empty Class-Path
// attribute (names are case-insensitive; a line starting with a space continues the previous
// one). ok is false when the manifest cannot be read.
func manifestClassPath(f *zip.File) (classPath, ok bool) {
	rc, err := f.Open()
	if err != nil {
		return false, false
	}
	defer rc.Close()
	var value *strings.Builder
	sc := bufio.NewScanner(rc)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		line := strings.TrimSuffix(sc.Text(), "\r")
		if line == "" {
			break
		}
		if strings.HasPrefix(line, " ") {
			if value != nil {
				value.WriteString(line[1:])
			}
			continue
		}
		if value != nil && strings.TrimSpace(value.String()) != "" {
			return true, true
		}
		value = nil
		if k, v, found := strings.Cut(line, ":"); found && strings.EqualFold(k, "Class-Path") {
			value = &strings.Builder{}
			value.WriteString(v)
		}
	}
	if sc.Err() != nil {
		return false, false
	}
	return value != nil && strings.TrimSpace(value.String()) != "", true
}

func dirPackages(root string) (map[string]bool, bool, bool) {
	pkgs, closed := map[string]bool{}, true
	ok := true
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			ok = false
			return fs.SkipAll
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		closed = addClassPackage(pkgs, filepath.ToSlash(rel)) && closed && !nestedArchive(rel)
		return nil
	})
	if err != nil || !ok {
		return nil, false, false
	}
	return pkgs, true, closed
}

// addClassPackage records the package of a class entry. It reports false when the entry's
// directory is not a package name, so no standard loader finds the class at that path.
func addClassPackage(pkgs map[string]bool, name string) bool {
	if !strings.HasSuffix(name, ".class") {
		return true
	}
	if rest, ok := strings.CutPrefix(name, "META-INF/versions/"); ok {
		if v, after, ok := strings.Cut(rest, "/"); ok && v != "" && strings.Trim(v, "0123456789") == "" {
			name = after
		}
	}
	i := strings.LastIndexByte(name, '/')
	if i <= 0 {
		return true
	}
	pkgs[name[:i]] = true
	for _, seg := range strings.Split(name[:i], "/") {
		for k, c := range []byte(seg) {
			if !(c == '_' || c == '$' || c >= 0x80 || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || k > 0 && '0' <= c && c <= '9') {
				return false
			}
		}
		if seg == "" {
			return false
		}
	}
	return true
}
