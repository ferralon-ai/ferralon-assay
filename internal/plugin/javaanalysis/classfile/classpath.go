package classfile

import (
	"archive/zip"
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
func ClasspathPackages(path, root string) (pkgs map[string]bool, ok bool) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, false
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, false
		}
		if fi, err = os.Stat(target); err != nil {
			return nil, false
		}
		if fi.IsDir() && !within(target, root) {
			return nil, false
		}
		path = target
	}
	switch {
	case fi.Mode().IsRegular():
		return jarPackages(path)
	case fi.IsDir():
		return dirPackages(path)
	}
	return nil, false
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

func jarPackages(path string) (map[string]bool, bool) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, false
	}
	defer zr.Close()
	pkgs := map[string]bool{}
	for _, f := range zr.File {
		addClassPackage(pkgs, f.Name)
	}
	return pkgs, true
}

func dirPackages(root string) (map[string]bool, bool) {
	pkgs := map[string]bool{}
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
		addClassPackage(pkgs, filepath.ToSlash(rel))
		return nil
	})
	if err != nil || !ok {
		return nil, false
	}
	return pkgs, true
}

func addClassPackage(pkgs map[string]bool, name string) {
	if !strings.HasSuffix(name, ".class") {
		return
	}
	if rest, ok := strings.CutPrefix(name, "META-INF/versions/"); ok {
		if v, after, ok := strings.Cut(rest, "/"); ok && v != "" && strings.Trim(v, "0123456789") == "" {
			name = after
		}
	}
	if i := strings.LastIndexByte(name, '/'); i > 0 {
		pkgs[name[:i]] = true
	}
}
