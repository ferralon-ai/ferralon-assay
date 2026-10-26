package javaanalysis

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// depcache.go — safe reads under a local artifact cache: the path checks the launch-entry
// reader's parent-POM lookups (launchpom.go) go through, so a coordinate the repository names
// never steers a read out of the cache, and the regular-file read every graph JAR goes through.

// splitCoordinate splits "groupId:artifactId" into its parts. ok is false unless
// both are non-empty and there is exactly one separator.
func splitCoordinate(coordinate string) (group, artifact string, ok bool) {
	parts := strings.Split(coordinate, ":")
	if len(parts) != 2 {
		return "", "", false
	}
	group, artifact = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if group == "" || artifact == "" {
		return "", "", false
	}
	return group, artifact, true
}

// validCacheSegment reports whether s can stand for one level of a cache path: it is
// non-empty and holds no path separator, no "..", and no NUL. Coordinates and versions come
// from the repository's own build files, so a crafted one ("../../planted/fake") must never
// steer a lookup out of the cache.
func validCacheSegment(s string) bool {
	return s != "" && s != "." && !strings.ContainsAny(s, "/\\\x00") && !strings.Contains(s, "..")
}

// validGAV reports whether a group, artifact and version are all valid cache segments.
func validGAV(group, artifact, version string) bool {
	return validCacheSegment(group) && validCacheSegment(artifact) && validCacheSegment(version)
}

// cacheLookup is the outcome of looking one relative path up under a cache root.
type cacheLookup int

const (
	cacheMiss   cacheLookup = iota // nothing is there, or only a directory
	cacheHit                       // a regular file whose real path stays inside the cache
	cacheEscape                    // the name resolves outside the cache, cannot be resolved or read, or is not a regular file
)

// missing reports whether err says nothing is at a path: no such name, or a non-directory
// where the path needs a directory. Any other failure (a permission, an I/O error) leaves the
// path's contents unknown, which is not the same as absent.
func missing(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

// inCache looks rel up under root. A hit returns the file's real path: every symlink resolved,
// and under root's own real path, so a symlinked root is fine but a link out of the cache is
// not. What an escaping link points at is not the build's cached artifact. Only a name that is
// not there is a miss; one that cannot be looked at could be the artifact the build used.
func inCache(root, rel string) (string, cacheLookup) {
	if root == "" {
		return "", cacheMiss
	}
	candidate := filepath.Join(root, rel)
	if _, err := os.Lstat(candidate); err != nil {
		if missing(err) {
			return "", cacheMiss
		}
		return "", cacheEscape
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", cacheEscape
	}
	real, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", cacheEscape
	}
	if !within(realRoot, real) {
		return "", cacheEscape
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", cacheEscape
	}
	if info.IsDir() {
		return "", cacheMiss
	}
	if !info.Mode().IsRegular() {
		return "", cacheEscape // a FIFO or device: reading it could block, and it is no cached artifact
	}
	return real, cacheHit
}

// within reports whether path lies under base; both are already resolved.
func within(base, path string) bool {
	r, err := filepath.Rel(base, path)
	return err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))
}

// rootLeavesCheckout reports whether a cache root inside the build directory resolves outside
// it. A cache the checkout carries is trusted as the build's own; one it only links to is
// somewhere else's bytes. A root outside the build directory (the user's caches) is never
// judged here, and a root that is not there leaves nothing to judge.
func rootLeavesCheckout(buildDir, root string) bool {
	if !within(filepath.Clean(buildDir), filepath.Clean(root)) {
		return false
	}
	realBuild, err := filepath.EvalSymlinks(buildDir)
	if err != nil {
		return true
	}
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		return !missing(err)
	}
	return !within(realBuild, real)
}

// readRegular reads a file it has checked, on the open descriptor, to be a regular file. The
// open does not block on a FIFO, and what is read is what was checked.
func readRegular(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	return io.ReadAll(f)
}
