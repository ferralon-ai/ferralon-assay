package goanalysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
)

type runCacheDirKey struct{}

// WithRunCacheDir returns ctx carrying the run cache: a directory the host creates for one scan and
// removes after it (see plugin.WithRunCacheDir). Each analyzer op runs in its own process, so without
// it every advisory re-executes govulncheck over the whole tree, rebuilds the reconciliation call
// graph, re-indexes the program's symbols and re-searches its ingresses, getting the same answer
// each time. With it, those per-tree results are computed once per scan and kept there. Without it, or with an empty dir, nothing is cached and
// every run computes its own.
func WithRunCacheDir(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, runCacheDirKey{}, dir)
}

// RunCacheDir returns the run cache directory ctx carries, or "" when it carries none.
func RunCacheDir(ctx context.Context) string {
	dir, _ := ctx.Value(runCacheDirKey{}).(string)
	return dir
}

// runCached returns the bytes compute produces for the given key, reusing an earlier result from the
// run cache when one exists. A failed compute is never stored. A cache that cannot be read or written
// degrades to computing, never to an error. Writes go through a rename so a concurrent reader sees
// either nothing or a whole entry.
func runCached(ctx context.Context, kind string, key []string, compute func() ([]byte, error)) ([]byte, error) {
	dir := RunCacheDir(ctx)
	if dir == "" {
		return compute()
	}
	path := runCachePath(dir, kind, key)
	if b, err := os.ReadFile(path); err == nil {
		return b, nil
	}
	b, err := compute()
	if err != nil {
		return nil, err
	}
	writeRunCacheEntry(dir, kind, path, b)
	return b, nil
}

// runCachePath is the file in the run cache dir that holds the entry of the given kind for key.
func runCachePath(dir, kind string, key []string) string {
	h := sha256.New()
	for _, k := range key {
		h.Write([]byte(k))
		h.Write([]byte{0})
	}
	return filepath.Join(dir, kind+"-"+hex.EncodeToString(h.Sum(nil)))
}

// writeRunCacheEntry stores b at path through a rename, so a concurrent reader sees either nothing
// or the whole entry. A write that fails leaves no entry and reports false.
func writeRunCacheEntry(dir, kind, path string, b []byte) bool {
	tmp, err := os.CreateTemp(dir, kind+"-*.tmp")
	if err != nil {
		return false
	}
	_, wErr := tmp.Write(b)
	cErr := tmp.Close()
	if wErr != nil || cErr != nil || os.Rename(tmp.Name(), path) != nil {
		_ = os.Remove(tmp.Name())
		return false
	}
	return true
}
