package goanalysis

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
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
	h := sha256.New()
	for _, k := range key {
		h.Write([]byte(k))
		h.Write([]byte{0})
	}
	path := filepath.Join(dir, kind+"-"+hex.EncodeToString(h.Sum(nil)))
	if b, err := os.ReadFile(path); err == nil {
		return b, nil
	}
	b, err := compute()
	if err != nil {
		return nil, err
	}
	if tmp, err := os.CreateTemp(dir, kind+"-*.tmp"); err == nil {
		_, wErr := tmp.Write(b)
		cErr := tmp.Close()
		if wErr != nil || cErr != nil || os.Rename(tmp.Name(), path) != nil {
			_ = os.Remove(tmp.Name())
		}
	}
	return b, nil
}

// loadCacheKey is the run cache key for a result derived from loading the program at buildDir. The
// load runs the go command under this process's environment, which also names the go command's
// environment file (GOENV), and that file can set GOFLAGS, build tags included, without any
// variable in the environment changing. The analyzer binary decides what is computed from the load.
// The key carries all four.
func loadCacheKey(buildDir string) []string {
	return append([]string{buildDir, analyzerIdentity(), goEnvFileIdentity()}, os.Environ()...)
}

// analyzerIdentity names the running analyzer binary by the digest of its executable, read once per
// process. A binary that cannot be read gets a value unique to this process, so its entries are
// never shared with another binary's.
var analyzerIdentity = sync.OnceValue(func() string {
	if d, err := executableDigest(); err == nil {
		return "analyzer:" + d
	}
	return "analyzer-unidentified:" + uniqueToken()
})

func executableDigest() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	f, err := os.Open(exe)
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

// goEnvFileIdentity names the contents of the go command's environment file as the go command
// resolves it: GOENV when set ("off" reads none), else go/env under the user config directory. A
// missing file reads as empty, as it does to the go command. A file that cannot be read gets a
// value unique to this call, so nothing is shared under it.
func goEnvFileIdentity() string {
	path := os.Getenv("GOENV")
	if path == "off" {
		return "goenv:off"
	}
	if path == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return "goenv-none:" + err.Error()
		}
		path = filepath.Join(dir, "go", "env")
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "goenv:absent"
	}
	if err != nil {
		return "goenv-unreadable:" + uniqueToken()
	}
	sum := sha256.Sum256(b)
	return "goenv:" + hex.EncodeToString(sum[:])
}

func uniqueToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
