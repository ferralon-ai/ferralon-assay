package jsanalysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
)

type runCacheDirKey struct{}

// WithRunCacheDir returns ctx carrying the run cache: a directory the host creates for one scan and
// removes after it (see plugin.WithJSRunCacheDir). Each op runs in its own process, so without it
// every advisory rereads and relinks the build's dependency code. Without it, or with an empty dir,
// nothing is cached.
func WithRunCacheDir(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, runCacheDirKey{}, dir)
}

// runCached returns the bytes compute produces for key, reusing an earlier result from the run
// cache when one exists. A failed compute is never stored, and a cache that cannot be read or
// written degrades to computing. Writes go through a rename so a concurrent reader sees either
// nothing or a whole entry.
func runCached(ctx context.Context, kind string, key []string, compute func() ([]byte, error)) ([]byte, error) {
	dir, _ := ctx.Value(runCacheDirKey{}).(string)
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
