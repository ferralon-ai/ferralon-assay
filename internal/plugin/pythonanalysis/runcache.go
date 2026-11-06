package pythonanalysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

type runCacheDirKey struct{}

// WithRunCacheDir returns ctx carrying the run cache: a directory the host creates for one scan and
// removes after it (see plugin.WithPythonRunCacheDir). Each op runs in its own process, so without it
// every advisory reparses the whole tree to rebuild the call graph, the ingresses and the symbol
// index, getting the same answer each time. With it, those per-tree results, and the reachability
// and symbol-resolution results derived from them, are computed once per scan. Without it, or with
// an empty dir, nothing is cached.
func WithRunCacheDir(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, runCacheDirKey{}, dir)
}

// runCacheSalt versions every key, so a change to what a cached result holds starts a fresh set.
const runCacheSalt = "python-v1"

// onRunCacheCompute, when set, is called each time a cached op computes instead of replaying an
// entry. Tests count through it.
var onRunCacheCompute func(kind string)

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

// cachedResult returns compute's result for key through the run cache, stored as the JSON the
// plugin protocol carries it as. The computing call returns its own value; a later one decodes
// the entry. An entry that does not decode is recomputed.
func cachedResult[T any](ctx context.Context, kind string, key []string, compute func() (T, error)) (T, error) {
	run := func() (T, error) {
		if onRunCacheCompute != nil {
			onRunCacheCompute(kind)
		}
		return compute()
	}
	var computed T
	var ran bool
	b, err := runCached(ctx, kind, append([]string{runCacheSalt}, key...), func() ([]byte, error) {
		v, err := run()
		if err != nil {
			return nil, err
		}
		computed, ran = v, true
		return json.Marshal(v)
	})
	if err != nil {
		var zero T
		return zero, err
	}
	if ran {
		return computed, nil
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return run()
	}
	return v, nil
}

// symbolsKey is a request's symbol list as one key part, so no symbol can run into its
// neighbour. A nil list and an empty one key alike, as both ask for nothing.
func symbolsKey(symbols []string) string {
	if symbols == nil {
		symbols = []string{}
	}
	b, _ := json.Marshal(symbols)
	return string(b)
}
