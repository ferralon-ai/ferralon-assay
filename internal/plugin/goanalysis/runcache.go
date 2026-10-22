package goanalysis

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
)

// EnvRunCacheDir names a directory the host creates for one scan and removes after it (see
// plugin.WithRunCacheDir). Each analyzer
// op runs in its own process, so without it every advisory's reachability run re-executes govulncheck
// over the whole tree and rebuilds the reconciliation call graph, getting the same answer each time.
// With it set, those per-tree results are computed once per scan and kept here. Unset, nothing is
// cached and every run computes its own.
var EnvRunCacheDir = brand.EnvPrefix + "_GO_RUN_CACHE_DIR"

// runCached returns the bytes compute produces for the given key, reusing an earlier result from the
// run cache when one exists. A failed compute is never stored. A cache that cannot be read or written
// degrades to computing, never to an error. Writes go through a rename so a concurrent reader sees
// either nothing or a whole entry.
func runCached(kind string, key []string, compute func() ([]byte, error)) ([]byte, error) {
	dir := os.Getenv(EnvRunCacheDir)
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
