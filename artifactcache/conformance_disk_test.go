package artifactcache_test

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
	"github.com/ferralon-ai/ferralon-assay/artifactcache/artifactcachetest"
)

// Test 5.2: the real disk-backed Store passes the exported conformance harness — zero
// process spawns during Lookup + full read, for both the hex and base64 probes. An empty
// cache root returns ErrDeclaredAbsent for both probes, which is conformant.
func TestDiskStoreConformance(t *testing.T) {
	root := t.TempDir()
	artifactcachetest.ConformanceTest(t, func() artifactcache.Store {
		return artifactcache.NewDiskStore(root)
	})
}
