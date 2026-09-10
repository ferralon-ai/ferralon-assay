package artifactcachetest

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
)

// TestConformanceHarnessExercised drives the exported layer-2 ConformanceTest against
// both Phase-1 fakes so the harness itself is tested this cycle: the declared-absent
// store (a trivial miss) and an in-memory store that serves ProbeRef (a full ReaderAt
// read path). Both must report zero process spawns.
func TestConformanceHarnessExercised(t *testing.T) {
	t.Run("declared_absent", func(t *testing.T) {
		ConformanceTest(t, artifactcache.NewDeclaredAbsentStore)
	})
	t.Run("mem_store_read_path", func(t *testing.T) {
		ConformanceTest(t, func() artifactcache.Store {
			return artifactcache.NewMemStore(map[artifactcache.Ref][]byte{
				ProbeRef: []byte("inert artifact bytes for the conformance read path"),
			})
		})
	})
}
