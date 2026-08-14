// Package artifactcachetest provides the exported conformance harness every
// artifactcache.Store implementation is held to. It lives in a sibling package (the
// net/http/httptest pattern) so the core artifactcache leaf imports only
// context/io/errors and never transitively pulls the test framework into a lane indexer.
package artifactcachetest

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
)

// ProbeRef is the Ref ConformanceTest looks up. A conformance-tested Store MAY serve
// bytes for ProbeRef to exercise the full ReaderAt read path; returning ErrDeclaredAbsent
// is equally conformant — the no-execution assertion holds either way.
var ProbeRef = artifactcache.Ref{
	PURL:   "pkg:generic/artifactcache/conformance-probe@0",
	Digest: "sha256:" + strings.Repeat("0", 64),
}

// ConformanceTest is the exported layer-2 harness every Store implementation is held to.
// It drives Lookup and, on a hit, a full io.ReaderAt read to EOF plus Close, and asserts
// that ZERO processes are spawned during the operation. The spawn check is a PATH shim:
// PATH is replaced with a directory whose only executables are sentinels that record any
// invocation, so any bare-name exec resolved through PATH is detected. This complements —
// it does not replace — the static layer-1 guarantee (see artifactcache/noexec_test.go)
// that the Store and Handle method sets expose no execution capability in the first place.
//
// PLAN-200 impls call this against their real Store; Phase-1 fakes (which return
// ErrDeclaredAbsent or serve inert in-memory bytes) pass trivially, which is the point:
// the harness is exercised now so the impl merely plugs in later.
func ConformanceTest(t *testing.T, newStore func() artifactcache.Store) {
	t.Helper()

	sentinel := installSpawnShim(t)

	store := newStore()
	h, err := store.Lookup(context.Background(), ProbeRef)
	switch {
	case errors.Is(err, artifactcache.ErrDeclaredAbsent):
		// Inert miss — conformant. Nothing further to read.
	case err != nil:
		t.Fatalf("Lookup returned unexpected error: %v", err)
	default:
		if h == nil {
			t.Fatalf("Lookup returned nil Handle with nil error")
		}
		readAllHandle(t, h)
		if err := h.Close(); err != nil {
			t.Fatalf("Handle.Close returned error: %v", err)
		}
	}

	if _, err := os.Stat(sentinel); err == nil {
		t.Fatalf("ConformanceTest: a process was spawned during Lookup/read (sentinel %q created)", sentinel)
	} else if !os.IsNotExist(err) {
		t.Fatalf("ConformanceTest: stat sentinel: %v", err)
	}
}

// readAllHandle reads the whole Handle through io.ReaderAt, asserting the bytes are
// reachable inertly. It reads in small chunks so a large artifact never lands wholesale
// in memory, mirroring how a real indexer streams the central directory.
func readAllHandle(t *testing.T, h artifactcache.Handle) {
	t.Helper()
	var off int64
	buf := make([]byte, 4096)
	size := h.Size()
	for {
		n, err := h.ReadAt(buf, off)
		off += int64(n)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Handle.ReadAt at offset %d: %v", off, err)
		}
		if n == 0 {
			t.Fatalf("Handle.ReadAt made no progress at offset %d", off)
		}
	}
	if size >= 0 && off != size {
		t.Fatalf("Handle read %d bytes, Size() reported %d", off, size)
	}
}

// installSpawnShim replaces PATH for the duration of the test with a directory whose
// only executables are sentinels: invoking any of them creates the returned sentinel
// file. It returns the sentinel path (which must NOT exist after an inert operation).
func installSpawnShim(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("spawn-shim detector is POSIX-only")
	}

	dir := t.TempDir()
	sentinel := filepath.Join(dir, "spawned")
	script := "#!/bin/sh\ntouch " + shellQuote(sentinel) + "\nexit 0\n"

	// Cover the command names a rogue implementation would most plausibly reach for.
	for _, name := range []string{"sh", "bash", "env", "git", "docker", "curl", "java", "python", "python3", "node", "mvn"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
			t.Fatalf("installSpawnShim: write %s: %v", name, err)
		}
	}

	oldPath, had := os.LookupEnv("PATH")
	if err := os.Setenv("PATH", dir); err != nil {
		t.Fatalf("installSpawnShim: setenv PATH: %v", err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("PATH", oldPath)
		} else {
			_ = os.Unsetenv("PATH")
		}
	})
	return sentinel
}

// shellQuote single-quotes a path for safe interpolation into the /bin/sh shim.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
