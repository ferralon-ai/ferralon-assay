package pythoncgx

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// IndexFailure is an engine failure while indexing a tree: a wasm trap (the linear-memory limit
// among them), the native process exiting, or the operation's context ending mid-index. It is
// a hard error. Its text leads with the tool_failure reason code so the cause reads the same
// wherever the error surfaces.
type IndexFailure struct {
	Transport Transport         `json:"transport"`
	Tree      string            `json:"tree"`
	Kind      EngineFailureKind `json:"kind"`
	Detail    string            `json:"detail"`
}

func (f *IndexFailure) Error() string {
	return fmt.Sprintf("%s: cgx %s engine failed indexing tree %s (%s): %s", reasonIndexFailed, f.Transport, f.Tree, f.Kind, f.Detail)
}

// deterministic reports whether indexing the same tree with the same engine and options is
// expected to fail the same way again. Other failures (a killed process, a deadline) may not
// recur, so their record expires.
func (f *IndexFailure) deterministic() bool {
	return f.Kind == EngineMemoryLimit || f.Kind == EngineTrap
}

// DefaultFailureTTL is how long a non-deterministic index failure is replayed before the index
// is attempted again.
const DefaultFailureTTL = 30 * time.Minute

// memoKey is everything that decides whether indexing a tree fails: the staged tree, the
// engine build and transport, and the options that shape indexing. Nothing about the process
// that asked is in it, so the record holds across scans, wrappers and hosts.
type memoKey struct {
	Tree        string    `json:"tree"`
	Engine      string    `json:"engine"`
	Transport   Transport `json:"transport"`
	PoolSize    int       `json:"pool_size"`
	MemoryLimit string    `json:"memory_limit"`
}

// failureMemo is the on-disk record of an IndexFailure.
type failureMemo struct {
	Key        memoKey       `json:"key"`
	RecordedAt time.Time     `json:"recorded_at"`
	Failure    *IndexFailure `json:"failure"`
}

// failureMemoPath names the record for key under the engine build's cache directory dir.
func failureMemoPath(dir string, key memoKey) string {
	data, _ := json.Marshal(key)
	sum := sha256.Sum256(data)
	return filepath.Join(dir, "index-failures", hex.EncodeToString(sum[:16])+".json")
}

// readFailureMemo returns the failure recorded at path for key, or nil: when there is none,
// when it cannot be read, when it was recorded for another key, or when it is non-deterministic
// and older than ttl. The index is then attempted again.
func readFailureMemo(path string, key memoKey, now time.Time, ttl time.Duration) *IndexFailure {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m failureMemo
	if json.Unmarshal(data, &m) != nil || m.Key != key || m.Failure == nil {
		return nil
	}
	if !m.Failure.deterministic() && now.Sub(m.RecordedAt) >= ttl {
		return nil
	}
	return m.Failure
}

func writeFailureMemo(path string, m failureMemo) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".memo-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}
