package pythoncgx

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// IndexFailure is an engine failure while indexing a tree: a wasm trap (the linear-memory limit
// among them) or the native process exiting. It is a hard error. Its text leads with the
// tool_failure reason code so the cause reads the same wherever the error surfaces.
type IndexFailure struct {
	Transport Transport         `json:"transport"`
	Tree      string            `json:"tree"`
	Kind      EngineFailureKind `json:"kind"`
	Detail    string            `json:"detail"`
}

func (f *IndexFailure) Error() string {
	return fmt.Sprintf("%s: cgx %s engine failed indexing tree %s (%s): %s", reasonIndexFailed, f.Transport, f.Tree, f.Kind, f.Detail)
}

// failureMemo is the on-disk record of an IndexFailure, valid for the scan that wrote it.
type failureMemo struct {
	Scan    string        `json:"scan"`
	Failure *IndexFailure `json:"failure"`
}

// failureMemoPath names the record for one tree under one engine build's cache directory and
// the options that shape indexing (the build is the directory's key; dataflow is never set).
func failureMemoPath(dir, tree string, cfg Config) string {
	sum := sha256.Sum256([]byte(tree + "\x00pool_size=" + strconv.Itoa(cfg.PoolSize)))
	return filepath.Join(dir, "index-failures", hex.EncodeToString(sum[:8])+".json")
}

// readFailureMemo returns the failure recorded at path by the same scan, or nil. A record from
// another scan, or one that cannot be read, is ignored: the index is then attempted again.
func readFailureMemo(path, scan string) *IndexFailure {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m failureMemo
	if json.Unmarshal(data, &m) != nil || m.Scan != scan || m.Failure == nil {
		return nil
	}
	return m.Failure
}

func writeFailureMemo(path, scan string, f *IndexFailure) error {
	data, err := json.Marshal(failureMemo{Scan: scan, Failure: f})
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
