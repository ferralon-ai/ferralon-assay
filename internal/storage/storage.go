// Package storage provides shared filesystem primitives for the on-disk stores.
package storage

import (
	"os"
	"path/filepath"
)

// LayoutVersion is the on-disk layout version written to the VERSION file.
const LayoutVersion = "1"

// Ensure creates root at mode 0o700 (no-op if it exists) and writes a VERSION
// file containing "1\n" at 0o600 if the file is not already present. Idempotent.
func Ensure(root string) error {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	vpath := filepath.Join(root, "VERSION")
	if _, err := os.Stat(vpath); os.IsNotExist(err) {
		return WriteAtomic(vpath, []byte(LayoutVersion+"\n"))
	}
	return nil
}

// WriteAtomic writes data to path via a same-directory temp file followed by an
// os.Rename (crash-safe on a single filesystem). The final file is 0o600. On any
// error the temp file is removed before returning.
func WriteAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	tmp, err := os.CreateTemp(dir, base+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	// Best-effort cleanup on failure.
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}
