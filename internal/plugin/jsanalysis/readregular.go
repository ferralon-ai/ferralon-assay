package jsanalysis

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// errNotRegular is returned for a path that names a pipe, socket, device or directory, or a
// symlink to one.
var errNotRegular = errors.New("not a regular file")

// readRegular reads the file at path, following symlinks, only when it is a regular file. A
// non-regular target is refused without being opened, since opening a pipe with no writer
// blocks. The open itself does not block, and the opened descriptor must be the same regular
// file. A path that does not exist returns an error os.IsNotExist reports; every other refusal
// is an ordinary error, which callers treat as a file they could not read.
func readRegular(path string) ([]byte, error) {
	want, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !want.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", path, errNotRegular)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	got, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !got.Mode().IsRegular() || !os.SameFile(want, got) {
		return nil, fmt.Errorf("%s: changed while it was opened", path)
	}
	return io.ReadAll(f)
}
