package pythonanalysis

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"
)

// errNotRegular is returned for a path that names a pipe, socket, device or directory, or a
// symlink to one.
var errNotRegular = errors.New("not a regular file")

// readRegular reads the file at path, following symlinks, only when it is a regular file. A
// non-regular target is refused without being opened, since opening a pipe with no writer
// blocks. The open itself does not block, and the opened descriptor must be the same regular
// file. A path that is not there returns an error absent reports; every other refusal is an
// ordinary error, which callers treat as a file they could not read.
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

// readPythonSource reads a .py source with readRegular and converts its line breaks to "\n",
// as Python's tokenizer does, so every scanner sees the lines Python does whatever the file's
// line endings.
func readPythonSource(path string) (string, error) {
	data, err := readRegular(path)
	if err != nil {
		return "", err
	}
	return universalNewlines(string(data)), nil
}

// absent reports whether err from a filesystem call means the path is not there: it does not
// exist, or a component of it is not a directory. Every other error (a permission denial, a
// symlink loop, a name too long, an I/O error, a refused non-regular file) means the path was
// not read, and a caller must not treat it as absent.
func absent(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}
