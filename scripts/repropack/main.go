// Command repropack writes the release tarball with bytes that depend on nothing but the payload.
//
// WHY THIS IS NOT `tar` AND `gzip`. The release asset's sha256 is what action.yml pins, so the
// archive has to be a pure function of the files inside it. Three properties of the shell recipe it
// replaces were not:
//
//   - `touch -t <stamp>` reads its argument in the caller's LOCAL time, so the member mtimes — and
//     therefore the digest — moved with the operator's timezone. Here the stamp is seconds since
//     the Unix epoch, which has no local reading.
//   - `--format=ustar` names a header layout, not a byte layout: bsdtar and GNU tar disagree on
//     what goes in the fields a regular file does not use (devmajor/devminor among them), so the
//     same payload archived on macOS and on a Linux runner differed. Here every field of every
//     header is written explicitly, by one implementation.
//   - Apple gzip and GNU gzip are different DEFLATE implementations and compress identical input
//     to different bytes. Here the compressor is Go's.
//
// The build already declares the Go toolchain load-bearing for byte-identity — two toolchains
// produce two different binaries, correctly, and every caller pins it. This makes the archive a
// function of that same pin instead of a function of whichever tar and gzip the host happens to
// ship, which is the only remaining way to say "same source, same bytes, any machine" honestly.
//
// Usage:
//
//	go run ./scripts/repropack -C <srcdir> -o <out.tar.gz> -epoch <seconds> <member>...
//
// Members are archived in the order given, which is part of the reproducibility contract. Every
// member must be a regular file: the payload is binaries plus an attribution file, and a symlink or
// a directory in it means the staging step did something unexpected, so it fails closed rather than
// archiving something the recipe did not intend.
package main

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func main() {
	src := flag.String("C", "", "directory the members are read from")
	out := flag.String("o", "", "path of the .tar.gz to write")
	epoch := flag.Int64("epoch", -1, "mtime stamped on every member, in seconds since the Unix epoch (UTC)")
	flag.Parse()

	if err := pack(*src, *out, *epoch, flag.Args()); err != nil {
		fmt.Fprintf(os.Stderr, "repropack: %v\n", err)
		os.Exit(1)
	}
}

func pack(src, out string, epoch int64, members []string) error {
	switch {
	case src == "":
		return fmt.Errorf("-C <srcdir> is required")
	case out == "":
		return fmt.Errorf("-o <out.tar.gz> is required")
	case epoch < 0:
		return fmt.Errorf("-epoch <seconds since the Unix epoch> is required and must not be negative")
	case len(members) == 0:
		return fmt.Errorf("no members named — refusing to write an empty archive")
	}

	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()

	// BestCompression, and a header carrying neither the source filename nor a timestamp — the
	// `gzip -n` posture, spelled as the absence of the fields rather than as a flag.
	zw, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return err
	}
	zw.Header.OS = 255 // unknown; the alternative is stamping the builder's operating system

	tw := tar.NewWriter(zw)
	for _, m := range members {
		if err := writeMember(tw, src, m, epoch); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return f.Close()
}

func writeMember(tw *tar.Writer, src, name string, epoch int64) error {
	path := filepath.Join(src, name)
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file (%s)", path, fi.Mode())
	}

	// The only bit of the on-disk mode that survives: whether the member is executable. Everything
	// else would carry the builder's umask into the archive.
	mode := int64(0o644)
	if fi.Mode().Perm()&0o100 != 0 {
		mode = 0o755
	}
	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Size:     fi.Size(),
		Mode:     mode,
		Uid:      0,
		Gid:      0,
		Uname:    "",
		Gname:    "",
		ModTime:  time.Unix(epoch, 0).UTC(),
		Format:   tar.FormatUSTAR,
	}); err != nil {
		return err
	}

	rf, err := os.Open(path)
	if err != nil {
		return err
	}
	defer rf.Close()
	n, err := io.Copy(tw, rf)
	if err != nil {
		return err
	}
	if n != fi.Size() {
		return fmt.Errorf("%s: read %d bytes, header declared %d — the file changed under us", path, n, fi.Size())
	}
	return nil
}
