package artifactcache

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
)

// seedArtifact writes bytes to the canonical path under root and returns the Ref that
// addresses them (digest = real sha256 of the bytes, in hex wire form).
func seedArtifact(t *testing.T, root string, data []byte) Ref {
	t.Helper()
	sum := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	path, err := CanonicalPath(root, digest)
	if err != nil {
		t.Fatalf("CanonicalPath: %v", err)
	}
	if err := os.MkdirAll(dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, data, 0o444); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	return Ref{PURL: "pkg:nuget/Seeded@1.0.0", Digest: digest}
}

func dir(path string) string {
	i := len(path) - 1
	for i >= 0 && path[i] != '/' {
		i--
	}
	return path[:i]
}

// Test 2.1: MISS on a never-acquired ref → ErrDeclaredAbsent, nil Handle.
func TestDiskStoreLookupMiss(t *testing.T) {
	store := NewDiskStore(t.TempDir())
	h, err := store.Lookup(t.Context(), Ref{PURL: "pkg:nuget/x@1", Digest: "sha256:" + hex.EncodeToString(make([]byte, 32))})
	if !errors.Is(err, ErrDeclaredAbsent) {
		t.Fatalf("Lookup miss err = %v, want ErrDeclaredAbsent", err)
	}
	if h != nil {
		t.Fatalf("Lookup miss returned non-nil Handle %v", h)
	}
}

// Test 6.2-shape: on a hit, Handle yields the exact bytes and the content-addressed Path.
func TestDiskStoreLookupHit(t *testing.T) {
	root := t.TempDir()
	data := []byte("inert nupkg bytes for the read path")
	ref := seedArtifact(t, root, data)
	store := NewDiskStore(root)

	h, err := store.Lookup(t.Context(), ref)
	if err != nil {
		t.Fatalf("Lookup hit: %v", err)
	}
	defer h.Close()
	if h.Size() != int64(len(data)) {
		t.Fatalf("Size() = %d, want %d", h.Size(), len(data))
	}
	want, err := CanonicalPath(root, ref.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if h.Path() != want {
		t.Fatalf("Path() = %q, want %q", h.Path(), want)
	}
	buf := make([]byte, len(data))
	if n, err := h.ReadAt(buf, 0); n != len(data) || (err != nil && !errors.Is(err, os.ErrClosed) && err.Error() != "EOF") {
		// os.File.ReadAt returns io.EOF exactly at end; a full read returns nil.
		if string(buf) != string(data) {
			t.Fatalf("ReadAt content = %q, want %q (n=%d err=%v)", buf, data, n, err)
		}
	}
	if string(buf) != string(data) {
		t.Fatalf("ReadAt content = %q, want %q", buf, data)
	}
}

// A ref.Digest that fails the gate surfaces on Lookup as ErrMalformedRef (distinct from a
// miss), and yields no Handle.
func TestDiskStoreLookupMalformed(t *testing.T) {
	store := NewDiskStore(t.TempDir())
	h, err := store.Lookup(t.Context(), Ref{PURL: "pkg:nuget/x@1", Digest: "md5:deadbeef"})
	if !errors.Is(err, ErrMalformedRef) {
		t.Fatalf("Lookup malformed err = %v, want ErrMalformedRef", err)
	}
	if h != nil {
		t.Fatalf("Lookup malformed returned non-nil Handle")
	}
}
