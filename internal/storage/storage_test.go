package storage_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/storage"
)

// TEGRON_HOME is both the brand-derived and legacy name on the OSS default build
// (brand.EnvPrefix == "TEGRON") — see envHome/legacyEnvHome in storage.go. Precedence (derived
// wins, legacy honored, regression guard) is proven build-tag-independently in
// brand/brand_env_test.go; these two tests prove the real DefaultRoot integration.
func TestDefaultRoot_HonorsTEGRON_HOME(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TEGRON_HOME", dir)
	got, err := storage.DefaultRoot()
	if err != nil {
		t.Fatalf("DefaultRoot: %v", err)
	}
	if got != dir {
		t.Fatalf("got %q, want %q", got, dir)
	}
}

func TestDefaultRoot_FallsBackToHome(t *testing.T) {
	t.Setenv("TEGRON_HOME", "")
	got, err := storage.DefaultRoot()
	if err != nil {
		t.Fatalf("DefaultRoot: %v", err)
	}
	if !strings.HasSuffix(got, filepath.Join(".ferralon", "tegron")) {
		t.Fatalf("got %q, want suffix .ferralon/tegron", got)
	}
}

func TestEnsure_WritesVersionAndIdempotent(t *testing.T) {
	root := t.TempDir()
	if err := storage.Ensure(root); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	// VERSION file exists with content "1\n".
	data, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		t.Fatalf("ReadFile VERSION: %v", err)
	}
	if string(data) != "1\n" {
		t.Fatalf("VERSION = %q, want %q", data, "1\n")
	}
	// Idempotent: second call must not error.
	if err := storage.Ensure(root); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
}

func TestEnsure_CreatesRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "newroot")
	if err := storage.Ensure(root); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatalf("stat root: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("root is not a directory")
	}
	// Mode should be 0o700 (owner rwx only).
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("root perm = %o, want 0700", info.Mode().Perm())
	}
}

func TestWriteAtomic_CreatesAndOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")

	data1 := []byte(`{"v":1}`)
	if err := storage.WriteAtomic(path, data1); err != nil {
		t.Fatalf("WriteAtomic (create): %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(data1) {
		t.Fatalf("got %q, want %q", got, data1)
	}

	// Overwrite.
	data2 := []byte(`{"v":2}`)
	if err := storage.WriteAtomic(path, data2); err != nil {
		t.Fatalf("WriteAtomic (overwrite): %v", err)
	}
	got2, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after overwrite: %v", err)
	}
	if string(got2) != string(data2) {
		t.Fatalf("overwrite got %q, want %q", got2, data2)
	}
}

func TestWriteAtomic_NoTempLeftBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	if err := storage.WriteAtomic(path, []byte("hello")); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestWriteAtomic_FileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	if err := storage.WriteAtomic(path, []byte("x")); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file perm = %o, want 0600", info.Mode().Perm())
	}
}

func TestLayoutVersionConstant(t *testing.T) {
	if storage.LayoutVersion != "1" {
		t.Fatalf("LayoutVersion = %q, want %q", storage.LayoutVersion, "1")
	}
}
