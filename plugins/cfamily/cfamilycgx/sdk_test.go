package cfamilycgx

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/cgx/sdk/go/cgx"
)

// engineStateError maps every Open failure to a loud engine-state error. An ABI mismatch (a
// module built from another cgx commit than this SDK, caught at instantiation rather than by
// the pin check above it) gets its own reason, distinguishable from a schema mismatch or an
// unconfigured engine, while still satisfying errors.Is(err, ErrEngineMismatch) for callers that
// only care that the engine and the SDK disagree.
func TestEngineStateError(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want error
	}{
		{"no_embedded_module", cgx.ErrNoEmbeddedModule, ErrEngineUnconfigured},
		{"abi_mismatch", cgx.ErrABIMismatch, ErrEngineABIMismatch},
		{"schema_mismatch", cgx.ErrSchemaMismatch, ErrEngineMismatch},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := engineStateError(c.err)
			if !errors.Is(got, c.want) {
				t.Errorf("engineStateError(%v) = %v, want %v", c.err, got, c.want)
			}
			if c.name != "abi_mismatch" {
				return
			}
			if !errors.Is(got, ErrEngineMismatch) {
				t.Errorf("ErrEngineABIMismatch does not satisfy errors.Is(_, ErrEngineMismatch)")
			}
			if r := engineReason(got); r != reasonEngineABIMismatch {
				t.Errorf("engineReason(%v) = %q, want %q", got, r, reasonEngineABIMismatch)
			}
		})
	}
}

// checkWasmCacheDir refuses a relative path, a symlink, a non-directory, a dir another user owns
// and a dir group or other can access; it accepts an unset dir untouched, accepts an existing
// private dir, and creates a private one that does not yet exist.
func TestCheckWasmCacheDir(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		if err := checkWasmCacheDir(Config{}); err != nil {
			t.Errorf("checkWasmCacheDir(unset) = %v, want nil", err)
		}
	})
	t.Run("relative", func(t *testing.T) {
		err := checkWasmCacheDir(Config{WasmCacheDir: "wazero-cache"})
		if !errors.Is(err, ErrEngineUnconfigured) {
			t.Errorf("checkWasmCacheDir(relative) = %v, want ErrEngineUnconfigured", err)
		}
	})
	t.Run("created_private", func(t *testing.T) {
		dir := t.TempDir() + "/wazero-cache"
		if err := checkWasmCacheDir(Config{WasmCacheDir: dir}); err != nil {
			t.Fatalf("checkWasmCacheDir(new) = %v", err)
		}
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o700 {
			t.Errorf("created cache dir mode = %v, want 0700", fi.Mode().Perm())
		}
	})
	t.Run("existing_private", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := checkWasmCacheDir(Config{WasmCacheDir: dir}); err != nil {
			t.Errorf("checkWasmCacheDir(existing private) = %v, want nil", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		target := t.TempDir()
		if err := os.Chmod(target, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "wazero-cache")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		err := checkWasmCacheDir(Config{WasmCacheDir: link})
		if !errors.Is(err, ErrEngineUnconfigured) {
			t.Errorf("checkWasmCacheDir(symlink to a private dir) = %v, want ErrEngineUnconfigured", err)
		}
	})
	t.Run("not_a_directory", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "wazero-cache")
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		err := checkWasmCacheDir(Config{WasmCacheDir: file})
		if !errors.Is(err, ErrEngineUnconfigured) {
			t.Errorf("checkWasmCacheDir(file) = %v, want ErrEngineUnconfigured", err)
		}
	})
	t.Run("foreign_owner", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(dir)
		if err != nil {
			t.Fatal(err)
		}
		owner, ok := fileOwner(info)
		if !ok {
			t.Skip("no file owner on this platform")
		}
		if err := checkPrivateDir(dir, info, owner); err != nil {
			t.Fatalf("checkPrivateDir(own uid) = %v, want nil", err)
		}
		if err := checkPrivateDir(dir, info, owner+1); !errors.Is(err, ErrEngineUnconfigured) {
			t.Errorf("checkPrivateDir(another uid) = %v, want ErrEngineUnconfigured", err)
		}
	})
	t.Run("group_writable", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o770); err != nil {
			t.Fatal(err)
		}
		err := checkWasmCacheDir(Config{WasmCacheDir: dir})
		if !errors.Is(err, ErrEngineUnconfigured) {
			t.Errorf("checkWasmCacheDir(group-writable) = %v, want ErrEngineUnconfigured", err)
		}
	})
}
