package acquire

import (
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Test 5.3: a full Acquire (fetch + verify + publish) spawns NO process. PATH is replaced with
// a directory whose only executables are sentinels that record any invocation; after an inert
// acquisition the sentinel must not exist. Verify uses crypto/sha*, never a sha*sum subprocess.
func TestAcquireSpawnsNoProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("spawn-shim detector is POSIX-only")
	}
	h := newHarness(t)
	data := []byte("bytes acquired under the spawn shim")
	h.serve(t, nugetHost, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))

	sentinel := installSpawnShim(t)

	acq := NewAcquirer(t.TempDir(), h.client)
	if _, err := acq.Acquire(t.Context(), nugetRef(data), nugetPolicy(nugetHost, false, RegistryCredentials{})); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatalf("a process was spawned during Acquire (sentinel %q created)", sentinel)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat sentinel: %v", err)
	}
}

// installSpawnShim replaces PATH with a dir of sentinel executables that touch a marker file
// when invoked. Returns the marker path (must NOT exist after an inert operation).
func installSpawnShim(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "spawned")
	script := "#!/bin/sh\ntouch '" + sentinel + "'\nexit 0\n"
	for _, name := range []string{"sh", "bash", "env", "curl", "wget", "git", "mvn", "npm", "dotnet", "pip", "pip3", "python", "python3", "node", "sha1sum", "sha256sum", "sha512sum", "shasum"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
			t.Fatalf("write shim %s: %v", name, err)
		}
	}
	t.Setenv("PATH", dir)
	return sentinel
}

// Test 5.4: the acquirer package's non-test source imports net/http and a crypto/sha* and does
// NOT import os/exec — a static guarantee no code path can shell out to a build/lifecycle tool.
func TestAcquirerImportsNoOSExec(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve package dir")
	}
	pkgDir := filepath.Dir(thisFile)

	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	sawNetHTTP, sawCryptoSHA := false, false
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(pkgDir, name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if path == "os/exec" {
				t.Errorf("%s imports os/exec — forbidden in the acquirer (no lifecycle/build execution)", name)
			}
			if path == "net/http" {
				sawNetHTTP = true
			}
			if strings.HasPrefix(path, "crypto/sha") {
				sawCryptoSHA = true
			}
		}
	}
	if !sawNetHTTP {
		t.Error("acquirer source does not import net/http (expected the fetch to use net/http)")
	}
	if !sawCryptoSHA {
		t.Error("acquirer source does not import crypto/sha* (expected in-process hashing)")
	}
}
