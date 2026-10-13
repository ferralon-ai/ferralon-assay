//go:build unix

package jsanalysis

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestCallGraph_InstalledManifestFIFO: a FIFO named package.json is not a regular file, so
// the installed-manifest read neither blocks on it nor trusts it, and the literal import()
// keeps dynamic_import_specifier. The timeout turns a blocking open into a failure, not a hang.
func TestCallGraph_InstalledManifestFIFO(t *testing.T) {
	root := writeProgram(t, map[string]string{
		"package.json": `{"name":"app"}`,
		"app.js":       "async function load(s) { const m = await import('x'); return m.parse(s); }\nload(process.argv);\n",
	})
	dir := filepath.Join(root, "node_modules", "x")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "package.json"), 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	type result struct {
		res plugin.CallGraphResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: root})
		done <- result{res, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("CallGraph: %v", r.err)
		}
		if !hasReason(r.res.Partiality, plugin.PartialReasonDynamicImportSpecifier) {
			t.Errorf("%s not declared; reasons %v", plugin.PartialReasonDynamicImportSpecifier, r.res.Partiality.Reasons)
		}
	case <-time.After(10 * time.Second):
		// Unblock the stuck open so the goroutine can finish.
		if f, err := os.OpenFile(filepath.Join(dir, "package.json"), os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			f.Close()
		}
		t.Fatal("CallGraph blocked on a FIFO named package.json")
	}
}
