package goanalysis

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// A Go module whose go command is missing, dangling, or exits non-zero is never a clean, empty
// inventory: it is a tool_failure partial that names the command and its error.
func TestResolveInventory_BrokenGoCommandIsPartialWithCause(t *testing.T) {
	failing := t.TempDir()
	if err := os.WriteFile(filepath.Join(failing, "go"), []byte("#!/bin/sh\necho 'toolchain exploded' >&2\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	dangling := t.TempDir()
	if err := os.Symlink(filepath.Join(dangling, "gone"), filepath.Join(dangling, "go")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, path, want string }{
		{"missing", t.TempDir(), `"go": executable file not found`},
		{"dangling", dangling, "go mod graph:"},
		{"failing", failing, "toolchain exploded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeDir(t, dir, map[string]string{"go.mod": "module example.com/w\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.7\n"})
			t.Setenv("PATH", tc.path)
			inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			if inv.Partiality.Complete || !contains(inv.Partiality.Reasons, plugin.PartialReasonToolFailure) {
				t.Fatalf("partiality = %+v, want tool_failure", inv.Partiality)
			}
			if !strings.HasPrefix(inv.Partiality.Cause, "go mod graph:") || !strings.Contains(inv.Partiality.Cause, tc.want) {
				t.Fatalf("cause = %q, want it to name the command and %q", inv.Partiality.Cause, tc.want)
			}
		})
	}
}
