package goanalysis

import (
	"os"
	"path/filepath"
	"testing"
)

// TestConstrainedOut: a file counts as left out by build constraints alone only when go/build excludes
// it under the scan's GOOS, GOARCH and tags whatever the cgo setting; a built file, a skipped name and
// an unreadable one are not constraints.
func TestConstrainedOut(t *testing.T) {
	cases := []struct {
		name string
		file string
		src  string
		env  []string
		want bool
	}{
		{"another GOOS in the name", "a_windows.go", "package p\n", []string{"GOOS=linux", "GOARCH=amd64"}, true},
		{"the scanned GOOS in the name", "a_linux.go", "package p\n", []string{"GOOS=linux", "GOARCH=amd64"}, false},
		{"another GOARCH in the name", "a_arm64.go", "package p\n", []string{"GOOS=linux", "GOARCH=amd64"}, true},
		{"a tag the scan does not set", "a.go", "//go:build prod\n\npackage p\n", []string{"GOOS=linux", "GOARCH=amd64"}, true},
		{"a tag the scan sets", "a.go", "//go:build prod\n\npackage p\n", []string{"GOOS=linux", "GOARCH=amd64", "GOFLAGS=-tags=prod"}, false},
		{"no constraint", "a.go", "package p\n", []string{"GOOS=linux", "GOARCH=amd64"}, false},
		{"cgo off is not a constraint", "a.go", "package p\n\nimport \"C\"\n", []string{"GOOS=linux", "GOARCH=amd64"}, false},
		{"a skipped name is not a constraint", "_a.go", "//go:build prod\n\npackage p\n", []string{"GOOS=linux", "GOARCH=amd64"}, false},
		{"a file go/build rejects", "a.go", "//go:build prod\n//go:build dev\n\npackage p\n", []string{"GOOS=linux", "GOARCH=amd64"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.file)
			if err := os.WriteFile(path, []byte(tc.src), 0o644); err != nil {
				t.Fatal(err)
			}
			if got := constrainedOut(path, tc.env); got != tc.want {
				t.Errorf("constrainedOut = %v, want %v", got, tc.want)
			}
		})
	}
}
