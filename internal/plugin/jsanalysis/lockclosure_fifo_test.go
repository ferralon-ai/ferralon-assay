//go:build unix

package jsanalysis

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestLockClosures_LinkToPipe: a symlink to a pipe leaves every closure unbounded, and the walk
// never opens the pipe, which would block it with no writer. A pipe itself declares nothing.
func TestLockClosures_LinkToPipe(t *testing.T) {
	const lock = `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/qs":{}}}`
	for _, tc := range []struct {
		name    string
		link    bool
		bounded bool
	}{
		{name: "a symlink to a pipe", link: true},
		{name: "a pipe", bounded: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeProgram(t, map[string]string{"package-lock.json": lock})
			if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o644); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
			if tc.link {
				treeSymlink(t, "pipe", filepath.Join(dir, "link"))
			}
			done := make(chan []string, 1)
			go func() { done <- newLockClosures(dir).closureOf("", "qs") }()
			select {
			case got := <-done:
				if bounded := got != nil; bounded != tc.bounded {
					t.Errorf("closureOf = %#v; bounded = %v, want %v", got, bounded, tc.bounded)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the walk blocked opening the pipe")
			}
		})
	}
}

// TestLockClosures_ReadersRefusePipes: each reader of a package.json or lockfile stats before it
// opens, so a pipe in its place is refused rather than blocking the read with no writer. An
// ancestor package.json that is a pipe counts as declaring an install, and a lock that is a pipe
// counts as unread: either leaves the closure unbounded.
func TestLockClosures_ReadersRefusePipes(t *testing.T) {
	const lock = `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/qs":{}}}`
	for _, tc := range []struct {
		name    string
		files   map[string]string
		pipe    string // a pipe here is refused
		regular string // the same path as a regular file is read
		read    func(dir string) bool
	}{
		{name: "an ancestor package.json", files: map[string]string{"app/package-lock.json": lock, "app/package.json": `{"name":"app"}`},
			pipe: "package.json", regular: `{"name":"root"}`, read: func(dir string) bool { return newLockClosures(dir).closureOf("app", "qs") != nil }},
		{name: "the governing lock", files: map[string]string{"package.json": `{"name":"app"}`},
			pipe: "package-lock.json", regular: lock, read: func(dir string) bool { return newLockClosures(dir).closureOf("", "qs") != nil }},
		{name: "a shrinkwrap beside a regular package-lock.json", files: map[string]string{"package.json": `{"name":"app"}`, "package-lock.json": lock},
			pipe: "npm-shrinkwrap.json", regular: lock, read: func(dir string) bool { return newLockClosures(dir).closureOf("", "qs") != nil }},
		{name: "a lock the walk checks for parsing", files: map[string]string{"package.json": `{"name":"app"}`},
			pipe: "package-lock.json", regular: lock, read: func(dir string) bool { return npmLockParses(filepath.Join(dir, "package-lock.json")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			control := map[string]string{tc.pipe: tc.regular}
			for name, body := range tc.files {
				control[name] = body
			}
			if !tc.read(writeProgram(t, control)) {
				t.Fatal("control: the regular file was not read")
			}
			dir := writeProgram(t, tc.files)
			if err := syscall.Mkfifo(filepath.Join(dir, tc.pipe), 0o644); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
			done := make(chan bool, 1)
			go func() { done <- tc.read(dir) }()
			select {
			case got := <-done:
				if got {
					t.Error("read through a pipe, want refused")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the read blocked opening the pipe")
			}
		})
	}
}
