//go:build unix

package kotlinanalysis

import "syscall"

func mkfifo(path string) error { return syscall.Mkfifo(path, 0o644) }
