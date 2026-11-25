//go:build linux || darwin

package goanalysis

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
)

// lockRunCacheEntry takes an exclusive lock beside the run cache entry at path, shared by every
// process the scan runs, and returns its release. It returns nil when no lock could be taken, or
// when ctx ended while another process held it. The kernel releases the lock of a process that
// dies, so a killed holder never strands a waiter.
func lockRunCacheEntry(ctx context.Context, path string) func() {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
			}
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			_ = f.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil
		case <-time.After(runCacheLockPoll):
		}
	}
}
