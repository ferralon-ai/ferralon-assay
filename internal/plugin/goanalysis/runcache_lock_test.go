//go:build linux || darwin

package goanalysis

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRunCachedComputesOnceAcrossCallers pins that callers asking for one key while it is being
// computed wait for that compute instead of starting their own, and that a waiter computes it
// itself when the compute fails or the waiter's ctx ends. The lock is a flock on its own open file,
// which conflicts within one process as it does across the plugin processes a scan runs.
func TestRunCachedComputesOnceAcrossCallers(t *testing.T) {
	tests := []struct {
		name       string
		holderErr  error
		cancelWait bool
		wantRuns   int32
		wantErr    error
	}{
		{name: "waiter reads the holder's entry", wantRuns: 1},
		{name: "waiter computes after the holder fails", holderErr: errors.New("killed"), wantRuns: 2},
		{name: "waiter stops when its ctx ends", cancelWait: true, wantRuns: 1, wantErr: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithRunCacheDir(context.Background(), t.TempDir())
			key := []string{"/src"}
			var runs atomic.Int32
			started, release := make(chan struct{}), make(chan struct{})
			var wg sync.WaitGroup
			var holderErr error
			wg.Go(func() {
				_, holderErr = runCached(ctx, "test", key, func() ([]byte, error) {
					runs.Add(1)
					close(started)
					<-release
					return []byte("entry"), tt.holderErr
				})
			})
			<-started
			waitCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			var got []byte
			var err error
			waited := make(chan struct{})
			go func() {
				defer close(waited)
				got, err = runCached(waitCtx, "test", key, func() ([]byte, error) {
					runs.Add(1)
					return []byte("entry"), nil
				})
			}()
			time.Sleep(4 * runCacheLockPoll)
			if tt.cancelWait {
				cancel()
				<-waited
			}
			close(release)
			wg.Wait()
			<-waited
			if !errors.Is(holderErr, tt.holderErr) {
				t.Fatalf("holder err = %v, want %v", holderErr, tt.holderErr)
			}
			if n := runs.Load(); n != tt.wantRuns {
				t.Errorf("computes = %d, want %d", n, tt.wantRuns)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("waiter err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && string(got) != "entry" {
				t.Errorf("waiter got %q, want the entry", got)
			}
		})
	}
}
