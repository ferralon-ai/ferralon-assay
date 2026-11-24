//go:build !(linux || darwin)

package goanalysis

import "context"

// lockRunCacheEntry takes no lock on this platform: concurrent processes each compute, as they
// would without a run cache.
func lockRunCacheEntry(context.Context, string) func() { return nil }
