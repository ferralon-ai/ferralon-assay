//go:build !unix

package cfamilycgx

import "os"

// fileOwner cannot name a file's owner off unix, so a configured wasm compile cache dir is
// refused there rather than trusted unchecked.
func fileOwner(os.FileInfo) (int, bool) { return 0, false }
