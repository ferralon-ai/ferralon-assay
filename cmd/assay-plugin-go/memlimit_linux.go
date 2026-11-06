package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// cgroupMemoryLimit is the cgroup v2 memory.max, else the v1 limit_in_bytes. v1 reports "no limit"
// as a near-MaxInt64 number, which the physical-memory minimum in deriveMemoryLimit absorbs.
func cgroupMemoryLimit() (uint64, bool) {
	for _, path := range []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		return parseCgroupLimit(string(raw))
	}
	return 0, false
}

func physicalMemory() (uint64, bool) {
	var si unix.Sysinfo_t
	if err := unix.Sysinfo(&si); err != nil || si.Totalram == 0 {
		return 0, false
	}
	return uint64(si.Totalram) * uint64(si.Unit), true
}
