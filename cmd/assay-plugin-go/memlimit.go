package main

import (
	"math"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

// memoryLimitPercent is the share of the machine's memory the plugin's Go heap may use before the
// collector works to stay under it: 60% is about 4.5 GiB on an 8 GB runner, just above the 4 GiB live
// heap of the largest cold reachability exec measured, so the cap trims GC headroom without thrashing.
// One plugin process runs per host call; the host issues them one at a time.
const memoryLimitPercent = 60

// memorySources are the machine facts the limit is derived from, injected so tests do not need a
// particular host.
type memorySources struct {
	getenv      func(string) string
	cgroupLimit func() (uint64, bool) // the cgroup memory limit, when one is set
	physical    func() (uint64, bool) // installed memory
}

// applyMemoryLimit sets a soft memory limit from the machine unless the operator set GOMEMLIMIT.
func applyMemoryLimit() {
	if limit, ok := deriveMemoryLimit(machineMemory); ok {
		debug.SetMemoryLimit(limit)
	}
}

var machineMemory = memorySources{
	getenv:      os.Getenv,
	cgroupLimit: cgroupMemoryLimit,
	physical:    physicalMemory,
}

// deriveMemoryLimit returns the soft limit in bytes, or false to keep the runtime default (no
// limit): GOMEMLIMIT is set, or the machine's memory cannot be determined.
func deriveMemoryLimit(s memorySources) (int64, bool) {
	if s.getenv("GOMEMLIMIT") != "" {
		return 0, false
	}
	var avail uint64
	if v, ok := s.cgroupLimit(); ok {
		avail = v
	}
	if v, ok := s.physical(); ok && (avail == 0 || v < avail) {
		avail = v
	}
	if avail == 0 {
		return 0, false
	}
	limit := avail / 100 * memoryLimitPercent
	if limit > math.MaxInt64 {
		return 0, false
	}
	return int64(limit), true
}

// parseCgroupLimit reads a cgroup memory limit file's contents; "max" and anything that is not a
// positive integer mean no limit.
func parseCgroupLimit(raw string) (uint64, bool) {
	v, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil || v == 0 {
		return 0, false
	}
	return v, true
}
