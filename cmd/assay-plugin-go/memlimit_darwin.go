package main

import "golang.org/x/sys/unix"

func cgroupMemoryLimit() (uint64, bool) { return 0, false }

func physicalMemory() (uint64, bool) {
	v, err := unix.SysctlUint64("hw.memsize")
	return v, err == nil && v > 0
}
