//go:build !linux && !darwin

package main

func cgroupMemoryLimit() (uint64, bool) { return 0, false }

func physicalMemory() (uint64, bool) { return 0, false }
