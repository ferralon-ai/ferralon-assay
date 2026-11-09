package main

import "testing"

func TestDeriveMemoryLimit(t *testing.T) {
	const gib = uint64(1) << 30
	cg := func(v uint64, ok bool) func() (uint64, bool) { return func() (uint64, bool) { return v, ok } }
	tests := []struct {
		name     string
		env      string
		cgroup   func() (uint64, bool)
		physical func() (uint64, bool)
		want     int64
		wantOK   bool
	}{
		{"cgroup limit wins over larger physical", "", cg(8*gib, true), cg(64*gib, true), int64(8 * gib / 100 * memoryLimitPercent), true},
		{"cgroup absent falls back to physical", "", cg(0, false), cg(16*gib, true), int64(16 * gib / 100 * memoryLimitPercent), true},
		{"cgroup unlimited sentinel above physical", "", cg(1<<63-4096, true), cg(16*gib, true), int64(16 * gib / 100 * memoryLimitPercent), true},
		{"cgroup only", "", cg(4*gib, true), cg(0, false), int64(4 * gib / 100 * memoryLimitPercent), true},
		{"nothing determinable", "", cg(0, false), cg(0, false), 0, false},
		{"GOMEMLIMIT set wins", "6GiB", cg(8*gib, true), cg(16*gib, true), 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := deriveMemoryLimit(memorySources{
				getenv:      func(string) string { return tt.env },
				cgroupLimit: tt.cgroup,
				physical:    tt.physical,
			})
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf("deriveMemoryLimit = (%d, %v), want (%d, %v)", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestParseCgroupLimit(t *testing.T) {
	tests := []struct {
		raw    string
		want   uint64
		wantOK bool
	}{
		{"8589934592\n", 8589934592, true},
		{"max\n", 0, false},
		{"", 0, false},
		{"0", 0, false},
		{"garbage", 0, false},
	}
	for _, tt := range tests {
		got, ok := parseCgroupLimit(tt.raw)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("parseCgroupLimit(%q) = (%d, %v), want (%d, %v)", tt.raw, got, ok, tt.want, tt.wantOK)
		}
	}
}
