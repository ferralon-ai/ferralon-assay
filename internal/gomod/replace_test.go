package gomod

import "testing"

func TestTargetPinned(t *testing.T) {
	const m = "example.com/m"
	tests := []struct {
		name        string
		path, vers  string
		wantVersion string
		wantPinned  bool
	}{
		{"the same module at a version", m, "v1.1.0", "v1.1.0", true},
		{"a fork", "example.com/fork", "v1.1.0", "", false},
		{"a fork under the module's path", m + "/v2", "v2.0.0", "", false},
		{"a relative directory", "./m", "", "", false},
		{"a parent directory", "../m", "", "", false},
		{"an absolute directory", "/src/m", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, ok := NewTarget(tt.path, tt.vers).Pinned(m)
			if v != tt.wantVersion || ok != tt.wantPinned {
				t.Fatalf("Pinned = %q, %v; want %q, %v", v, ok, tt.wantVersion, tt.wantPinned)
			}
		})
	}
}
