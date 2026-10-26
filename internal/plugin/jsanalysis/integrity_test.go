package jsanalysis

import "testing"

func TestMapIntegrityStrongestFirst(t *testing.T) {
	tests := []struct {
		name, sri, want string
	}{
		{"empty", "", ""},
		{"single sha512", "sha512-AAA", "sha512:AAA"},
		{"sha1 only accepted", "sha1-BBB", "sha1:BBB"},
		{"sha1 before sha512", "sha1-BBB sha512-AAA", "sha512:AAA"},
		{"sha256 before sha512", "sha256-CCC sha512-AAA", "sha512:AAA"},
		{"sha512 before sha1", "sha512-AAA sha1-BBB", "sha512:AAA"},
		{"md5 is weaker than sha1", "md5-XXX sha1-BBB", "sha1:BBB"},
		{"sha384 outranks sha256 and sha1", "sha1-BBB sha384-DDD sha256-CCC", "sha384:DDD"},
		{"sha512 outranks sha384", "sha384-DDD sha512-AAA", "sha512:AAA"},
		{"options stripped", "sha512-AAA?foo", "sha512:AAA"},
		{"malformed tokens skipped", "sha512- -x sha256-CCC", "sha256:CCC"},
		{"malformed only", "nohash", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mapIntegrity(tt.sri); got != tt.want {
				t.Fatalf("mapIntegrity(%q) = %q, want %q", tt.sri, got, tt.want)
			}
		})
	}
}
