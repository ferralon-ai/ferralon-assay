package corpus

import "testing"

func TestValidate_IndeterminatePairing(t *testing.T) {
	fixtures, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(fixtures) == 0 {
		t.Fatal("Load: no fixtures")
	}
	base := fixtures[0]

	cases := []struct {
		name      string
		direction string
		strength  string
		wantErr   bool
	}{
		{"indeterminate pair", "indeterminate", "indeterminate", false},
		{"indeterminate direction, reasoned strength", "indeterminate", "reasoned", true},
		{"indeterminate direction, proven strength", "indeterminate", "proven", true},
		{"exploitable direction, indeterminate strength", "exploitable", "indeterminate", true},
		{"not_exploitable direction, indeterminate strength", "not_exploitable", "indeterminate", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := base
			f.ExpectedVerdict.Direction = tc.direction
			f.ExpectedVerdict.Strength = tc.strength
			f.ExpectedVerdict.Label = expectedLabel(tc.direction, tc.strength)
			err := f.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
