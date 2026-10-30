package goanalysis

import (
	"context"
	"testing"
)

// TestWithGoWork: the analyzer runs under the GOWORK the request names, off when it names none, and
// refuses one it cannot place: a relative go.work would resolve against each go command's directory.
func TestWithGoWork(t *testing.T) {
	cases := []struct {
		name, req, want string
		wantErr         bool
	}{
		{"none", "", "off", false},
		{"off", "off", "off", false},
		{"absolute", "/repo/go.work", "/repo/go.work", false},
		{"relative", "go.work", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, err := withGoWork(context.Background(), tc.req)
			if (err != nil) != tc.wantErr {
				t.Fatalf("withGoWork(%q) error = %v, want error %v", tc.req, err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if got := goWork(ctx); got != tc.want {
				t.Fatalf("goWork = %q, want %q", got, tc.want)
			}
			env := buildEnv(ctx, []string{"GOWORK=/developer/go.work", "HOME=/h"})
			if env[len(env)-1] != "GOWORK="+tc.want {
				t.Fatalf("buildEnv does not end with GOWORK=%s: %v", tc.want, env)
			}
		})
	}
	if got := goWork(context.Background()); got != "off" {
		t.Fatalf("goWork with no request = %q, want off", got)
	}
}
