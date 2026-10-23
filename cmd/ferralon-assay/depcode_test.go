package main

import (
	"testing"
)

func TestDependencyCodeOption(t *testing.T) {
	tests := []struct {
		name, mode, cache, envMode string
		wantOpt, wantErr           bool
	}{
		{name: "default off"},
		{name: "explicit off", mode: "off"},
		{name: "fetch with cache", mode: "fetch", cache: t.TempDir(), wantOpt: true},
		{name: "fetch default cache", mode: "fetch", wantOpt: true},
		{name: "offline with cache", mode: "offline", cache: t.TempDir(), wantOpt: true},
		{name: "offline without cache", mode: "offline", wantErr: true},
		{name: "typo", mode: "fecth", wantErr: true},
		{name: "env enables", envMode: "offline", cache: t.TempDir(), wantOpt: true},
		{name: "flag off beats env", mode: "off", envMode: "fetch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(envDependencyCode, tt.envMode)
			t.Setenv(envDependencyCache, "")
			mode, cache := tt.mode, tt.cache
			f := &runFlags{depCode: &mode, depCache: &cache}
			opt, err := f.dependencyCodeOption()
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if (opt != nil) != tt.wantOpt {
				t.Fatalf("option set = %v, want %v", opt != nil, tt.wantOpt)
			}
		})
	}
}
