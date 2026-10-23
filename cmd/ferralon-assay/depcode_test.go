package main

import (
	"slices"
	"testing"
	"time"
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
			mode, cache, npmrcEnv, timeout := tt.mode, tt.cache, "", ""
			f := &runFlags{depCode: &mode, depCache: &cache, depNPMRCEnv: &npmrcEnv, depTimeout: &timeout}
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

func TestDependencyAcquisitionConfigEnvAndTimeout(t *testing.T) {
	tests := []struct {
		name, npmrcEnv, envNPMRCEnv, timeout string
		wantAllow                            []string
		wantTimeout                          time.Duration
		wantErr                              bool
	}{
		{name: "defaults"},
		{name: "operator-added names", npmrcEnv: "CORP_TOKEN, ART_TOKEN", wantAllow: []string{"CORP_TOKEN", "ART_TOKEN"}},
		{name: "names from the environment", envNPMRCEnv: "CORP_TOKEN", wantAllow: []string{"CORP_TOKEN"}},
		{name: "malformed name", npmrcEnv: "CORP-TOKEN", wantErr: true},
		{name: "timeout", timeout: "90s", wantTimeout: 90 * time.Second},
		{name: "malformed timeout", timeout: "soon", wantErr: true},
		{name: "non-positive timeout", timeout: "0s", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(envDependencyCode, "")
			t.Setenv(envDependencyCache, "")
			t.Setenv(envDependencyNPMRCEnv, tt.envNPMRCEnv)
			t.Setenv(envDependencyTimeout, "")
			mode, cache, npmrcEnv, timeout := "offline", t.TempDir(), tt.npmrcEnv, tt.timeout
			f := &runFlags{depCode: &mode, depCache: &cache, depNPMRCEnv: &npmrcEnv, depTimeout: &timeout}
			cfg, err := f.dependencyAcquisitionConfig()
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if !slices.Equal(cfg.AllowEnv, tt.wantAllow) || cfg.Timeout != tt.wantTimeout {
				t.Fatalf("AllowEnv %q Timeout %v, want %q %v", cfg.AllowEnv, cfg.Timeout, tt.wantAllow, tt.wantTimeout)
			}
		})
	}
}
