package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

const (
	envDependencyCode     = brand.EnvPrefix + "_DEPENDENCY_CODE"
	envDependencyCache    = brand.EnvPrefix + "_DEPENDENCY_CACHE"
	envDependencyNPMRCEnv = brand.EnvPrefix + "_DEPENDENCY_NPMRC_ENV"
	envDependencyTimeout  = brand.EnvPrefix + "_DEPENDENCY_TIMEOUT"
)

var envVarName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// dependencyCodeOption resolves the -dependency-* flags into the acquisition option, or nil
// when it is off, which is the default and leaves a scan unchanged.
func (f *runFlags) dependencyCodeOption() (pipeline.AssessOption, error) {
	cfg, err := f.dependencyAcquisitionConfig()
	if err != nil || cfg == nil {
		return nil, err
	}
	return pipeline.WithDependencyAcquisition(*cfg), nil
}

// dependencyAcquisitionConfig resolves -dependency-code, -dependency-cache,
// -dependency-npmrc-env and -dependency-timeout, each overriding its environment variable. An
// unknown mode, a malformed variable name or a malformed duration is an error: a typo must not
// silently change what the scan reads or which credential it may present.
//
// The npm configuration reader sees only NPM_CONFIG_USERCONFIG, NPM_CONFIG_REGISTRY,
// NODE_AUTH_TOKEN, NPM_TOKEN and the names -dependency-npmrc-env adds; any other ${VAR} a
// .npmrc references reads as unset (artifactcache/acquire/npmrc.go).
func (f *runFlags) dependencyAcquisitionConfig() (*pipeline.DependencyAcquisition, error) {
	mode := flagOrEnv(*f.depCode, envDependencyCode)
	cache := flagOrEnv(*f.depCache, envDependencyCache)
	var m pipeline.DependencyCodeMode
	switch mode {
	case "", "off":
		return nil, nil
	case string(pipeline.DependencyCodeFetch):
		m = pipeline.DependencyCodeFetch
		if cache == "" {
			base, err := os.UserCacheDir()
			if err != nil {
				return nil, fmt.Errorf("-dependency-code=fetch: no -dependency-cache and no user cache directory: %w", err)
			}
			cache = filepath.Join(base, brand.Name, "artifacts")
		}
	case string(pipeline.DependencyCodeOffline):
		m = pipeline.DependencyCodeOffline
		if cache == "" {
			return nil, fmt.Errorf("-dependency-code=offline reads only a seeded cache: set -dependency-cache or %s", envDependencyCache)
		}
	default:
		return nil, fmt.Errorf("-dependency-code=%q: want off, fetch or offline", mode)
	}
	abs, err := filepath.Abs(cache)
	if err != nil {
		return nil, fmt.Errorf("-dependency-cache: %w", err)
	}
	var allow []string
	for _, name := range strings.Split(flagOrEnv(*f.depNPMRCEnv, envDependencyNPMRCEnv), ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !envVarName.MatchString(name) {
			return nil, fmt.Errorf("-dependency-npmrc-env: %q is not an environment variable name", name)
		}
		allow = append(allow, name)
	}
	var timeout time.Duration
	if v := flagOrEnv(*f.depTimeout, envDependencyTimeout); v != "" {
		timeout, err = time.ParseDuration(v)
		if err != nil || timeout <= 0 {
			return nil, fmt.Errorf("-dependency-timeout=%q: want a positive duration such as 15m", v)
		}
	}
	return &pipeline.DependencyAcquisition{Mode: m, CacheDir: abs, LookupEnv: os.LookupEnv, AllowEnv: allow, Timeout: timeout}, nil
}

func flagOrEnv(flag, env string) string {
	if v := strings.TrimSpace(flag); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv(env))
}
