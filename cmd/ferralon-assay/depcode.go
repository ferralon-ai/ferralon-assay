package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

const (
	envDependencyCode  = brand.EnvPrefix + "_DEPENDENCY_CODE"
	envDependencyCache = brand.EnvPrefix + "_DEPENDENCY_CACHE"
)

// dependencyCodeOption resolves -dependency-code / -dependency-cache into the acquisition
// option, or nil when it is off, which is the default and leaves a scan unchanged. An unknown
// mode is an error: a typo must not silently change what the scan reads.
//
// The process environment is handed to the npm configuration reader, which consults only
// NPM_CONFIG_USERCONFIG, NPM_CONFIG_REGISTRY and the ${VAR} references the .npmrc files make
// (artifactcache/acquire/npmrc.go).
func (f *runFlags) dependencyCodeOption() (pipeline.AssessOption, error) {
	mode := strings.TrimSpace(*f.depCode)
	if mode == "" {
		mode = strings.TrimSpace(os.Getenv(envDependencyCode))
	}
	cache := strings.TrimSpace(*f.depCache)
	if cache == "" {
		cache = strings.TrimSpace(os.Getenv(envDependencyCache))
	}
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
	return pipeline.WithDependencyAcquisition(pipeline.DependencyAcquisition{Mode: m, CacheDir: abs, LookupEnv: os.LookupEnv}), nil
}
