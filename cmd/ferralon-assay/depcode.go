package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
)

const (
	envDependencyCode     = brand.EnvPrefix + "_DEPENDENCY_CODE"
	envDependencyCache    = brand.EnvPrefix + "_DEPENDENCY_CACHE"
	envDependencyNPMRCEnv = brand.EnvPrefix + "_DEPENDENCY_NPMRC_ENV"
	envDependencyTimeout  = brand.EnvPrefix + "_DEPENDENCY_TIMEOUT"
)

var envVarName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// fetchFailureFailsRun is the policy for a JS scan whose dependency fetch failed (a registry
// error, a refused or missing credential, the deadline, or a partial fetch). Either way the scan
// reads no dependency code, exactly as with -dependency-code=off, and its Report names the cause.
//
// THIS IS THE SINGLE LINE THAT DECIDES WHETHER THAT RUN FAILS. false: it exits as the off run
// would. true: it exits non-zero once its Report is published, and cve-watch holds its cursor,
// as a JVM scan without its build graph does.
const fetchFailureFailsRun = false

// dependencyCodeOption resolves the -dependency-* flags into the acquisition option, or nil
// when they turn it off, and records on f.depRun the handle the Report and the exit status read.
// Fetch is the default.
func (f *runFlags) dependencyCodeOption() (pipeline.AssessOption, error) {
	cfg, err := f.dependencyAcquisitionConfig()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		f.depRun = &depCodeRun{source: report.DependencyCodeSourceOff}
		return nil, nil
	}
	run := &depCodeRun{source: string(cfg.Mode)}
	cfg.Observe = run.observe
	f.depRun = run
	return pipeline.WithDependencyAcquisition(*cfg), nil
}

// depCodeRun is what a run's dependency code acquisition came to: the configured source and, when
// a fetch failed, the cause.
type depCodeRun struct {
	source string
	mu     sync.Mutex
	fell   *report.DependencyCodeCause
}

func (d *depCodeRun) observe(res pipeline.DependencyAcquisitionResult) {
	if res.Fallback == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fell != nil {
		return
	}
	d.fell = &report.DependencyCodeCause{Kind: res.Fallback.Kind, Detail: res.Fallback.Detail}
	fmt.Fprintf(os.Stderr, "%s: dependency code not read, scanning as with it off: %s\n", brand.Name, describeCause(d.fell))
}

// forLanguage is d for a JS scan and nil for every other language, whose Report carries no
// dependency_code field.
func (d *depCodeRun) forLanguage(language string) *depCodeRun {
	if language != checkout.LangJS {
		return nil
	}
	return d
}

func (d *depCodeRun) cause() *report.DependencyCodeCause {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.fell
}

// stamp records the run's dependency code on rep: the dependency_code field and, after a
// fallback, the scan-level tool_failure:dependency_code_unavailable note. Both are disclosure;
// the verdicts are the ones the scan reached reading no dependency code.
func (d *depCodeRun) stamp(rep *report.Report) {
	if d == nil {
		return
	}
	dc := &report.DependencyCode{Source: d.source}
	if c := d.cause(); c != nil {
		dc.Cause = c
		rep.AddPartiality(report.PartialityNote{Reason: report.PartialReasonDependencyCodeUnavailable, Ecosystem: "npm", Detail: describeCause(c)})
	}
	rep.DependencyCode = dc
}

// err is the run's exit error once its Report is published. fetchFailureFailsRun decides it.
func (d *depCodeRun) err() error {
	c := d.cause()
	if c == nil || !fetchFailureFailsRun {
		return nil
	}
	return fmt.Errorf("dependency code not read: %s", describeCause(c))
}

// runExit is a scan's exit status once its Report is published: the JVM build graph's
// fail-closed error joined with the dependency-code policy's.
func runExit(graph *jvmGraph, deps *depCodeRun) error {
	return errors.Join(graph.err(), deps.err())
}

func describeCause(c *report.DependencyCodeCause) string {
	if c.Detail == "" {
		return c.Kind
	}
	return c.Kind + ": " + c.Detail
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
	mode := flagOrEnv(*f.depCode, os.Getenv(envDependencyCode))
	cache := flagOrEnv(*f.depCache, os.Getenv(envDependencyCache))
	var m pipeline.DependencyCodeMode
	switch mode {
	case "off":
		return nil, nil
	case "", string(pipeline.DependencyCodeFetch):
		m = pipeline.DependencyCodeFetch
		if cache == "" {
			base, err := os.UserCacheDir()
			switch {
			case err == nil:
				cache = filepath.Join(base, brand.Name, "artifacts")
			case mode == "":
				// The default must not turn a host with no user cache directory into a failed run.
				// A private per-run directory, not a shared temp path another user could seed.
				if cache, err = os.MkdirTemp("", brand.Name+"-artifacts-*"); err != nil {
					return nil, fmt.Errorf("-dependency-code: no user cache directory and no temp directory: %w", err)
				}
			default:
				return nil, fmt.Errorf("-dependency-code=fetch: no -dependency-cache and no user cache directory: %w", err)
			}
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
	for _, name := range strings.Split(flagOrEnv(*f.depNPMRCEnv, os.Getenv(envDependencyNPMRCEnv)), ",") {
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
	if v := flagOrEnv(*f.depTimeout, os.Getenv(envDependencyTimeout)); v != "" {
		timeout, err = time.ParseDuration(v)
		if err != nil || timeout <= 0 {
			return nil, fmt.Errorf("-dependency-timeout=%q: want a positive duration such as 15m", v)
		}
	}
	return &pipeline.DependencyAcquisition{Mode: m, CacheDir: abs, LookupEnv: os.LookupEnv, AllowEnv: allow, Timeout: timeout}, nil
}

// flagOrEnv returns flag when set, else env. Callers read env with os.Getenv on the constant so
// the internal/brand entry-point gate can resolve every key.
func flagOrEnv(flag, env string) string {
	if v := strings.TrimSpace(flag); v != "" {
		return v
	}
	return strings.TrimSpace(env)
}
