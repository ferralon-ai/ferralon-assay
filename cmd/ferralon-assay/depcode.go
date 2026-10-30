package main

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
	"github.com/ferralon-ai/ferralon-assay/artifactcache/acquire"
	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
	"github.com/ferralon-ai/ferralon-assay/statestore"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

const (
	envDependencyCode        = brand.EnvPrefix + "_DEPENDENCY_CODE"
	envDependencyCache       = brand.EnvPrefix + "_DEPENDENCY_CACHE"
	envDependencyUncredCache = brand.EnvPrefix + "_DEPENDENCY_UNCREDENTIALED_CACHE"
	envDependencyNPMRCEnv    = brand.EnvPrefix + "_DEPENDENCY_NPMRC_ENV"
	envDependencyTimeout     = brand.EnvPrefix + "_DEPENDENCY_TIMEOUT"
)

var envVarName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// The dependency-code policy decides, per registry, what a failed fetch does to the run. A
// registry that refused a token the run sent fails the run, on every run kind. A registry that
// served this build some packages and failed others is read for what it served, and the JS lane
// withholds each package it did not. Otherwise the scan reads no dependency code, exactly as with
// -dependency-code=off, and its Report names the cause; on a cve-watch earnest run a registry
// that is stuck rather than misconfigured also holds the cursor, and a hold that has lasted
// stallRuns earnest runs and stallAge fails the run.
const (
	stallRuns = 3
	stallAge  = 24 * time.Hour
)

// Run-failing dependency fetch kinds, as depFetchError.Kind.
const (
	kindCredentialRejected = "credential_rejected"
	kindFetchStalled       = "dependency_fetch_stalled"
)

// depFetchError is the exit error of a run the dependency-code policy fails, once its Report is
// published. Registry is the registry's base URL: stderr may name a host, the Report never does.
type depFetchError struct {
	Kind     string
	Registry string
	// Detail is the refused package for kindCredentialRejected.
	Detail string
	// HeldRuns and Since are the stalled hold for kindFetchStalled.
	HeldRuns int
	Since    time.Time
}

func (e *depFetchError) Error() string {
	switch e.Kind {
	case kindCredentialRejected:
		return fmt.Sprintf("dependency code not read: %s: registry %s refused the token this run sent (HTTP 401 or 403) for %s. "+
			"The token may be expired or wrong, it may lack read access to the package, or a curation proxy in front of the registry "+
			"(such as Artifactory curation or a Nexus firewall) may be blocking the package", e.Kind, e.Registry, e.Detail)
	case kindFetchStalled:
		return fmt.Sprintf("dependency code not read: %s: registry %s has served nothing on %d cve-watch runs since %s, "+
			"holding the advisory cursor; any advisories those runs found stay new until a run reads from it",
			e.Kind, e.Registry, e.HeldRuns, e.Since.UTC().Format(time.RFC3339))
	}
	return "dependency code not read: " + e.Kind
}

// registryAction is what the policy does about one registry's fetches on one run.
type registryAction int

const (
	actionRead     registryAction = iota // every fetch from it completed
	actionPartial                        // read what it served; the lane withholds the rest per package
	actionFallback                       // read no dependency code
	actionHold                           // read no dependency code, and a cve-watch earnest run keeps its cursor
	actionRed                            // a token it was sent was refused: the run fails
)

// registryTally is what one run's acquisitions did against one registry. failed counts fetches
// that did not complete apart from those the run's deadline cancelled, which say nothing about the
// registry.
type registryTally struct {
	read, network, failed, cancelled, missing, unavailable int
	rejected                                               string // the first package whose token was refused
}

func (t *registryTally) add(o pipeline.DependencyOutcome) {
	switch {
	case o.Outcome == pipeline.OutcomeReadNetwork:
		t.read++
		t.network++
	case o.Outcome == pipeline.OutcomeReadCache:
		t.read++
	case o.Outcome == pipeline.UnreadCancelled:
		t.cancelled++
	case pipeline.FetchFailed(o.Outcome):
		t.failed++
		switch {
		case pipeline.CredentialRejected(o.Outcome, o.Detail):
			if t.rejected == "" {
				t.rejected = o.PURL
			}
		case o.Outcome == pipeline.UnreadPolicyRefused && o.Detail == artifactcache.PolicyMissingCredential:
			t.missing++
		case o.Outcome == pipeline.UnreadUnavailable:
			t.unavailable++
		}
	}
}

// classifyRegistry is the policy for one registry, given its stored entry. A token refused is red
// whether or not the registry served anything else: an expired token, a token without read access
// and a curation proxy blocking a package answer alike, and none of them is fixed by waiting. A
// registry that served some packages is partial. One that served none is stuck, and holds, when it
// answered with a transient error, or when it has served this repository before and failed for a
// reason other than a missing credential: a registry that has never served it (an unreachable host,
// a wrong URL) and a credential the runner did not provide are configuration, which no number of
// held runs fixes, so they fall back.
func classifyRegistry(t registryTally, prior statestore.RegistryFetch) registryAction {
	switch {
	case t.rejected != "":
		return actionRed
	case t.failed == 0 && t.cancelled == 0:
		return actionRead
	case t.read > 0:
		return actionPartial
	case t.failed == 0:
		return actionFallback
	case t.unavailable > 0:
		return actionHold
	case prior.HasServed && t.failed > t.missing:
		return actionHold
	}
	return actionFallback
}

// tallyLocked is the run's outcomes per registry, for a caller that holds d.mu. A package with no
// registry (offline, no usable integrity, an npm configuration that failed closed) is in none.
func (d *depCodeRun) tallyLocked() map[string]registryTally {
	regs := map[string]registryTally{}
	for _, o := range d.outcomes {
		if o.Registry == "" {
			continue
		}
		t := regs[o.Registry]
		t.add(o)
		regs[o.Registry] = t
	}
	return regs
}

// incompleteLocked reports whether the run read less dependency code than its lock pins: it fell
// back, or a registry failed some of its fetches.
func (d *depCodeRun) incompleteLocked() bool {
	return d.fell != nil || slices.ContainsFunc(d.outcomes, func(o pipeline.DependencyOutcome) bool {
		return pipeline.FetchFailed(o.Outcome)
	})
}

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

// depCodeRun is what a run's dependency code acquisition came to: the configured source, every
// package outcome the acquisitions observed, the first cause when one fell back and, once record
// has run, a hold that has stalled.
type depCodeRun struct {
	source   string
	mu       sync.Mutex
	observed bool
	outcomes []pipeline.DependencyOutcome
	fell     *report.DependencyCodeCause
	hinted   map[string]bool
	stalled  *depFetchError
	// held is the registries record counted one more held run against, stalled ones included.
	held []depFetchError
}

func (d *depCodeRun) observe(res pipeline.DependencyAcquisitionResult) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.observed = true
	d.outcomes = append(d.outcomes, res.Outcomes...)
	d.hintLocked(res.Outcomes)
	if res.Fallback == nil {
		if n := countFetchFailed(res.Outcomes); n > 0 {
			fmt.Fprintf(os.Stderr, "%s: dependency code partly read: %d of %d lock-pinned packages not fetched; the scan withholds each of them\n", brand.Name, n, len(res.Outcomes))
		}
		return
	}
	if d.fell != nil {
		return
	}
	d.fell = &report.DependencyCodeCause{Kind: res.Fallback.Kind, Detail: res.Fallback.Detail}
	fmt.Fprintf(os.Stderr, "%s: dependency code not read, scanning as with it off: %s\n", brand.Name, d.fell.Describe())
}

// hintLocked tells the operator, once per registry, that a registry answered 401 or 403 to a
// request that carried no token: a credential the runner did not provide, not one the registry
// refused.
func (d *depCodeRun) hintLocked(outcomes []pipeline.DependencyOutcome) {
	for _, o := range outcomes {
		if o.Registry == "" || d.hinted[o.Registry] || o.Outcome != pipeline.UnreadPolicyRefused || o.Detail != artifactcache.PolicyMissingCredential {
			continue
		}
		if d.hinted == nil {
			d.hinted = map[string]bool{}
		}
		d.hinted[o.Registry] = true
		fmt.Fprintf(os.Stderr, "%s: %s\n", brand.Name, missingTokenHint(o.Registry, o.TokenEnv))
	}
}

// missingTokenHint says what would give registry the token it needs, naming the variable that
// left its auth value empty when there is one.
func missingTokenHint(registry string, env acquire.TokenEnv) string {
	switch env.State {
	case acquire.TokenEnvUnset:
		return fmt.Sprintf("registry %s needs a token and %s is unset: set it for the scan step to read that registry's packages", registry, env.Name)
	case acquire.TokenEnvEmpty:
		return fmt.Sprintf("registry %s needs a token and %s is set but empty: give it the token for the scan step to read that registry's packages", registry, env.Name)
	case acquire.TokenEnvNotAllowed:
		return fmt.Sprintf("registry %s needs a token and its auth entry reads %s, which the scan reads only when -dependency-npmrc-env names it: "+
			"set it for the scan step and add it to -dependency-npmrc-env to read that registry's packages", registry, env.Name)
	}
	return fmt.Sprintf("registry %s needs a token and the npm configuration supplies none for it: add an auth entry to read that registry's packages", registry)
}

func countFetchFailed(outcomes []pipeline.DependencyOutcome) int {
	n := 0
	for _, o := range outcomes {
		if pipeline.FetchFailed(o.Outcome) {
			n++
		}
	}
	return n
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
// the verdicts are the ones the scan reached reading no dependency code. A partial read adds
// neither: it read the code it fetched, and the JS lane withholds each package it did not as
// uninspectable_package.
//
// A writing run stamps twice: before the state write (disclose), so the stored report.json and
// every later run that publishes its rows carry the note, and again on publish, which also covers a
// run that writes nothing (pr-inherit). The second adds nothing: the notes deduplicate and the field
// is set to the same value.
func (d *depCodeRun) stamp(rep *report.Report) {
	if d == nil {
		return
	}
	dc := &report.DependencyCode{Source: d.source}
	if c := d.cause(); c != nil {
		dc.Cause = c
		rep.AddPartiality(report.PartialityNote{Reason: report.PartialReasonDependencyCodeUnavailable, Ecosystem: "npm", Detail: c.Describe()})
	}
	rep.DependencyCode = dc
}

// disclose is the run's trigger Disclosure, or nil for a scan with no dependency code to record
// (not JS).
func (d *depCodeRun) disclose() trigger.Disclosure {
	if d == nil {
		return nil
	}
	return d.stamp
}

// err is the run's exit error once its Report is published: a *depFetchError when a registry
// refused a token the run sent, on any run kind, or, on a cve-watch earnest run, when record found
// a hold that has stalled. Every other fetch failure exits as the off run would.
func (d *depCodeRun) err() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	regs := d.tallyLocked()
	for _, key := range slices.Sorted(maps.Keys(regs)) {
		if t := regs[key]; t.rejected != "" {
			return &depFetchError{Kind: kindCredentialRejected, Registry: key, Detail: t.rejected}
		}
	}
	if d.stalled != nil {
		return d.stalled
	}
	return nil
}

// fetchNotes is what the run's dependency code fetch needs from the operator, per registry, for the
// job summary: a refused token, a token the run did not have, a cursor record held or a hold that
// stalled. A registry appears once, under the outcome that decides the run: refused, then stalled,
// then held, then missing a token. It reads what record left, so a caller consults it after the
// state write.
func (d *depCodeRun) fetchNotes() []resultsink.DependencyFetchNote {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	held := map[string]depFetchError{}
	for _, h := range d.held {
		held[h.Registry] = h
	}
	missing := map[string]acquire.TokenEnv{}
	for _, o := range d.outcomes {
		if o.Registry == "" || o.Outcome != pipeline.UnreadPolicyRefused || o.Detail != artifactcache.PolicyMissingCredential {
			continue
		}
		if _, ok := missing[o.Registry]; !ok {
			missing[o.Registry] = o.TokenEnv
		}
	}
	regs := d.tallyLocked()
	var notes []resultsink.DependencyFetchNote
	for _, key := range slices.Sorted(maps.Keys(regs)) {
		h, wasHeld := held[key]
		env, wasMissing := missing[key]
		// A registry that held or stalled the cursor while asking for a token it did not get is
		// told what would give it the token, as it would be had it not held.
		var token string
		if wasMissing {
			hint := missingTokenHint(key, env)
			token = " " + strings.ToUpper(hint[:1]) + hint[1:] + "."
		}
		switch t := regs[key]; {
		case t.rejected != "":
			notes = append(notes, resultsink.DependencyFetchNote{
				Registry: key, Outcome: resultsink.DependencyFetchCredentialRejected, Package: t.rejected,
				Hint: "Renew the token or give it read access to the package. If a curation proxy such as Artifactory curation or a Nexus firewall fronts the registry, check whether it blocks the package.",
			})
		case d.stalled != nil && d.stalled.Registry == key:
			notes = append(notes, resultsink.DependencyFetchNote{
				Registry: key, Outcome: resultsink.DependencyFetchStalled, HeldRuns: d.stalled.HeldRuns, Since: d.stalled.Since,
				Hint: "Check that the registry is up and reachable from the runner. Until a run reads from it, any advisories these runs found stay new and any verdicts they withheld stay withheld." + token,
			})
		case wasHeld:
			notes = append(notes, resultsink.DependencyFetchNote{
				Registry: key, Outcome: resultsink.DependencyFetchHeld, HeldRuns: h.HeldRuns, Since: h.Since,
				Hint: fmt.Sprintf("Any advisories this run found stay new, and any verdicts it withheld are assessed again on the next run. If the registry still serves nothing after %d held runs over %d hours, the run fails.", stallRuns, int(stallAge.Hours())) + token,
			})
		case wasMissing:
			notes = append(notes, resultsink.DependencyFetchNote{
				Registry: key, Outcome: resultsink.DependencyFetchMissingCredential,
				Hint: missingTokenHint(key, env) + ".",
			})
		}
	}
	return notes
}

// holds reports whether the dependency-code policy holds a cve-watch cursor, given the stored
// dependency-fetch record: whether any registry it fetched from holds. It reads the acquisitions
// observed so far, so a caller consults it after the re-assessments.
func (d *depCodeRun) holds(stored *statestore.DepFetch) bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for key, t := range d.tallyLocked() {
		if holdsRegistry(t, stored, key) {
			return true
		}
	}
	return false
}

// holdsRegistry is the one rule that both holds a cve-watch cursor and counts the run against the
// registry's stall cap, so a run is counted exactly when the registry held it.
func holdsRegistry(t registryTally, stored *statestore.DepFetch, key string) bool {
	var prior statestore.RegistryFetch
	if stored != nil {
		prior = stored.Registries[key]
	}
	return classifyRegistry(t, prior) == actionHold
}

// fetchUpdate is the run's depfetch.json hook, or nil for a scan with no dependency acquisition to
// record (not JS), which carries the stored record. Such a scan sharing the state ref neither adds to
// nor clears the reassess list and retries no stored row, a row withheld as dependency_not_fetched
// included; the trigger still withholds every row of its own whose advisory the list names.
func (d *depCodeRun) fetchUpdate() trigger.DependencyFetchUpdate {
	if d == nil {
		return nil
	}
	return func(prior *statestore.DepFetch, run trigger.DependencyFetchRun) *statestore.DepFetch {
		return d.record(prior, run, time.Now().UTC())
	}
}

// record is the depfetch.json a writing run leaves, from the stored record prior, which it does not
// modify. A run with dependency code off carries prior's registries and drops its reassess list: the
// verdicts it reached are the declared off verdicts, which its dependency_code field discloses, and
// a list it kept would make every later cve-watch run under off assess the same rows again to the
// same off verdicts. Any other run that observed no acquisition (none reached) carries prior.
// Otherwise, per registry: a network fetch sets has_served; on a cve-watch earnest run whose cursor
// held, a registry holdsRegistry holds counts one more held run, stamping first_held_at at now on
// the first, and otherwise reading anything from the registry resets its count. A held count of
// stallRuns or more with first_held_at stallAge or more before now stalls the run, which err then
// fails. A baseline never touches the held count. A run of either kind that read all its lock pins
// removes from reassess the advisories it assessed: a baseline every entry naming one by ID or
// alias, since it rebuilds every row, and a cve-watch run only entries naming one by ID, since it
// replaces only the rows of the IDs it assessed. A cve-watch earnest run that read less than its
// lock pins (it fell back, or a registry failed some fetches) adds the ID of each advisory it
// assessed that concerns a package it missed (missedLocked) or came out undetermined, and removes
// the entries naming by ID each other one it assessed. An advisory concerning a package the run
// cannot name as npm, and every advisory when the missed packages cannot be established, counts as
// concerning one it missed. Every other refutation the run reached without some package's code is
// the JS lane's to withhold: each unread package scopes an unbounded uninspectable_package limit,
// so a not_exploitable on a read package comes out undetermined, and stays listed for a run that
// reads more to reach again. A baseline that read less neither adds nor removes. An advisory whose assessment fails is
// not among the assessed, so an assessment that fails on every run leaves its entry listed and its
// row retried on every cve-watch run: the failure leaves the row undetermined, and nothing reached
// with its package's code has replaced it.
//
// A lost CAS can leave the count higher than the runs that held since the registry last served:
// Merge keeps the larger held_runs and the earliest first_held_at, so a reset written by a
// concurrent run that read can be lost, reviving the streak it ended, and the next held run after
// the registry recovered can fail at once. The error is only ever toward failing early, never
// late: no merge lowers a count or moves a first hold later.
func (d *depCodeRun) record(prior *statestore.DepFetch, run trigger.DependencyFetchRun, now time.Time) *statestore.DepFetch {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.observed {
		if d.source != report.DependencyCodeSourceOff || prior == nil || len(prior.Reassess) == 0 {
			return prior
		}
		return &statestore.DepFetch{Registries: maps.Clone(prior.Registries)}
	}
	d.stalled, d.held = nil, nil
	next := &statestore.DepFetch{}
	if prior != nil {
		next.Registries = maps.Clone(prior.Registries)
		next.Reassess = slices.Clone(prior.Reassess)
	}
	regs := d.tallyLocked()
	for _, key := range slices.Sorted(maps.Keys(regs)) {
		t := regs[key]
		e := next.Registries[key]
		if t.network > 0 {
			e.HasServed = true
		}
		if !run.Baseline {
			switch {
			case run.Held && holdsRegistry(t, prior, key):
				e.HeldRuns++
				if e.FirstHeldAt.IsZero() {
					e.FirstHeldAt = now
				}
				d.held = append(d.held, depFetchError{Kind: kindFetchStalled, Registry: key, HeldRuns: e.HeldRuns, Since: e.FirstHeldAt})
				if d.stalled == nil && e.HeldRuns >= stallRuns && now.Sub(e.FirstHeldAt) >= stallAge {
					d.stalled = &depFetchError{Kind: kindFetchStalled, Registry: key, HeldRuns: e.HeldRuns, Since: e.FirstHeldAt}
				}
			case t.read > 0:
				e.HeldRuns, e.FirstHeldAt = 0, time.Time{}
			}
		}
		if next.Registries == nil {
			next.Registries = map[string]statestore.RegistryFetch{}
		}
		next.Registries[key] = e
	}
	switch incomplete := d.incompleteLocked(); {
	case incomplete && !run.Baseline:
		missed, known := d.missedLocked()
		var read []string
		for _, a := range run.Assessed {
			if known && !run.Undetermined[a.ID] && !concernsMissed(run.Packages[a.ID], missed) {
				read = append(read, a.ID)
				continue
			}
			next.Reassess = append(next.Reassess, a.ID)
		}
		next.Reassess = slices.DeleteFunc(next.Reassess, func(id string) bool { return slices.Contains(read, id) })
	case !incomplete:
		next.Reassess = slices.DeleteFunc(next.Reassess, func(id string) bool {
			if run.Baseline {
				return namesAny(run.Assessed, id)
			}
			return slices.ContainsFunc(run.Assessed, func(a report.Advisory) bool { return a.ID == id })
		})
	}
	return next
}

// missedLocked returns the npm names of the packages whose code the run's fetches did not read, or
// false when that set cannot be established: an acquisition fell back, a failed fetch names no npm
// package, or no fetch failed.
func (d *depCodeRun) missedLocked() (map[string]bool, bool) {
	if d.fell != nil {
		return nil, false
	}
	missed := map[string]bool{}
	for _, o := range d.outcomes {
		if !pipeline.FetchFailed(o.Outcome) {
			continue
		}
		name, ok := npmName(o.PURL)
		if !ok {
			return nil, false
		}
		missed[name] = true
	}
	return missed, len(missed) > 0
}

// concernsMissed reports whether an advisory concerning purls (DependencyFetchRun.Packages) may
// concern a package in missed: it names one, names a package that is not an npm package URL, or
// names none.
func concernsMissed(purls []string, missed map[string]bool) bool {
	if len(purls) == 0 {
		return true
	}
	for _, p := range purls {
		name, ok := npmName(p)
		if !ok || missed[name] {
			return true
		}
	}
	return false
}

// npmName returns an npm package URL's package name, scope included and version dropped, folded to
// lower case, or false when purl is not an npm package URL. The same name spelled in two cases
// matches, so the fold only widens what counts as missed.
func npmName(purl string) (string, bool) {
	typ, name, ok := trigger.PackageName(purl)
	if !ok || typ != "npm" {
		return "", false
	}
	return strings.ToLower(name), true
}

// namesAny reports whether id is the ID or an alias of one of advs.
func namesAny(advs []report.Advisory, id string) bool {
	return slices.ContainsFunc(advs, func(a report.Advisory) bool {
		return a.ID == id || slices.Contains(a.Aliases, id)
	})
}

// runExit is a scan's exit status once its Report is published: the JVM build graph's
// fail-closed error joined with the dependency-code policy's.
func runExit(graph *jvmGraph, deps *depCodeRun) error {
	return errors.Join(graph.err(), deps.err())
}

// dependencyAcquisitionConfig resolves -dependency-code, -dependency-cache,
// -dependency-uncredentialed-cache, -dependency-npmrc-env and -dependency-timeout, each overriding
// its environment variable. An
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
	uncredDir, err := uncredentialedCacheDir(flagOrEnv(*f.depUncredCache, os.Getenv(envDependencyUncredCache)), abs)
	if err != nil {
		return nil, err
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
	return &pipeline.DependencyAcquisition{Mode: m, CacheDir: abs, UncredentialedDir: uncredDir, LookupEnv: os.LookupEnv, AllowEnv: allow, Timeout: timeout}, nil
}

// uncredentialedCacheDir resolves -dependency-uncredentialed-cache against the resolved
// -dependency-cache. Set, neither directory may contain the other: the point is that a caller can
// persist the uncredentialed cache without carrying a credentialed tarball, and -dependency-cache
// inside it would be persisted with it.
func uncredentialedCacheDir(dir, cache string) (string, error) {
	if dir == "" {
		return "", nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("-dependency-uncredentialed-cache: %w", err)
	}
	if within(abs, cache) || within(cache, abs) {
		return "", fmt.Errorf("-dependency-uncredentialed-cache %q and -dependency-cache %q overlap: they must be separate directories", abs, cache)
	}
	return abs, nil
}

// within reports whether path is dir or lies under it. Both are absolute and clean.
func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// flagOrEnv returns flag when set, else env. Callers read env with os.Getenv on the constant so
// the internal/brand entry-point gate can resolve every key.
func flagOrEnv(flag, env string) string {
	if v := strings.TrimSpace(flag); v != "" {
		return v
	}
	return strings.TrimSpace(env)
}
