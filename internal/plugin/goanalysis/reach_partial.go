package goanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"golang.org/x/tools/go/packages"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// A govulncheck load fails whole when any package it visits fails (a cgo header that is missing, a
// type error), and x/vuln has no flag to tolerate one. When that failure is settled, the scan instead
// runs govulncheck once more over the build's packages less the roots that import a package the load
// could not read: the partial run. Its symbol findings are paths that exist in the build, so they
// stand. Its silence covers only what it loaded, so every refutation it would ground and every
// advisory it says nothing about is withheld as a tool failure.

// govulncheckPartialKind names the run cache entry that holds a partial run, under the same key as
// the stream and the settled failure it replaces.
const govulncheckPartialKind = "govulncheck-partial"

// govulncheckPartialMarker identifies a partial run record; an entry without it is no record.
const govulncheckPartialMarker = "govulncheck-partial/v2"

// partialRun is a govulncheck run over the build less Excluded, the roots of ./... that are or
// import a package in Unloadable, which the full run's load could not read. Modules names each
// unloadable package's module as a scoped limit does (modulePURL).
type partialRun struct {
	Marker     string            `json:"marker"`
	Unloadable []string          `json:"unloadable"`
	Modules    map[string]string `json:"modules"`
	Excluded   []string          `json:"excluded"`
	Stream     []byte            `json:"stream"`
}

// govulncheckOrPartial returns the govulncheck stream for buildDir under env (govulncheckCached),
// or, when that run's failure settles, the stream of the partial run partial computes from the
// failure. The run that settles the failure attempts the partial run before the failure is stored,
// so a run that replays the failure finds what it made. A replay that finds neither a partial run
// nor a refusal retries it from the package errors the failure record kept, within the scan's retry
// bound (claimPartialRetry); one that cannot retry returns the failure as it is. A failure whose
// partial run could not be made carries the reason.
func govulncheckOrPartial(ctx context.Context, buildDir string, env []string, settle bool, stream func() ([]byte, error), partial func(failure error) ([]byte, error)) ([]byte, *partialRun, error) {
	key := append([]string{buildDir}, env...)
	var run *partialRun
	attempted := false
	out, err := govulncheckCached(ctx, buildDir, env, settle, func() ([]byte, error) {
		out, err := stream()
		if settle && settledGovulncheckFailure(err) {
			attempted = true
			var perr error
			run, perr = firstPartialRun(ctx, key, err, partial)
			if perr != nil {
				// The reason goes into the failure itself, so the record the failure settles
				// into, and every replay of it, carries it too.
				noteNoPartialRun(err, "no partial govulncheck run: ", perr)
			}
		}
		return out, err
	})
	if err == nil {
		return out, nil, nil
	}
	if run == nil && !attempted && settle && settledGovulncheckFailure(err) {
		var perr error
		if run, perr = retryPartialRun(ctx, key, err, partial); perr != nil {
			noteNoPartialRun(err, "no partial govulncheck run on retry: ", perr)
		}
	}
	if run == nil {
		return nil, nil, err
	}
	return run.Stream, run, nil
}

// noteNoPartialRun appends why no partial run was made to the govulncheck failure err.
func noteNoPartialRun(err error, prefix string, perr error) {
	var failed *govulncheckError
	if errors.As(err, &failed) {
		failed.stderr = strings.TrimSpace(failed.stderr + "\n" + prefix + perr.Error())
	}
}

// settledGovulncheckFailure reports whether err is a settled govulncheck failure, fresh or replayed.
func settledGovulncheckFailure(err error) bool {
	var failed *govulncheckError
	return errors.As(err, &failed) && failed.settled
}

// govulncheckPartialRefusedKind names the run cache entry that marks a partial run that cannot be
// made for the key: its failure would repeat (partialRunRefusal), so no later run retries it.
const govulncheckPartialRefusedKind = "govulncheck-partial-refused"

// govulncheckPartialRefusedMarker is the whole of a refusal entry; an entry without it is none.
const govulncheckPartialRefusedMarker = "govulncheck-partial-refused/v1"

// maxPartialRunRetries bounds the partial runs a scan retries per tree and environment after the
// first one failed transiently. A retry costs about a govulncheck run, so an outage that outlasts
// the scan (the vulnerability database unreachable) costs at most this many runs rather than one per
// advisory; two retries, each made by a later advisory after that advisory's own work, outlast a
// blip.
const maxPartialRunRetries = 2

// errPartialRunRefused is the reason a run gives when an earlier run refused the partial run.
var errPartialRunRefused = errors.New("an earlier run found the partial run cannot be made")

// partialRunRefusal is a partial run failure that a run from the same failure would repeat: the
// failure's package errors, the build's packages and govulncheck's load of them are all settled, so
// only a fault of the machine could change the outcome, and a refusal is never one. A failure not
// marked so may be transient and is retried within the bound.
type partialRunRefusal struct{ err error }

func (e *partialRunRefusal) Error() string { return e.err.Error() }
func (e *partialRunRefusal) Unwrap() error { return e.err }

// partialRunRefused reports whether a partial run failed for good.
func partialRunRefused(err error) bool {
	var refusal *partialRunRefusal
	return errors.As(err, &refusal)
}

// partialRunsMade holds, by run cache path, the partial runs this process made, so one whose run
// cache write failed still answers the later advisories of the scan this process serves as it
// answered the first.
var partialRunsMade sync.Map

// firstPartialRun returns the partial run for a failure the caller has just settled: one stored or
// made earlier, else one it makes now. A refusal stored earlier is not retried.
func firstPartialRun(ctx context.Context, key []string, failure error, partial func(failure error) ([]byte, error)) (*partialRun, error) {
	run, refused := knownPartialRun(ctx, key)
	switch {
	case run != nil:
		return run, nil
	case refused:
		return nil, errPartialRunRefused
	}
	return makePartialRun(ctx, key, failure, partial)
}

// retryPartialRun returns the partial run for a replayed failure: one stored or made earlier, else
// one it makes from the failure's recorded package errors, when a retry slot is left. It returns
// neither run nor error when it makes no attempt.
func retryPartialRun(ctx context.Context, key []string, failure error, partial func(failure error) ([]byte, error)) (*partialRun, error) {
	if run, refused := knownPartialRun(ctx, key); run != nil || refused {
		return run, nil
	}
	if len(failurePackageErrors(failure)) == 0 || !claimPartialRetry(ctx, key) {
		return nil, nil
	}
	return makePartialRun(ctx, key, failure, partial)
}

// knownPartialRun returns the partial run this process made or the run cache holds for key, or
// whether the run cache holds a refusal of it.
func knownPartialRun(ctx context.Context, key []string) (*partialRun, bool) {
	dir := RunCacheDir(ctx)
	if dir == "" {
		return nil, false
	}
	if run, ok := partialRunsMade.Load(runCachePath(dir, govulncheckPartialKind, key)); ok {
		return run.(*partialRun), false
	}
	if run := storedPartialRun(ctx, key); run != nil {
		return run, false
	}
	b, err := os.ReadFile(runCachePath(dir, govulncheckPartialRefusedKind, key))
	return nil, err == nil && string(b) == govulncheckPartialRefusedMarker
}

// makePartialRun runs partial for failure and keeps the outcome: a run in the run cache and in this
// process, a refusal in the run cache. A failure that may be transient is kept nowhere.
func makePartialRun(ctx context.Context, key []string, failure error, partial func(failure error) ([]byte, error)) (*partialRun, error) {
	dir := RunCacheDir(ctx)
	b, err := partial(failure)
	var run *partialRun
	if err == nil {
		if run = decodePartialRun(b); run == nil {
			err = &partialRunRefusal{errors.New("the partial run record does not decode")}
		}
	}
	if dir == "" {
		return run, err
	}
	switch {
	case run != nil:
		path := runCachePath(dir, govulncheckPartialKind, key)
		partialRunsMade.Store(path, run)
		writeRunCacheEntry(dir, govulncheckPartialKind, path, b)
	case partialRunRefused(err):
		writeRunCacheEntry(dir, govulncheckPartialRefusedKind, runCachePath(dir, govulncheckPartialRefusedKind, key), []byte(govulncheckPartialRefusedMarker))
	}
	return run, err
}

// claimPartialRetry takes one of the scan's maxPartialRunRetries retry slots for key, reporting
// whether one was left. A slot is a file created exclusively, so concurrent advisories never share
// one; a slot that cannot be created for any other reason is not taken.
func claimPartialRetry(ctx context.Context, key []string) bool {
	dir := RunCacheDir(ctx)
	if dir == "" {
		return false
	}
	for i := range maxPartialRunRetries {
		f, err := os.OpenFile(runCachePath(dir, fmt.Sprintf("%s-retry%d", govulncheckPartialKind, i), key), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = f.Close()
			return true
		}
		if !errors.Is(err, fs.ErrExist) {
			return false
		}
	}
	return false
}

// storedPartialRun returns the partial run the run cache holds for key, or nil.
func storedPartialRun(ctx context.Context, key []string) *partialRun {
	dir := RunCacheDir(ctx)
	if dir == "" {
		return nil
	}
	b, err := os.ReadFile(runCachePath(dir, govulncheckPartialKind, key))
	if err != nil {
		return nil
	}
	return decodePartialRun(b)
}

// decodePartialRun decodes a partial run record, or returns nil when b is none.
func decodePartialRun(b []byte) *partialRun {
	var run partialRun
	if json.Unmarshal(b, &run) != nil || run.Marker != govulncheckPartialMarker || len(run.Excluded) == 0 || len(run.Unloadable) == 0 {
		return nil
	}
	return &run
}

// listedPackage is one package `go list -deps` reports for the build.
type listedPackage struct {
	ImportPath string
	Dir        string
	DepOnly    bool
	Imports    []string
	Module     *listedModule // none for the standard library
}

// purl names the module of p as modulePURL does.
func (p listedPackage) purl() string {
	switch {
	case p.Module == nil:
		return stdlibPURL
	case p.Module.Main:
		return ""
	}
	return "pkg:golang/" + p.Module.Path
}

// partialGovulncheck makes the partial run for a govulncheck failure over buildDir under env: it
// lists the build's packages under the same env the failed load ran with, and runs govulncheck over
// the roots it keeps.
func partialGovulncheck(ctx context.Context, buildDir string, env []string, failure error) ([]byte, error) {
	return partialRunRecord(buildDir, failurePackageErrors(failure), func() ([]listedPackage, error) {
		return listBuildPackages(ctx, buildDir, env)
	}, func(patterns []string) ([]byte, error) {
		return govulncheckStream(ctx, buildDir, env, patterns)
	})
}

// partialRunRecord returns the partial run record for a load that failed with perrs: the packages
// they name (P), the roots of ./... whose imports reach one (R_P), and govulncheck's stream over the
// other roots. It refuses (partialRunRefusal) when the failure carries no package errors, when an
// error names no package the build lists, when every root reaches P, when a kept root's import path
// would not reach govulncheck as itself (one holding "..." is a wildcard that could match an
// excluded root, and one starting with "-" a flag), and when the run over the kept roots fails to
// load them for good. Any other failure (the listing, a run that failed short of a settled load) may
// be transient.
func partialRunRecord(buildDir string, perrs []packages.Error, list func() ([]listedPackage, error), run func(patterns []string) ([]byte, error)) ([]byte, error) {
	if len(perrs) == 0 {
		return nil, &partialRunRefusal{errors.New("no package errors to bound a partial run")}
	}
	graph, err := list()
	if err != nil {
		return nil, err
	}
	unloadable, err := unloadablePackages(buildDir, perrs, graph)
	if err != nil {
		return nil, &partialRunRefusal{err}
	}
	excluded, kept := excludedRoots(graph, unloadable)
	if len(kept) == 0 {
		return nil, &partialRunRefusal{fmt.Errorf("every root imports a package govulncheck could not load (%s)", strings.Join(unloadable, ", "))}
	}
	for _, p := range kept {
		if strings.Contains(p, "...") || strings.HasPrefix(p, "-") {
			return nil, &partialRunRefusal{fmt.Errorf("root %q cannot be passed to govulncheck as a literal pattern", p)}
		}
	}
	out, err := run(kept)
	if settledGovulncheckFailure(err) {
		return nil, &partialRunRefusal{err}
	}
	if err != nil {
		return nil, err
	}
	modules := map[string]string{}
	for _, p := range graph {
		if slices.Contains(unloadable, p.ImportPath) {
			modules[p.ImportPath] = p.purl()
		}
	}
	return json.Marshal(partialRun{Marker: govulncheckPartialMarker, Unloadable: unloadable, Modules: modules, Excluded: excluded, Stream: out})
}

// posFile matches a go/packages error position, file:line or file:line:col.
var posFile = regexp.MustCompile(`^(.+?):\d+(?::\d+)?$`)

// unloadablePackages returns the import paths of the packages perrs name, sorted. An error names
// its package by the directory of its position (relative to buildDir when not absolute), or, with
// none (a failed cgo or compile step), by the "# importpath" line the go command heads its output
// with. An error that names no package of graph fails, since what it hides is then unknown.
func unloadablePackages(buildDir string, perrs []packages.Error, graph []listedPackage) ([]string, error) {
	byDir := map[string][]string{}
	listed := map[string]bool{}
	for _, p := range graph {
		listed[p.ImportPath] = true
		if p.Dir != "" {
			byDir[realDir(p.Dir)] = append(byDir[realDir(p.Dir)], p.ImportPath)
		}
	}
	var out []string
	for _, pe := range perrs {
		var named []string
		if m := posFile.FindStringSubmatch(pe.Pos); m != nil {
			file := m[1]
			if !filepath.IsAbs(file) {
				file = filepath.Join(buildDir, file)
			}
			named = byDir[realDir(filepath.Dir(file))]
		} else if pe.Pos == "" {
			if head, ok := strings.CutPrefix(strings.SplitN(pe.Msg, "\n", 2)[0], "# "); ok {
				if path, _, _ := strings.Cut(head, " "); listed[path] {
					named = []string{path}
				}
			}
		}
		if len(named) == 0 {
			return nil, fmt.Errorf("package error names no listed package: %s", pe.Error())
		}
		out = append(out, named...)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// realDir is dir with symbolic links resolved, so that two spellings of one directory (macOS's /var
// and /private/var) compare equal; dir cleaned when it cannot be resolved.
func realDir(dir string) string {
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		return real
	}
	return filepath.Clean(dir)
}

// excludedRoots splits the roots of ./... (the packages graph lists that are not DepOnly) into those
// that are, or whose imports directly or through other packages reach, a package of unloadable, and
// the rest.
// Both come back sorted.
func excludedRoots(graph []listedPackage, unloadable []string) (excluded, kept []string) {
	imports := make(map[string][]string, len(graph))
	for _, p := range graph {
		imports[p.ImportPath] = p.Imports
	}
	reaches := map[string]bool{}
	for _, p := range unloadable {
		reaches[p] = true
	}
	var reach func(path string) bool
	reach = func(path string) bool {
		if r, ok := reaches[path]; ok {
			return r
		}
		reaches[path] = false
		for _, imp := range imports[path] {
			if reach(imp) {
				reaches[path] = true
				break
			}
		}
		return reaches[path]
	}
	for _, p := range graph {
		switch {
		case p.DepOnly:
		case reach(p.ImportPath):
			excluded = append(excluded, p.ImportPath)
		default:
			kept = append(kept, p.ImportPath)
		}
	}
	slices.Sort(excluded)
	slices.Sort(kept)
	return excluded, kept
}

// listBuildPackages lists the packages of ./... and their dependencies in buildDir under env, as
// the govulncheck load sees them: tests excluded. It never fetches: a settled failure already
// resolved every module offline (packagesResolveOffline).
func listBuildPackages(ctx context.Context, buildDir string, env []string) ([]listedPackage, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-e", "-deps", "-json=ImportPath,Dir,DepOnly,Imports,Module", "./...")
	cmd.Dir = buildDir
	cmd.Env = append(slices.Clone(env), "GOPROXY=off")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list for a partial govulncheck run (%q): %w", buildDir, err)
	}
	var graph []listedPackage
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var p listedPackage
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		graph = append(graph, p)
	}
	return graph, nil
}

// withholdForPartialRun shapes a result read off a partial run. A symbol finding is a path in the
// build and stands. A refutation, and an advisory the run says nothing about, rest on a search that
// left the excluded roots out, so neither stands: each declares tool_failure. Every result names
// what the run left out.
func withholdForPartialRun(res plugin.ReachabilityResult, scanned vulnScan) plugin.ReachabilityResult {
	run := scanned.partial
	if run == nil {
		return res
	}
	switch {
	case res.Refutation != nil:
		res.Refutation = nil
		res.Partiality = withReason(res.Partiality, plugin.PartialReasonToolFailure)
	case len(scanned.findings) == 0:
		reasons := slices.DeleteFunc(slices.Clone(res.Partiality.Reasons), func(r string) bool {
			return r == plugin.PartialReasonAdvisoryUnknownToAnalyzer
		})
		scoped := res.Partiality.Scoped
		res.Partiality = withReason(plugin.Partial(reasons...), plugin.PartialReasonToolFailure)
		res.Partiality.Scoped = scoped
	}
	res.Partiality.Complete = false
	res.Partiality.Scoped = append(slices.Clone(res.Partiality.Scoped), partialRunLimits(run)...)
	return res
}

// partialRunLimits discloses a partial run as unbounded tool_failure limits, one per module of a
// package the run could not load (Package as a scoped limit names it), each naming those packages
// and the roots the run left out.
func partialRunLimits(run *partialRun) []plugin.ScopedReason {
	byModule := map[string][]string{}
	for _, p := range run.Unloadable {
		byModule[run.Modules[p]] = append(byModule[run.Modules[p]], p)
	}
	var limits []plugin.ScopedReason
	for _, mod := range slices.Sorted(maps.Keys(byModule)) {
		limits = append(limits, plugin.ScopedReason{
			Reason:  plugin.PartialReasonToolFailure,
			Package: mod,
			Path: fmt.Sprintf("govulncheck could not load %s; it searched the build less the roots that are or import a package it could not load: %s",
				nameList(byModule[mod]), nameList(run.Excluded)),
		})
	}
	return limits
}

// nameList joins names, naming at most five.
func nameList(names []string) string {
	if len(names) > 5 {
		return strings.Join(names[:5], ", ") + fmt.Sprintf(" and %d more", len(names)-5)
	}
	return strings.Join(names, ", ")
}
