package goanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/scan"

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
const govulncheckPartialMarker = "govulncheck-partial/v1"

// partialRun is a govulncheck run over the build less Excluded, the roots of ./... whose imports
// reach a package in Unloadable, which the full run's load could not read.
type partialRun struct {
	Marker     string   `json:"marker"`
	Unloadable []string `json:"unloadable"`
	Excluded   []string `json:"excluded"`
	Stream     []byte   `json:"stream"`
}

// govulncheckOrPartial returns the govulncheck stream for buildDir under env (govulncheckCached),
// or, when that run's failure settles, the stream of the partial run partial computes from the
// failure. The partial run is computed once per tree and environment in a scan: it is stored before
// the failure is, so a run that replays the failure finds it, and a failure replayed with no partial
// run stored means the partial run could not be made. Any failure without a partial run is returned
// as it is.
func govulncheckOrPartial(ctx context.Context, buildDir string, env []string, settle bool, stream func() ([]byte, error), partial func(failure error) ([]byte, error)) ([]byte, *partialRun, error) {
	key := append([]string{buildDir}, env...)
	var run *partialRun
	out, err := govulncheckCached(ctx, buildDir, env, settle, func() ([]byte, error) {
		out, err := stream()
		if settle && settledGovulncheckFailure(err) {
			if b, perr := runCached(ctx, govulncheckPartialKind, key, func() ([]byte, error) { return partial(err) }); perr == nil {
				run = decodePartialRun(b)
			}
		}
		return out, err
	})
	if err == nil {
		return out, nil, nil
	}
	if run == nil && settle && settledGovulncheckFailure(err) {
		run = storedPartialRun(ctx, key)
	}
	if run == nil {
		return nil, nil, err
	}
	return run.Stream, run, nil
}

// settledGovulncheckFailure reports whether err is a settled govulncheck failure, fresh or replayed.
func settledGovulncheckFailure(err error) bool {
	var failed *govulncheckError
	return errors.As(err, &failed) && failed.settled
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
}

// partialGovulncheck makes the partial run for a govulncheck failure over buildDir under env: it
// lists the build's packages under the same env the failed load ran with, and runs govulncheck over
// the roots it keeps.
func partialGovulncheck(ctx context.Context, buildDir string, env []string, failure error) ([]byte, error) {
	return partialRunRecord(loadPackageErrors(failure), func() ([]listedPackage, error) {
		return listBuildPackages(ctx, buildDir, env)
	}, func(patterns []string) ([]byte, error) {
		return govulncheckPatterns(ctx, buildDir, env, patterns)
	})
}

// partialRunRecord returns the partial run record for a load that failed with perrs: the packages
// they name (P), the roots of ./... whose imports reach one (R_P), and govulncheck's stream over the
// other roots. It fails when the failure carries no package errors (a replayed one), when an error
// names no package the build lists, and when every root reaches P.
func partialRunRecord(perrs []packages.Error, list func() ([]listedPackage, error), run func(patterns []string) ([]byte, error)) ([]byte, error) {
	if len(perrs) == 0 {
		return nil, errors.New("no package errors to bound a partial run")
	}
	graph, err := list()
	if err != nil {
		return nil, err
	}
	unloadable, err := unloadablePackages(perrs, graph)
	if err != nil {
		return nil, err
	}
	excluded, kept := excludedRoots(graph, unloadable)
	if len(kept) == 0 {
		return nil, fmt.Errorf("every root imports a package govulncheck could not load (%s)", strings.Join(unloadable, ", "))
	}
	out, err := run(kept)
	if err != nil {
		return nil, err
	}
	return json.Marshal(partialRun{Marker: govulncheckPartialMarker, Unloadable: unloadable, Excluded: excluded, Stream: out})
}

// posFile matches a go/packages error position, file:line or file:line:col.
var posFile = regexp.MustCompile(`^(.+?):\d+(?::\d+)?$`)

// unloadablePackages returns the import paths of the packages perrs name, sorted. An error names
// its package by the directory of its position, or, with none (a failed cgo or compile step), by the
// "# importpath" line the go command heads its output with. An error that names no package of
// graph fails, since what it hides is then unknown.
func unloadablePackages(perrs []packages.Error, graph []listedPackage) ([]string, error) {
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
			named = byDir[realDir(filepath.Dir(m[1]))]
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
// whose imports, directly or through other packages, reach a package of unloadable, and the rest.
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
// the govulncheck load sees them: tests excluded.
func listBuildPackages(ctx context.Context, buildDir string, env []string) ([]listedPackage, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-e", "-deps", "-json=ImportPath,Dir,DepOnly,Imports", "./...")
	cmd.Dir = buildDir
	cmd.Env = env
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

// govulncheckPatterns runs govulncheck over patterns in buildDir under env and returns its -json
// stream. Every failure is an error: the partial run is only ever a replacement for a failed one.
func govulncheckPatterns(ctx context.Context, buildDir string, env, patterns []string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := scan.Command(ctx, append([]string{"-C", buildDir, "-json", "-mode=source", "-scan=symbol"}, patterns...)...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		var ec interface{ ExitCode() int }
		if !errors.As(err, &ec) || (ec.ExitCode() != 0 && ec.ExitCode() != 3) {
			return nil, fmt.Errorf("partial govulncheck run: %w: %s", err, strings.TrimSpace(stderr.String()))
		}
	}
	return stdout.Bytes(), nil
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
	res.Partiality.Scoped = append(slices.Clone(res.Partiality.Scoped), plugin.ScopedReason{
		Reason: plugin.PartialReasonToolFailure,
		Path: fmt.Sprintf("govulncheck could not load %s; it searched the build less %s, which import it",
			nameList(run.Unloadable), nameList(run.Excluded)),
	})
	return res
}

// nameList joins names, naming at most five.
func nameList(names []string) string {
	if len(names) > 5 {
		return strings.Join(names[:5], ", ") + fmt.Sprintf(" and %d more", len(names)-5)
	}
	return strings.Join(names, ", ")
}
