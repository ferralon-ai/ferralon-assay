package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/internal/brand"
)

// restoreDotNet runs `dotnet restore` in dir when a project there has neither restore output
// (obj/project.assets.json) nor a packages.lock.json, so the .NET lane reads the dependency graph
// the build resolves instead of only the declared references. The lane decides on its own whether
// the restore output describes the project as it stands; this step only produces it. A failure is
// classified the way a build-graph failure is (toolchain_absent, tool_failed) and logged to w; the
// scan goes on without restore output.
//
// A root solution is restored first; any project still without output afterwards (one the
// solution does not list, or every project when the solution restore failed) is then restored on
// its own.
func restoreDotNet(ctx context.Context, dir string, w io.Writer) {
	start := time.Now()
	targets := dotnetRestoreTargets(dir)
	if len(targets) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, dotnetRestoreTimeout)
	defer cancel()
	f := runDotNetRestore(ctx, dir, targets)
	if f == nil || f.Kind != buildgraph.KindToolchainAbsent {
		if isSolution(targets[0]) {
			if rest := unrestoredProjects(dir); len(rest) > 0 {
				if g := runDotNetRestore(ctx, dir, rest); f == nil {
					f = g
				}
			}
		}
	}
	if f != nil {
		fmt.Fprintf(w, "%s: dotnet restore: %s\n", brand.Name, f.Cause())
	}
	logPhase(w, "restore", time.Since(start))
}

// dotnetRestoreTimeout bounds the whole step, so an unreachable package feed costs a bounded share
// of the scan rather than the scan's budget.
const dotnetRestoreTimeout = 5 * time.Minute

// dotnetRestoreTargets lists what to restore, relative to dir: nothing when every project already
// has restore output or a lock file, else the root's only solution when it has exactly one, else
// each project that has neither.
func dotnetRestoreTargets(dir string) []string {
	missing := unrestoredProjects(dir)
	if len(missing) == 0 {
		return nil
	}
	if sln := rootSolutions(dir); len(sln) == 1 {
		return sln
	}
	return missing
}

// unrestoredProjects lists, relative to dir and sorted, the projects that have neither restore
// output nor a lock file.
func unrestoredProjects(dir string) []string {
	var missing []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree yields no project; keep walking.
		}
		if d.IsDir() {
			if p != dir && skipRestoreDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !isDotNetProject(d.Name()) {
			return nil
		}
		pd := filepath.Dir(p)
		if regular(filepath.Join(pd, "obj", "project.assets.json")) || regular(filepath.Join(pd, "packages.lock.json")) {
			return nil
		}
		if rel, err := filepath.Rel(dir, p); err == nil {
			missing = append(missing, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(missing)
	return missing
}

// rootSolutions lists dir's own .sln and .slnx files.
func rootSolutions(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var sln []string
	for _, e := range entries {
		if isSolution(e.Name()) && e.Type().IsRegular() {
			sln = append(sln, e.Name())
		}
	}
	return sln
}

// runDotNetRestore restores each target in turn and returns the first failure.
func runDotNetRestore(ctx context.Context, dir string, targets []string) *buildgraph.Failure {
	tool, err := exec.LookPath("dotnet")
	if err != nil {
		return &buildgraph.Failure{Kind: buildgraph.KindToolchainAbsent, Log: "no dotnet on PATH"}
	}
	env := append(os.Environ(), "DOTNET_CLI_TELEMETRY_OPTOUT=1", "DOTNET_NOLOGO=1", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1", "MSBUILDDISABLENODEREUSE=1")
	var first *buildgraph.Failure
	for _, t := range targets {
		// An absolute path, so a file name starting with "-" is never read as an option.
		cmd := exec.CommandContext(ctx, tool, "restore", filepath.Join(dir, filepath.FromSlash(t)))
		cmd.Dir = dir
		cmd.Env = env
		cmd.WaitDelay = 10 * time.Second
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil && first == nil {
			first = &buildgraph.Failure{Kind: buildgraph.KindToolFailed, Detail: "restore", Log: out.String()}
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				first.Log = err.Error()
			}
		}
	}
	return first
}

func isSolution(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".sln", ".slnx":
		return true
	}
	return false
}

func isDotNetProject(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".csproj", ".fsproj", ".vbproj":
		return true
	}
	return false
}

// skipRestoreDir matches the .NET lane's own walk: build output, package caches and dot
// directories hold no project of the build.
func skipRestoreDir(name string) bool {
	switch name {
	case "bin", "obj", "packages", "node_modules", "TestResults":
		return true
	}
	return strings.HasPrefix(name, ".")
}

func regular(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode().IsRegular()
}
