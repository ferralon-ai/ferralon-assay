package goanalysis

import (
	"context"
	"go/build"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// pluginBuild says which package plugin a build compiled.
type pluginBuild int

const (
	// pluginLoads: the real package, or no package plugin whose files say otherwise.
	pluginLoads pluginBuild = iota
	// pluginCgoOff: the stub, and only because cgo is off. The same build with cgo on loads plugins.
	pluginCgoOff
	// pluginNoPlatform: the stub with cgo on too: the GOOS has no plugins.
	pluginNoPlatform
)

// pluginBuildOf reports which package plugin the load of dir compiled, read from the files the load
// resolved for the standard library's plugin package under env. The stub (plugin_stubs.go) has an
// Open that only returns an error. A build that does not import plugin, or whose files do not say,
// loads plugins; so does a load holding more than one package plugin unless every one is a stub.
//
// A stub is there because cgo is off unless the build is shown to compile it with cgo on as well:
// the go command resolves the build's GOOS and GOARCH, and the stub's own build constraints hold for
// them with cgo enabled. Anything short of that reads as cgo off, the answer that declares a limit.
func pluginBuildOf(ctx context.Context, dir string, loaded []*packages.Package, env []string) pluginBuild {
	found, least := false, pluginNoPlatform
	packages.Visit(loaded, nil, func(p *packages.Package) {
		if p.PkgPath != "plugin" || p.Module != nil {
			return
		}
		found = true
		kind := pluginLoads
		stub := slices.IndexFunc(p.GoFiles, func(f string) bool { return filepath.Base(f) == "plugin_stubs.go" })
		if stub >= 0 && !slices.ContainsFunc(p.GoFiles, func(f string) bool { return filepath.Base(f) == "plugin_dlopen.go" }) {
			kind = pluginCgoOff
			if builtWithCgo(ctx, dir, env, p.GoFiles[stub]) {
				kind = pluginNoPlatform
			}
		}
		least = min(least, kind)
	})
	if !found {
		return pluginLoads
	}
	return least
}

// builtWithCgo reports whether the build of dir under env would compile file with cgo enabled: the
// go command resolves the build's GOOS and GOARCH, and file's build constraints hold for them. It is
// false when either is unknown.
func builtWithCgo(ctx context.Context, dir string, env []string, file string) bool {
	cmd := exec.CommandContext(ctx, "go", "env", "GOOS", "GOARCH")
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	target := strings.Fields(string(out))
	if len(target) != 2 {
		return false
	}
	bc := build.Default
	bc.GOOS, bc.GOARCH = target[0], target[1]
	bc.BuildTags = goflagsTags(env)
	bc.CgoEnabled = true
	ok, err := bc.MatchFile(filepath.Dir(file), filepath.Base(file))
	return err == nil && ok
}

// runTimeReason returns the reason runTimeCallees declares for the function named name, and whether
// it declares one. plugin.Open declares none in a build whose GOOS has no plugins, and
// plugin_load:cgo_off in one that compiled the stub only because cgo is off.
func (s *ssaProgram) runTimeReason(name string) (string, bool) {
	r, ok := runTimeCallees[name]
	if ok && r == plugin.PartialReasonPluginLoad {
		switch s.plugin {
		case pluginNoPlatform:
			return "", false
		case pluginCgoOff:
			return plugin.PartialReasonPluginLoadCgoOff, true
		}
	}
	return r, ok
}

// statePluginScope says, in the detail of each refutation kept beside a limit that holds only
// because the scanned build has cgo off, the program view's among them, the build setting the
// refutation holds for.
// plugin_load:cgo_off: the program reaches plugin.Open, which loads nothing with cgo off.
// cgo:files_dropped: the build left out cgo files, none of which was found to call into the
// advisory's module. Either way the same program built with cgo on was not checked.
func statePluginScope(res plugin.ReachabilityResult) plugin.ReachabilityResult {
	var scopes []string
	if slices.Contains(res.Partiality.Reasons, plugin.PartialReasonPluginLoadCgoOff) {
		scopes = append(scopes, pluginScopeDetail)
	}
	if slices.ContainsFunc(res.Partiality.Scoped, func(s plugin.ScopedReason) bool {
		return s.Reason == plugin.PartialReasonCgoFilesDropped
	}) {
		scopes = append(scopes, cgoFilesScopeDetail)
	}
	if len(scopes) == 0 {
		return res
	}
	state := func(r plugin.Refutation) plugin.Refutation {
		stated := scopes
		if r.Detail != "" {
			stated = append([]string{r.Detail}, scopes...)
		}
		r.Detail = strings.Join(stated, "; ")
		return r
	}
	if res.Refutation != nil {
		stated := state(*res.Refutation)
		res.Refutation = &stated
	}
	res.Refutations = slices.Clone(res.Refutations)
	for i, r := range res.Refutations {
		res.Refutations[i] = state(r)
	}
	if res.ProgramView != nil {
		view := *res.ProgramView
		view.Refutation = state(view.Refutation)
		view.Refutations = slices.Clone(view.Refutations)
		for i, r := range view.Refutations {
			view.Refutations[i] = state(r)
		}
		res.ProgramView = &view
	}
	return res
}

// assumePluginsSeparate attaches plugin.AssumptionPluginsNotAssessed to each refutation resting on
// the build importing none of the advisory's vulnerable packages, when the program reaches
// plugin.Open in a build that can load plugins (plugin_load).
func assumePluginsSeparate(res plugin.ReachabilityResult) plugin.ReachabilityResult {
	if !slices.Contains(res.Partiality.Reasons, plugin.PartialReasonPluginLoad) {
		return res
	}
	assume := func(r plugin.Refutation) plugin.Refutation {
		if r.Basis == plugin.RefutationAnalyzerPackageNotImported && !slices.Contains(r.Assumptions, plugin.AssumptionPluginsNotAssessed) {
			r.Assumptions = append(slices.Clone(r.Assumptions), plugin.AssumptionPluginsNotAssessed)
		}
		return r
	}
	if res.Refutation != nil {
		assumed := assume(*res.Refutation)
		res.Refutation = &assumed
	}
	res.Refutations = slices.Clone(res.Refutations)
	for i, r := range res.Refutations {
		res.Refutations[i] = assume(r)
	}
	return res
}

// pluginScopeDetail and cgoFilesScopeDetail are what statePluginScope adds to a refutation's detail.
const (
	pluginScopeDetail   = "holds for CGO_ENABLED=0, where the plugin.Open call the program reaches loads nothing; a build with cgo on was not checked"
	cgoFilesScopeDetail = "holds for CGO_ENABLED=0, which leaves the build's cgo files out; a build with cgo on was not checked"
)
