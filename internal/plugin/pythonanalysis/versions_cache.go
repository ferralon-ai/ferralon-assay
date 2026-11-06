package pythonanalysis

import (
	"context"
	"errors"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/scriptsurface"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// versionSurfaces and installedCopies read only the files under one build dir: no environment
// variable, clock, working directory or process state, and a symlink that leaves the dir is
// refused. With the tree fixed for the scan, as it is for every run cache entry, BuildDir alone
// keys their results.

// surfacesSnapshot is versionSurfaces' results in a form that survives the run cache's JSON
// round trip, which drops the unexported fields of pipInstall and poetryInstall.
type surfacesSnapshot struct {
	Manifests      []string
	Unread         bool
	ScriptWithheld bool
	Installs       map[string][]pipInstallSnapshot
	Poetry         map[string][]poetryInstallSnapshot
	Tooling        map[string]bool
	Unrecognised   string
	Inactive       []scriptsurface.Site
	ConfigNamed    bool
}

type pipInstallSnapshot struct {
	NoDeps, RequireHashes bool
}

type poetryInstallSnapshot struct {
	Only, With, Without []string
	BuildsRoot          bool
	Pyprojects          []string
}

func snapshotSurfaces(manifests []string, unread, scriptWithheld bool, installs pipInstalls, poetry poetryInstalls, tooling map[string]bool, unrecognised string, inactive []scriptsurface.Site, configNamed bool) surfacesSnapshot {
	s := surfacesSnapshot{
		Manifests: manifests, Unread: unread, ScriptWithheld: scriptWithheld, Tooling: tooling,
		Unrecognised: unrecognised, Inactive: inactive, ConfigNamed: configNamed,
	}
	if installs != nil {
		s.Installs = make(map[string][]pipInstallSnapshot, len(installs))
		for k, v := range installs {
			for _, i := range v {
				s.Installs[k] = append(s.Installs[k], pipInstallSnapshot{i.noDeps, i.requireHashes})
			}
			if v != nil && s.Installs[k] == nil {
				s.Installs[k] = []pipInstallSnapshot{}
			}
		}
	}
	if poetry != nil {
		s.Poetry = make(map[string][]poetryInstallSnapshot, len(poetry))
		for k, v := range poetry {
			if v != nil {
				s.Poetry[k] = []poetryInstallSnapshot{}
			}
			for _, i := range v {
				s.Poetry[k] = append(s.Poetry[k], poetryInstallSnapshot{
					Only: i.only, With: i.with, Without: i.without, BuildsRoot: i.buildsRoot, Pyprojects: i.pyprojects,
				})
			}
		}
	}
	return s
}

func (s surfacesSnapshot) unpack() (manifests []string, unread, scriptWithheld bool, installs pipInstalls, poetry poetryInstalls, tooling map[string]bool, unrecognised string, inactive []scriptsurface.Site, configNamed bool) {
	if s.Installs != nil {
		installs = make(pipInstalls, len(s.Installs))
		for k, v := range s.Installs {
			if v != nil {
				installs[k] = []pipInstall{}
			}
			for _, i := range v {
				installs[k] = append(installs[k], pipInstall{noDeps: i.NoDeps, requireHashes: i.RequireHashes})
			}
		}
	}
	if s.Poetry != nil {
		poetry = make(poetryInstalls, len(s.Poetry))
		for k, v := range s.Poetry {
			if v != nil {
				poetry[k] = []poetryInstall{}
			}
			for _, i := range v {
				poetry[k] = append(poetry[k], poetryInstall{
					poetrySelection: poetrySelection{only: i.Only, with: i.With, without: i.Without, buildsRoot: i.BuildsRoot},
					pyprojects:      i.Pyprojects,
				})
			}
		}
	}
	return s.Manifests, s.Unread, s.ScriptWithheld, installs, poetry, s.Tooling, s.Unrecognised, s.Inactive, s.ConfigNamed
}

// versionSurfacesCached is versionSurfaces through the run cache: one scan of the tree per
// scan instead of one per exec. versionSurfaces has no error result; a surface it could not read
// shows in its own unread and withheld results, which are cached as they are. Every call gets
// results of its own, never a shared map or slice.
func versionSurfacesCached(ctx context.Context, root string) (manifests []string, unread, scriptWithheld bool, installs pipInstalls, poetry poetryInstalls, tooling map[string]bool, unrecognised string, inactive []scriptsurface.Site, configNamed bool) {
	snap, _ := cachedResult(ctx, "versurf", []string{root}, func() (surfacesSnapshot, error) {
		return snapshotSurfaces(versionSurfaces(root)), nil
	})
	return snap.unpack()
}

type copiesSnapshot struct {
	Copies  []plugin.ResolvedDependency
	Origins []manifestOriginSnapshot
	OK      bool
}

type manifestOriginSnapshot struct {
	Dir       string
	Lock      string
	LockedBy  []string
	Spec      string
	DirectRef bool
}

var errCopiesIncomplete = errors.New("pythonanalysis: installed copies not fully read")

// installedCopiesCached is installedCopies through the run cache. A read that did not finish
// (ok false) is returned but never stored, so the next call reads again.
func installedCopiesCached(ctx context.Context, root string) (copies []plugin.ResolvedDependency, origins []manifestOrigin, ok bool) {
	var incomplete copiesSnapshot
	snap, err := cachedResult(ctx, "instcopies", []string{root}, func() (copiesSnapshot, error) {
		c, o, ok := installedCopies(root)
		s := copiesSnapshot{Copies: c, OK: ok}
		if o != nil {
			s.Origins = make([]manifestOriginSnapshot, 0, len(o))
		}
		for _, m := range o {
			s.Origins = append(s.Origins, manifestOriginSnapshot{m.dir, m.lock, m.lockedBy, m.spec, m.directRef})
		}
		if !ok {
			incomplete = s
			return s, errCopiesIncomplete
		}
		return s, nil
	})
	if err != nil {
		snap = incomplete
	}
	if snap.Origins != nil {
		origins = make([]manifestOrigin, 0, len(snap.Origins))
	}
	for _, m := range snap.Origins {
		origins = append(origins, manifestOrigin{dir: m.Dir, lock: m.Lock, lockedBy: m.LockedBy, spec: m.Spec, directRef: m.DirectRef})
	}
	return snap.Copies, origins, snap.OK
}
