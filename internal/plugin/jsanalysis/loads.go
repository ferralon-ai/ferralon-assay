package jsanalysis

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// nodeInertBuiltins are the Node builtin modules that load no code. Calling into one runs
// runtime code, and any first-party function it calls back is an escape root (escape.go),
// so the call hides no edge.
var nodeInertBuiltins = map[string]bool{
	"assert": true, "assert/strict": true, "async_hooks": true, "buffer": true,
	"console": true, "constants": true, "crypto": true, "dgram": true,
	"diagnostics_channel": true, "dns": true, "dns/promises": true, "domain": true,
	"events": true, "fs": true, "fs/promises": true, "http": true, "http2": true,
	"https": true, "net": true, "os": true, "path": true, "path/posix": true,
	"path/win32": true, "perf_hooks": true, "punycode": true, "querystring": true,
	"readline": true, "readline/promises": true, "stream": true, "stream/consumers": true,
	"stream/promises": true, "stream/web": true, "string_decoder": true, "sys": true,
	"timers": true, "timers/promises": true, "tls": true, "trace_events": true,
	"tty": true, "url": true, "util": true, "util/types": true, "v8": true, "zlib": true,
}

// nodeCodeLoadingBuiltins are the Node builtins through which a program can load or run
// code this lane does not see: module loaders, script evaluation, workers and child
// processes, native addons and extensions, and the test runner.
var nodeCodeLoadingBuiltins = map[string]bool{
	"module": true, "vm": true, "worker_threads": true, "child_process": true,
	"cluster": true, "repl": true, "inspector": true, "inspector/promises": true,
	"wasi": true, "process": true, "test": true, "test/reporters": true, "sea": true,
	"sqlite": true,
}

// nodeBuiltin reports whether spec names a Node builtin module and whether that builtin
// can load code. A `node:` specifier this table does not know is treated as code-loading.
func nodeBuiltin(spec string) (builtin, loadsCode bool) {
	name, prefixed := strings.CutPrefix(spec, "node:")
	switch {
	case nodeInertBuiltins[name]:
		return true, false
	case nodeCodeLoadingBuiltins[name]:
		return true, true
	case prefixed:
		return true, true
	}
	return false, false
}

// installedPackage reports whether an unprefixed builtin name is also installed as an npm
// package visible from fromModule (a polyfill such as `events` or `punycode`). Node itself
// prefers the builtin, but a bundler resolves the package, so the load is treated as the
// package's.
func (rs *resolver) installedPackage(fromModule, pkgName, spec string) bool {
	if strings.HasPrefix(spec, "node:") {
		return false
	}
	dir := moduleDir(fromModule)
	if rs.prog.lockClosures().closureOf(dir, pkgName) != nil {
		return true
	}
	for d := dir; ; d = lockParent(d) {
		if _, err := os.Stat(filepath.Join(rs.prog.root, filepath.FromSlash(d), "node_modules", filepath.FromSlash(pkgName), "package.json")); err == nil {
			return true
		}
		if d == "" {
			return false
		}
	}
}

// validNPMName reports whether name has the shape of an npm package name ("name" or
// "@scope/name"), so it can stand as a ScopedReason's Package.
func validNPMName(name string) bool {
	if name == "" || strings.HasPrefix(name, ".") || strings.ContainsAny(name, " \\:") {
		return false
	}
	if scope, rest, ok := strings.Cut(name, "/"); ok {
		return strings.HasPrefix(scope, "@") && len(scope) > 1 && rest != "" && !strings.Contains(rest, "/")
	}
	return !strings.HasPrefix(name, "@")
}

// npmPURL is the versionless PURL of an npm package, the form ScopedReason Package and
// Targets carry.
func npmPURL(name string) string {
	return strings.TrimSuffix(makePURL(name, ""), "@")
}

// lockClosures returns the program's lockfile closure index, built on first use.
func (p *program) lockClosures() *lockClosures {
	if p.locks == nil {
		p.locks = newLockClosures(p.root)
	}
	return p.locks
}

// scopedKey identifies one scoped limit: a reason code against one package.
type scopedKey struct {
	reason, pkg string
}

// scopedEntry is one accumulated scoped limit. bounded is false once any contributing load
// could not bound its closure, after which targets is ignored.
type scopedEntry struct {
	path    string
	bounded bool
	targets map[string]bool
}

// scopedLimits accumulates the call graph's per-package limits: one ScopedReason per
// (reason, package), located at the first module (in file order) that contributed it, with
// Targets the union of every contributing load's closure.
type scopedLimits struct {
	lc      *lockClosures
	entries map[scopedKey]*scopedEntry
}

func newScopedLimits(lc *lockClosures) *scopedLimits {
	return &scopedLimits{lc: lc, entries: map[scopedKey]*scopedEntry{}}
}

// addPackageLoad records that file (in module's directory) loads npm package pkg in a way
// that hides edges, under reason. Targets are pkg plus its installed closure as seen from
// module's directory, or unbounded when the lockfile cannot say.
func (s *scopedLimits) addPackageLoad(reason, pkg, module, file string) {
	key := scopedKey{reason: reason, pkg: npmPURL(pkg)}
	e := s.entries[key]
	if e == nil {
		e = &scopedEntry{path: file, bounded: true, targets: map[string]bool{}}
		s.entries[key] = e
	}
	if !e.bounded {
		return
	}
	closure := s.lc.closureOf(moduleDir(module), pkg)
	if closure == nil {
		e.bounded = false
		e.targets = nil
		return
	}
	for _, name := range closure {
		if name == "" {
			e.targets[""] = true
			continue
		}
		e.targets[npmPURL(name)] = true
	}
}

// list returns the accumulated limits in a deterministic order.
func (s *scopedLimits) list() []plugin.ScopedReason {
	keys := make([]scopedKey, 0, len(s.entries))
	for k := range s.entries {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].reason != keys[j].reason {
			return keys[i].reason < keys[j].reason
		}
		return keys[i].pkg < keys[j].pkg
	})
	out := make([]plugin.ScopedReason, 0, len(keys))
	for _, k := range keys {
		e := s.entries[k]
		sr := plugin.ScopedReason{Reason: k.reason, Package: k.pkg, Path: e.path}
		if e.bounded {
			sr.Targets = make([]string, 0, len(e.targets))
			for t := range e.targets {
				sr.Targets = append(sr.Targets, t)
			}
			sort.Strings(sr.Targets)
		}
		out = append(out, sr)
	}
	return out
}
