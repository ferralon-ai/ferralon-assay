package assembly

// spanningset.go — the whole-program LOADER glue (PLAN-350 barrier-3b, deliverable 1).
//
// The verdict engine (depreach.NewEngine) consumes a []*Assembly and builds the
// spanning CHA over it; the cross-assembly stitch (a TypeRef whose resolution scope
// is another assembly resolving against the CHA's global type index) is already the
// design. This file's only job is to ASSEMBLE that set from a build: the first-party
// assembly, then each dependency whose compiled .dll can be LOCATED (barrier-3a's
// ResolveDependencyDlls) and READ (ReadAssembly).
//
// It is pure locate+read+assemble: no restore, no fetch, no execution, no system
// assembly, and — critically — NO VERDICT LOGIC. The engine/trigger classifies; the
// loader only supplies bytes.
//
// A dependency that does not locate or does not parse is a DECLARED MISS: it is
// simply absent from the loaded set. Per barrier-2's soundness core that makes every
// call into it out-of-set ⇒ a completeness hazard ⇒ `undetermined`, NEVER a silent
// leaf and NEVER a fabricated empty assembly. The miss is recorded (not fabricated,
// not dropped) so a caller can see WHY the set is what it is.

// DepRef names one dependency to load, in project.assets.json coordinates: Target is
// the assets targets key ("net8.0" or "net8.0/linux-x64") and PkgKey is "<id>/<version>".
// These are exactly the keys ResolveDependencyDlls consumes, derivable from the same
// project.assets.json barrier-3a parses (or supplied by the caller). Runtime is the
// runtime the first-party build was produced for; it picks the implementation of a
// package that ships one per runtime.
type DepRef struct {
	Target  string
	PkgKey  string
	Runtime Runtime
}

// Runtime is the runtime identifier a build was produced for, as its outputs record it.
type Runtime struct {
	RID       string // e.g. "linux-x64"; "" when no output records one (a portable build)
	Ambiguous bool   // the build's outputs record more than one runtime
}

// DepMiss is one dependency that could not be added to the spanning set — either its
// dll did not locate (a declared miss, never a fetch) or its bytes did not parse into
// a valid assembly. Recorded so the miss is observable, never silently a clean leaf.
type DepMiss struct {
	Dep    DepRef
	Reason string // MissNotLocated | MissUnreadable | MissReferenceAssembly
}

// SpanningSet is the assembled whole-program input for depreach.NewEngine: the
// first-party assembly first, then each located+read dependency in request order.
// Misses carries the declared misses (absent from Assemblies by design).
type SpanningSet struct {
	Assemblies []*Assembly
	Misses     []DepMiss
}

// LoadSpanningSet assembles the []*Assembly spanning set the verdict engine consumes.
// firstParty is the already-read first-party assembly (its own location/read is the
// caller's concern — LocateBuildOutput + ReadAssembly — and is not re-done here); it
// is placed first when non-nil. Each dep's dlls are located via ResolveDependencyDlls
// (assets path, then NuGet global cache, then build output — each a declared miss when
// absent, never a fetch) and read via ReadAssembly. A dep that does not locate, does not
// parse, or is a reference assembly (stub bodies) is recorded in Misses and left OUT of
// the set (out-of-set ⇒ the engine's completeness hazard), never fabricated into an empty
// assembly. A dep restore recorded as carrying no assembly, with none found on disk by
// any locator, is neither loaded nor a miss.
// locator may be nil.
func LoadSpanningSet(buildDir string, firstParty *Assembly, locator *AssetsLocator, deps []DepRef) SpanningSet {
	set := SpanningSet{}
	if firstParty != nil {
		set.Assemblies = append(set.Assemblies, firstParty)
	}
	for _, d := range deps {
		asms, reason := ReadDependency(buildDir, d, locator)
		if reason == MissNotLocated && locator.HasNoAssemblies(d.Target, d.PkgKey) {
			continue // restore recorded no assembly and none is on disk: no code to load
		}
		if reason != "" {
			set.Misses = append(set.Misses, DepMiss{Dep: d, Reason: reason})
			continue
		}
		set.Assemblies = append(set.Assemblies, asms...)
	}
	return set
}

// Declared-miss reasons.
const (
	MissNotLocated        = "not located"
	MissUnreadable        = "unreadable"
	MissReferenceAssembly = "reference assembly"
	MissFrameworkSupplied = "framework-supplied"
	// MissRIDUnknown: the package ships per-runtime implementations and the build records
	// no runtime that restore resolved, so which bytes run is not known.
	MissRIDUnknown = "runtime identifier unknown"
	// MissRIDAmbiguous: the package ships per-runtime implementations and the build's
	// outputs record more than one runtime.
	MissRIDAmbiguous = "runtime identifier ambiguous"
)

// ReadDependency locates and reads every dll of one dependency. reason is "" on
// success, else the declared miss (Miss*). A package is all-or-nothing: one bad dll
// makes the whole package a miss.
func ReadDependency(buildDir string, d DepRef, locator *AssetsLocator) ([]*Assembly, string) {
	paths, reason := dependencyDlls(buildDir, d, locator)
	if reason != "" {
		return nil, reason
	}
	asms := make([]*Assembly, 0, len(paths))
	for _, p := range paths {
		a, ok := ReadAssembly(p)
		if !ok || a == nil || a.Failed {
			return nil, MissUnreadable
		}
		if a.IsReferenceAssembly() {
			return nil, MissReferenceAssembly
		}
		asms = append(asms, a)
	}
	return asms, ""
}

// dependencyDlls locates the dlls that run for one dependency. A package that ships
// per-runtime implementations is read only from the "<tfm>/<rid>" target restore
// resolved for the build's runtime, and only through the assets path: its lib/ dll,
// which the path-convention fallbacks would find, is often a stub the runtime replaces.
func dependencyDlls(buildDir string, d DepRef, locator *AssetsLocator) ([]string, string) {
	target := d.Target
	ridSpecific := locator.RIDSpecific(d.Target, d.PkgKey)
	if ridSpecific {
		switch {
		case d.Runtime.Ambiguous:
			return nil, MissRIDAmbiguous
		case d.Runtime.RID == "" || !locator.HasPackage(d.Target+"/"+d.Runtime.RID, d.PkgKey):
			return nil, MissRIDUnknown
		}
		target = d.Target + "/" + d.Runtime.RID
	}
	if locator.FrameworkSupplied(target, d.PkgKey) {
		return nil, MissFrameworkSupplied
	}
	if ridSpecific {
		paths, ok := locator.LocateDlls(NugetPackageRoots(buildDir, locator), target, d.PkgKey)
		if !ok {
			return nil, MissNotLocated
		}
		return paths, ""
	}
	paths, ok := ResolveDependencyDlls(buildDir, target, d.PkgKey, locator)
	if !ok {
		return nil, MissNotLocated
	}
	return paths, ""
}
