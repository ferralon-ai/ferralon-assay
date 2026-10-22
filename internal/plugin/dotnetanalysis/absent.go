package dotnetanalysis

// absent.go — proving a NuGet package is not present in the build. The claim is made only
// when this lane positively saw every way a package can reach the build and none of them
// carries it: every project's installed set is restore's own trusted project.assets.json,
// which also names the packs the SDK downloads beside it, every MSBuild file read is modeled
// down to the items restore never sees, and the tree holds no assembly, script, foreign
// project or package manager restore does not govern. Anything outside that closed list
// leaves the claim unmade, and the lane answers as it always has. What a deploy step adds
// (a Dockerfile, a base image, a runtime installed on the host) is outside the build and
// outside the claim.

import (
	"context"
	"encoding/xml"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// partialReasonDependencyNotInBuild: the package is not present in the build, so none of its
// code runs there. It is scoped to the package's own PURL and never run-wide.
const partialReasonDependencyNotInBuild = "dependency_not_in_build"

// inertItems are the item types parseMSBuild skips that bring no package into the build:
// source, files, and references to the framework the SDK provides. Any other skipped item
// type is opaque.
var inertItems = []string{
	"compile", "none", "content", "embeddedresource", "folder", "using", "internalsvisibleto",
	"assemblyattribute", "frameworkreference", "reference", "additionalfiles", "page",
	"resource", "applicationdefinition", "service", "bootstrapperpackage", "supportedplatform",
}

// frameworkAssemblies are the simple names, besides System and System.*, a bare Reference
// may carry and still resolve from the framework. A Reference to any other name resolves
// from files and search paths this lane does not follow, so it is opaque.
var frameworkAssemblies = []string{
	"mscorlib", "netstandard", "microsoft.csharp", "microsoft.visualbasic", "windowsbase",
	"presentationcore", "presentationframework",
}

// inertProperties are the properties a project may set and stay closed: target frameworks,
// output kind, compiler settings and descriptive metadata, none of which names a file, a
// directory or a pack. Any other property, besides a restore property restore accepts
// (restoreSafe), is opaque: the SDK reads many properties as files to import, places to
// resolve references from, or platforms whose packs restore never records.
var inertProperties = []string{
	"targetframework", "targetframeworks", "outputtype", "nullable", "implicitusings",
	"langversion", "rootnamespace", "treatwarningsaserrors", "warningsaserrors",
	"warningsnotaserrors", "nowarn", "warninglevel", "defineconstants", "optimize",
	"debugtype", "debugsymbols", "deterministic", "invariantglobalization", "ispackable",
	"istestproject", "generateassemblyinfo", "version", "versionprefix", "versionsuffix",
	"assemblyversion", "fileversion", "informationalversion", "company", "product",
	"authors", "description", "copyright", "title", "neutrallanguage",
}

// referenceMetadata is the metadata a Reference or FrameworkReference may carry. A HintPath,
// or anything else, is opaque.
var referenceMetadata = []string{"specificversion", "private", "requiredtargetframework", "embedinteroptypes", "aliases"}

// sdkDeliveredPrefixes name the packs the SDK can deliver without recording them as a
// package restore installs (shared-framework, runtime, host, AOT, workload and SDK packs).
// Their absence from the restore record proves nothing. Targeting packs (a ".ref" suffix) and
// the downloads restore does record (downloadDependencies) are excluded as well.
var sdkDeliveredPrefixes = []string{
	"microsoft.netcore.app", "microsoft.aspnetcore.app", "microsoft.windowsdesktop.app",
	"microsoft.dotnet.ilcompiler", "microsoft.net.runtime.", "microsoft.net.workload.",
	"microsoft.net.sdk.", "microsoft.netframework.referenceassemblies", "netstandard.library",
	"runtime.",
}

// solutionProject matches a quoted project path in a .sln, .slnx or .slnf.
var solutionProject = regexp.MustCompile(`(?i)["']([^"'\r\n]*\.[a-z]*proj)["']`)

// assemblyItem reports whether a lowercased item type references an assembly by name.
func assemblyItem(name string) bool {
	return name == "reference" || name == "frameworkreference"
}

// frameworkAssembly reports whether a Reference's Include (its first comma-separated part)
// names an assembly the framework provides.
func frameworkAssembly(include string) bool {
	n := normalizeNuGetCoordinate(include)
	return n == "system" || strings.HasPrefix(n, "system.") || slices.Contains(frameworkAssemblies, n)
}

// inertProperty reports whether a property (lowercased) is one of inertProperties or a
// restore property, which restore itself governs (parseMSBuild already rejected any it
// doesn't accept).
func inertProperty(name string) bool {
	return slices.Contains(inertProperties, name) || restoreProperty(name)
}

// attrValue returns the value of the unprefixed attribute key, matched without case.
func attrValue(attrs []xml.Attr, key string) string {
	for _, a := range attrs {
		if a.Name.Space == "" && strings.EqualFold(a.Name.Local, key) {
			return a.Value
		}
	}
	return ""
}

// simpleAssemblyName reports whether a Reference's Include (its first comma-separated part)
// is a bare assembly name, resolved from the framework, rather than a file.
func simpleAssemblyName(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, `/\;*?$@%`) {
		return false
	}
	switch strings.ToLower(filepath.Ext(s)) {
	case ".dll", ".exe", ".winmd":
		return false
	}
	return true
}

// inertOpaque reports whether a value inside the skipped subtree rooted at item (lowercased)
// could name code outside the tree or an assembly file: a parent or rooted path, a wildcard
// (which can reach the directories treeClosed does not walk), a path through a bin, obj or
// .git directory, a property, item or metadata reference, an escape (MSBuild unescapes %XX
// before it touches a path), or an assembly, native library or package file name. Compile items name source, and
// ProjectExtensions is tooling metadata; neither is opaque.
func inertOpaque(item, value string) bool {
	if item == "compile" || item == "projectextensions" {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(value))
	for _, s := range []string{"..", "*", "?", "$(", "@(", "%", ".dll", ".exe", ".winmd", ".nupkg"} {
		if strings.Contains(v, s) {
			return true
		}
	}
	for seg := range strings.FieldsFuncSeq(v, func(r rune) bool { return r == '/' || r == '\\' || r == ';' }) {
		seg = strings.TrimSpace(seg)
		if seg == "bin" || seg == "obj" || seg == ".git" || strings.Contains(seg, ".so.") {
			return true
		}
		switch filepath.Ext(seg) {
		case ".so", ".dylib", ".a":
			return true
		}
	}
	return strings.HasPrefix(v, "/") || strings.HasPrefix(v, `\`) || len(v) > 1 && v[1] == ':'
}

// completeBuild reports whether want (normalized) is provably not present in the build once
// installedCopies has settled every project on restore's own record. It is false when:
//
//   - want is a pack the SDK delivers outside the restore record (sdkDeliveredPrefixes, a
//     ".ref" targeting pack, or a project's recorded downloadDependencies);
//   - a project is not settled on a trusted project.assets.json (a current lockfile alone
//     doesn't record the SDK's downloads), or a target framework names a platform, whose
//     workload packs restore never records;
//   - a lockfile or packages.config has no project file beside it;
//   - a project read anything opaque, including an Import path holding an escape, or names
//     want as a Reference or FrameworkReference;
//   - want names one of the build's projects by file name (a project that sets PackageId or
//     AssemblyName is never settled on restore's record, so it never gets here);
//   - the tree is not closed (treeClosed).
func completeBuild(ev *evaluator, manifests []string, projects map[string]*projectDir, want string) bool {
	if strings.HasSuffix(want, ".ref") {
		return false
	}
	for _, p := range sdkDeliveredPrefixes {
		if strings.HasPrefix(want, p) {
			return false
		}
	}
	for _, m := range manifests {
		if projects[filepath.Dir(m)] == nil {
			return false
		}
	}
	for real := range ev.projects {
		if normalizeNuGetCoordinate(strings.TrimSuffix(filepath.Base(real), filepath.Ext(real))) == want {
			return false
		}
		pe := ev.eval(real)
		if pe.reason != "" || pe.opaque || slices.Contains(pe.assemblyRefs, want) {
			return false
		}
		if pe.tfms == nil || slices.ContainsFunc(pe.tfms, func(t string) bool { return strings.Contains(t, "#") }) {
			return false
		}
		ac := ev.checkAssets(pe)
		if ac.status != assetsTrusted || !ac.graph.downloadsRead || slices.Contains(ac.graph.downloads, want) {
			return false
		}
	}
	refs := make(map[string]bool)
	for real := range ev.projects {
		for _, r := range ev.eval(real).assemblyRefs {
			refs[r] = true
		}
	}
	return treeClosed(ev.rootReal, ev.projects, refs)
}

// treeClosed reports whether the tree holds nothing that brings code into the build outside
// the projects' restore: no symlink, no assembly, native library or package file, no file named
// exactly as a Reference (refs, normalized), which MSBuild resolves as a raw file name, no
// script that references packages itself, no project of another kind, no Paket, and no
// solution naming a project outside the tree's project files. Only the root's .git and each
// project's own bin and obj directories, which hold its build output and restore output, are
// not walked; no inert item may reach into them (inertOpaque).
func treeClosed(rootReal string, projects, refs map[string]bool) bool {
	output := map[string]bool{filepath.Join(rootReal, ".git"): true}
	for p := range projects {
		output[filepath.Join(filepath.Dir(p), "bin")] = true
		output[filepath.Join(filepath.Dir(p), "obj")] = true
	}
	closed := true
	err := filepath.WalkDir(rootReal, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			closed = false
			return filepath.SkipAll
		}
		if d.Type()&fs.ModeSymlink != 0 {
			closed = false
			return filepath.SkipAll
		}
		if d.IsDir() {
			if output[path] {
				return filepath.SkipDir
			}
			return nil
		}
		name := strings.ToLower(d.Name())
		ext := filepath.Ext(name)
		switch {
		case name == "paket.dependencies", name == "paket.lock", name == "paket.references":
			closed = false
		case slices.Contains([]string{".dll", ".exe", ".winmd", ".nupkg", ".so", ".dylib", ".a", ".fsx", ".csx", ".cake", ".projitems", ".shproj"}, ext):
			closed = false
		case strings.Contains(name, ".so."), refs[name]:
			closed = false
		case strings.HasSuffix(ext, "proj") && !isProjectFile(name):
			closed = false
		case ext == ".sln" || ext == ".slnx" || ext == ".slnf":
			closed = solutionCovered(path, projects)
		}
		if !closed {
			return filepath.SkipAll
		}
		return nil
	})
	return err == nil && closed
}

// solutionCovered reports whether every project a solution file names is one of projects.
func solutionCovered(path string, projects map[string]bool) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, m := range solutionProject.FindAllStringSubmatch(string(data), -1) {
		rel := filepath.FromSlash(strings.ReplaceAll(strings.ReplaceAll(m[1], `\\`, "/"), `\`, "/"))
		real, err := filepath.EvalSymlinks(filepath.Join(filepath.Dir(path), rel))
		if err != nil || !projects[real] {
			return false
		}
	}
	return true
}

// notInBuild is the partiality of a package the build does not contain: one scoped reason
// bounded to the package's own PURL, nothing run-wide.
func notInBuild(id string) plugin.Partiality {
	purl := nugetPackageURL(id)
	return plugin.Partiality{Scoped: []plugin.ScopedReason{{
		Reason:  partialReasonDependencyNotInBuild,
		Package: purl,
		Path:    strings.TrimSpace(id) + " is not present in the build",
		Targets: []string{purl},
	}}}
}

// absentFromBuild reports whether NuGet package id is provably not present in the build.
func absentFromBuild(buildDir, id string) bool {
	res, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: buildDir, Coordinate: id})
	return err == nil && res.Exhaustive && !res.Found
}
