package dotnetanalysis

// absent.go — proving a NuGet package is not present in the build. The claim is made only
// when this lane positively saw every way a package can reach the build and none of them
// carries it: every project's installed set is restore's own record (a trusted
// project.assets.json or a current packages.lock.json), every MSBuild file read is modeled
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

// referenceMetadata is the metadata a Reference or FrameworkReference may carry. A HintPath,
// or anything else, is opaque.
var referenceMetadata = []string{"specificversion", "private", "requiredtargetframework", "embedinteroptypes", "aliases"}

// sdkDeliveredPrefixes name the packs the SDK downloads without recording them as a package
// restore installs (shared-framework, runtime, host and AOT packs). Their absence from the
// restore record proves nothing.
var sdkDeliveredPrefixes = []string{
	"microsoft.netcore.app", "microsoft.aspnetcore.app", "microsoft.windowsdesktop.app",
	"microsoft.dotnet.ilcompiler", "runtime.",
}

// solutionProject matches a quoted project path in a .sln, .slnx or .slnf.
var solutionProject = regexp.MustCompile(`(?i)["']([^"'\r\n]*\.[a-z]*proj)["']`)

// assemblyItem reports whether a lowercased item type references an assembly by name.
func assemblyItem(name string) bool {
	return name == "reference" || name == "frameworkreference"
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
// could name code outside the tree or an assembly file: a parent or rooted path, a property,
// item or metadata reference, or an assembly or package file name. Compile items name
// source, and ProjectExtensions is tooling metadata; neither is opaque.
func inertOpaque(item, value string) bool {
	if item == "compile" || item == "projectextensions" {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(value))
	for _, s := range []string{"..", "$(", "@(", "%(", ".dll", ".exe", ".winmd", ".nupkg"} {
		if strings.Contains(v, s) {
			return true
		}
	}
	return strings.HasPrefix(v, "/") || strings.HasPrefix(v, `\`) || len(v) > 1 && v[1] == ':'
}

// completeBuild reports whether want (normalized) is provably not present in the build once
// installedCopies has settled every project on restore's own record. It is false when:
//
//   - want is a pack the SDK delivers outside the restore record (sdkDeliveredPrefixes);
//   - a lockfile or packages.config has no project file beside it;
//   - a project read anything opaque, or names want as a Reference or FrameworkReference;
//   - want names one of the build's projects by file name (a project that sets PackageId or
//     AssemblyName is never settled on restore's record, so it never gets here);
//   - the tree is not closed (treeClosed).
func completeBuild(ev *evaluator, manifests []string, projects map[string]*projectDir, want string) bool {
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
	}
	return treeClosed(ev.rootReal, ev.projects)
}

// treeClosed reports whether the tree holds nothing that brings code into the build outside
// the projects' restore: no symlink, no assembly or package file, no script that references
// packages itself, no project of another kind, no Paket, and no solution naming a project
// outside the tree's project files. Directories skipDir skips hold build output and restored
// packages.
func treeClosed(rootReal string, projects map[string]bool) bool {
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
			if path != rootReal && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		name := strings.ToLower(d.Name())
		ext := filepath.Ext(name)
		switch {
		case name == "paket.dependencies", name == "paket.lock", name == "paket.references":
			closed = false
		case slices.Contains([]string{".dll", ".exe", ".winmd", ".nupkg", ".fsx", ".csx", ".cake", ".projitems", ".shproj"}, ext):
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
