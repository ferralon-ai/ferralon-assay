package dotnetanalysis

import (
	"bytes"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
)

// legacyProjectDoc is the top level of a project file, read only to tell a legacy
// packages.config project from an SDK-style one and to check it against the classic template.
type legacyProjectDoc struct {
	SDK      string `xml:"Sdk,attr"`
	Children []struct {
		XMLName xml.Name
		SDK     string `xml:"Sdk,attr"`
		Project string `xml:"Project,attr"`
		Elems   []struct {
			XMLName xml.Name
		} `xml:",any"`
	} `xml:",any"`
}

// readLegacyProject reads and decodes the project file at path; ok is false when it can't be
// read as a regular file inside the tree or doesn't decode.
func readLegacyProject(rootReal, path string) (legacyProjectDoc, []byte, bool) {
	data, _, st := readInput(rootReal, path)
	if st != inputRead {
		return legacyProjectDoc{}, nil, false
	}
	var proj legacyProjectDoc
	if err := xml.NewDecoder(bytes.NewReader(data)).Decode(&proj); err != nil {
		return legacyProjectDoc{}, nil, false
	}
	return proj, data, true
}

// packagesConfigGoverns reports whether every project file in files restores from the
// packages.config beside it: a legacy project, with no SDK and no PackageReference anywhere in
// the file. NuGet ignores packages.config for an SDK-style project or one that uses
// PackageReference. A project that can't be read doesn't govern; the evaluator then reports it.
func packagesConfigGoverns(rootReal string, files []string) bool {
	for _, f := range files {
		proj, data, ok := readLegacyProject(rootReal, f)
		if !ok || proj.SDK != "" || bytes.Contains(bytes.ToLower(data), []byte("packagereference")) {
			return false
		}
		for _, c := range proj.Children {
			if c.SDK != "" || strings.EqualFold(c.XMLName.Local, "Sdk") {
				return false
			}
		}
	}
	return true
}

// stockLegacyImports lists the imports a legacy project template carries, lowercased with
// backslash separators. Each is a file MSBuild ships, which adds no PackageReference.
var stockLegacyImports = map[string]bool{
	`$(msbuildextensionspath)\$(msbuildtoolsversion)\microsoft.common.props`: true,
	`$(msbuildtoolspath)\microsoft.csharp.targets`:                           true,
	`$(msbuildbinpath)\microsoft.csharp.targets`:                             true,
	`$(msbuildtoolspath)\microsoft.visualbasic.targets`:                      true,
	`$(msbuildbinpath)\microsoft.visualbasic.targets`:                        true,
}

// legacyTemplateOnly reports whether the project at path is built only from what the classic
// project template writes: every <Import> is one MSBuild ships (stockLegacyImports), every
// property it sets is one those imports read without importing anything (legacyInertProperty),
// and its other top-level elements are ItemGroup and ProjectExtensions. The stock imports pull
// in any file a property such as CustomAfterMicrosoftCommonTargets names, and a redefined
// MSBuildExtensionsPath swaps the stock files for others; any such file could add a
// PackageReference, and then NuGet ignores packages.config. A project that can't be read
// doesn't count.
func legacyTemplateOnly(rootReal, path string) bool {
	proj, _, ok := readLegacyProject(rootReal, path)
	if !ok {
		return false
	}
	for _, c := range proj.Children {
		switch strings.ToLower(c.XMLName.Local) {
		case "import":
			if !stockLegacyImports[strings.ToLower(strings.ReplaceAll(strings.TrimSpace(c.Project), "/", `\`))] {
				return false
			}
		case "propertygroup":
			for _, prop := range c.Elems {
				if !legacyInertProperty[strings.ToLower(prop.XMLName.Local)] {
					return false
				}
			}
		case "itemgroup", "projectextensions":
		default:
			return false
		}
	}
	return true
}

// legacyInertProperty lists, lowercased, the properties the classic project template sets. The
// stock imports read each of them, but none names a file to import or a path to import from.
var legacyInertProperty = map[string]bool{
	"configuration": true, "platform": true, "projectguid": true, "projecttypeguids": true,
	"outputtype": true, "appdesignerfolder": true, "rootnamespace": true, "assemblyname": true,
	"targetframeworkversion": true, "targetframeworkprofile": true,
	"filealignment": true, "deterministic": true, "debugsymbols": true, "debugtype": true,
	"optimize": true, "outputpath": true, "defineconstants": true, "errorreport": true,
	"warninglevel": true, "prefer32bit": true, "platformtarget": true, "autogeneratebindingredirects": true,
	"productversion": true, "schemaversion": true, "startupobject": true, "applicationicon": true,
	"langversion": true, "treatwarningsaserrors": true, "nowarn": true, "documentationfile": true,
	"signassembly": true, "assemblyoriginatorkeyfile": true, "allowunsafeblocks": true,
	"nugetpackageimportstamp": true, "mytype": true, "optionexplicit": true, "optioncompare": true,
	"optionstrict": true, "optioninfer": true,
}

// implicitImport reports whether MSBuild imports, or reads arguments from, a file this reader
// doesn't model when it evaluates the project at path: a Directory.Build.props/.targets/.rsp or
// Directory.Packages.props in the project's directory or any ancestor, the project's .user
// file, or a <project>.*.props/.targets under its obj directory. imports caches the
// per-directory answer for the Directory files; a directory that can't be listed counts as one
// that holds them.
func implicitImport(path string, imports map[string]bool) bool {
	base := filepath.Base(path)
	if _, err := os.Lstat(path + ".user"); err == nil || !os.IsNotExist(err) {
		return true
	}
	entries, err := os.ReadDir(filepath.Join(filepath.Dir(path), "obj"))
	if err != nil && !os.IsNotExist(err) {
		return true
	}
	for _, e := range entries {
		n := strings.ToLower(e.Name())
		if strings.HasPrefix(n, strings.ToLower(base)+".") && (strings.HasSuffix(n, ".props") || strings.HasSuffix(n, ".targets")) {
			return true
		}
	}
	for dir := filepath.Dir(path); ; {
		held, ok := imports[dir]
		if !ok {
			held = directoryImports(dir)
			imports[dir] = held
		}
		if held {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// directoryImports reports whether dir holds a file MSBuild picks up from every project at or
// below it, matched without regard to case, or can't be listed.
func directoryImports(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return !os.IsNotExist(err)
	}
	for _, e := range entries {
		for _, name := range []string{"Directory.Build.props", "Directory.Build.targets", "Directory.Build.rsp", "Directory.Packages.props"} {
			if strings.EqualFold(e.Name(), name) {
				return true
			}
		}
	}
	return false
}
