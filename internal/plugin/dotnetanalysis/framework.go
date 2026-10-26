package dotnetanalysis

// framework.go — which assemblies the IL engine may treat as the shared framework.
//
// The decision reads only what the build recorded, never the machine's installed runtime:
//
//   - the first-party build must bind to a project.assets.json target for .NET Core 3.1 or
//     later, where Microsoft.NETCore.App is the platform every program runs on;
//   - the candidate names are the embedded Microsoft.NETCore.App reference list (the union
//     of FrameworkList.xml across 3.1 through 10.0; a union is safe because a program can
//     only reference an assembly its target framework or one of its packages supplies);
//   - a name some restored package supplies itself is not framework: that package's bytes
//     are either loaded (and read) or a declared miss, never a trusted leaf;
//   - a name the loaded set supplies is not framework either.
//
// Microsoft.CSharp and Microsoft.VisualBasic ship in Microsoft.NETCore.App but are the
// dynamic binder and late binding, so they stay out. Microsoft.AspNetCore.App and the
// Microsoft.Extensions.* hosting and dependency-injection assemblies are not in the list at
// all: they construct and invoke application types from configuration, so calls into them
// stay hazards. Those hazards also cover the entry points the IL search does not root
// (ingress_il.go): middleware a host activates by type (UseMiddleware's Invoke/InvokeAsync),
// Startup.Configure and ConfigureServices, SignalR hubs, gRPC services, views compiled into
// a separate assembly, lambdas held in generic closure classes, and a controller whose base
// is unloaded and which has neither the name suffix nor [Controller]. A hosted Main stays
// undetermined only because its call into the host is a hazard; making these assemblies
// framework leaves without first rooting those shapes turns each into a false
// not_exploitable (TestReachability_ASPNetUnrootedEntriesRelyOnHostingHazard).
//
// Five assemblies appear in both Microsoft.NETCore.App and Microsoft.AspNetCore.App
// (Microsoft.Win32.Registry, System.IO.Pipelines, System.Security.AccessControl,
// System.Security.Cryptography.Cng, System.Security.Principal.Windows); they are core
// platform libraries and stay framework.

import (
	_ "embed"
	"strconv"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
)

//go:embed frameworklist/microsoft.netcore.app.txt
var netCoreAppList string

// frameworkExcluded are Microsoft.NETCore.App assemblies whose members bind at run time.
var frameworkExcluded = map[string]bool{
	"microsoft.csharp":           true,
	"microsoft.visualbasic":      true,
	"microsoft.visualbasic.core": true,
}

// netCoreAppNames parses the embedded list into lower-cased names.
func netCoreAppNames() map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(netCoreAppList, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[strings.ToLower(line)] = true
	}
	return out
}

// frameworkNames returns the assembly names the engine may treat as shared framework for
// this build, or nil when the model does not apply (no bound netcoreapp >= 3.1 target, or
// no restore output to say what the packages supply).
func frameworkNames(build firstPartyBuild, locator *assembly.AssetsLocator, loaded []*assembly.Assembly) map[string]bool {
	if locator == nil || !netCoreAppAtLeast31(build.target) {
		return nil
	}
	names := netCoreAppNames()
	for n := range frameworkExcluded {
		delete(names, n)
	}
	for _, n := range locator.PackageAssemblyNames(build.target) {
		delete(names, strings.ToLower(n))
	}
	for _, a := range loaded {
		if a != nil {
			delete(names, strings.ToLower(a.Name))
		}
	}
	return names
}

// netCoreAppAtLeast31 reports whether an assets target key names .NET Core 3.1 or later
// (netcoreapp3.1, net5.0, net8.0-windows, ...).
func netCoreAppAtLeast31(target string) bool {
	tfm, _, _ := strings.Cut(target, "/") // a RID-specific key never binds, but be safe
	c, ok := canonicalTFM(tfm)
	if !ok {
		return false
	}
	ident, ver, _ := strings.Cut(c, "|")
	if ident != "netcoreapp" {
		return false
	}
	ver, _, _ = strings.Cut(ver, "#")
	majorS, rest, _ := strings.Cut(ver, ".")
	minorS, _, _ := strings.Cut(rest, ".")
	major, err1 := strconv.Atoi(majorS) // canonicalTFM admits digits only
	minor, err2 := strconv.Atoi(minorS)
	return err1 == nil && err2 == nil && (major > 3 || major == 3 && minor >= 1)
}

// frameworkSuppliedMiss reports whether a spanning-set miss is a package the shared
// framework supplies at run time: restore recorded it as "_._" over compile dlls whose
// every name is a framework assembly here. Such a package's code is the framework's, which
// the model already covers, so it is not a missing dependency.
func frameworkSuppliedMiss(m assembly.DepMiss, locator *assembly.AssetsLocator, fw map[string]bool) bool {
	if fw == nil || m.Reason != assembly.MissFrameworkSupplied {
		return false
	}
	names := locator.FrameworkCompileNames(m.Dep.Target, m.Dep.PkgKey)
	if len(names) == 0 {
		return false
	}
	for _, n := range names {
		if !fw[strings.ToLower(n)] {
			return false
		}
	}
	return true
}
