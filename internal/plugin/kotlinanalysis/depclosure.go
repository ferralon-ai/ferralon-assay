package kotlinanalysis

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/depreach"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// depclosure.go — load the build's resolved dependency closure so Reachability traces from
// first-party code into the exact dependency bytecode the build resolved. The JARs are the build
// graph's (javaanalysis.RuntimeSelection): every file on a module's runtime classpath, as the
// repository's own Maven or Gradle resolved it, read only once it still has the sha256 the graph
// recorded. Without a graph nothing is loaded and the run-wide build_graph_absent reason withholds
// Searched.
//
// A coordinate the modules resolved at more than one runtime version is a scoped blind spot
// rather than a guess: loading either could trace bytes that never run.
//
// A dependency whose JAR cannot be read is a blind spot bounded by what it could reach (contract
// §4): javaanalysis.BlindSpotTargets, first-party code ("") plus every package of each module
// that resolved it.
//
// The graph's classpath is a union across modules with no launch order, so a dependency class
// whose binary name an earlier JAR already defined is a scoped duplicate_class: which copy runs
// is unknown.
//
// A dependency the graph does not list at all is never silently trusted: depreach treats any
// call into a class that is neither loaded nor platform as an unloaded_dependency hazard, so
// reaching it makes the search undetermined.

// partialReasonDuplicateClass is the scoped reason for a dependency class whose binary name a
// previously loaded JAR already defined. The engine keeps one body per name, so the shadowed
// body's edges are unseen.
const partialReasonDuplicateClass = plugin.PartialReasonRelationshipUnexpressed + ":duplicate_class"

// partialReasonRuntimeVersionAmbiguous is the scoped reason for a dependency whose runtime
// version cannot be selected: the build graph's modules resolved it at more than one runtime
// version. Loading any one candidate could trace bytes that never run, so none is loaded.
const partialReasonRuntimeVersionAmbiguous = plugin.PartialReasonRelationshipUnexpressed + ":runtime_version_ambiguous"

// depClosure is the loaded dependency bytecode plus the scoped blind spots loading it incurred.
type depClosure struct {
	classes []classfile.Class
	scoped  []plugin.ScopedReason
	// loaded maps a JAR's group:artifact:version[:classifier] to the path that was opened, for
	// evidence.
	loaded map[string]string
	// cp lists what every classpath JAR defines, opened or not; a JAR that cannot be read or
	// listed leaves it unlisted.
	cp depreach.Classpath
	// reasons are declared run-wide and mean the loaded bytes may not be the code that runs, so
	// no empty search is Searched: the build graph is absent, a build of the other tool sits
	// beside it, or a JVM launch option the lanes do not model is set
	// (javaanalysis.LaunchOptionReasons).
	reasons []string
}

// loadDependencyClosure loads every runtime JAR the build graph names. firstParty names classes
// already loaded from the build output; a dependency class with the same binary name is skipped
// (the build output is what the build packaged).
func loadDependencyClosure(buildDir string, firstParty map[string]bool, opts ...javaanalysis.Option) *depClosure {
	g := javaanalysis.BuildGraph(opts...)
	dc := &depClosure{loaded: map[string]string{}, reasons: javaanalysis.LaunchOptionReasons(buildDir, g)}
	if g == nil {
		dc.reasons = append(dc.reasons, javaanalysis.PartialReasonBuildGraphAbsent)
		return dc
	}
	dc.cp.JDK = g.RuntimeJDK()
	if javaanalysis.OtherToolBuild(g, buildDir) {
		dc.reasons = append(dc.reasons, javaanalysis.PartialReasonOtherToolBuild)
	}
	load, misses := javaanalysis.RuntimeSelection(g)
	for _, m := range misses {
		dc.cp.Unlisted = true // no JAR is listed for it
		reason := partialReasonNoDependencyArtifact
		if m.Ambiguous {
			reason = partialReasonRuntimeVersionAmbiguous
		}
		dc.scoped = append(dc.scoped, plugin.ScopedReason{
			Reason:  reason,
			Package: "pkg:maven/" + strings.Replace(m.Coordinate, ":", "/", 1),
			Path:    m.Detail,
			Targets: javaanalysis.BlindSpotTargets(g, m.Coordinate),
		})
	}

	definedBy := map[string]string{} // class binary name -> the GAV that defined it
	shadowed := map[string]bool{}    // "<kept gav>|<shadowed gav>" pairs already reported
	for _, j := range load {
		gav := j.GAV()
		blind := func(reason, path string) {
			dc.scoped = append(dc.scoped, plugin.ScopedReason{
				Reason:  reason,
				Package: j.PackageURL(),
				Path:    path,
				Targets: javaanalysis.BlindSpotTargets(g, j.Coordinate),
			})
		}
		data, ok := javaanalysis.ReadRuntimeJar(j)
		if !ok {
			dc.cp.Unlisted = true
			blind(plugin.PartialReasonToolFailure, gav+": "+filepath.Base(j.Path)+" unreadable or changed since the build resolved it")
			continue
		}
		pkgs, listed, closed := classfile.JarBytesPackages(data)
		dc.cp.Add(pkgs, listed && closed)
		if !listed {
			blind(plugin.PartialReasonToolFailure, gav)
			continue
		}
		jr, err := classfile.LoadJarBytes(data)
		if err != nil {
			blind(plugin.PartialReasonToolFailure, gav)
			continue
		}
		if len(jr.Failed) > 0 {
			// Unparsed classes are absent from the engine, so a call into one is already an
			// unloaded_dependency hazard; the scoped reason discloses the gap and bounds it.
			blind(plugin.PartialReasonToolFailure, gav+": "+jr.Failed[0])
		}
		dc.loaded[gav] = j.Path
		for _, c := range jr.Classes {
			if firstParty[c.Name] {
				continue
			}
			if prev, dup := definedBy[c.Name]; dup {
				if key := prev + "|" + gav; !shadowed[key] {
					shadowed[key] = true
					blind(partialReasonDuplicateClass, fmt.Sprintf("%s shadowed by %s: %s", gav, prev, c.Name))
				}
				continue
			}
			definedBy[c.Name] = gav
			dc.classes = append(dc.classes, c)
		}
	}
	return dc
}
