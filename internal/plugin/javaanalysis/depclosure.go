package javaanalysis

import "strings"

// depclosure.go — Maven coordinate and PURL helpers shared by the dependency readers. The
// blind-spot bound they feed is BlindSpotTargets (graph.go).

// mavenPURLNoVersion renders "pkg:maven/<group>/<artifact>" for a "group:artifact"
// coordinate.
func mavenPURLNoVersion(coordinate string) string {
	group, artifact, ok := splitCoordinate(coordinate)
	if !ok {
		return ""
	}
	return "pkg:maven/" + group + "/" + artifact
}

// CoordinateOfPURL returns the "group:artifact" coordinate and version of a Maven PURL
// ("pkg:maven/<group>/<artifact>[@version][?qualifiers]"). ok is false for any other PURL.
func CoordinateOfPURL(purl string) (coordinate, version string, ok bool) {
	const prefix = "pkg:maven/"
	if !strings.HasPrefix(purl, prefix) {
		return "", "", false
	}
	rest := purl[len(prefix):]
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		version = strings.TrimSpace(rest[i+1:])
		rest = rest[:i]
	}
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return "", "", false
	}
	group, artifact := strings.TrimSpace(rest[:slash]), strings.TrimSpace(rest[slash+1:])
	if group == "" || artifact == "" || strings.Contains(artifact, "/") {
		return "", "", false
	}
	return group + ":" + artifact, version, true
}
