// manifest.go — the shared ecosystem→manifest-file mapping.
//
// A dependency finding carries no source location: the Report models the resolved
// package, not the line that declares it. The conventional manifest file for the
// package's ecosystem (Go → go.mod, npm → package.json, …) is therefore the honest,
// deterministic file to anchor a finding to. Both the SARIF projection (one location
// per result, required by GitHub code scanning) and the Tier-0 GitHub annotation
// surface (::warning file=…::) consume this single source of truth so the anchor is
// consistent across artifacts.
package report

import "strings"

// ManifestForEcosystem maps an OSV/PURL ecosystem name to its conventional manifest
// file. The match is case-insensitive. It returns "" when the ecosystem is unknown,
// leaving the caller to decide on a fallback (the SARIF projection substitutes a
// non-empty sentinel; the annotation surface omits the file= property).
func ManifestForEcosystem(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "go":
		return "go.mod"
	case "npm":
		return "package.json"
	case "maven":
		return "pom.xml"
	case "pypi":
		return "requirements.txt"
	case "cargo":
		return "Cargo.toml"
	case "rubygems":
		return "Gemfile"
	default:
		return ""
	}
}
