package acquire

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
)

// RegistryConfig is the per-ecosystem registry/mirror configuration behind the Policy
// object. BaseURL is the registry root a backend maps a coordinate onto; RequireAuth marks a
// private registry for which an anonymous fetch must be refused (ErrPolicyRefused,
// missing-credential) rather than silently 401'ing into a false miss.
type RegistryConfig struct {
	BaseURL     string
	RequireAuth bool
}

// RegistryBackend maps an inventory coordinate to a fetch URL using the ecosystem's layout.
// It is deliberately THIN: it never fetches and never touches a credential (that is the
// single audited shared core in the Acquirer). ResolveURL returns ErrUnpinnedArtifact when
// the coordinate does not resolve to a single verifiable artifact.
type RegistryBackend interface {
	Ecosystem() string
	ResolveURL(ref artifactcache.Ref, reg RegistryConfig) (string, error)
}

// ecosystemOf extracts the PURL type ("npm", "nuget", "pypi", "maven") from ref.PURL
// ("pkg:npm/...").
func ecosystemOf(purl string) (string, bool) {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return "", false
	}
	eco, _, ok := strings.Cut(rest, "/")
	if !ok || eco == "" {
		return "", false
	}
	return strings.ToLower(eco), true
}

// coordinate splits "pkg:<eco>/<name>@<version>" into the (url-decoded) name and version.
// name may be a scoped npm package ("@scope/pkg"); version is whatever follows the LAST '@'.
func coordinate(purl string) (name, version string, err error) {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return "", "", fmt.Errorf("not a purl: %q", purl)
	}
	_, body, ok := strings.Cut(rest, "/")
	if !ok || body == "" {
		return "", "", fmt.Errorf("purl has no coordinate body: %q", purl)
	}
	at := strings.LastIndexByte(body, '@')
	if at <= 0 || at == len(body)-1 {
		return "", "", fmt.Errorf("purl has no @version: %q", purl)
	}
	name, err = url.PathUnescape(body[:at])
	if err != nil {
		return "", "", fmt.Errorf("purl name is not valid percent-encoding: %w", err)
	}
	version, err = url.PathUnescape(body[at+1:])
	if err != nil {
		return "", "", fmt.Errorf("purl version is not valid percent-encoding: %w", err)
	}
	return name, version, nil
}

// npmBackend resolves an npm coordinate to its tarball URL using the registry layout
// <base>/<name>/-/<unscoped>-<version>.tgz. Digest = the SRI from the lockfile
// (sha512:<base64>); precise. LANDED.
type npmBackend struct{}

// NewNPMBackend returns the npm registry backend.
func NewNPMBackend() RegistryBackend { return npmBackend{} }

func (npmBackend) Ecosystem() string { return "npm" }

func (npmBackend) ResolveURL(ref artifactcache.Ref, reg RegistryConfig) (string, error) {
	name, version, err := coordinate(ref.PURL)
	if err != nil {
		return "", &artifactcache.UnpinnedReason{PURL: ref.PURL, Detail: "npm-coordinate-unparseable"}
	}
	unscoped := name
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		unscoped = name[i+1:]
	}
	base := strings.TrimRight(reg.BaseURL, "/")
	return fmt.Sprintf("%s/%s/-/%s-%s.tgz", base, name, unscoped, version), nil
}

// nugetBackend resolves a NuGet coordinate to its flat-container URL
// <base>/<id-lower>/<ver>/<id-lower>.<ver>.nupkg. Note Artifact.Identity is the package
// FOLDER (<id>/<ver>), not the .nupkg filename — the backend derives the filename. Digest =
// sha512:<base64>; precise. LANDED.
type nugetBackend struct{}

// NewNuGetBackend returns the NuGet flat-container backend.
func NewNuGetBackend() RegistryBackend { return nugetBackend{} }

func (nugetBackend) Ecosystem() string { return "nuget" }

func (nugetBackend) ResolveURL(ref artifactcache.Ref, reg RegistryConfig) (string, error) {
	id, version, err := coordinate(ref.PURL)
	if err != nil {
		return "", &artifactcache.UnpinnedReason{PURL: ref.PURL, Detail: "nuget-coordinate-unparseable"}
	}
	idLower := strings.ToLower(id)
	verLower := strings.ToLower(version)
	base := strings.TrimRight(reg.BaseURL, "/")
	return fmt.Sprintf("%s/%s/%s/%s.%s.nupkg", base, idLower, verLower, idLower, verLower), nil
}

// pypiBackend is LANDED but ambiguous (OQ2). The Python inventory carries the first declared
// lockfile hash but NOT the target-platform wheel filename/URL, so a coordinate maps to many
// files (sdist + per-ABI wheels), each a distinct hash. Since Ref carries only PURL+Digest
// (no resolved URL), a coordinate never resolves to a single verifiable (url, digest) here:
// ResolveURL returns ErrUnpinnedArtifact. It NEVER fetches a guessed wheel (which would
// surface as a false integrity failure on a non-corrupt artifact) and never treats the
// coordinate as an empty success. The wheel-selection gap is routed to PLAN-170; until the
// inventory retains the resolved (url, digest), Python acquisition is a declared partiality.
type pypiBackend struct{}

// NewPyPIBackend returns the PyPI backend (always ErrUnpinnedArtifact until PLAN-170 lands
// the resolved artifact URL in the inventory).
func NewPyPIBackend() RegistryBackend { return pypiBackend{} }

func (pypiBackend) Ecosystem() string { return "pypi" }

func (pypiBackend) ResolveURL(ref artifactcache.Ref, _ RegistryConfig) (string, error) {
	return "", &artifactcache.UnpinnedReason{PURL: ref.PURL, Detail: "python-wheel-selection-gap"}
}

// mavenBackend is DEFERRED (OQ4). Java has no landed inventory, so DependencyArtifact.Digest
// is unpopulated for Maven, and its checksum ships fetch-time (sibling .sha1/.sha256 or Gradle
// verification-metadata.xml) — a distinct trust shape not built now. The stub declares the
// deferral as an unpinned partiality (no single verifiable (url, digest) is available);
// PLAN-140/240 pick up the fetch-time-integrity path when Java inventory lands.
type mavenBackend struct{}

// NewMavenBackend returns the deferred Maven stub.
func NewMavenBackend() RegistryBackend { return mavenBackend{} }

func (mavenBackend) Ecosystem() string { return "maven" }

func (mavenBackend) ResolveURL(ref artifactcache.Ref, _ RegistryConfig) (string, error) {
	return "", &artifactcache.UnpinnedReason{PURL: ref.PURL, Detail: "maven-inventory-deferred"}
}
