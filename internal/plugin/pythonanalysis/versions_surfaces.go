package pythonanalysis

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/scriptsurface"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// --- install surfaces ------------------------------------------------------------
//
// Version resolution reads the manifests manifestFiles discovers. Every other file under the
// build dir that names or holds a Python install surface, found by the shared walk
// (buildtree.Candidates, which enters everything but node_modules and site-packages, .git
// included), vetoes the pin unless it is one of the few surfaces read here and found to
// declare nothing (declaresNothing). Classification is by name, case-insensitively, or by
// content, so a surface this lane has no reader for vetoes by default instead of being
// listed one name at a time.

// versionSurfaces returns the manifests version resolution parses, whether any other install
// surface under root goes unread, whether a script surface may install a package no manifest
// or lock read here names (scriptsurface.Veto.Withheld), every pip install -r the script
// surfaces run, and the distributions an allowed self-upgrade installs at a version nothing
// read here records (pipSelfUpgrade), which a caller withholds as it would every pin.
func versionSurfaces(root string) (manifests []string, unread, scriptWithheld bool, installs pipInstalls, tooling map[string]bool) {
	manifests, walked := manifestFiles(root)
	unread = !walked
	discovered := make(map[string]bool, len(manifests))
	for _, m := range manifests {
		discovered[m] = true
	}
	// A requirement file a pyproject.toml or setup.cfg names in a file directive is read by
	// that manifest's reader; when the manifest cannot read it, the manifest fails instead.
	via := map[string]bool{}
	for _, m := range manifests {
		if base := filepath.Base(m); base != "pyproject.toml" && base != "setup.cfg" {
			continue
		}
		if decls, ok := manifestDecls(m); ok {
			for _, f := range decls.files {
				via[filepath.Clean(f)] = true
			}
		}
	}
	read := func(path string) bool {
		if wideMarked(path) {
			return false
		}
		return discovered[path] || via[filepath.Clean(path)] || declaresNothing(path)
	}
	installs, tooling = pipInstalls{}, map[string]bool{}
	veto := scriptsurface.New(root, read, newScriptSpec(installs, tooling))
	for _, c := range buildtree.Candidates(root, veto.Classify(pyInstallSurface), veto.FullyRead) {
		if !c.FullyRead {
			unread = true
		}
	}
	scriptWithheld = veto.Withheld()
	return manifests, unread || scriptWithheld, scriptWithheld, installs, tooling
}

// wideMarked reports whether the file at path starts with a UTF-16 or UTF-32 byte-order mark.
// pip decodes such a file, but the readers here take its bytes as UTF-8, so what they find in
// it is not what it declares.
func wideMarked(path string) bool {
	data, err := readRegular(path)
	if err != nil {
		return false
	}
	return bytes.HasPrefix(data, []byte{0xFF, 0xFE}) || bytes.HasPrefix(data, []byte{0xFE, 0xFF}) ||
		bytes.HasPrefix(data, []byte{0, 0, 0xFE, 0xFF})
}

// pyInstallSurface reports whether the file at path, with its buildtree.Head (nil when binary,
// empty or not a regular file, and then judged through buildtree.NULHeadMatch), names or holds
// a Python install surface, and the rule that matched. Every file ManifestCandidates classifies
// (pyCandidate) is one too.
func pyInstallSurface(path string, head []byte) (string, bool) {
	if why, ok := pySurfaceName(path); ok {
		return why, true
	}
	if why, ok := pySurfaceContent(path, head); ok {
		return why, true
	}
	return pyCandidate(path, head)
}

// pyForeignLocks are lowercased *.lock and *.lockb names other ecosystems own; every other one
// is a Python install surface.
var pyForeignLocks = map[string]bool{
	"cargo.lock": true, "gemfile.lock": true, "composer.lock": true, "yarn.lock": true,
	"bun.lock": true, "bun.lockb": true, "deno.lock": true, "flake.lock": true, "podfile.lock": true,
	"mix.lock": true, "pubspec.lock": true, "conan.lock": true, "paket.lock": true,
	"packages.lock": true, "shard.lock": true, "renv.lock": true, "elm.lock": true, "esy.lock": true,
}

func pySurfaceName(path string) (string, bool) {
	if inner, ok := buildtree.TemplateInner(path); ok {
		if why, ok := pySurfaceName(inner); ok {
			return "templated " + why, true
		}
	}
	lower := strings.ToLower(filepath.Base(path))
	ext := filepath.Ext(lower)
	dir := strings.ToLower(filepath.Base(filepath.Dir(path)))
	switch {
	case isManifest(lower):
		return "manifest name", true
	case strings.HasPrefix(lower, "pipfile"), lower == "pixi.toml", strings.HasPrefix(lower, "pylock.") && ext == ".toml",
		lower == "tox.ini", lower == "noxfile.py":
		return "install surface name", true
	case isCondaEnvName(lower), strings.HasPrefix(lower, "conda-lock") && (ext == ".yml" || ext == ".yaml"):
		return "conda name", true
	case ext == ".in" && lower != "manifest.in":
		return "requirements input name", true
	case (ext == ".txt" || ext == ".lock" || ext == ".pip") &&
		(strings.Contains(lower, "requirement") || strings.Contains(lower, "constraint") || strings.HasPrefix(dir, "requirements")):
		return "requirements file name", true
	case (ext == ".lock" || ext == ".lockb") && !pyForeignLocks[lower]:
		return "lockfile name", true
	}
	return "", false
}

// isCondaEnvName reports whether a lowercased file name is a conda environment file's.
func isCondaEnvName(lower string) bool {
	ext := filepath.Ext(lower)
	return (ext == ".yml" || ext == ".yaml") && !strings.HasPrefix(lower, "conda-lock") &&
		(strings.HasPrefix(lower, "environment") || strings.HasPrefix(lower, "conda"))
}

// pySurfaceDocExts are formats no Python installer reads its configuration from, so a TOML or
// YAML snippet quoted in one is documentation. A requirements file can have any name, so the
// requirement-line rule still applies to them.
var pySurfaceDocExts = map[string]bool{
	".md": true, ".markdown": true, ".rst": true, ".adoc": true, ".html": true, ".htm": true,
	".ipynb": true, ".py": true, ".pyi": true,
}

// pySurfaceTOMLHeaders are tables only a Python project, lock or environment declares.
var pySurfaceTOMLHeaders = []string{
	"[project]", "[build-system]", "[dependency-groups]", "[pypi-dependencies]", "[packages]", "[dev-packages]",
	"[tool.poetry", "[tool.pdm", "[tool.uv", "[tool.hatch", "[tool.setuptools", "[tool.pixi",
}

// pySurfaceLockMarkers are strings a Python lock's [[package]] entries carry.
var pySurfaceLockMarkers = []string{"requires-python", "requires_python", "python-versions", "pythonhosted.org", "pypi.org"}

func pySurfaceContent(path string, head []byte) (string, bool) {
	if head == nil {
		return buildtree.NULHeadMatch(path, pySurfaceContent)
	}
	src := string(head)
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".py" {
		if (strings.Contains(src, "setup(") || strings.Contains(src, "setuptools")) && strings.Contains(src, "_require") {
			return "setup() call content", true
		}
		return "", false
	}
	if requirementLinesContent(src) {
		return "requirement lines", true
	}
	if pySurfaceDocExts[ext] {
		return "", false
	}
	var tomlTable, lockPackage, condaDeps, condaPip bool
	for _, raw := range strings.Split(src, "\n") {
		l := strings.TrimRight(raw, "\r")
		t := strings.TrimSpace(l)
		for _, h := range pySurfaceTOMLHeaders {
			if t == h || strings.HasPrefix(h, "[tool.") && strings.HasPrefix(t, h) && len(t) > len(h) && (t[len(h)] == ']' || t[len(h)] == '.') {
				tomlTable = true
			}
		}
		lockPackage = lockPackage || t == "[[package]]"
		condaDeps = condaDeps || strings.HasPrefix(l, "dependencies:")
		condaPip = condaPip || t == "- pip:" || strings.HasPrefix(l, "channels:")
	}
	switch {
	case tomlTable:
		return "Python TOML table", true
	case lockPackage && !strings.Contains(src, "crates.io-index") && !strings.Contains(src, "@generated by Cargo"):
		for _, m := range pySurfaceLockMarkers {
			if strings.Contains(src, m) {
				return "Python lock content", true
			}
		}
	case condaDeps && condaPip:
		return "conda environment content", true
	}
	return "", false
}

// requirementLineRE is a PEP 508 requirement: a project name, optional extras, then an optional
// version clause or direct reference and an optional marker.
var requirementLineRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\s*(\[[^\]]*\])?\s*(\(?\s*(===|==|~=|!=|<=|>=|<|>)\s*[^\s,;()]+(\s*,\s*(===|==|~=|!=|<=|>=|<|>)\s*[^\s,;()]+)*\s*\)?|@\s*\S+)?\s*(;.*)?$`)

// requirementLinesContent reports whether src reads as a pip requirements file: every
// non-comment logical line is a PEP 508 requirement or a pip option, and at least one carries
// a version clause, a direct reference or an option, so a list of bare words (a word list, a
// VERSION file) is not taken for one.
func requirementLinesContent(src string) bool {
	strong := false
	for _, raw := range joinContinuations(src) {
		line := strings.TrimSpace(stripReqCommentSafe(raw))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "-") {
			if len(line) < 2 || !(line[1] == '-' || line[1] >= 'a' && line[1] <= 'z' || line[1] >= 'A' && line[1] <= 'Z') {
				return false
			}
			strong = true
			continue
		}
		if i := strings.Index(line, " --"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		m := requirementLineRE.FindStringSubmatch(line)
		if m == nil {
			return false
		}
		if m[2] != "" {
			strong = true
		}
	}
	return strong
}

// declaresNothing reports whether a surface version resolution does not parse was read here
// and found to declare no dependency: a Pipfile with no package category, a conda
// environment that installs only the interpreter and pip, tox.ini with no deps key, or a
// noxfile that never installs. Every other surface, and any of these that cannot be read,
// declares something.
func declaresNothing(path string) bool {
	data, err := readRegular(path)
	if err != nil {
		return false
	}
	lower := strings.ToLower(filepath.Base(path))
	switch {
	case strings.HasPrefix(lower, "pipfile") && !strings.HasSuffix(lower, ".lock"):
		return !pipfileDeclares(data)
	case isCondaEnvName(lower):
		return !condaDeclares(data)
	case lower == "tox.ini":
		return !toxDeclares(string(data))
	case lower == "noxfile.py":
		return !bytes.Contains(data, []byte(".install("))
	}
	return false
}

// toxDeclares reports whether a tox.ini sets deps in any section.
func toxDeclares(src string) bool {
	for _, line := range strings.Split(src, "\n") {
		if k, _, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "deps" {
			return true
		}
	}
	return false
}

// --- installed copies -------------------------------------------------------------

// installedCopies reads the distributions installed in every site-packages directory under
// root, which the shared walk does not enter: each *.dist-info or *.egg-info names one by its
// metadata's Name and Version. A symlink, whether the site-packages directory itself or an entry
// in it, is followed when it resolves inside root, whatever its target is named, and makes ok
// false when it leaves root or does not resolve. Each site-packages directory is read once at
// its real path, and so is each metadata file: a link can make one directory both a
// site-packages and a metadata entry, and each role reads it. A copy whose metadata cannot be
// read makes ok false.
func installedCopies(root string) (copies []plugin.ResolvedDependency, origins []manifestOrigin, ok bool) {
	ok = true
	realRoot, rootErr := filepath.EvalSymlinks(root)
	escapes := func(path string) bool { return rootErr != nil || !buildtree.Inside(realRoot, path) }
	// once reports whether path's real path is seen for the first time in the role whose set
	// is seen. A path that does not resolve makes ok false.
	dirSeen, metaSeen := map[string]bool{}, map[string]bool{}
	once := func(seen map[string]bool, path string) bool {
		real, err := filepath.EvalSymlinks(path)
		if err != nil {
			ok = false
			return false
		}
		if seen[real] {
			return false
		}
		seen[real] = true
		return true
	}
	_ = buildtree.Walk(root, func(e buildtree.Entry, err error) error {
		if err != nil || e.D.Name() != "site-packages" || !e.Skipped && !e.Symlink {
			return nil
		}
		if e.Symlink && e.Escapes {
			ok = false
			return nil
		}
		if !once(dirSeen, e.Path) {
			return nil
		}
		ents, rerr := os.ReadDir(e.Path)
		if rerr != nil {
			ok = false
			return nil
		}
		for _, d := range ents {
			name := d.Name()
			p := filepath.Join(e.Path, name)
			isDir := d.IsDir()
			if d.Type()&fs.ModeSymlink != 0 {
				if escapes(p) {
					ok = false
					continue
				}
				fi, serr := os.Stat(p)
				if serr != nil {
					ok = false
					continue
				}
				isDir = fi.IsDir()
			}
			var meta string
			switch {
			case strings.HasSuffix(name, ".dist-info") && isDir:
				meta = filepath.Join(p, "METADATA")
			case strings.HasSuffix(name, ".egg-info") && isDir:
				meta = filepath.Join(p, "PKG-INFO")
			case strings.HasSuffix(name, ".egg-info"):
				meta = p
			default:
				continue
			}
			if !once(metaSeen, meta) {
				continue
			}
			dist, version, mok := readDistMetadata(meta)
			if !mok {
				ok = false
				continue
			}
			copies = append(copies, pyResolved(dist, version, true, "site-packages"))
			origins = append(origins, manifestOrigin{dir: e.Path})
		}
		return nil
	})
	return copies, origins, ok
}

// readDistMetadata returns the Name and Version headers of a core-metadata file. ok is false
// when it cannot be read or names no project.
func readDistMetadata(path string) (name, version string, ok bool) {
	data, err := readRegular(path)
	if err != nil {
		return "", "", false
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			break
		}
		if v, found := strings.CutPrefix(line, "Name:"); found {
			name = strings.TrimSpace(v)
		} else if v, found := strings.CutPrefix(line, "Version:"); found {
			version = strings.TrimSpace(v)
		}
	}
	return name, version, name != ""
}
