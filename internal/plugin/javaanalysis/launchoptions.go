package javaanalysis

// launchoptions.go — the JVM launch options a checkout can set, for the JVM reachability lanes.
// A launch option can run code no call graph shows before main: an agent, a system class
// loader, a security manager, a logging config class, a provider the JDK looks up by property,
// a classpath entry. The lanes model only an allowlist of options known not to load or select
// code. Every file in the checkout but the artifacts of the build's own Maven local repository
// is scanned for launch-option tokens; each occurrence is either classified inert, accounted
// for by a reader that can see its whole value, or it withholds Searched. Options that only the
// deploy environment sets (platform config vars, another repository's entrypoint, an env file
// outside the checkout) are residue.

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const (
	// PartialReasonLaunchAgent: a launch surface loads a Java agent (-javaagent, -agentlib,
	// -agentpath, -Xrun, a JAR's Launcher-Agent-Class) or extends the boot classpath.
	PartialReasonLaunchAgent = plugin.PartialReasonRelationshipUnexpressed + ":launch_jvm_agent"
	// PartialReasonLaunchOption: a launch surface sets a JVM option outside the modeled
	// allowlist, names options in a form that cannot be read, or cannot itself be read.
	PartialReasonLaunchOption = plugin.PartialReasonRelationshipUnexpressed + ":launch_jvm_option"
)

// LaunchOptionReasons scans every file under buildDir and returns the reasons its launch-option
// tokens declare, sorted: none when every occurrence is accounted for. node_modules and
// site-packages are skipped, and so are the artifact files of a local repository inside buildDir
// that g's build resolved its dependencies from (launchScan.repoArtifact); without g, or when
// none of its artifact files lies inside buildDir, nothing else is. A file or directory that
// cannot be read, and a symlink that dangles, escapes buildDir, or leads into a skipped
// directory, withholds Searched. A -jar of the build's own artifact (ownJarOperand) withholds it
// only when the build can change what that JAR runs (jarHazards).
func LaunchOptionReasons(buildDir string, g *buildgraph.Graph) []string {
	s := &launchScan{reasons: map[string]bool{}}
	s.walk(buildDir, buildgraph.LocalRepositories(g))
	s.settleOwnJars(g)
	out := make([]string, 0, len(s.reasons))
	for r := range s.reasons {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// checkoutDefines reports whether any file the LaunchOptionReasons walk reads with no local
// repository left out sets one of keys as a system property on a command line (-D<key> or
// --define <key>, with or without a value), as Maven's -D does for a POM property. A file it
// cannot read counts as setting one.
func checkoutDefines(buildDir string, keys map[string]bool) bool {
	alts := make([]string, 0, len(keys))
	for k := range keys {
		alts = append(alts, regexp.QuoteMeta(k))
	}
	sort.Strings(alts)
	re, err := regexp.Compile(`(?:-D|--define(?:=|\s+))\s*["']?(?:` + strings.Join(alts, "|") + `)(?:[^A-Za-z0-9_.\-]|$)`)
	if err != nil {
		return true
	}
	s := &launchScan{reasons: map[string]bool{}, defines: re}
	s.walk(buildDir, nil)
	return s.defined || s.unread
}

func (s *launchScan) define(data []byte) {
	if s.defines.Match(data) {
		s.defined = true
	}
}

// launchSkipDirs hold another ecosystem's installed packages, owned by the JS and Python lanes.
var launchSkipDirs = map[string]bool{"node_modules": true, "site-packages": true}

type launchScan struct {
	reasons map[string]bool
	// defines, when set, switches the scan to looking only for -D settings of given keys.
	defines *regexp.Regexp
	defined bool // a -D the defines pattern matched
	unread  bool // a file or directory could not be read
	// repos are the real paths of the build's local repositories inside the walked root.
	repos []string
	// ownJar: a -jar launch named this build's own artifact (ownJarOperand). ownJars are the
	// launches settleOwnJars checks against the build's modules.
	ownJar  bool
	ownJars []ownJarRef
	// jarHazard: the build can give its JAR a manifest or loader that changes what a -jar
	// launch runs (jarManifestHazard, jarLoaderHazard).
	jarHazard bool
	// copyInto names the tools ("maven", "gradle") whose build files copy into the output
	// directory a -jar glob matches in (jarCopyHazards), so the glob can match a JAR the build
	// does not produce.
	copyInto map[string]bool
	// finalNames are the literal <finalName> values in the tree's POMs, keyed by the POM's
	// directory.
	finalNames map[string][]string
	// argsKey: a file in the tree sets a container's args, which a container passes after the
	// command it runs. cmdFiles holds, per file, whether it sets a container command or
	// entrypoint (containerKeys); a container passes its command after its entrypoint.
	argsKey  bool
	cmdFiles map[string]uint8
}

const (
	keyCommand uint8 = 1 << iota
	keyEntrypoint
)

// ownJarRef is a -jar operand ownJarOperand took for the build's own artifact. tool is the tool
// whose output directory the path names, with dir the module directory before it; tool is ""
// for a bare artifact file name. name is the file name, "" for a POM's own artifact property.
//
// file is the file holding the launch; appendable marks a launch a container can pass more
// arguments to than the line shows: a Dockerfile ENTRYPOINT, or a launch in a file that sets a
// container command or entrypoint.
type ownJarRef struct {
	tool, dir, name string
	file            string
	appendable      bool
}

func (s *launchScan) unreadable() { s.reasons[PartialReasonLaunchOption] = true }
func (s *launchScan) readFail()   { s.unread = true; s.unreadable() }
func (s *launchScan) agent()      { s.reasons[PartialReasonLaunchAgent] = true }

// walk visits every file under root at its real path. A symlinked directory is walked at its
// real path when that lies inside root's real path and outside a skipped directory; links are
// never followed by the directory walk itself, and each link target directory is walked at
// most once, so the walk terminates on cycles. repos are the local repositories the build
// resolved its artifacts from; those strictly inside root have their artifacts skipped.
func (s *launchScan) walk(root string, repos []string) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		s.readFail()
		return
	}
	for _, r := range repos {
		// A relative path, which the tool never resolves, is inside nothing (strictlyInside).
		if real, err := filepath.EvalSymlinks(r); err == nil && strictlyInside(realRoot, real) {
			s.repos = append(s.repos, real)
		}
	}
	walked := map[string]bool{realRoot: true}
	s.walkDir(realRoot, realRoot, walked)
}

func (s *launchScan) walkDir(realRoot, dir string, walked map[string]bool) {
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			s.readFail()
			return nil
		}
		rel, _ := filepath.Rel(realRoot, path)
		switch {
		case d.IsDir():
			if path != dir && launchSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
		case d.Type()&fs.ModeSymlink != 0:
			s.link(realRoot, path, rel, walked)
		case d.Type().IsRegular():
			if !s.repoArtifact(path) {
				s.file(path, filepath.ToSlash(rel))
			}
		}
		return nil
	})
	if err != nil {
		s.readFail()
	}
}

// link resolves one symlink: an in-root directory is walked at its real path, an in-root file
// is read through the link, and anything else withholds Searched.
func (s *launchScan) link(realRoot, path, rel string, walked map[string]bool) {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		s.readFail() // dangling, or a component cannot be read
		return
	}
	trel, err := filepath.Rel(realRoot, target)
	if err != nil || trel == ".." || strings.HasPrefix(trel, ".."+string(filepath.Separator)) {
		s.readFail() // escapes the checkout
		return
	}
	for _, part := range strings.Split(trel, string(filepath.Separator)) {
		if launchSkipDirs[part] {
			s.readFail()
			return
		}
	}
	fi, err := os.Stat(target)
	if err != nil {
		s.readFail()
		return
	}
	switch {
	case fi.IsDir():
		if !walked[target] {
			walked[target] = true
			s.walkDir(realRoot, target, walked)
		}
	case fi.Mode().IsRegular():
		if !s.repoArtifact(path) {
			s.file(path, filepath.ToSlash(rel))
		}
	}
}

// repoArtifact reports whether path, as the walk reached it, is an artifact file of one of the
// build's local repositories: <repo>/<group path>/<artifact>/<version>/<file>, the file named
// <artifact>-<version> followed by '.' or '-' (a classifier, an extension, a checksum, a
// .lastUpdated marker), or for a -SNAPSHOT version <artifact>-<base>- and a timestamp digit.
// These are the files the scan does not read when the repository lies outside the checkout, so
// leaving them out gives an in-checkout repository the same coverage; a parent POM or BOM among
// them is no more read than it is there. A launch that runs one of them names it on a surface
// outside the repository, and the walk reads that surface. Anything else under a repository, such as a launch script or a project file beside the
// artifacts, is scanned.
func (s *launchScan) repoArtifact(path string) bool {
	for _, repo := range s.repos {
		if !strictlyInside(repo, path) {
			continue
		}
		rel, _ := filepath.Rel(repo, path)
		parts := strings.Split(rel, string(filepath.Separator))
		n := len(parts)
		if n < 4 {
			return false
		}
		return repoArtifactName(parts[n-1], parts[n-3], parts[n-2])
	}
	return false
}

// strictlyInside reports whether p lies under dir and is not dir itself, both real absolute
// paths; a relative p is under no absolute dir.
func strictlyInside(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func repoArtifactName(name, artifact, version string) bool {
	if rest, ok := strings.CutPrefix(name, artifact+"-"+version); ok && rest != "" && (rest[0] == '.' || rest[0] == '-') {
		return true
	}
	base, ok := strings.CutSuffix(version, "-SNAPSHOT")
	if !ok || base == "" {
		return false
	}
	rest, ok := strings.CutPrefix(name, artifact+"-"+base+"-")
	return ok && rest != "" && rest[0] >= '0' && rest[0] <= '9'
}

const (
	// launchTextLimit is the largest file read whole; larger files are scanned in windows
	// with no reader context, so every name or classpath token in them withholds Searched.
	launchTextLimit = 8 << 20
	launchWindow    = 1 << 20
	launchOverlap   = 512
	// launchNestedLimit bounds a JAR read into memory from inside a distribution archive.
	launchNestedLimit = 64 << 20
)

func launchHasSuffix(lower string, suffixes ...string) bool {
	for _, x := range suffixes {
		if strings.HasSuffix(lower, x) {
			return true
		}
	}
	return false
}

func isCodeArchive(lower string) bool { return launchHasSuffix(lower, ".jar", ".war", ".ear") }
func isTarArchive(lower string) bool {
	return launchHasSuffix(lower, ".tar", ".tgz", ".tar.gz", ".tbz2", ".tbz", ".tar.bz2")
}

// unopenedArchive reports a compressed archive the scanner cannot decompress.
func unopenedArchive(lower string) bool {
	return launchHasSuffix(lower, ".tar.xz", ".txz", ".tar.zst", ".tzst", ".tar.lz", ".tar.lzma", ".tar.z", ".7z", ".rar")
}

// file scans one checkout file. A code archive is read for its manifest only; a distribution
// archive (.zip, .tar, gzip or bzip2 tar) is read entry by entry; another compressed archive
// cannot be read; anything else is scanned as text.
func (s *launchScan) file(path, rel string) {
	lower := strings.ToLower(rel)
	switch {
	case unopenedArchive(lower):
		s.readFail()
		return
	case isCodeArchive(lower) && s.defines != nil:
		return
	case isCodeArchive(lower):
		zr, err := zip.OpenReader(path)
		if err != nil {
			s.readFail()
			return
		}
		defer zr.Close()
		s.manifest(&zr.Reader)
		return
	case strings.HasSuffix(lower, ".zip"):
		zr, err := zip.OpenReader(path)
		if err != nil {
			s.readFail()
			return
		}
		defer zr.Close()
		s.zipEntries(&zr.Reader)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		s.readFail()
		return
	}
	defer f.Close()
	if isTarArchive(lower) {
		s.tarEntries(f, lower)
		return
	}
	fi, err := f.Stat()
	if err != nil {
		s.readFail()
		return
	}
	s.content(rel, false, f, fi.Size())
}

// content scans one file's bytes: whole when small enough, else in windows.
func (s *launchScan) content(rel string, inDist bool, r io.Reader, size int64) {
	if size >= 0 && size <= launchTextLimit {
		data, err := io.ReadAll(r)
		if err != nil {
			s.readFail()
			return
		}
		if s.defines != nil {
			s.define(decodeUTF16(data))
			return
		}
		s.text(rel, inDist, decodeUTF16(data))
		return
	}
	buf := make([]byte, launchWindow+launchOverlap)
	carry := 0
	for {
		n, err := io.ReadFull(r, buf[carry:])
		chunk := buf[:carry+n]
		final := errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
		if s.defines != nil {
			s.define(chunk)
		} else {
			s.jarHazards(rel, chunk)
			s.jarCopyHazards(rel, chunk)
			s.containerKeys(rel, chunk)
			s.tokensOnly(chunk, final)
		}
		if final {
			return
		}
		if err != nil {
			s.readFail()
			return
		}
		carry = copy(buf, chunk[len(chunk)-launchOverlap:])
	}
}

// decodeUTF16 returns a UTF-16 file with a byte-order mark as UTF-8; other data unchanged.
func decodeUTF16(data []byte) []byte {
	var le bool
	switch {
	case bytes.HasPrefix(data, []byte{0xff, 0xfe}):
		le = true
	case bytes.HasPrefix(data, []byte{0xfe, 0xff}):
	default:
		return data
	}
	units := make([]uint16, 0, len(data)/2)
	for i := 2; i+1 < len(data); i += 2 {
		if le {
			units = append(units, uint16(data[i])|uint16(data[i+1])<<8)
		} else {
			units = append(units, uint16(data[i])<<8|uint16(data[i+1]))
		}
	}
	return []byte(string(utf16.Decode(units)))
}

// manifest reads a JAR's META-INF/MANIFEST.MF: a Launcher-Agent-Class starts an agent when
// the JAR is launched with -jar, and a Class-Path extends the classpath of every launch that
// puts the JAR on it. Add-Opens, Add-Exports and Spring Boot's PropertiesLauncher change only
// what a -jar launch runs, so they count against the build's own artifact (settleOwnJars).
func (s *launchScan) manifest(zr *zip.Reader) {
	for _, f := range zr.File {
		if !strings.EqualFold(f.Name, "META-INF/MANIFEST.MF") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			s.readFail()
			return
		}
		data, err := io.ReadAll(io.LimitReader(rc, launchTextLimit))
		rc.Close()
		if err != nil {
			s.readFail()
			return
		}
		text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n ", "")
		for _, line := range strings.Split(text, "\n") {
			name, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "launcher-agent-class":
				s.agent()
			case "class-path":
				if strings.TrimSpace(value) != "" {
					s.unreadable()
				}
			case "add-opens", "add-exports":
				s.jarHazard = true
			}
		}
		if jarLoaderHazard.MatchString(text) {
			s.jarHazard = true
		}
	}
}

func (s *launchScan) zipEntries(zr *zip.Reader) {
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			s.readFail()
			continue
		}
		s.entry(f.Name, rc, int64(f.UncompressedSize64))
		rc.Close()
	}
}

func (s *launchScan) tarEntries(r io.Reader, lower string) {
	switch {
	case launchHasSuffix(lower, ".tbz2", ".tbz", ".tar.bz2"):
		r = bzip2.NewReader(r)
	case !strings.HasSuffix(lower, ".tar"):
		zr, err := gzip.NewReader(r)
		if err != nil {
			s.readFail()
			return
		}
		defer zr.Close()
		r = zr
	}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			s.readFail()
			return
		}
		if h.Typeflag == tar.TypeReg {
			s.entry(h.Name, tr, h.Size)
		}
	}
}

// entry scans one distribution-archive entry: a nested code archive for its manifest, a class
// file not at all (its code is the call graph's), anything else as text.
func (s *launchScan) entry(name string, r io.Reader, size int64) {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".class"):
	case isCodeArchive(lower) && s.defines != nil:
	case isCodeArchive(lower) || strings.HasSuffix(lower, ".zip"):
		data, err := io.ReadAll(io.LimitReader(r, launchNestedLimit+1))
		if err != nil || len(data) > launchNestedLimit {
			s.readFail()
			return
		}
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			s.readFail()
			return
		}
		s.manifest(zr)
	default:
		s.content(name, true, r, size)
	}
}

// jvmOptionVar reports whether an environment variable carries JVM options for the program:
// the JVM's and the java launcher's own variables, JAVA_OPTS-style variables, a Gradle start
// script's <APP>_OPTS, and MAVEN_OPTS and GRADLE_OPTS, whose JVM runs the program under
// exec:java or a run task. SBT's and Ant's variables configure their own JVM.
func isJVMOptionVar(name string) bool {
	return !buildToolVars[name] && (strings.Contains(name, "JAVA_TOOL_OPTIONS") ||
		strings.Contains(name, "JAVA_OPTIONS") || strings.Contains(name, "_OPTS"))
}

// buildToolVars configure a build tool's own JVM, not the program's.
var buildToolVars = map[string]bool{"SBT_OPTS": true, "ANT_OPTS": true}

// options classifies one option list, token by token.
func (s *launchScan) options(tokens []string) {
	for i := 0; i < len(tokens); i++ {
		switch classifyLaunchOption(tokens[i]) {
		case optionAgent:
			s.agent()
		case optionUnmodeled:
			s.unreadable()
		case optionTakesValue:
			i++
		}
	}
}

type optionClass int

const (
	optionInert optionClass = iota
	optionTakesValue
	optionAgent
	optionUnmodeled
)

var agentOptionPrefixes = []string{"-javaagent:", "-agentlib:", "-agentpath:", "-Xrun", "-Xbootclasspath"}

// inertProperties are system properties that select no code: the JDK reads them as plain
// values. Encoding properties are inert only for a standard charset (inertEncodings).
var inertProperties = map[string]bool{
	"java.awt.headless": true, "java.net.preferIPv4Stack": true,
	"java.net.preferIPv6Addresses": true, "java.security.egd": true,
	"user.language": true, "user.country": true, "user.region": true, "user.variant": true,
	"user.script": true, "user.timezone": true, "user.name": true,
}

var encodingProperties = map[string]bool{
	"file.encoding": true, "sun.jnu.encoding": true, "stdout.encoding": true, "stderr.encoding": true,
}

// inertEncodings are the charsets every JDK resolves from java.base without a provider lookup.
var inertEncodings = map[string]bool{
	"UTF-8": true, "UTF8": true, "US-ASCII": true, "ISO-8859-1": true, "UTF-16": true,
	"UTF-16BE": true, "UTF-16LE": true, "COMPAT": true,
}

var inertJVMFlags = map[string]bool{
	"-server": true, "-client": true, "-ea": true, "-da": true, "-esa": true, "-dsa": true,
	"-enableassertions": true, "-disableassertions": true,
	"-enablesystemassertions": true, "-disablesystemassertions": true,
}

var inertFlagPrefixes = []string{"-Xmx", "-Xms", "-Xss", "-Xmn", "-Xlog:", "-verbose:", "-ea:", "-da:",
	"-enableassertions:", "-disableassertions:", "-Xdock:"}

// inertXX are -XX options that size or tune the VM and load no code.
var inertXX = map[string]bool{
	"MaxRAMPercentage": true, "InitialRAMPercentage": true, "MinRAMPercentage": true, "MaxRAM": true,
	"MetaspaceSize": true, "MaxMetaspaceSize": true, "MaxDirectMemorySize": true,
	"ReservedCodeCacheSize": true, "UseG1GC": true, "UseParallelGC": true, "UseSerialGC": true,
	"UseZGC": true, "ZGenerational": true, "UseShenandoahGC": true, "UseContainerSupport": true,
	"ExitOnOutOfMemoryError": true, "CrashOnOutOfMemoryError": true,
	"HeapDumpOnOutOfMemoryError": true, "HeapDumpPath": true, "MaxGCPauseMillis": true,
	"ActiveProcessorCount": true, "UseStringDeduplication": true,
}

// valueOptions take the next token as their value; module access options grant reflective
// access only. Classpath, JAR and module-path options name the launch's code and are
// unmodeled.
var valueOptions = map[string]bool{"--add-opens": true, "--add-exports": true, "--add-reads": true}

func classifyLaunchOption(opt string) optionClass {
	for _, p := range agentOptionPrefixes {
		if strings.HasPrefix(opt, p) {
			return optionAgent
		}
	}
	if valueOptions[opt] {
		return optionTakesValue
	}
	for _, p := range []string{"--add-opens=", "--add-exports=", "--add-reads="} {
		if strings.HasPrefix(opt, p) {
			return optionInert
		}
	}
	if inertJVMFlags[opt] {
		return optionInert
	}
	for _, p := range inertFlagPrefixes {
		if strings.HasPrefix(opt, p) {
			return optionInert
		}
	}
	if prop, ok := strings.CutPrefix(opt, "-D"); ok {
		name, value, _ := strings.Cut(prop, "=")
		switch {
		case encodingProperties[name]:
			if inertEncodings[strings.ToUpper(value)] {
				return optionInert
			}
		case inertProperties[name]:
			return optionInert
		}
		return optionUnmodeled
	}
	if xx, ok := strings.CutPrefix(opt, "-XX:"); ok {
		name := strings.TrimLeft(xx, "+-")
		name, _, _ = strings.Cut(name, "=")
		if inertXX[name] {
			return optionInert
		}
	}
	return optionUnmodeled
}

// expansionWord matches a word that is one whole variable expansion: $NAME, ${NAME},
// ${NAME:-default} and the other parameter forms, $(NAME), %NAME%.
var expansionWord = regexp.MustCompile(`^(?:\$\{?([A-Za-z_][A-Za-z0-9_]*)(?::?[-=+?][^}]*)?\}?|\$\(([A-Za-z_][A-Za-z0-9_]*)\)|%([A-Za-z_][A-Za-z0-9_]*)%)$`)

// splitOptionWords splits a shell-quoted option string into words. A word that is a whole
// expansion of another JVM option variable is that variable's value, read where it is set (or
// deploy-time residue); any other word that expands a variable cannot be read.
func splitOptionWords(value string) (words []string, unreadable bool) {
	for _, w := range strings.Fields(strings.NewReplacer(`"`, " ", "'", " ", `\`, " ").Replace(value)) {
		if m := expansionWord.FindStringSubmatch(w); m != nil {
			if !isJVMOptionVar(m[1] + m[2] + m[3]) {
				unreadable = true
			}
			continue
		}
		if strings.Contains(w, "$") || strings.Contains(w, "%") || strings.Contains(w, "`") {
			switch classifyLaunchOption(w) {
			case optionAgent, optionInert:
				// An agent whatever path it names; inert whatever value. An unquoted expansion
				// word-splits, so a value carrying an agent (HEAP="1g -javaagent:x") is caught
				// where the checkout assigns it; one set only at deploy time is residue, as for -D.
				words = append(words, w)
				continue
			}
			if prop, ok := strings.CutPrefix(w, "-D"); ok {
				// A property's value is read only for the encoding properties.
				name, _, _ := strings.Cut(prop, "=")
				if !strings.ContainsAny(name, "$%`") && !encodingProperties[name] {
					words = append(words, w)
					continue
				}
			}
			unreadable = true
			continue
		}
		words = append(words, w)
	}
	return words, unreadable
}

func (s *launchScan) optionString(value string) {
	words, unreadable := splitOptionWords(value)
	if unreadable {
		s.unreadable()
	}
	s.options(words)
}

// optionHead finds candidate launch-option tokens; launchOptionToken validates each.
var optionHead = regexp.MustCompile(`-(?:D|XX:|javaagent|agentlib|agentpath|Xrun|Xbootclasspath|cp|classpath|jar|p)|--(?:add-modules|upgrade-module-path|patch-module|limit-modules|class-path|module-path)`)

type launchToken struct {
	start, end int
	word       string
}

func isLaunchDelim(b byte) bool {
	return b <= ' ' || b == 0x7f || strings.IndexByte("\"'`,[]();|&<>}\\", b) >= 0
}

// leftBoundary reports whether a token may start at i: at a word start, or after the `:-` of a
// parameter default.
func leftBoundary(data []byte, i int) bool {
	if i == 0 {
		return true
	}
	b := data[i-1]
	if b <= ' ' || strings.IndexByte("\"'`[](){},;=:+|&<>", b) >= 0 {
		return true
	}
	if b == 'J' && i >= 2 && data[i-2] == '-' && leftBoundary(data, i-2) {
		return true // kotlin, jshell and javac pass -J<option> to their JVM
	}
	return b == '-' && i >= 2 && data[i-2] == ':'
}

var propertyNameByte = func() (t [256]bool) {
	for _, c := range "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-${%" {
		t[c] = true
	}
	return t
}()

// launchOptionTokens returns every launch-option token in data. A token is a whole word; one
// that touches a control byte or is not UTF-8 is binary data, not text, and is skipped. So is
// one in a binary file (past its script text, for a script with a payload) whose surrounding
// run of non-space bytes is not UTF-8: delimiters that happen to fall in compressed data. An
// agent token is never skipped that way.
func launchOptionTokens(data []byte) []launchToken {
	var out []launchToken
	binaryFrom := bytes.IndexByte(data, 0)
	if binaryFrom >= 0 && !bytes.HasPrefix(data, []byte("#!")) {
		binaryFrom = -1
		if n := bytes.Count(data, []byte{0}); binaryMagic(data) || n >= binaryMinNULs && n*binaryNULDensity >= len(data) {
			binaryFrom = 0
		}
	}
	for pos := 0; pos < len(data); {
		loc := optionHead.FindIndex(data[pos:])
		if loc == nil {
			break
		}
		h := pos + loc[0]
		head := string(data[h : pos+loc[1]])
		if !leftBoundary(data, h) {
			pos = h + 1
			continue
		}
		end, joined := h, false
		for end < len(data) {
			if n := lineContinuation(data, end); n > 0 {
				end += n
				joined = true
				continue
			}
			if isLaunchDelim(data[end]) {
				break
			}
			end++
		}
		pos = end
		if binaryAdjacent(data, h, end) || binaryFrom >= 0 && h >= binaryFrom && !utf8.Valid(binaryRun(data, h, end)) &&
			classifyLaunchOption(string(data[h:end])) != optionAgent {
			continue
		}
		word := string(data[h:end])
		if joined {
			word = strings.NewReplacer("\\\r\n", "", "\\\n", "").Replace(word)
		}
		if !utf8.ValidString(word) {
			continue
		}
		switch head {
		case "-D":
			quoted, unparsed := false, false
			if end < len(data) && (data[end] == '"' || data[end] == '\'') && !strings.Contains(word, "=") {
				// -D"k=v", -D'k', -Dk"ey": the shell joins the quoted segment into the name.
				quoted = true
				close := bytes.IndexByte(data[end+1:], data[end])
				if close < 0 || bytes.IndexByte(data[end+1:end+1+close], '\n') >= 0 {
					unparsed = true
				} else {
					word += string(data[end+1 : end+1+close])
					end += close + 2
					pos = end
					unparsed = end < len(data) && !isLaunchDelim(data[end])
				}
			}
			name, _, _ := strings.Cut(word[2:], "=")
			if unparsed || name == "" || !validPropertyName(name) {
				if quoted || joined || strings.HasPrefix(word, "-D=") {
					out = append(out, launchToken{start: h, end: end, word: "-D"})
				}
				continue
			}
			if strings.HasSuffix(word, "=") && end < len(data) && (data[end] == '"' || data[end] == '\'') {
				if close := bytes.IndexByte(data[end+1:], data[end]); close >= 0 && bytes.IndexByte(data[end+1:end+1+close], '\n') < 0 {
					word += string(data[end+1 : end+1+close])
					end += close + 2
					pos = end
				}
			}
		case "-XX:":
			if len(word) == len(head) {
				continue
			}
		case "-cp", "-classpath", "-jar", "-p":
			if word != head {
				continue
			}
		case "--class-path", "--module-path", "--add-modules", "--upgrade-module-path", "--patch-module", "--limit-modules":
			if word != head && !strings.HasPrefix(word, head+"=") {
				continue
			}
		}
		out = append(out, launchToken{start: h, end: end, word: word})
	}
	return out
}

// lineContinuation returns the length of a backslash line continuation at i, or 0.
func lineContinuation(data []byte, i int) int {
	if data[i] != '\\' {
		return 0
	}
	switch {
	case i+1 < len(data) && data[i+1] == '\n':
		return 2
	case i+2 < len(data) && data[i+1] == '\r' && data[i+2] == '\n':
		return 3
	}
	return 0
}

// binaryAdjacent reports whether data[a:b] touches a control byte other than whitespace: a
// string in a binary serialization (a class file, Gradle's execution history), not text. The
// launcher reads no options from such a file; options embedded in binaries are residue.
func binaryAdjacent(data []byte, a, b int) bool {
	ctl := func(c byte) bool { return c < ' ' && c != '\t' && c != '\n' && c != '\r' && c != '\f' && c != '\v' }
	return a > 0 && ctl(data[a-1]) || b < len(data) && ctl(data[b])
}

// A file without a shebang is binary when it opens with a binary format's magic, or its NULs
// number at least binaryMinNULs and one in binaryNULDensity bytes: compressed data, not a text
// file with a stray NUL.
const binaryMinNULs, binaryNULDensity = 4, 512

var binaryMagics = [][]byte{[]byte("wOFF"), []byte("wOF2"), []byte("PK\x03\x04"), []byte("\x89PNG"),
	[]byte("GIF8"), []byte("\xff\xd8\xff"), []byte("\xca\xfe\xba\xbe"), []byte("\x1f\x8b")}

func binaryMagic(data []byte) bool {
	for _, m := range binaryMagics {
		if bytes.HasPrefix(data, m) {
			return true
		}
	}
	return false
}

// binaryRun widens data[a:b] to the run of bytes around it that are neither whitespace nor
// control bytes.
func binaryRun(data []byte, a, b int) []byte {
	for a > 0 && data[a-1] > ' ' && data[a-1] != 0x7f {
		a--
	}
	for b < len(data) && data[b] > ' ' && data[b] != 0x7f {
		b++
	}
	return data[a:b]
}

func validPropertyName(name string) bool {
	for i := 0; i < len(name); i++ {
		if !propertyNameByte[name[i]] {
			return false
		}
	}
	return true
}

func isClasspathToken(w string) bool {
	switch w {
	case "-cp", "-classpath", "-jar", "--class-path", "--module-path":
		return true
	}
	return strings.HasPrefix(w, "--class-path=") || strings.HasPrefix(w, "--module-path=")
}

// launchName finds the names that carry JVM options without being options themselves: option
// variables, the Gradle and Maven DSL properties that become JVM options, the JAR manifest
// attributes that start an agent or extend the classpath, and the CLASSPATH variable.
var launchName = regexp.MustCompile(`\b[A-Za-z0-9_]*(?:JAVA_TOOL_OPTIONS|JAVA_OPTIONS|_OPTS)[A-Za-z0-9_]*\b|\b(?:applicationDefaultJvmArgs|defaultJvmOpts|jvmFlags?|jvmArguments|jvmArgs|jvmArgumentProviders|argLine)\b|\bLauncher-Agent-Class\b|\bClass-Path\b|\bCLASSPATH\b`)

// launchNames returns the launch-name occurrences in text. A file with a NUL byte is a binary
// serialization (a class file, Gradle's execution history) that the launcher reads no options
// from: a name in it is data, and options embedded in binaries are residue. Option tokens in
// binaries still classify themselves.
func launchNames(data []byte) [][]int {
	if i := bytes.IndexByte(data, 0); i >= 0 {
		if !bytes.HasPrefix(data, []byte("#!")) {
			return nil
		}
		data = data[:i] // a script with an appended payload: its text is the script
	}
	var out [][]int
	for _, loc := range launchName.FindAllIndex(data, -1) {
		if !binaryAdjacent(data, loc[0], loc[1]) {
			out = append(out, loc)
		}
	}
	return out
}

var launchDSLNames = map[string]bool{
	"applicationDefaultJvmArgs": true, "defaultJvmOpts": true, "jvmFlags": true, "jvmFlag": true, "jvmArguments": true,
	"jvmArgs": true, "argLine": true,
}

// tokensOnly classifies the tokens of a window of a large file, with no reader context. An
// occurrence running into the window's end is read whole from the next, overlapping window.
func (s *launchScan) tokensOnly(data []byte, final bool) {
	for _, t := range launchOptionTokens(data) {
		if !final && t.end == len(data) {
			if t.start < len(data)-launchOverlap {
				s.unreadable() // the next window starts inside it
			}
			continue
		}
		if t.word == "-p" {
			continue
		}
		s.options([]string{t.word})
	}
	for _, loc := range launchNames(data) {
		n := string(data[loc[0]:loc[1]])
		if !final && loc[1] == len(data) {
			continue
		}
		switch {
		case n == "Launcher-Agent-Class":
			s.agent()
		case !buildToolVars[n]:
			s.unreadable()
		}
	}
}

type launchSpanKind int

const (
	// spanBuild: a build tool's own JVM or command line. Its -D and -XX options are claimed,
	// except properties a build plugin turns into launch options (jib.*, spring-boot.*).
	spanBuild launchSpanKind = iota
	// spanTest: a Gradle jvmArgs in a test task's block, or a Maven argLine in the Surefire or
	// Failsafe plugin: the test JVM only.
	spanTest
)

type launchSpan struct {
	start, end int
	kind       launchSpanKind
}

// launchFile is one text file under scan, with the reader context its occurrences need.
type launchFile struct {
	s           *launchScan
	rel         string
	data        []byte
	lines       []int // start offset of each line
	gradlew     bool
	mavenw      bool
	startScript bool
	pom         bool
	spans       []launchSpan
	testScopes  [][2]int     // Surefire/Failsafe plugin elements
	braces      map[int]int  // a Gradle script's code-level braces: open offset to close offset
	testOpens   map[int]bool // the opening braces of a Gradle script's test-task blocks
	yamlLines   map[int]bool // 1-based lines whose name occurrence a YAML reader classified
	template    map[int]bool // 0-based start-script template comment lines
}

func (s *launchScan) text(rel string, inDist bool, data []byte) {
	s.jarHazards(rel, data)
	s.jarCopyHazards(rel, data)
	s.containerKeys(rel, data)
	tokens := launchOptionTokens(data)
	names := launchNames(data)
	javaCtx := bytes.Contains(data, []byte("java")) && (bytes.Contains(data, []byte("-p")) || bytes.Contains(data, []byte("@")))
	if len(tokens) == 0 && len(names) == 0 && !javaCtx {
		return
	}
	base := strings.ToLower(rel[strings.LastIndex(rel, "/")+1:])
	f := &launchFile{s: s, rel: rel, data: data, gradlew: isGradleWrapper(rel, inDist, data), mavenw: isMavenWrapper(rel, inDist, data),
		startScript: isStartScript(rel, inDist), pom: base == "pom.xml", yamlLines: map[int]bool{}, template: map[int]bool{}}
	f.lines = append(f.lines, 0)
	for i, b := range data {
		if b == '\n' && i+1 < len(data) {
			f.lines = append(f.lines, i+1)
		}
	}
	f.buildSpans(rel)
	f.testSpans(base)
	if f.gradlew || f.mavenw || f.startScript {
		for i := range f.lines {
			if startScriptCommentLines[strings.Join(strings.Fields(f.line(i)), " ")] {
				f.template[i] = true
			}
		}
	}
	if launchHasSuffix(base, ".yaml", ".yml", ".json") {
		f.yaml()
	}
	for _, t := range tokens {
		f.option(t)
	}
	for _, loc := range names {
		f.name(loc[0], loc[1])
	}
	if javaCtx {
		f.javaContext()
	}
}

// isGradleWrapper reports whether rel is the checkout's Gradle wrapper script: gradlew or
// gradlew.bat at the root, carrying the template's wrapper entry point.
func isGradleWrapper(rel string, inDist bool, data []byte) bool {
	return !inDist && (rel == "gradlew" || rel == "gradlew.bat") &&
		(bytes.Contains(data, []byte("org.gradle.wrapper.GradleWrapperMain")) || bytes.Contains(data, []byte("gradle-wrapper.jar")))
}

// isMavenWrapper reports whether rel is the checkout's Maven wrapper script: mvnw or mvnw.cmd
// at the root, carrying the template's wrapper entry point.
func isMavenWrapper(rel string, inDist bool, data []byte) bool {
	return !inDist && (rel == "mvnw" || rel == "mvnw.cmd") &&
		(bytes.Contains(data, []byte("org.apache.maven.wrapper.MavenWrapperMain")) || bytes.Contains(data, []byte("maven-wrapper.jar")))
}

// isStartScript reports whether rel is a Gradle-generated start script: build/scripts/<name>
// or build/install/<app>/bin/<name> in any project, or <app>/bin/<name> in a distribution.
func isStartScript(rel string, inDist bool) bool {
	parts := strings.Split(rel, "/")
	n := len(parts)
	if inDist {
		return n == 3 && parts[1] == "bin"
	}
	return n >= 3 && parts[n-3] == "build" && parts[n-2] == "scripts" ||
		n >= 5 && parts[n-5] == "build" && parts[n-4] == "install" && parts[n-2] == "bin"
}

// startScriptCommentLines are the lines of Gradle's start-script and wrapper templates and
// Maven's wrapper template that name options or option variables: the comments, and the Maven
// wrapper's prepending of .mvn/jvm.config to MAVEN_OPTS (that file is scanned where it lies).
var startScriptCommentLines = map[string]bool{
	"# * -classpath": true, "# * -D...appname settings": true, "# * --module-path (only if needed)": true,
	"# set MAVEN_OPTS=-Xdebug -Xrunjdwp:transport=dt_socket,server=y,suspend=y,address=8000":    true,
	"@REM set MAVEN_OPTS=-Xdebug -Xrunjdwp:transport=dt_socket,server=y,suspend=y,address=8000": true,
	`MAVEN_OPTS="$(concat_lines "$MAVEN_PROJECTBASEDIR/.mvn/jvm.config") $MAVEN_OPTS"`:          true,
}

func (f *launchFile) lineOf(off int) int {
	return sort.Search(len(f.lines), func(i int) bool { return f.lines[i] > off }) - 1
}

func (f *launchFile) lineEnd(i int) int {
	if i+1 < len(f.lines) {
		return f.lines[i+1] - 1
	}
	return len(f.data)
}

func (f *launchFile) line(i int) string {
	return strings.TrimRight(string(f.data[f.lines[i]:f.lineEnd(i)]), "\r\n")
}

func (f *launchFile) inSpan(off int, kind launchSpanKind) bool {
	for _, sp := range f.spans {
		if sp.kind == kind && off >= sp.start && off < sp.end {
			return true
		}
	}
	return false
}

// logicalLines returns the byte ranges of the file's logical lines: backslash continuations
// (and caret continuations in batch files) are joined.
func (f *launchFile) logicalLines() [][2]int {
	var out [][2]int
	start := 0
	for i := range f.lines {
		l := strings.TrimRight(f.line(i), " \t")
		if (strings.HasSuffix(l, `\`) || strings.HasSuffix(l, "^")) && i+1 < len(f.lines) {
			continue
		}
		out = append(out, [2]int{f.lines[start], f.lineEnd(i)})
		start = i + 1
	}
	return out
}

// launchWords splits a command line into words and the separators ; | & between commands.
var launchWords = regexp.MustCompile(`[;|&]+|[^\s"'\[\](),;|&]+`)

var buildToolCommands = map[string]bool{
	"mvn": true, "mvnw": true, "mvn.cmd": true, "mvnw.cmd": true, "gradle": true, "gradlew": true,
	"gradle.bat": true, "gradlew.bat": true, "sbt": true, "ant": true, "cmake": true, "gcc": true,
	"g++": true, "cc": true, "clang": true, "clang++": true,
}

func commandBase(w string) string {
	w = w[strings.LastIndexAny(w, `/\`)+1:]
	return strings.ToLower(w)
}

func isJavaCommand(w string) bool {
	switch commandBase(w) {
	case "java", "java.exe", "javaw", "javaw.exe":
		return true
	}
	return false
}

// buildSpans marks the build tools' own option surfaces: the wrapper scripts and Maven's
// command-line config file whole, a build-tool command up to the next command or java word,
// and a line that assigns SBT's or Ant's option variable or Gradle's daemon JVM arguments.
// Maven's .mvn/jvm.config, like MAVEN_OPTS, configures the JVM exec:java runs the program in.
func (f *launchFile) buildSpans(rel string) {
	if f.gradlew || strings.HasSuffix(rel, ".mvn/maven.config") || rel == ".mvn/maven.config" {
		f.spans = append(f.spans, launchSpan{0, len(f.data), spanBuild})
		return
	}
	for _, ll := range f.logicalLines() {
		seg := f.data[ll[0]:ll[1]]
		open := -1
		for _, loc := range launchWords.FindAllIndex(seg, -1) {
			w := string(seg[loc[0]:loc[1]])
			switch {
			case strings.ContainsAny(w[:1], ";|&") || isJavaCommand(w):
				if open >= 0 {
					f.spans = append(f.spans, launchSpan{ll[0] + open, ll[0] + loc[0], spanBuild})
					open = -1
				}
			case open < 0 && buildToolCommands[commandBase(w)]:
				open = loc[1]
			case open < 0:
				k := w
				if i := strings.IndexAny(k, "=:"); i >= 0 {
					k = k[:i]
				}
				if buildToolVars[k] || k == "org.gradle.jvmargs" || k == "kotlin.daemon.jvmargs" {
					open = loc[0]
				}
			}
		}
		if open >= 0 {
			f.spans = append(f.spans, launchSpan{ll[0] + open, ll[1], spanBuild})
		}
	}
}

var testArgs = regexp.MustCompile(`\bjvmArgs\b|<argLine>`)

// testSpans marks the jvmArgs and argLine values that configure only a test JVM: a jvmArgs
// directly in a Gradle test task's block, and an argLine in the Surefire or Failsafe plugin.
// Every other jvmArgs (run, bootRun, any JavaExec) and argLine configures a JVM that may run
// the program.
func (f *launchFile) testSpans(base string) {
	switch {
	case base == "pom.xml":
		f.testScopes = f.surefireScopes()
	case launchHasSuffix(base, ".gradle", ".gradle.kts"):
		f.braces = gradleBraces(f.data, strings.HasSuffix(base, ".kts"))
		f.testOpens = map[int]bool{}
		for _, loc := range gradleTestBlock.FindAllIndex(f.data, -1) {
			f.testOpens[loc[1]-1] = true // testScope only asks about code-level braces
		}
	default:
		return
	}
	for _, loc := range testArgs.FindAllIndex(f.data, -1) {
		scopeEnd, ok := f.testScope(loc[0])
		if !ok {
			continue
		}
		var end int
		if string(f.data[loc[0]:loc[1]]) == "<argLine>" {
			i := bytes.Index(f.data[loc[1]:], []byte("</argLine>"))
			if i < 0 {
				continue
			}
			end = loc[1] + i
		} else {
			rest := string(f.data[loc[1]:])
			trimmed := strings.TrimLeft(rest, " \t")
			for _, op := range []string{"+=", "=", ".addAll", ".add", ".set"} {
				if strings.HasPrefix(trimmed, op) {
					trimmed = strings.TrimLeft(trimmed[len(op):], " \t")
					break
				}
			}
			start := loc[1] + len(rest) - len(trimmed)
			if expr, ok := bracketedExpr(trimmed); ok {
				end = start + len(expr)
			} else if end, ok = literalArgsEnd(f.data, start, strings.HasSuffix(base, ".kts")); !ok {
				continue
			}
		}
		f.spans = append(f.spans, launchSpan{loc[0], min(end, scopeEnd), spanTest})
	}
}

// literalArgsEnd returns where an unbracketed jvmArgs value starting at i ends: string
// literals, commas and comments, up to the first ';', line end or '}' (after a comma the value
// continues on the next line). ok is false when anything else comes first or the lexer cannot
// classify a token: a value with no positive end is not test-only, so none of it is exempt.
func literalArgsEnd(data []byte, i int, kts bool) (int, bool) {
	comma := false
	for i < len(data) {
		ok := true
		switch at := data[i:]; {
		case at[0] == ';' || at[0] == '}' || (at[0] == '\n' || at[0] == '\r') && !comma:
			return i, true
		case isGradleSpace(at[0]):
			i++
		case at[0] == ',':
			i, comma = i+1, true
		case bytes.HasPrefix(at, []byte("//")):
			for i < len(data) && data[i] != '\n' {
				i++
			}
		case bytes.HasPrefix(at, []byte("/*")):
			i, ok = skipBlockComment(data, i, kts)
		case stringQuote(at, kts) != "":
			i, ok = skipString(data, i, stringQuote(at, kts), kts)
			comma = false
		default:
			ok = false
		}
		if !ok {
			return 0, false
		}
	}
	return 0, false
}

// gradleTestBlock matches the opening of a block that configures Gradle test tasks: test { },
// tasks.test { }, tasks.named("test") { }, and withType<Test> { } or withType(Test) { }, each
// optionally through .configure or .configureEach.
var gradleTestBlock = regexp.MustCompile(`(?m)(?:^[ \t]*|\btasks\.)test[ \t]*(?:\.configure[ \t]*)?\{` +
	`|\btasks\.named(?:<Test>)?\([ \t]*["']test["'][ \t]*(?:,[ \t]*Test(?:::class(?:\.java)?)?[ \t]*)?\)[ \t]*(?:\.configure[ \t]*)?\{` +
	`|\bwithType(?:<Test>[ \t]*(?:\([ \t]*\))?|\([ \t]*Test(?:::class(?:\.java)?)?[ \t]*\))[ \t]*(?:\.configureEach[ \t]*)?\{`)

var (
	mavenPlugin     = regexp.MustCompile(`<plugin>`)
	mavenArtifactID = regexp.MustCompile(`<artifactId>\s*([^<\s]+)\s*</artifactId>`)
)

// testScope reports whether off configures only a test task, and where that configuration
// ends. In a Gradle script the innermost block holding off decides: it must be a test task's
// block, so a run or bootRun block nested anywhere inside one is not test configuration, and
// the setting must be the test task's own (see testReceiver). In a POM, off must lie in a
// Surefire or Failsafe plugin element.
func (f *launchFile) testScope(off int) (int, bool) {
	if f.braces == nil {
		return rangeEnd(f.testScopes, off)
	}
	open, end := -1, 0
	for o, c := range f.braces {
		if o < off && off < c && o > open {
			open, end = o, c
		}
	}
	return end, open >= 0 && f.testOpens[open] && testReceiver(f.data, off)
}

// testReceiver reports whether the setting named at off is called on the enclosing task: bare,
// or through it. or this. Any other receiver (tasks.run.get(), run, tasks.getByName("run"),
// project.tasks.findByName("bootRun"), foo) configures a different task from inside the
// block, whatever its name.
func testReceiver(data []byte, off int) bool {
	i := off
	for i > 0 && isGradleSpace(data[i-1]) {
		i--
	}
	if i == 0 || data[i-1] != '.' {
		return optionStatementStart(data, off)
	}
	for _, r := range []string{"it", "this"} {
		if k := i - 1 - len(r); k >= 0 && string(data[k:i-1]) == r && optionStatementStart(data, k) {
			return true
		}
	}
	return false
}

// optionStatementStart reports whether an expression starting at i begins a statement: only
// whitespace separates it from an opening or closing brace or a semicolon, or from the end
// of a line whose last character can end a statement.
func optionStatementStart(data []byte, i int) bool {
	newline := false
	for i > 0 && isGradleSpace(data[i-1]) {
		newline = newline || data[i-1] == '\n'
		i--
	}
	if i == 0 {
		return true
	}
	switch c := data[i-1]; {
	case c == '{' || c == '}' || c == ';':
		return true
	case c == ')' || c == ']' || c == '"' || c == '\'' || c == '`' || c == '_' || c == '$' || c >= 0x80 ||
		'0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z':
		return newline
	}
	return false
}

func isGradleSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

// surefireScopes returns the byte ranges of a POM's Surefire and Failsafe <plugin> elements.
func (f *launchFile) surefireScopes() [][2]int {
	var out [][2]int
	for _, loc := range mavenPlugin.FindAllIndex(f.data, -1) {
		end := bytes.Index(f.data[loc[1]:], []byte("</plugin>"))
		if end < 0 {
			continue
		}
		body := f.data[loc[1] : loc[1]+end]
		// The plugin's own coordinates precede its configuration, executions and dependencies.
		head := body
		for _, child := range []string{"<configuration>", "<executions>", "<dependencies>"} {
			if i := bytes.Index(head, []byte(child)); i >= 0 {
				head = head[:i]
			}
		}
		if m := mavenArtifactID.FindSubmatch(head); m != nil {
			switch string(m[1]) {
			case "maven-surefire-plugin", "maven-failsafe-plugin":
				out = append(out, [2]int{loc[1], loc[1] + end})
			}
		}
	}
	return out
}

// rangeEnd returns the end of the innermost range holding off.
func rangeEnd(ranges [][2]int, off int) (int, bool) {
	end, ok := 0, false
	for _, r := range ranges {
		if off >= r[0] && off < r[1] && (!ok || r[1] < end) {
			end, ok = r[1], true
		}
	}
	return end, ok
}

// gradleBraces returns a Gradle script's code-level braces, each opening brace's offset mapped
// to its closing brace's. It skips comments (nested in Kotlin), strings, string templates and
// backtick names. At the first token it cannot classify it stops, and every brace still open
// there has no match: a lone '/' in Groovy (a slashy or dollar-slashy string, or division), a
// backtick, '/' or newline inside a template, a newline inside a one-line string, anything
// unterminated, and a '}' with no '{'. A block it cannot close is not a test task's block.
func gradleBraces(data []byte, kts bool) map[int]int {
	pairs := map[int]int{}
	var open []int
	for i := 0; i < len(data); {
		ok := true
		switch at := data[i:]; {
		case bytes.HasPrefix(at, []byte("//")):
			for i < len(data) && data[i] != '\n' {
				i++
			}
		case bytes.HasPrefix(at, []byte("/*")):
			i, ok = skipBlockComment(data, i, kts)
		case at[0] == '/':
			ok = kts // Kotlin has no slashy strings: a lone '/' divides
			i++
		case stringQuote(at, kts) != "":
			i, ok = skipString(data, i, stringQuote(at, kts), kts)
		case at[0] == '`':
			j := bytes.IndexAny(at[1:], "`\n")
			ok = j >= 0 && at[1+j] == '`'
			i += j + 2
		case at[0] == '{':
			open = append(open, i)
			i++
		case at[0] == '}':
			if ok = len(open) > 0; ok {
				pairs[open[len(open)-1]] = i
				open = open[:len(open)-1]
			}
			i++
		default:
			i++
		}
		if !ok {
			break
		}
	}
	return pairs
}

// skipBlockComment returns the offset after the comment opening at i. Kotlin comments nest;
// Groovy's end at the first "*/".
func skipBlockComment(data []byte, i int, kts bool) (int, bool) {
	depth := 0
	for i < len(data) {
		switch at := data[i:]; {
		case bytes.HasPrefix(at, []byte("/*")) && (kts || depth == 0):
			depth++
			i += 2
		case bytes.HasPrefix(at, []byte("*/")):
			depth--
			i += 2
			if depth == 0 {
				return i, true
			}
		default:
			i++
		}
	}
	return 0, false
}

// skipString returns the offset after the string literal opening at i with quote q. Kotlin's
// raw strings take no escapes; double-quoted strings carry ${} templates.
func skipString(data []byte, i int, q string, kts bool) (int, bool) {
	triple := len(q) == 3
	for i += len(q); i < len(data); {
		switch at := data[i:]; {
		case at[0] == '\\' && !(kts && triple):
			i += 2
		case bytes.HasPrefix(at, []byte(q)):
			return i + len(q), true
		case at[0] == '\n' && !triple:
			return 0, false
		case q[0] == '"' && bytes.HasPrefix(at, []byte("${")):
			var ok bool
			if i, ok = skipTemplate(data, i+2, kts); !ok {
				return 0, false
			}
		default:
			i++
		}
	}
	return 0, false
}

// skipTemplate returns the offset after the template whose body starts at i, counting its
// braces and skipping the strings inside it. A backtick, '/' or newline inside a template is
// not classified.
func skipTemplate(data []byte, i int, kts bool) (int, bool) {
	for depth := 1; i < len(data); {
		at := data[i:]
		switch q := stringQuote(at, kts); {
		case q != "":
			var ok bool
			if i, ok = skipString(data, i, q, kts); !ok {
				return 0, false
			}
		case at[0] == '{':
			depth++
			i++
		case at[0] == '}':
			if depth--; depth == 0 {
				return i + 1, true
			}
			i++
		case at[0] == '`' || at[0] == '/' || at[0] == '\n':
			return 0, false
		default:
			i++
		}
	}
	return 0, false
}

// stringQuote returns the quote opening a string literal at the start of at, or "".
func stringQuote(at []byte, kts bool) string {
	switch {
	case bytes.HasPrefix(at, []byte(`"""`)) || !kts && bytes.HasPrefix(at, []byte("'''")):
		return string(at[:3])
	case at[0] == '"' || at[0] == '\'':
		return string(at[:1])
	}
	return ""
}

// option classifies one option token.
func (f *launchFile) option(t launchToken) {
	if t.word == "-p" || f.inSpan(t.start, spanTest) || f.template[f.lineOf(t.start)] {
		return
	}
	if f.mavenw && f.templateMavenProperty(t) {
		return
	}
	if isClasspathToken(t.word) {
		if t.word == "-jar" && f.ownJarOperand(t) {
			return
		}
		if !f.templateClasspath(t) {
			f.s.unreadable()
		}
		return
	}
	switch classifyLaunchOption(t.word) {
	case optionAgent:
		f.s.agent()
	case optionUnmodeled:
		// The Maven wrapper is not a build-tool invocation the program runs under: an option on
		// any of its lines reaches the JVM it starts.
		if f.mavenw || !f.inSpan(t.start, spanBuild) || !buildClaimable(t.word) {
			f.s.unreadable()
		}
	}
}

// buildClaimable reports whether an unmodeled option in a build-tool span configures only the
// build. Jib and Spring Boot properties can set the program's own JVM options, main class or
// base image, except Jib's push target (jib.to.*) and the Spring profiles spring-boot:run
// activates, which the analysis already covers (a @Profile never narrows resolution).
func buildClaimable(w string) bool {
	if strings.HasPrefix(w, "-XX:") {
		return true
	}
	prop, ok := strings.CutPrefix(w, "-D")
	if !ok {
		return false
	}
	name, _, _ := strings.Cut(prop, "=")
	switch {
	case strings.HasPrefix(name, "jib.to."), name == "spring-boot.run.profiles":
		return true
	}
	return !strings.HasPrefix(name, "jib.") && !strings.HasPrefix(name, "spring-boot.")
}

// templateClasspath reports whether a classpath token is a template's own: a Gradle start
// script's -classpath "$CLASSPATH" (Gradle 7 and earlier escape it for eval), the Gradle
// wrapper script's wrapper JAR, or the Maven wrapper script's wrapper JAR and the downloader
// it compiles into .mvn/wrapper.
func (f *launchFile) templateClasspath(t launchToken) bool {
	rest := strings.TrimLeft(f.restOfLine(t.end), " \t")
	if f.mavenw {
		switch t.word {
		case "-classpath":
			return wordIs(rest, `"$MAVEN_PROJECTBASEDIR/.mvn/wrapper/maven-wrapper.jar"`) ||
				wordIs(rest, `%WRAPPER_JAR%`) && f.templateWrapperJar()
		case "-cp":
			return wordIs(rest, ".mvn/wrapper MavenWrapperDownloader")
		}
		return false
	}
	if !f.gradlew && !f.startScript {
		return false
	}
	switch t.word {
	case "-classpath":
		return wordIs(rest, `"$CLASSPATH"`) || wordIs(rest, `"\"$CLASSPATH\""`) || wordIs(rest, `"%CLASSPATH%"`)
	case "-jar":
		return f.gradlew && (wordIs(rest, `"$APP_HOME/gradle/wrapper/gradle-wrapper.jar"`) ||
			wordIs(rest, `"%APP_HOME%\gradle\wrapper\gradle-wrapper.jar"`))
	}
	return false
}

// ownJarOperand reports whether the JAR a -jar token launches is this build's own artifact, and
// records it: a path ending in target/<name>.jar or build/libs/<name>.jar inside the checkout
// (the Maven and Gradle output directories), a POM's ${project.build.finalName}.jar or
// ${project.artifactId}-${project.version}.jar, or a file named <artifactId>-<version>.jar that
// settleOwnJars finds among the build's modules. settleOwnJars also requires the directory before
// target/ or build/libs/, or the POM's own directory, to be one of the modules. The operand is the
// first word after the token that is not an option, on the same line; options between them are
// tokens of their own and classify themselves. Anything else, a variable or a word on a
// continuation line included, names a JAR the build does not produce. The words after the operand
// are the program's arguments: an option among them other than ownJarArg, or a variable, can
// name code the JAR loads, so the operand counts as foreign.
func (f *launchFile) ownJarOperand(t launchToken) bool {
	rest := f.restOfLine(t.end)
	if f.pom {
		rest = xmlTag.ReplaceAllString(rest, " ")
	} else if end := strings.TrimRight(rest, " \t\r"); strings.HasSuffix(end, "\\") || strings.HasSuffix(end, "^") ||
		strings.ContainsRune(rest, '`') {
		return false
	}
	words := strings.FieldsFunc(rest, ownJarDelim)
	var op string
	for i, w := range words {
		if !strings.HasPrefix(w, "-") {
			op = w
			for _, a := range words[i+1:] {
				if strings.HasPrefix(a, "-") && !ownJarArg.MatchString(a) || !strings.HasPrefix(a, "-") && strings.ContainsAny(a, "$%") {
					return false
				}
			}
			break
		}
	}
	app := f.appendable(t)
	segs := strings.Split(strings.TrimPrefix(op, "./"), "/")
	n := len(segs)
	name := segs[n-1]
	if f.pom && (name == "${project.build.finalName}.jar" || name == "${project.artifactId}-${project.version}.jar") &&
		!strings.ContainsAny(strings.Join(segs[:n-1], "/"), "$%`\\") {
		f.s.ownJars = append(f.s.ownJars, ownJarRef{tool: "maven", dir: path.Dir(f.rel), file: f.rel, appendable: app})
		f.s.ownJar = true
		return true
	}
	if !ownJarWord.MatchString(op) || !strings.HasSuffix(name, ".jar") || len(name) == len(".jar") {
		return false
	}
	// The directory before target/ or build/libs/ must be a module's clean relative path, which
	// rules out absolute paths, ./.. segments and globs there.
	switch {
	case n >= 2 && segs[n-2] == "target":
		f.s.ownJars = append(f.s.ownJars, ownJarRef{tool: "maven", dir: ownJarDir(segs[:n-2]), name: name, file: f.rel, appendable: app})
	case n >= 3 && segs[n-3] == "build" && segs[n-2] == "libs":
		f.s.ownJars = append(f.s.ownJars, ownJarRef{tool: "gradle", dir: ownJarDir(segs[:n-3]), name: name, file: f.rel, appendable: app})
	case !strings.Contains(name, "*"):
		f.s.ownJars = append(f.s.ownJars, ownJarRef{name: name, file: f.rel, appendable: app})
	default:
		return false
	}
	f.s.ownJar = true
	return true
}

// appendable reports whether a container can pass the launch at t arguments its line does not
// show: t sits in a Dockerfile ENTRYPOINT, in a file that sets a container command or entrypoint
// (Kubernetes passes a container's args after its command, Compose a service's command after its
// entrypoint), or in a file whose values another file splices into a command (spliceFile).
// Whether some file sets such arguments is known only once the whole tree is read
// (containerKeys, argsAppended).
func (f *launchFile) appendable(t launchToken) bool {
	if isDockerfile(f.rel) {
		i := f.lineOf(t.start)
		for i > 0 && dockerContinued(f.line(i-1)) {
			i--
		}
		return dockerEntrypoint.MatchString(f.line(i))
	}
	_, command, entrypoint := keyedFile(f.rel, f.data)
	return spliceFile(f.rel) || command || entrypoint
}

// dockerContinued reports whether a Dockerfile line continues onto the next: it ends in the
// default escape character.
func dockerContinued(line string) bool {
	return strings.HasSuffix(strings.TrimRight(line, " \t\r"), "\\")
}

// spliceFile reports whether rel holds values another file splices into a command: an env file,
// which Compose and shells interpolate, or a Helm values file, which templates render.
func spliceFile(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	if base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env") {
		return true
	}
	return strings.HasPrefix(base, "values") && (strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml"))
}

func isDockerfile(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	return strings.HasPrefix(base, "dockerfile") || strings.HasPrefix(base, "containerfile") || strings.HasSuffix(base, ".dockerfile")
}

// containerKeys records whether a file sets a container's args, command or entrypoint: a
// Dockerfile ENTRYPOINT or CMD instruction, or a key keyedFile reads.
func (s *launchScan) containerKeys(rel string, data []byte) {
	var k uint8
	if isDockerfile(rel) {
		if dockerEntrypointAny.Match(data) {
			k |= keyEntrypoint
		}
		if dockerCmd.Match(data) {
			k |= keyCommand
		}
	} else {
		args, command, entrypoint := keyedFile(rel, data)
		if args {
			s.argsKey = true
		}
		if command {
			k |= keyCommand
		}
		if entrypoint {
			k |= keyEntrypoint
		}
	}
	if k != 0 {
		if s.cmdFiles == nil {
			s.cmdFiles = map[string]uint8{}
		}
		s.cmdFiles[rel] |= k
	}
}

// keyedFile reports whether a non-Dockerfile sets a container's args, command or entrypoint: a
// YAML, JSON or Jsonnet key, quoted or not, in any case and set with : or +:, at the start of a
// line or a flow collection's entry; the same key set with = in an HCL, TOML or Starlark file,
// including as a call's first argument; in a Python file (Pulumi, CDK), a keyword argument set to
// a list, or written key=value with no spaces as PEP 8 does; a JSON patch path ending in /args or
// /command, in a file with an op key; or a withArgs or withCommand call, or its Mixin form. An =
// assignment elsewhere (a Gradle bootRun block, a script's args variable) is not a container
// key. appendable and containerKeys both read it, so they agree on what a key is.
func keyedFile(rel string, data []byte) (args, command, entrypoint bool) {
	assign, py := assignKeyFile(rel), strings.EqualFold(path.Ext(rel), ".py")
	patch := jsonPatchOp.Match(data)
	set := func(colon, eq, kw, p *regexp.Regexp) bool {
		return colon.Match(data) || assign && eq.Match(data) || py && kw.Match(data) || patch && p != nil && p.Match(data)
	}
	return set(containerArgs, containerArgsAssign, containerArgsKeyword, containerArgsPath),
		set(containerCommand, containerCommandAssign, containerCommandKeyword, containerCommandPath),
		set(containerEntrypoint, containerEntrypointAssign, containerEntrypointKeyword, nil)
}

// assignKeyFile reports whether rel is a file where a container key is set with =: HCL
// (Terraform, Nomad, including templated names such as job.nomad.tpl), TOML (fly.toml) or
// Starlark (Bazel BUILD files).
func assignKeyFile(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	if base == "build" || base == "build.bazel" {
		return true
	}
	parts := strings.Split(base, ".")
	for _, ext := range parts[1:] {
		switch ext {
		case "tf", "hcl", "nomad", "toml", "bzl":
			return true
		}
	}
	return false
}

// argsAppended reports whether some file can pass the appendable launch r arguments: any file
// sets a container's args, r's own file sets both an entrypoint and a command, or another file
// sets a command or an entrypoint (a Compose override, a Kubernetes manifest for the image a
// Dockerfile builds, a Kustomize patch). Which container a key belongs to is not resolved.
func (s *launchScan) argsAppended(r ownJarRef) bool {
	if !r.appendable {
		return false
	}
	if s.argsKey || s.cmdFiles[r.file] == keyCommand|keyEntrypoint {
		return true
	}
	for f, k := range s.cmdFiles {
		if f != r.file && k != 0 {
			return true
		}
	}
	return false
}

var (
	dockerEntrypoint           = regexp.MustCompile(`(?i)^\s*entrypoint\s`)
	dockerEntrypointAny        = regexp.MustCompile(`(?im)^\s*entrypoint\s`)
	dockerCmd                  = regexp.MustCompile(`(?im)^\s*cmd\s`)
	containerArgs              = regexp.MustCompile(`(?im)(?:^|[{,\[])[\s-]*["']?args["']?\s*\+?\s*:|\bwithArgs(?:Mixin)?\s*\(`)
	containerCommand           = regexp.MustCompile(`(?im)(?:^|[{,\[])[\s-]*["']?command["']?\s*\+?\s*:|\bwithCommand(?:Mixin)?\s*\(`)
	containerEntrypoint        = regexp.MustCompile(`(?im)(?:^|[{,\[])[\s-]*["']?entrypoint["']?\s*\+?\s*:`)
	containerArgsAssign        = regexp.MustCompile(`(?im)(?:^|[{,\[(])\s*["']?args["']?\s*\+?\s*=`)
	containerCommandAssign     = regexp.MustCompile(`(?im)(?:^|[{,\[(])\s*["']?command["']?\s*\+?\s*=`)
	containerEntrypointAssign  = regexp.MustCompile(`(?im)(?:^|[{,\[(])\s*["']?entrypoint["']?\s*\+?\s*=`)
	containerArgsPath          = regexp.MustCompile(`(?i)path["']?\s*:\s*["']?/\S*/args\b`)
	containerArgsKeyword       = regexp.MustCompile(`(?im)\bargs\s*=\s*\[|(?:^|[,(])\s*args=[^=]`)
	containerCommandKeyword    = regexp.MustCompile(`(?im)\bcommand\s*=\s*\[|(?:^|[,(])\s*command=[^=]`)
	containerEntrypointKeyword = regexp.MustCompile(`(?im)\bentry_?point\s*=\s*\[|(?:^|[,(])\s*entry_?point=[^=]`)
	containerCommandPath       = regexp.MustCompile(`(?i)path["']?\s*:\s*["']?/\S*/command\b`)
	jsonPatchOp                = regexp.MustCompile(`(?im)(?:^|[{,\[])[\s-]*["']?op["']?\s*:`)
)

// ownJarDir is the module directory, "." or a relative slash path, that segs name.
func ownJarDir(segs []string) string {
	if len(segs) == 0 {
		return "."
	}
	return strings.Join(segs, "/")
}

// ownJarArg is a program argument that sets the server's port or its profiles, which select among
// the JAR's own code and add none.
var ownJarArg = regexp.MustCompile(`^--(?:server\.port|spring\.profiles\.active)=[A-Za-z0-9.,_-]*$`)

// ownJarDelim separates the words of a command line, a JSON or YAML list, or an XML element's text.
// A backslash and a brace stay in the word: a Windows path or a property reference.
func ownJarDelim(r rune) bool {
	return r <= ' ' || r == 0x7f || strings.ContainsRune("\"'`,[]();|&<>", r)
}

// ownJarWord is a path the shell and the launcher take literally, but for a * glob.
var ownJarWord = regexp.MustCompile(`^[A-Za-z0-9._+/*-]+$`)

var (
	// jarManifestHazard, in a build file, is a manifest attribute that adds code or access to a
	// -jar launch, or a Spring Boot ZIP or DIR layout, which launches with PropertiesLauncher, or
	// a layout factory, which can launch with anything.
	jarManifestHazard = regexp.MustCompile(`(?i)(?:^|[^\w-])(?:add-opens|add-exports|class-path|launcher-agent-class)\b|addclasspath|layoutfactory|\blayout\s*=\s*['"](?:zip|dir)['"]`)
	// jarPomLayout is a Spring Boot repackage layout in a POM; one not in jarSafeLayouts, a
	// property reference included, may be ZIP or DIR.
	jarPomLayout   = regexp.MustCompile(`(?i)<layout>\s*([^<]*?)\s*</layout>`)
	jarSafeLayouts = map[string]bool{"jar": true, "war": true, "none": true}
	// jarLoaderHazard, anywhere, is Spring Boot's PropertiesLauncher, the loader path it reads, or
	// the repackage layout set as a property.
	jarLoaderHazard = regexp.MustCompile(`(?i)propertieslauncher|loader[._]path|spring-boot\.repackage\.layout`)
	// jarHeaderHazard, anywhere, is an Add-Opens or Add-Exports manifest header: a manifest line,
	// or the quoted attribute name a build script or a bnd file passes on.
	jarHeaderHazard = regexp.MustCompile(`(?im)^[ \t]*add-(?:opens|exports)[ \t]*:|["']add-(?:opens|exports)["']`)
)

var (
	// gradleJarHeader is a line opening a block that configures a JAR task: jar, bootJar,
	// shadowJar, a task of type Jar, register<Jar>, withType(Jar) and the like.
	gradleJarHeader = regexp.MustCompile(`(?im)^[^\n{]*\b\w*jar\b[^\n{]*\{`)
	// gradleCheckedInTree is a file collection built from paths in the checkout.
	gradleCheckedInTree = regexp.MustCompile(`(?i)\b(?:fileTree|files|zipTree|tarTree)\s*\(\s*(?:["']|file\s*\(|dir\s*[:=]|mapOf\s*\(|project\.file|rootProject\.file|layout\.projectDirectory)|\bprojectDirectory\b`)
	// gradleFromLiteral is a from() of a path literal.
	gradleFromLiteral = regexp.MustCompile(`\bfrom\b\s*\(?\s*(?:(?:\w+\.)*file\s*\(\s*)?["']([^"']*)["']`)
	// gradleTextFiles are checked-in files a JAR commonly carries that hold no code.
	gradleTextFiles = map[string]bool{"license": true, "notice": true, "copying": true, "readme": true}
)

// gradleJarTakesCheckedIn reports whether a Gradle build file's JAR task puts files from the
// checkout into its JAR: a from() of a path literal or a file collection over checked-in paths
// (fileTree("vendor"), files("lib/x.jar"), zipTree("lib/x.jar")). Those can carry code no module
// of the graph builds. The module's sources and resolved configurations (from
// sourceSets.main.output, from { configurations.runtimeClasspath... zipTree(it) }) are the
// graph's own code. A text file with a non-code extension, or a license or notice, adds none.
// A from() of a variable is not resolved.
func gradleJarTakesCheckedIn(data []byte) bool {
	for _, loc := range gradleJarHeader.FindAllIndex(data, -1) {
		body := gradleBlock(data, loc[1]-1)
		if gradleCheckedInTree.Match(body) {
			return true
		}
		for _, m := range gradleFromLiteral.FindAllSubmatch(body, -1) {
			if !gradleTextFile(string(m[1])) {
				return true
			}
		}
	}
	return false
}

// gradleBlock is the text of the brace block opening at data[open], to its matching brace or the
// end of the file.
func gradleBlock(data []byte, open int) []byte {
	depth := 0
	for i := open; i < len(data); i++ {
		switch data[i] {
		case '{':
			depth++
		case '}':
			if depth--; depth == 0 {
				return data[open : i+1]
			}
		}
	}
	return data[open:]
}

// gradleTextFile reports whether a from() path names a single text file: a license, notice,
// copying or readme file, or a file whose extension is not that of an archive or class.
func gradleTextFile(p string) bool {
	base := strings.ToLower(path.Base(p))
	stem, ext, dotted := strings.Cut(base, ".")
	if gradleTextFiles[stem] {
		return true
	}
	if !dotted || strings.ContainsAny(base, "*$") {
		return false
	}
	switch path.Ext(base) {
	case ".jar", ".zip", ".war", ".ear", ".class", ".tar", ".gz", ".tgz":
		return false
	}
	return ext != ""
}

// jarHazards records whether a file can change what a -jar launch of the build's artifact runs.
func (s *launchScan) jarHazards(rel string, data []byte) {
	if s.jarHazard {
		return
	}
	base := strings.ToLower(rel[strings.LastIndex(rel, "/")+1:])
	gradle := strings.HasSuffix(base, ".gradle") || strings.HasSuffix(base, ".gradle.kts")
	build := base == "pom.xml" || base == "manifest.mf" || gradle
	if build && jarManifestHazard.Match(data) || jarLoaderHazard.Match(data) || jarHeaderHazard.Match(data) ||
		gradle && gradleJarTakesCheckedIn(data) {
		s.jarHazard = true
		return
	}
	if base == "pom.xml" {
		for _, m := range jarPomLayout.FindAllSubmatch(data, -1) {
			if !jarSafeLayouts[strings.ToLower(string(m[1]))] {
				s.jarHazard = true
				return
			}
		}
	}
}

var (
	// jarPomOutput is a POM plugin's output directory, or the directory or file an Ant task
	// writes (todir, tofile, destfile, dest); jarPomFinalName a literal artifact name;
	// jarPomDestFileName the file name a dependency copy gives its artifact.
	jarPomOutput       = regexp.MustCompile(`(?is)<outputDirectory\b[^>]*>(.*?)</outputDirectory>|\b(todir|tofile|destfile|dest)\s*=\s*["']([^"']*)["']`)
	jarPomDestFileName = regexp.MustCompile(`(?i)<destFileName>\s*([^<]*?)\s*</destFileName>`)
	jarPomFinalName    = regexp.MustCompile(`<finalName>\s*([A-Za-z0-9._+-]+)\s*</finalName>`)
	// jarPomSubdir is an output directory below target/ or of no build output at all, which a
	// target/*.jar glob does not match in, unless it is target itself (pomCopiesIntoTarget).
	jarPomSubdir = regexp.MustCompile(`^(?:\$\{(?:project\.build\.directory|project\.basedir|basedir)\}/|target/)?[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*/?$`)
	// jarGradleDest is a Gradle copy's or archive task's destination; jarGradleLiteralDest a
	// destination given as a plain string literal, $buildDir aside (gradleCopiesIntoLibs).
	jarGradleDest        = regexp.MustCompile(`\b(?:into|destinationDir(?:ectory)?)\b`)
	jarGradleLiteralDest = regexp.MustCompile(`^\s*(?:\(\s*|=\s*|\.set\(\s*)?(?:file\(\s*)?["']((?:\$\{?buildDir\}?/)?[^"'$\n]*)["']`)
	// jarGradleAnt is an Ant task's destination in a Gradle build (ant.copy(todir: ...)).
	jarGradleAnt = regexp.MustCompile(`(?i)\b(todir|tofile|destfile|dest)\s*[:=]\s*["']([^"']*)["']`)
)

// jarCopyHazards records the tools whose build files copy into the directory a -jar glob of the
// build's output matches in, and the POMs' literal artifact names.
func (s *launchScan) jarCopyHazards(rel string, data []byte) {
	if s.copyInto == nil {
		s.copyInto = map[string]bool{}
	}
	base := strings.ToLower(rel[strings.LastIndex(rel, "/")+1:])
	switch {
	case base == "pom.xml":
		for _, m := range jarPomOutput.FindAllSubmatch(data, -1) {
			v := string(m[3])
			var dirs []string
			switch strings.ToLower(string(m[2])) {
			case "":
				dirs = []string{strings.TrimSpace(string(m[1]))}
			case "todir":
				dirs = []string{v}
			case "dest": // a directory for unzip, a file or a directory for get
				dirs = []string{v, path.Dir(v)}
			default:
				dirs = []string{path.Dir(v)}
			}
			for _, d := range dirs {
				if pomCopiesIntoTarget(d) {
					s.copyInto["maven"] = true
				}
			}
		}
		for _, m := range jarPomDestFileName.FindAllSubmatch(data, -1) {
			if strings.ContainsAny(string(m[1]), "/\\") {
				s.copyInto["maven"] = true
			}
		}
		if s.finalNames == nil {
			s.finalNames = map[string][]string{}
		}
		dir := path.Dir(rel)
		for _, m := range jarPomFinalName.FindAllSubmatch(data, -1) {
			s.finalNames[dir] = append(s.finalNames[dir], string(m[1]))
		}
	case strings.HasSuffix(base, ".gradle") || strings.HasSuffix(base, ".gradle.kts"):
		if gradleCopiesIntoLibs(data) {
			s.copyInto["gradle"] = true
		}
		for _, m := range jarGradleAnt.FindAllSubmatch(data, -1) {
			v := string(m[2])
			dirs := []string{path.Dir(v)}
			switch strings.ToLower(string(m[1])) {
			case "todir":
				dirs = []string{v}
			case "dest":
				dirs = []string{v, path.Dir(v)}
			}
			for _, d := range dirs {
				if gradleDestHitsLibs(d) {
					s.copyInto["gradle"] = true
				}
			}
		}
	}
}

// pomCopiesIntoTarget reports whether a POM output directory d can be the directory a
// target/*.jar glob matches in: anything but a plain directory whose last segment is not target.
// A directory relative to one POM is taken as relative to every module, since a plugin's
// configuration is inherited: mall-admin/target in a root POM can be a module's target.
func pomCopiesIntoTarget(d string) bool {
	if !jarPomSubdir.MatchString(d) || strings.Contains(d, "..") {
		return true
	}
	if rest, ok := strings.CutPrefix(d, "${project.build.directory}"); ok {
		d = "target" + rest
	}
	for _, p := range []string{"${project.basedir}/", "${basedir}/"} {
		d = strings.TrimPrefix(d, p)
	}
	// The module directory itself holds target/, so a copy of a tree into it can write there.
	c := path.Clean(d)
	return c == "." || path.Base(c) == "target"
}

// gradleCopiesIntoLibs reports whether a Gradle build file can copy or write into a libs
// directory: some into or destinationDir(ectory) whose argument is not a string literal on its
// own line, or is one naming libs. A variable, a closure or a provider chain can resolve to
// build/libs, so only a literal clears it.
func gradleCopiesIntoLibs(data []byte) bool {
	for _, loc := range jarGradleDest.FindAllIndex(data, -1) {
		m := jarGradleLiteralDest.FindSubmatch(data[loc[1]:])
		if m == nil || gradleDestHitsLibs(string(m[1])) {
			return true
		}
	}
	return false
}

// gradleDestHitsLibs reports whether a Gradle destination can be build/libs or a directory above
// it, where a copied tree can land in it: one naming libs, one using a variable other than a
// leading $buildDir, or build, the project directory or a parent of it.
func gradleDestHitsLibs(v string) bool {
	v = strings.ToLower(v)
	for _, p := range []string{"${builddir}", "$builddir"} {
		if rest, ok := strings.CutPrefix(v, p); ok {
			v = "build" + rest
			break
		}
	}
	if strings.Contains(v, "libs") || strings.ContainsAny(v, "$`\\") {
		return true
	}
	c := path.Clean(v)
	return c == "." || c == "build" || c == ".." || strings.HasPrefix(c, "../")
}

// settleOwnJars withholds Searched for the -jar launches ownJarOperand accepted when the build can
// change what its JAR runs, or when one names a JAR g's modules do not produce: a file name that is
// none of their artifacts, an output directory that is not a module of the tool that writes it,
// a name in it that is not that module's artifact, or a glob there while the build copies other
// JARs into it.
func (s *launchScan) settleOwnJars(g *buildgraph.Graph) {
	if !s.ownJar {
		return
	}
	if s.jarHazard || g == nil {
		s.unreadable()
		return
	}
	for _, r := range s.ownJars {
		if !s.ownJarProduced(g, r) || s.argsAppended(r) {
			s.unreadable()
			return
		}
	}
}

// ownJarProduced reports whether one of g's modules produces the JAR r names.
func (s *launchScan) ownJarProduced(g *buildgraph.Graph, r ownJarRef) bool {
	for _, m := range g.Modules {
		tool := m.Tool
		if tool == "" {
			tool = g.Tool.Name
		}
		if r.tool != "" && (m.Path != r.dir || tool != r.tool) {
			continue
		}
		switch {
		case r.name == "":
			return true
		case strings.Contains(r.name, "*"):
			return !s.copyInto[r.tool]
		case ownArtifactName(r.name, s.artifactStems(m, tool, r.tool != "")):
			return true
		}
	}
	return false
}

// artifactStems are the file names, without .jar, a module's tool gives its artifact:
// artifactId-version, under each Gradle alias too, an unversioned name for a Gradle project
// without a version when the launch names its output directory (inOutput), and the literal
// finalNames of the module's own POM.
func (s *launchScan) artifactStems(m buildgraph.Module, tool string, inOutput bool) []string {
	var stems []string
	for _, nd := range m.Nodes {
		if nd.ID != m.Root || nd.Artifact == "" {
			continue
		}
		names := []string{nd.Artifact}
		if tool == "gradle" {
			for _, a := range m.Aliases {
				names = append(names, a[strings.LastIndex(a, ":")+1:])
			}
		}
		for _, a := range names {
			switch {
			case nd.Version != "" && nd.Version != "unspecified":
				stems = append(stems, a+"-"+nd.Version)
			case tool == "gradle" && inOutput:
				stems = append(stems, a)
			}
		}
	}
	if tool == "maven" {
		stems = append(stems, s.finalNames[m.Path]...)
	}
	return stems
}

// ownArtifactName reports whether name is <stem>.jar or <stem>-<classifier>.jar for one of stems.
func ownArtifactName(name string, stems []string) bool {
	stem, ok := strings.CutSuffix(name, ".jar")
	if !ok {
		return false
	}
	for _, st := range stems {
		if rest, ok := strings.CutPrefix(stem, st); ok && (rest == "" || len(rest) > 1 && rest[0] == '-') {
			return true
		}
	}
	return false
}

// templateMavenProperty reports whether t is a property the Maven wrapper template passes
// Maven's JVM, closed as the template closes it: its home and project directory.
func (f *launchFile) templateMavenProperty(t launchToken) bool {
	rest := f.restOfLine(t.end)
	switch t.word {
	case "-Dmaven.home=${M2_HOME", "-Dmaven.multiModuleProjectDirectory=${MAVEN_PROJECTBASEDIR":
		return wordIs(rest, `}"`)
	case "-Dmaven.multiModuleProjectDirectory=%MAVEN_PROJECTBASEDIR%":
		return wordIs(rest, `"`)
	}
	return false
}

// restOfLine is the text from i to the end of its line.
func (f *launchFile) restOfLine(i int) string {
	rest := f.data[i:]
	if j := bytes.IndexByte(rest, '\n'); j >= 0 {
		rest = rest[:j]
	}
	return string(rest)
}

// wordIs reports whether rest, the rest of a line, starts with the words lit, ending there: the
// shell would join anything else that follows onto the same word.
func wordIs(rest, lit string) bool {
	after, ok := strings.CutPrefix(rest, lit)
	return ok && (after == "" || strings.ContainsRune(" \t\r", rune(after[0])))
}

// templateWrapperJar reports whether the Maven wrapper batch script is an upstream template,
// Apache Maven Wrapper 3.1.0 to 3.3.4 or Takari maven-wrapper 0.2.0 to 0.5.6, with at most its
// comments edited. cmd can assign WRAPPER_JAR in more forms than a reader can enumerate, so the
// script's code lines must be exactly a template's.
func (f *launchFile) templateWrapperJar() bool {
	fp, ok := cmdCodeFingerprint(f.data)
	return ok && mavenWrapperTemplates[fp]
}

// cmdCodeFingerprint hashes a batch script's code lines, line endings normalized to LF. A REM line
// is dropped as inert unless cmd could read it as more: it continues onto the next line or
// follows one that does (a trailing caret), or it holds a %- or !-expansion, which cmd expands
// before it sees REM. A script with a control character or a bare CR does not fingerprint.
func cmdCodeFingerprint(data []byte) (string, bool) {
	for _, c := range data {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return "", false
		}
	}
	s := strings.ReplaceAll(string(data), "\r\n", "\n")
	if strings.Contains(s, "\r") {
		return "", false
	}
	var code []string
	prev := ""
	for _, line := range strings.Split(s, "\n") {
		inert := cmdRemark.MatchString(line) && !strings.HasSuffix(line, "^") &&
			!strings.HasSuffix(prev, "^") && !strings.ContainsAny(line, "%!")
		if !inert {
			code = append(code, line)
		}
		prev = line
	}
	sum := sha256.Sum256([]byte(strings.Join(code, "\n")))
	return hex.EncodeToString(sum[:]), true
}

var cmdRemark = regexp.MustCompile(`(?i)^[ \t]*@?rem(?:[ \t].*)?$`)

// mavenWrapperTemplates holds cmdCodeFingerprint of each upstream mvnw.cmd that sets WRAPPER_JAR.
// Apache's bin, script and source distributions of one version share a fingerprint.
var mavenWrapperTemplates = map[string]bool{
	"361e8194ff865c389423b366b89af6122b00741b7fc227e7b67fef73449f92bb": true, // Apache 3.1.0
	"32243652660a21297ee4ef74b08025536cd43de597aaadbbfe20d449647fe461": true, // Apache 3.1.1
	"62e6ee9ee0de204630df0655b0db4da482390adfe3f754f1c4db80a5f70ce446": true, // Apache 3.2.0
	"7059f02bbdf291eebf37742187667ef957215e70a4e603105e33de51eae945e0": true, // Apache 3.3.0
	"0798e541fffc8ff869baf784d4b07f8c94749a64d53d3375c92d19a81ac9c6c7": true, // Apache 3.3.1
	"af4d20788627bc79ddfe2f12702fae6d8aa9d2feb0c906190a937e5b41fb1f21": true, // Apache 3.3.2
	"66749d2f050b62555a642b05a794f233d10a1425d177bfeb2f5b93ecc77ef16b": true, // Apache 3.3.3
	"271a94bbeb24386f1df54627001ba5aec6f47f8b02ff33a7cfa3f42d9319168e": true, // Apache 3.3.4
	"754dab2ba0d567eb745b9a67dc42813f558703566ea72bec5b80d50a321bd18e": true, // Takari 0.2.0-0.2.3
	"435e6e62dc1a422f17eaef93a1bda62db7d906cef0d8074e29bb6b3e81164421": true, // Takari 0.3.0
	"fd1747782fd67e3f7410c3f3e894b5de5d1161dbd73a9094e257d92e0bce4dcf": true, // Takari 0.4.0-0.4.1
	"368ded28290c11b6446f509aaf919423ed7508d952e3e3b66649fd1ac2e51398": true, // Takari 0.4.2
	"4a0ccc5ddbd763b3889fc73bd2bf9fffdf367e4dd709dea798e8556b36bd501e": true, // Takari 0.5.0
	"f8da45155d4b2a00cfbe30da7629ccc181e39de5d6ec20dec0ad964f6ecf8a58": true, // Takari 0.5.1
	"b512311cfcb31dbd3cf979701f51d0e8a205a9a0350bd737fe35ce5f57fb0d80": true, // Takari 0.5.2
	"208c88bee29a70badda9f4e9ac140739c520ca12ea6495e098efc87476a5885d": true, // Takari 0.5.3
	"eaa16c19994ec84d7a3a64dc7e55e3ba010156f2c9b5dcb61ee446420776a567": true, // Takari 0.5.4
	"216dbbf27259f1694f54f8cc266df42c744c0f16e0e4ff0f23a3c69dce90d40a": true, // Takari 0.5.5
	"446bf654db5d5da0baa81a1b4e67b9252bec9b7da045d9d218073ddeeb134fd2": true, // Takari 0.5.6
}

// name classifies one occurrence of a launch name. An option variable is accounted for when it
// is expanded, sits on a comment line, is assigned a literal on the same line, or a YAML/JSON
// reader attached it to a scalar value; a DSL property when its value is a literal list.
func (f *launchFile) name(a, b int) {
	n := string(f.data[a:b])
	switch n {
	case "Launcher-Agent-Class":
		f.s.agent()
		return
	case "Class-Path":
		f.s.unreadable()
		return
	}
	if f.inSpan(a, spanTest) || buildToolVars[n] || launchExpansion(f.data, a, b) {
		return
	}
	if n == "argLine" && (a == 0 || f.data[a-1] != '<') {
		return // Maven's argLine is an element; the name elsewhere is a reference to it
	}
	li := f.lineOf(a)
	line := f.line(li)
	if isLaunchCommentLine(line) || f.template[li] {
		return
	}
	if launchDSLNames[n] {
		f.dsl(a, b)
		return
	}
	if n == "CLASSPATH" {
		// java reads CLASSPATH when no -cp is given: it names the launch's code. The Gradle
		// templates set it for their own -classpath "$CLASSPATH"; the Maven wrapper converts
		// it for Cygwin and passes its own -classpath.
		if !f.gradlew && !f.mavenw && !f.startScript && strings.TrimSpace(line[:a-f.lines[li]]) != "unset" {
			f.s.unreadable()
		}
		return
	}
	if n == "jvmArgumentProviders" {
		if _, ok := f.testScope(a); !ok {
			f.s.unreadable() // providers compute options at execution time
		}
		return
	}
	if f.yamlLines[li+1] {
		return
	}
	col := a - f.lines[li]
	if v, ok := assignedValue(line, col, col+len(n)); ok {
		f.s.optionString(v)
		return
	}
	switch strings.TrimSpace(line[:col]) + "|" + strings.TrimSpace(line[col+len(n):]) {
	case "export|", "unset|":
		return
	}
	f.s.unreadable()
}

// launchExpansion reports whether data[a:b] is a variable expansion: $NAME, ${NAME}, $(NAME),
// %NAME%, !NAME!, or a GitHub Actions ${{ env.NAME }} context reference.
func launchExpansion(data []byte, a, b int) bool {
	switch {
	case a >= 1 && data[a-1] == '$':
		return true
	case a >= 2 && data[a-2] == '$' && (data[a-1] == '{' || data[a-1] == '('):
		return true
	case a >= 1 && b < len(data) && (data[a-1] == '%' && data[b] == '%' || data[a-1] == '!' && data[b] == '!'):
		return true
	}
	lineStart := bytes.LastIndexByte(data[:a], '\n') + 1
	prefix := string(data[lineStart:a])
	for _, ctx := range []string{"env.", "secrets.", "vars."} {
		if strings.HasSuffix(prefix, ctx) {
			open := strings.LastIndex(prefix, "${{")
			return open >= 0 && !strings.Contains(prefix[open:], "}}")
		}
	}
	return false
}

func isLaunchCommentLine(line string) bool {
	t := strings.TrimSpace(line)
	lower := strings.ToLower(t)
	for _, p := range []string{"#", "//", "/*", "*", "<!--", "::", ";"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	lower = strings.TrimPrefix(lower, "@")
	return lower == "rem" || strings.HasPrefix(lower, "rem ") || strings.HasPrefix(lower, "rem\t")
}

var assignOp = regexp.MustCompile(`^\s*(\?=|\+=|::=|:=|=|:)\s*`)

// assignedValue returns the literal a line assigns to the name at line[a:b]: NAME=value and
// the make/YAML/JSON/TOML operators, Dockerfile's legacy ENV NAME value, Kotlin's "NAME" to
// "value", and a call's ("NAME", "value"). ok is false when the value is not on the line.
func assignedValue(line string, a, b int) (string, bool) {
	after := line[b:]
	quoted := a > 0 && (line[a-1] == '"' || line[a-1] == '\'') && strings.HasPrefix(after, line[a-1:a])
	if quoted {
		after = after[1:]
	}
	var rest string
	op := ""
	if m := assignOp.FindStringSubmatch(after); m != nil {
		op, rest = m[1], after[len(m[0]):]
	} else if strings.EqualFold(strings.TrimSpace(line[:a]), "ENV") && strings.HasPrefix(after, " ") {
		op, rest = "ENV", strings.TrimSpace(after)
	} else if m := regexp.MustCompile(`^\s+to\s+|^\s*,\s*`).FindString(after); quoted && m != "" {
		if strings.TrimSpace(m) == "," && !strings.HasSuffix(strings.TrimRight(line[:a-1], " \t"), "(") {
			return "", false
		}
		op, rest = strings.TrimSpace(m), after[len(m):]
	} else {
		return "", false
	}
	rest = strings.TrimRight(rest, " \t\r")
	if rest != "" && (rest[0] == '"' || rest[0] == '\'') {
		q := rest[0]
		for i := 1; i < len(rest); i++ {
			switch rest[i] {
			case '\\':
				i++
			case q:
				return rest[1:i], true
			}
		}
		return "", false // the literal continues past the line
	}
	if op == ":" && (rest == "" || rest[0] == '|' || rest[0] == '>') {
		return "", false // a YAML block or nested value
	}
	if i := strings.Index(rest, " #"); i >= 0 {
		rest = rest[:i]
	}
	return rest, true
}

var xmlTag = regexp.MustCompile(`<[^>]*>`)

// dsl classifies a Gradle or Maven DSL property that becomes launch options: an XML element's
// text (a property reference in it cannot be read), or an assignment, call or set(...) whose value is a
// list of string literals (or a + concatenation of such lists). Anything else cannot be read.
func (f *launchFile) dsl(a, b int) {
	d := f.data
	n := string(d[a:b])
	if a >= 2 && d[a-2] == '<' && d[a-1] == '/' {
		return
	}
	if a >= 1 && d[a-1] == '<' {
		gt := bytes.IndexByte(d[b:], '>')
		if gt < 0 {
			f.s.unreadable()
			return
		}
		if gt > 0 && d[b+gt-1] == '/' {
			return
		}
		body := d[b+gt+1:]
		end := bytes.Index(body, []byte("</"+n+">"))
		if end < 0 {
			f.s.unreadable()
			return
		}
		f.s.optionString(xmlTag.ReplaceAllString(string(body[:end]), " "))
		return
	}
	rest := string(d[b:])
	trimmed := strings.TrimLeft(rest, " \t")
	switch {
	case strings.HasPrefix(trimmed, "+="):
		trimmed = trimmed[2:]
	case strings.HasPrefix(trimmed, "=") && !strings.HasPrefix(trimmed, "=="):
		trimmed = trimmed[1:]
	case strings.HasPrefix(trimmed, ".set("):
		trimmed = trimmed[4:]
	case strings.HasPrefix(trimmed, "("):
	case len(trimmed) < len(rest) && (strings.HasPrefix(trimmed, `"`) || strings.HasPrefix(trimmed, "'")):
	default:
		f.s.unreadable() // a read, or a mutation of the property
		return
	}
	lits, ok := literalListExpr(trimmed)
	if !ok {
		f.s.unreadable()
		return
	}
	for _, lit := range lits {
		if strings.Contains(lit, "$") {
			if prop, ok := strings.CutPrefix(lit, "-D"); !ok || strings.ContainsAny(strings.SplitN(prop, "=", 2)[0], "$") {
				f.s.unreadable()
				continue
			}
		}
		f.s.options([]string{lit})
	}
}

var (
	stringLiteral = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'`)
	listWrapper   = regexp.MustCompile(`\b(listOf|mutableListOf|arrayListOf|setOf|arrayOf)\b|[()\[\],\s]`)
)

// literalListExpr reads a value made only of string literals: string literals and list
// expressions of them, joined by + or ,, followed by nothing but the end of the statement.
func literalListExpr(text string) ([]string, bool) {
	var lits []string
	for {
		text = strings.TrimLeft(text, " \t")
		var item string
		if strings.HasPrefix(text, `"`) || strings.HasPrefix(text, "'") {
			loc := stringLiteral.FindStringIndex(text)
			if loc == nil || loc[0] != 0 {
				return nil, false
			}
			item = text[:loc[1]]
		} else {
			expr, ok := bracketedExpr(text)
			if !ok {
				return nil, false
			}
			item = expr
		}
		if strings.TrimSpace(listWrapper.ReplaceAllString(stringLiteral.ReplaceAllString(item, ""), "")) != "" {
			return nil, false
		}
		for _, m := range stringLiteral.FindAllStringSubmatch(item, -1) {
			lits = append(lits, m[1]+m[2])
		}
		text = strings.TrimLeft(text[len(item):], " \t")
		if strings.HasPrefix(text, "+") || strings.HasPrefix(text, ",") {
			text = text[1:]
			continue
		}
		end, _, _ := strings.Cut(text, "\n")
		end = strings.TrimSpace(end)
		for _, p := range []string{"", "}", ")", ";", "//", "/*"} {
			if p == "" && end == "" || p != "" && strings.HasPrefix(end, p) {
				return lits, true
			}
		}
		return nil, false
	}
}

// bracketedExpr returns the leading list expression of text: an optional wrapper call name,
// then a balanced (...) or [...] group. ok is false when text does not start that way.
func bracketedExpr(text string) (string, bool) {
	trimmed := strings.TrimLeft(text, " \t")
	i := 0
	for i < len(trimmed) && (trimmed[i] == '_' || trimmed[i] >= 'a' && trimmed[i] <= 'z' || trimmed[i] >= 'A' && trimmed[i] <= 'Z') {
		i++
	}
	if i >= len(trimmed) || trimmed[i] != '(' && trimmed[i] != '[' {
		return "", false
	}
	depth := 0
	var quote byte
	for j := i; j < len(trimmed); j++ {
		c := trimmed[j]
		switch {
		case quote != 0:
			if c == '\\' {
				j++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '(' || c == '[':
			depth++
		case c == ')' || c == ']':
			depth--
			if depth == 0 {
				return trimmed[:j+1], true
			}
		}
	}
	return "", false
}

// javaContext finds the options that are launch options only after a java command word: -p
// (the module path) and @argfile. A k8s command/args split is joined by the YAML reader.
func (f *launchFile) javaContext() {
	for _, ll := range f.logicalLines() {
		seg := f.data[ll[0]:ll[1]]
		if isLaunchCommentLine(string(seg)) || !bytes.Contains(seg, []byte("java")) {
			continue
		}
		java := false
		for _, loc := range launchWords.FindAllIndex(seg, -1) {
			w := string(seg[loc[0]:loc[1]])
			switch {
			case strings.ContainsAny(w[:1], ";|&"):
				java = false
			case isJavaCommand(w):
				java = true
			case java && javaContextOption(w) && !f.inSpan(ll[0]+loc[0], spanTest):
				f.s.unreadable()
			}
		}
	}
}

func javaContextOption(w string) bool { return w == "-p" || len(w) > 1 && w[0] == '@' }

// yaml reads a YAML or JSON file: a mapping entry NAME: scalar, a {name: NAME, value: scalar}
// entry, and a container's command/args, whose concatenation is one command line. A name the
// reader attaches to a scalar is classified here and its line recorded; a name it cannot
// attach (valueFrom, a block it cannot parse) is left to withhold Searched.
func (f *launchFile) yaml() {
	dec := yaml.NewDecoder(bytes.NewReader(f.data))
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			return
		}
		f.yamlNode(&doc)
	}
}

func (f *launchFile) yamlNode(n *yaml.Node) {
	if n.Kind != yaml.MappingNode {
		for _, c := range n.Content {
			f.yamlNode(c)
		}
		return
	}
	var nameNode, value *yaml.Node
	var command, args []string
	hasCommand := false
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		switch {
		case k.Value == "name" && v.Kind == yaml.ScalarNode && isJVMOptionVar(v.Value):
			nameNode = v
		case k.Value == "value":
			value = v
		case isJVMOptionVar(k.Value) && v.Kind == yaml.ScalarNode:
			f.s.optionString(v.Value)
			f.yamlLines[k.Line] = true
		case k.Value == "command" || k.Value == "entrypoint":
			hasCommand = k.Value == "command" || hasCommand
			command = append(command, yamlWords(v)...)
		case k.Value == "args":
			args = yamlWords(v)
		}
		f.yamlNode(v)
	}
	if nameNode != nil && value != nil && value.Kind == yaml.ScalarNode {
		f.s.optionString(value.Value)
		f.yamlLines[nameNode.Line] = true
	}
	java := false
	for _, w := range append(command, args...) {
		if isJavaCommand(w) {
			java = true
		} else if java && javaContextOption(w) {
			f.s.unreadable()
		}
	}
	if !hasCommand && len(command) == 0 {
		for _, w := range args {
			if javaContextOption(w) && w != "-p" {
				f.s.unreadable() // the image's entrypoint may be java
			}
		}
	}
}

// yamlWords returns a command's words: a list's scalars, or a scalar's fields.
func yamlWords(n *yaml.Node) []string {
	switch n.Kind {
	case yaml.ScalarNode:
		return strings.Fields(n.Value)
	case yaml.SequenceNode:
		var out []string
		for _, c := range n.Content {
			if c.Kind == yaml.ScalarNode {
				out = append(out, strings.Fields(c.Value)...)
			}
		}
		return out
	}
	return nil
}
