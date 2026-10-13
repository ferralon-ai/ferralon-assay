package kotlinanalysis

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// runtimeclasspath.go — read the exact runtime classpath a Gradle `application` build hands
// the JVM. The start script Gradle generates (build/scripts/<name>, copied to
// build/install/<name>/bin/<name> by installDist) carries the full ordered classpath and the
// launch main class:
//
//	CLASSPATH=$APP_HOME/lib/app-1.0.jar:$APP_HOME/lib/minio-8.5.4.jar:...
//	set -- \
//	        -classpath "$CLASSPATH" \
//	        io.ktor.server.netty.EngineMain \
//
// Without a lockfile the inventory only knows the declared direct dependencies, so the
// transitive closure (and the Kotlin stdlib, which the Kotlin Gradle plugin adds implicitly)
// would stay unloaded. The start script names every JAR, transitive ones included, so when it
// is present it replaces the inventory as the list of code to load.

// runtimeClasspath is the launch classpath read from the build's start scripts.
type runtimeClasspath struct {
	// entries are the classpath JAR file names, in launch order when ordered is true.
	entries []string
	// ordered is true when every start script found carries the same classpath, so the JVM's
	// first-definition-wins rule applies to it: a later JAR's copy of an already-defined
	// class is never loaded.
	ordered bool
	// mainClasses are the launch main classes the scripts name (binary names, '/'-separated).
	mainClasses []string
	// libDirs are the directories that hold the classpath JARs when installDist ran.
	libDirs []string
	// launchAgents are the DEFAULT_JVM_OPTS options, from any script, that load a Java agent or
	// extend the boot classpath.
	launchAgents []string
}

// startScriptDirs are where Gradle writes the generated start scripts: `startScripts` (run by
// `assemble`/`build` for the application plugin) and `installDist`.
var startScriptDirs = []string{
	filepath.Join("build", "scripts"),
	filepath.Join("build", "install", "*", "bin"),
}

var javaBinaryName = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*$`)

// findRuntimeClasspath reads every Gradle start script under buildDir. ok is false when none
// parses, and the caller falls back to the inventory.
func findRuntimeClasspath(buildDir string) (runtimeClasspath, bool) {
	var scripts []string
	for _, pattern := range startScriptDirs {
		dirs, _ := filepath.Glob(filepath.Join(buildDir, pattern))
		for _, d := range dirs {
			entries, err := os.ReadDir(d)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if !e.IsDir() && !strings.HasSuffix(e.Name(), ".bat") {
					scripts = append(scripts, filepath.Join(d, e.Name()))
				}
			}
		}
	}
	sort.Strings(scripts)

	var rc runtimeClasspath
	var first []string
	seenEntry := map[string]bool{}
	seenMain := map[string]bool{}
	parsed := 0
	rc.ordered = true
	for _, s := range scripts {
		cp, main, ok := parseStartScript(s)
		if !ok {
			continue
		}
		parsed++
		rc.launchAgents = append(rc.launchAgents, launchAgentOptions(s)...)
		if parsed == 1 {
			first = cp
		} else if strings.Join(cp, ":") != strings.Join(first, ":") {
			rc.ordered = false
		}
		for _, e := range cp {
			if !seenEntry[e] {
				seenEntry[e] = true
				rc.entries = append(rc.entries, e)
			}
		}
		if main != "" && !seenMain[main] {
			seenMain[main] = true
			rc.mainClasses = append(rc.mainClasses, main)
		}
	}
	if parsed == 0 {
		return runtimeClasspath{}, false
	}
	if !rc.ordered {
		sort.Strings(rc.entries)
	}
	sort.Strings(rc.mainClasses)
	rc.libDirs, _ = filepath.Glob(filepath.Join(buildDir, "build", "install", "*", "lib"))
	return rc, true
}

// parseStartScript reads a Gradle unix start script. The classpath is accepted only when every
// entry is a plain $APP_HOME/lib/<file>.jar; any other form (a wildcard, a module path, a
// hand-edited script) makes the script unusable rather than half-read. main is "" when the
// launch line names no plain class (e.g. a --module launch).
func parseStartScript(path string) (classpath []string, main string, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", false
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if sc.Err() != nil {
		return nil, "", false
	}

	found := false
	for i, line := range lines {
		if !found && strings.HasPrefix(line, "CLASSPATH=") {
			value := strings.TrimPrefix(line, "CLASSPATH=")
			if value == "" {
				return nil, "", false
			}
			for _, e := range strings.Split(value, ":") {
				name, isLib := strings.CutPrefix(e, "$APP_HOME/lib/")
				if !isLib || name == "" || strings.ContainsAny(name, `/*"'$`) || !strings.HasSuffix(name, ".jar") {
					return nil, "", false
				}
				classpath = append(classpath, name)
			}
			found = true
			continue
		}
		if strings.TrimSpace(line) == `-classpath "$CLASSPATH" \` && i+1 < len(lines) {
			cand := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(lines[i+1]), `\`))
			if javaBinaryName.MatchString(cand) {
				main = strings.ReplaceAll(cand, ".", "/")
			}
		}
	}
	return classpath, main, found
}

// launchAgentPrefixes are JVM options that run code from outside the classpath.
var launchAgentPrefixes = []string{"-javaagent:", "-agentlib:", "-agentpath:", "-Xbootclasspath"}

// launchAgentOptions returns the options on a start script's DEFAULT_JVM_OPTS lines that begin
// with a launchAgentPrefixes entry. Gradle writes each option quoted
// (DEFAULT_JVM_OPTS='"-Xmx64m" "-javaagent:/opt/a.jar"'), so quotes are stripped first.
func launchAgentOptions(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		value, ok := strings.CutPrefix(strings.TrimSpace(line), "DEFAULT_JVM_OPTS=")
		if !ok {
			continue
		}
		for _, opt := range strings.Fields(strings.NewReplacer(`"`, " ", "'", " ", `\`, " ").Replace(value)) {
			for _, p := range launchAgentPrefixes {
				if strings.HasPrefix(opt, p) {
					out = append(out, opt)
					break
				}
			}
		}
	}
	return out
}

// classpathJar is one start-script classpath entry located on disk.
type classpathJar struct {
	path string
	// group, artifact and version are read from the Gradle cache path the file name was
	// found under; empty when the cache does not hold it under exactly one coordinate.
	group, artifact, version string
}

func (j classpathJar) packageURL() string {
	if j.group == "" {
		return ""
	}
	return "pkg:maven/" + j.group + "/" + j.artifact
}

// locateClasspathJar finds a classpath entry's file: the installDist lib directory, the
// project's own build/libs, then the Gradle module cache by file name. ok is false when no file is found, or when only the cache holds it and
// its copies there disagree on coordinate or bytes: which one the build ran is then unknown.
func locateClasspathJar(buildDir string, rc runtimeClasspath, index map[string][]string, name string) (classpathJar, bool) {
	group, artifact, version := cacheCoordinate(index[name])
	for _, d := range append(append([]string(nil), rc.libDirs...), filepath.Join(buildDir, firstPartyJarDir)) {
		if p := filepath.Join(d, name); fileExists(p) {
			return classpathJar{path: p, group: group, artifact: artifact, version: version}, true
		}
	}
	hits := index[name]
	if group == "" || !sameBytes(hits) {
		return classpathJar{}, false
	}
	return classpathJar{path: hits[0], group: group, artifact: artifact, version: version}, true
}

// gradleCacheIndex maps each JAR file name in the Gradle module caches to its paths
// (<root>/<group>/<artifact>/<version>/<hash>/<file>).
func gradleCacheIndex(buildDir string) map[string][]string {
	index := map[string][]string{}
	for _, root := range gradleCacheRoots(buildDir) {
		hits, _ := filepath.Glob(filepath.Join(root, "*", "*", "*", "*", "*.jar"))
		for _, h := range hits {
			index[filepath.Base(h)] = append(index[filepath.Base(h)], h)
		}
	}
	return index
}

// cacheCoordinate returns the single group/artifact/version the cache paths agree on, or ""
// when there are none or they disagree.
func cacheCoordinate(paths []string) (group, artifact, version string) {
	for _, p := range paths {
		versionDir := filepath.Dir(filepath.Dir(p))
		v := filepath.Base(versionDir)
		a := filepath.Base(filepath.Dir(versionDir))
		g := filepath.Base(filepath.Dir(filepath.Dir(versionDir)))
		if group == "" {
			group, artifact, version = g, a, v
			continue
		}
		if g != group || a != artifact || v != version {
			return "", "", ""
		}
	}
	return group, artifact, version
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
