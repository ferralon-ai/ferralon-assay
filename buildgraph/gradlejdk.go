package buildgraph

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// gradleJDKRange is the oldest Gradle release that runs on each JDK, from Gradle's compatibility
// matrix; a Gradle older than a JDK's entry cannot run on that JDK.
var gradleJDKRange = []struct {
	jdk          int
	major, minor int
}{
	{17, 7, 3}, {18, 7, 5}, {19, 7, 6}, {20, 8, 3}, {21, 8, 5}, {22, 8, 8}, {23, 8, 10}, {24, 8, 14}, {25, 9, 1},
}

// maxGradleJDK is the newest JDK the Gradle release runs on, or 0 when that is not known: the
// release is older than the matrix (its newest JDK is then 16 or older), or reaches the matrix's
// newest row (it may run on JDKs newer than the matrix lists). Either way it is left to the job.
func maxGradleJDK(major, minor int) int {
	jdk := 0
	for i, e := range gradleJDKRange {
		if major > e.major || major == e.major && minor >= e.minor {
			if i == len(gradleJDKRange)-1 {
				return 0
			}
			jdk = e.jdk
		}
	}
	return jdk
}

// minGradleJDK is the oldest JDK the Gradle release runs on.
func minGradleJDK(major int) int {
	if major >= 9 {
		return 17
	}
	return 8
}

var wrapperVersion = regexp.MustCompile(`gradle-(\d+)\.(\d+)(?:[.\-][^/]*)?-(?:bin|all)\.zip$`)

// wrapperGradleVersion reads the Gradle release the wrapper of dir downloads.
func wrapperGradleVersion(dir string) (major, minor int, ok bool) {
	f, err := os.Open(filepath.Join(dir, "gradle", "wrapper", "gradle-wrapper.properties"))
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		k, v, found := strings.Cut(s.Text(), "=")
		if !found || strings.TrimSpace(k) != "distributionUrl" {
			continue
		}
		m := wrapperVersion.FindStringSubmatch(strings.TrimSpace(v))
		if m == nil {
			return 0, 0, false
		}
		major, _ = strconv.Atoi(m[1])
		minor, _ = strconv.Atoi(m[2])
		return major, minor, true
	}
	return 0, 0, false
}

// jdkMajorAt is the feature release of the JDK installed at home, read from its release file,
// or 0 when that cannot be read.
func jdkMajorAt(home string) int {
	f, err := os.Open(filepath.Join(home, "release"))
	if err != nil {
		return 0
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if v, ok := strings.CutPrefix(s.Text(), "JAVA_VERSION="); ok {
			return javaMajor(strings.Trim(v, `"`))
		}
	}
	return 0
}

// jobJavaHome is the JDK a Gradle wrapper runs on in env: JAVA_HOME, else the java on PATH.
func jobJavaHome(env []string) string {
	if h := envValue(env, "JAVA_HOME"); h != "" {
		return h
	}
	p, err := lookPath("java", env)
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		p = resolved
	}
	return filepath.Dir(filepath.Dir(p))
}

var providedJDK = regexp.MustCompile(`^JAVA_HOME_(\d+)_[A-Za-z0-9]+$`)

// gradleJDK returns env with JAVA_HOME and PATH set to a JDK the wrapper's Gradle runs on, when
// the job's own JDK is newer than that Gradle supports. The JDK is one the job environment
// provides as JAVA_HOME_<feature>_<arch> (as GitHub-hosted runners and setup-java do), the newest
// in the Gradle's range. env is returned unchanged when the run conditions state a JDK or a
// JAVA_HOME or PATH (the build then runs on what they state), when the build names its own
// Gradle JVM (org.gradle.java.home), when the wrapper's Gradle release or the job's JDK cannot be
// read, when the job's JDK is in range, or when no provided JDK is; the build then runs as the
// job set it up, and a Gradle that cannot run there fails the step.
//
// provided names the variable of the JDK chosen, for the graph to record.
func gradleJDK(dir string, env []string, c Conditions) (out []string, provided string) {
	if c.JDK != "" {
		return env, ""
	}
	for _, k := range []string{"JAVA_HOME", "PATH"} {
		if _, stated := c.Env[k]; stated {
			return env, ""
		}
	}
	if gradleJavaHomeSet(dir, env) {
		return env, ""
	}
	major, minor, ok := wrapperGradleVersion(dir)
	if !ok {
		return env, ""
	}
	hi, lo := maxGradleJDK(major, minor), minGradleJDK(major)
	job := jdkMajorAt(jobJavaHome(env))
	if hi == 0 || job == 0 || job <= hi {
		return env, ""
	}
	type jdk struct {
		feature    int
		name, home string
	}
	var found []jdk
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m := providedJDK.FindStringSubmatch(k)
		if m == nil || !filepath.IsAbs(v) {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		// The variable's name is a claim; the JDK's own release file decides.
		if n < lo || n > hi || jdkMajorAt(v) != n || !isFile(filepath.Join(v, "bin", "java")) {
			continue
		}
		found = append(found, jdk{n, k, v})
	}
	if len(found) == 0 {
		return env, ""
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].feature != found[j].feature {
			return found[i].feature > found[j].feature
		}
		return found[i].name < found[j].name
	})
	home := found[0].home
	return environ(env, map[string]string{
		"JAVA_HOME": home,
		"PATH":      filepath.Join(home, "bin") + string(os.PathListSeparator) + envValue(env, "PATH"),
	}), found[0].name
}

// gradleJavaHomeSet reports whether the build names the JVM Gradle runs on itself, as
// org.gradle.java.home in the checkout's or the Gradle user home's gradle.properties, or in
// GRADLE_OPTS or JAVA_OPTS. Gradle then runs there whatever JAVA_HOME says.
func gradleJavaHomeSet(dir string, env []string) bool {
	const key = "org.gradle.java.home"
	for _, k := range []string{"GRADLE_OPTS", "JAVA_OPTS"} {
		if strings.Contains(envValue(env, k), key) {
			return true
		}
	}
	userHome := envValue(env, "GRADLE_USER_HOME")
	if userHome == "" {
		if h := envValue(env, "HOME"); h != "" {
			userHome = filepath.Join(h, ".gradle")
		}
	}
	for _, d := range []string{dir, userHome} {
		if d == "" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(d, "gradle.properties"))
		if err == nil && strings.Contains(string(b), key) {
			return true
		}
	}
	return false
}

func isFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// envValue is the last value env gives key.
func envValue(env []string, key string) string {
	v := ""
	for _, kv := range env {
		if rest, ok := strings.CutPrefix(kv, key+"="); ok {
			v = rest
		}
	}
	return v
}
