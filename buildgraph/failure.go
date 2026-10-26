package buildgraph

import (
	"regexp"
	"strconv"
	"strings"
)

// Failure kinds. A failed resolution is exactly one of these; Cause renders it with its detail.
const (
	// KindToolchainAbsent: no wrapper and no tool on PATH, or the tool found no Java.
	KindToolchainAbsent = "toolchain_absent"
	// KindJDKMismatch: the stated JDK's major version is not the one the tool ran on.
	KindJDKMismatch = "jdk_mismatch"
	// KindCredentials: a repository refused the tool for want of credentials.
	KindCredentials = "credentials"
	// KindToolFailed: a step exited nonzero, or its output was missing or unreadable.
	KindToolFailed = "tool_failed"
	// KindGraphRejected: the graph failed a validation check.
	KindGraphRejected = "graph_rejected"
)

// Failure is why no graph was produced. Log carries the tail of the failing step's output.
type Failure struct {
	Kind   string
	Detail string
	Log    string
}

// Cause is the typed cause: the kind, then ":" and the detail when there is one.
func (f *Failure) Cause() string {
	if f.Detail == "" {
		return f.Kind
	}
	return f.Kind + ":" + f.Detail
}

func (f *Failure) Error() string { return "build graph: " + f.Cause() }

const logTail = 4096

func tail(out []byte) string {
	if len(out) > logTail {
		out = out[len(out)-logTail:]
	}
	return string(out)
}

var (
	// Maven: "Could not transfer artifact … from/to central (https://…): status code: 401, …"; the
	// Wagon transport before 3.9 says "…: authentication failed for <url>, status: 401 …".
	mavenAuth = regexp.MustCompile(`from/to ([^\s()]+) \([^)]*\): (?:status code: |(?:authentication|authorization) failed for [^,\s]+, status: )(?:401|403)\b`)
	// Gradle: "Could not GET 'https://host/…'. Received status code 401 from server: …"; Gradle 9
	// breaks the line before "Received".
	gradleAuth = regexp.MustCompile(`Could not (?:GET|HEAD) '([a-z]+://[^/']+)[^']*'\.\s+Received status code (?:401|403)\b`)
	noJava     = regexp.MustCompile(`JAVA_HOME (?:is not set|is set to an invalid directory|environment variable is not defined correctly|not found)|Unable to locate a Java Runtime|no 'java' command could be found`)
)

// classify turns a failed step's output into its failure: missing Java or refused credentials
// when the output says so, otherwise the step itself.
func classify(step string, out []byte) *Failure {
	log := tail(out)
	if noJava.Match(out) {
		return &Failure{Kind: KindToolchainAbsent, Log: log}
	}
	if m := mavenAuth.FindSubmatch(out); m != nil {
		return &Failure{Kind: KindCredentials, Detail: string(m[1]), Log: log}
	}
	if m := gradleAuth.FindSubmatch(out); m != nil {
		return &Failure{Kind: KindCredentials, Detail: string(m[1]), Log: log}
	}
	return &Failure{Kind: KindToolFailed, Detail: step, Log: log}
}

// checkJDK fails when a JDK was stated and the tool's JVM has another major version.
func checkJDK(want, have string) *Failure {
	if want == "" {
		return nil
	}
	w, h := javaMajor(want), javaMajor(have)
	if w == 0 || w != h {
		return &Failure{Kind: KindJDKMismatch, Detail: want + "/" + have}
	}
	return nil
}

// JDKMajor is the feature release of the JDK the run conditions state, or 0 when they state none
// or one javaMajor cannot read.
func (c Conditions) JDKMajor() int { return javaMajor(c.JDK) }

// RuntimeJDK is the feature release of the JDK the program runs on: the one the run conditions
// state, or 0 when they state none, or a module's toolchain selects another or went unread, since
// the stated JDK then does not describe the platform that module's code meets.
func (g *Graph) RuntimeJDK() int {
	jdk := g.Conditions.JDKMajor()
	for _, m := range g.Modules {
		if !m.JDKToolchainsKnown {
			return 0
		}
		for _, t := range m.JDKToolchains {
			if javaMajor(t) != jdk {
				return 0
			}
		}
	}
	return jdk
}

// javaMajor reads the feature release from a Java version string: "21.0.12" is 21, "1.8.0_392"
// is 8, "17" is 17. Anything else is 0.
func javaMajor(v string) int {
	v = strings.TrimSpace(v)
	if rest, ok := strings.CutPrefix(v, "1."); ok {
		v = rest
	}
	end := strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' })
	if end >= 0 {
		v = v[:end]
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}
