package scriptsurface

import (
	"regexp"
	"strings"
)

// earthTarget is the stage an adapted Earthfile starts wherever Earthly starts or changes a
// build context the Dockerfile rule cannot follow. Its first FROM names it, so each later one
// builds on a stage that may hold anything.
const earthTarget = "FROM earthly-target AS earthly-target"

var (
	// earthHeaderRE matches an Earthfile target or function header: an unindented name and a
	// colon.
	earthHeaderRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*:\s*(?:#.*)?$`)
	// earthFromRE matches a FROM that builds on another Earthfile target (+base, ./dir+base).
	earthFromRE = regexp.MustCompile(`^FROM\s+(?:--\S+\s+)*\S*\+`)
)

// earthReset are Earthfile commands after which a target's working directory and contents are
// not what the lines before them made: a context run on the host, a function body or call,
// a clone, and the branches and loops whose bodies may run zero or many times.
var earthReset = map[string]bool{
	"LOCALLY": true, "COMMAND": true, "FUNCTION": true, "DO": true, "GIT": true, "IF": true,
	"ELSE": true, "END": true, "FOR": true, "TRY": true, "CATCH": true, "FINALLY": true,
	"WAIT": true, "WITH": true,
}

// earthPlain are Earthfile commands that run no command in the target and change neither its
// working directory nor its contents.
var earthPlain = map[string]bool{
	"VERSION": true, "PROJECT": true, "IMPORT": true, "BUILD": true, "SAVE": true, "CACHE": true,
	"HOST": true, "PIPELINE": true, "TRIGGER": true,
}

// earthfileAsDockerfile adapts an Earthfile for the Dockerfile rule, line for line. RUN,
// COPY, WORKDIR, ENV and ARG keep their Dockerfile meaning. Every target, and every FROM on
// another target, starts a stage whose working directory is unknown and whose contents may be
// anything, as do the earthReset commands; a reset line that names a token is kept, so the
// rule withholds on it as on any instruction it does not know. earthPlain lines are inert.
func (v *Veto) earthfileAsDockerfile(src string) string {
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines)+1)
	out = append(out, earthTarget)
	cont := false
	for _, l := range lines {
		t := strings.TrimSpace(l)
		was := cont
		cont = strings.HasSuffix(strings.TrimRight(l, " \t\r"), `\`)
		if was {
			out = append(out, l)
			continue
		}
		word, _, _ := strings.Cut(t, " ")
		switch {
		case earthHeaderRE.MatchString(l), earthFromRE.MatchString(t):
			out = append(out, earthTarget)
		case earthReset[word] && !v.hasToken(t):
			out = append(out, earthTarget)
		case earthPlain[word]:
			out = append(out, "LABEL earthly")
		default:
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}
