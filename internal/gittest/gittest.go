// Package gittest is test support for code that runs git against fixture repositories.
//
// A test binary started from a git hook or from `git rebase --exec` inherits the variables git
// uses to locate its repository (GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE, ...). A fixture command
// that inherits them acts on the enclosing repository instead of the fixture: `git init` re-inits
// it, `git config` edits its config, `git commit` moves its branch. Every test that execs git goes
// through this package so the fixture is the only repository the command can see.
package gittest

import (
	"os"
	"os/exec"
	"strings"
)

// locatingVars are the variables git reads to find a repository, its object store, its index or
// its configuration, plus the ones that bound or rewrite discovery. The first group is the output
// of `git rev-parse --local-env-vars`; the rest are documented in git(1).
var locatingVars = []string{
	"GIT_ALTERNATE_OBJECT_DIRECTORIES",
	"GIT_CONFIG",
	"GIT_CONFIG_PARAMETERS",
	"GIT_CONFIG_COUNT",
	"GIT_OBJECT_DIRECTORY",
	"GIT_DIR",
	"GIT_WORK_TREE",
	"GIT_IMPLICIT_WORK_TREE",
	"GIT_GRAFT_FILE",
	"GIT_INDEX_FILE",
	"GIT_NO_REPLACE_OBJECTS",
	"GIT_REPLACE_REF_BASE",
	"GIT_PREFIX",
	"GIT_SHALLOW_FILE",
	"GIT_COMMON_DIR",

	"GIT_NAMESPACE",
	"GIT_CEILING_DIRECTORIES",
	"GIT_DISCOVERY_ACROSS_FILESYSTEM",
	"GIT_QUARANTINE_PATH",
	"GIT_INTERNAL_SUPER_PREFIX",
}

// identity is the author and committer every fixture commit carries, so no test reads the
// identity from the developer's git config.
var identity = []string{
	"GIT_AUTHOR_NAME=Test",
	"GIT_AUTHOR_EMAIL=test@example.com",
	"GIT_COMMITTER_NAME=Test",
	"GIT_COMMITTER_EMAIL=test@example.com",
}

func isScrubbed(key string) bool {
	if strings.HasPrefix(key, "GIT_CONFIG_KEY_") || strings.HasPrefix(key, "GIT_CONFIG_VALUE_") {
		return true
	}
	for _, v := range locatingVars {
		if key == v {
			return true
		}
	}
	for _, kv := range identity {
		if name, _, _ := strings.Cut(kv, "="); key == name {
			return true
		}
	}
	return false
}

// Scrub returns env without the repository-locating and identity variables. Use it when a test
// builds its own environment from a base that may already carry them.
func Scrub(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		key, _, _ := strings.Cut(kv, "=")
		if !isScrubbed(key) {
			out = append(out, kv)
		}
	}
	return out
}

// Env returns the process environment with the repository-locating variables removed and the
// fixed author and committer identity set. Append to it for per-command settings.
func Env() []string {
	return append(Scrub(os.Environ()), identity...)
}

// Command returns a git command that runs with Env.
func Command(args ...string) *exec.Cmd {
	cmd := exec.Command("git", args...)
	cmd.Env = Env()
	return cmd
}

// ScrubProcess removes the repository-locating variables from this process's own environment.
// Call it from TestMain in a package whose tests reach git indirectly (production code that execs
// git, or a script a test runs), where there is no command to hand Env to.
func ScrubProcess() {
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		if isScrubbed(key) {
			os.Unsetenv(key)
		}
	}
	for _, kv := range identity {
		name, value, _ := strings.Cut(kv, "=")
		os.Setenv(name, value)
	}
}
