package buildgraph

import "strings"

// credentialEnv names the CI variables a repository's own build must never inherit: the job token,
// the Actions runtime and OIDC tokens, and the runner files a step writes to reach the job's later
// steps. A pull request controls the build code, so a write-capable token in its environment is a
// token the pull request can use, and a build that can append to $GITHUB_ENV or $GITHUB_PATH can set
// the environment of a later step that holds the token.
var credentialEnv = []string{
	"GITHUB_TOKEN",
	"GH_TOKEN",
	"ACTIONS_ID_TOKEN_REQUEST_TOKEN",
	"ACTIONS_ID_TOKEN_REQUEST_URL",
	"ACTIONS_RUNTIME_TOKEN",
	"ACTIONS_CACHE_URL",
	"GITHUB_ENV",
	"GITHUB_PATH",
	"GITHUB_OUTPUT",
	"GITHUB_STATE",
	"GITHUB_STEP_SUMMARY",
}

// CredentialEnv returns the names StripCredentials removes, as a copy the caller may keep.
func CredentialEnv() []string {
	return append([]string(nil), credentialEnv...)
}

// StripCredentials returns env without the CI credential variables. Every subprocess that runs a
// repository's own build or package tooling takes its environment through it. Registry
// credentials the build needs (.npmrc, Maven settings) are files or other variables and stay.
// Names match case-insensitively, as they do on Windows. The input is not modified.
func StripCredentials(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if isCredentialEnv(k) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func isCredentialEnv(k string) bool {
	for _, c := range credentialEnv {
		if strings.EqualFold(k, c) {
			return true
		}
	}
	return false
}
