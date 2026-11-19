package buildgraph

import "strings"

// credentialEnv names the CI credentials a repository's own build must never inherit: the job
// token and the Actions runtime and OIDC tokens. A pull request controls the build code, so a
// write-capable token in its environment is a token the pull request can use.
var credentialEnv = []string{
	"GITHUB_TOKEN",
	"GH_TOKEN",
	"ACTIONS_ID_TOKEN_REQUEST_TOKEN",
	"ACTIONS_ID_TOKEN_REQUEST_URL",
	"ACTIONS_RUNTIME_TOKEN",
	"ACTIONS_CACHE_URL",
}

// StripCredentials returns env without the CI credential variables. Every subprocess that runs a
// repository's own build or package tooling takes its environment through it. Registry
// credentials the build needs (.npmrc, Maven settings) are files or other variables and stay.
// The input is not modified.
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
		if k == c {
			return true
		}
	}
	return false
}
