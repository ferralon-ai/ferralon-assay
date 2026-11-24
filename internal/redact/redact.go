// Package redact removes the credentials a tool error can echo from text bound for a report.
package redact

import "regexp"

// secretREs match the credentials a tool error can echo, each with what replaces them: the
// userinfo of a URL (with or without a scheme, up to the authority's last '@', since a password
// may hold one), a user:password@host without one (a proxy setting), query-string values, an
// Authorization header, a bearer token and a GitLab PRIVATE-TOKEN header; a token= or npm
// _authToken= setting outside a query string; a .netrc entry's password; and a bare GitHub, GitLab
// or npm token, by its prefix and a body of a token's length (the prefix is kept). A Go
// module@version has no ':' before its '@', so it is kept; a word that only contains "token" or
// "password" (tokenizer, password-reset) has no value to redact, so it is kept.
var secretREs = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`((?:[A-Za-z][A-Za-z0-9+.-]*:)?//)[^/\s]*@`), "${1}REDACTED@"},
	{regexp.MustCompile(`[^\s/:@]+:[^\s/]*@`), "REDACTED@"},
	{regexp.MustCompile(`([?&][^\s?&#=]+=)[^\s&#]*`), "${1}REDACTED"},
	{regexp.MustCompile(`(?i)\b((?:proxy-)?authorization)\s*[:=]\s*(?:(?:bearer|basic|token|digest)\s+)?[^\s,;]+`), "${1}: REDACTED"},
	{regexp.MustCompile(`(?i)\b(bearer)\s+[^\s,;]+`), "${1} REDACTED"},
	{regexp.MustCompile(`(?i)\b(private-token)\s*[:=]\s*[^\s,;]+`), "${1}: REDACTED"},
	{regexp.MustCompile(`(?i)(_authToken)\s*=\s*[^\s,;]+`), "${1}=REDACTED"},
	{regexp.MustCompile(`(?i)\b([A-Za-z0-9_-]*token)=[^\s&#,;]+`), "${1}=REDACTED"},
	{regexp.MustCompile(`(?i)\b((?:machine\s+\S+(?:\s+(?:login|account)\s+\S+)*|default(?:\s+(?:login|account)\s+\S+)+)\s+password)\s+\S+`), "${1} REDACTED"},
	{regexp.MustCompile(`\b(gh[pousr]_)[A-Za-z0-9]{36,}`), "${1}REDACTED"},
	{regexp.MustCompile(`\b(github_pat_)[A-Za-z0-9_]{22,}`), "${1}REDACTED"},
	{regexp.MustCompile(`\b(glpat-)[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]+)*`), "${1}REDACTED"},
	{regexp.MustCompile(`\b(npm_)[A-Za-z0-9]{36,}`), "${1}REDACTED"},
}

// Secrets returns s with every credential secretREs match replaced.
func Secrets(s string) string {
	for _, r := range secretREs {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}
