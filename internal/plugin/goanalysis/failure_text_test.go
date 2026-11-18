package goanalysis

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/tools/go/packages"
)

// loadFailure has the shape x/vuln returns for a failed package load: its text in Error, its errors
// in an Errors field.
type loadFailure struct{ Errors []packages.Error }

func (e *loadFailure) Error() string {
	var b strings.Builder
	b.WriteString("govulncheck: loading packages: \nThere are errors with the provided package patterns:\n\n")
	for _, pe := range e.Errors {
		fmt.Fprintln(&b, pe)
	}
	b.WriteString("\nFor details on package patterns, see https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns.\n")
	return b.String()
}

var loadErrorLine = regexp.MustCompile(`^(.+?:\d+:\d+): (.*)$`)

// loadFailureFromText rebuilds the error a load failure returns from its text, as the plugin
// captured it for netbird.
func loadFailureFromText(t *testing.T, text string) *loadFailure {
	t.Helper()
	failure := &loadFailure{}
	for _, line := range strings.Split(text, "\n") {
		if m := loadErrorLine.FindStringSubmatch(line); m != nil && !strings.HasPrefix(line, "For details") {
			failure.Errors = append(failure.Errors, packages.Error{Pos: m[1], Msg: m[2]})
		}
	}
	if len(failure.Errors) == 0 || failure.Error() != text {
		t.Fatalf("test text does not round-trip through a load failure:\n%q\n%q", failure.Error(), text)
	}
	return failure
}

// netbirdLoadText is the head and tail of the error netbird's failed load returned: the load errors
// in the cause, nothing on stderr.
const netbirdLoadText = "govulncheck: loading packages: \nThere are errors with the provided package patterns:\n\n" +
	"/Users/u/go/pkg/mod/github.com/netbirdio/wails/v3@v3.0.0-beta.3.0.20261028091752-cfa103160796/pkg/application/menu_linux.go:7:12: undefined: pointer\n" +
	"/Users/u/go/pkg/mod/github.com/netbirdio/wails/v3@v3.0.0-beta.3.0.20261028091752-cfa103160796/pkg/application/menuitem_linux.go:12:13: undefined: pointer\n" +
	"/Users/u/go/pkg/mod/github.com/netbirdio/wails/v3@v3.0.0-beta.3.0.20261028091752-cfa103160796/pkg/application/screen_linux.go:9:10: undefined: linuxApp\n" +
	"/scan/netbird/management/server/store/sql_store_proxy.go:66:53: undefined: go_sqlite.Error\n" +
	"\nFor details on package patterns, see https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns.\n"

func TestFailureText(t *testing.T) {
	const buildDir = "/scan/netbird"
	t.Setenv("GOMODCACHE", "/Users/u/go/pkg/mod")
	exit := errors.New("exit status 1")
	netbird := loadFailureFromText(t, netbirdLoadText)
	inner := loadFailureFromText(t, "govulncheck: loading packages: \nThere are errors with the provided package patterns:\n\n/b/x.go:1:1: inner bad\n\nFor details on package patterns, see https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns.\n")
	outer := &govulncheckError{buildDir: "/b", cause: loadFailureFromText(t, "govulncheck: loading packages: \nThere are errors with the provided package patterns:\n\n/b/y.go:2:2: outer bad\n\nFor details on package patterns, see https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns.\n")}
	noteNoPartialRun(outer, "no partial govulncheck run: ", &govulncheckError{buildDir: "/b", cause: inner})

	tests := []struct {
		name string
		err  error
		want string
	}{
		{"not a govulncheck failure is unchanged", errors.New("parse: bad"), "parse: bad"},
		{"wrapped failure keeps its own text", fmt.Errorf("outer: %w", &govulncheckError{buildDir: buildDir, cause: exit}),
			"outer: " + (&govulncheckError{buildDir: buildDir, cause: exit}).Error()},
		{"netbird: load text in the cause, stderr empty; module path trimmed, trailer not counted",
			&govulncheckError{buildDir: buildDir, cause: netbird},
			"github.com/netbirdio/wails/v3/pkg/application/menu_linux.go:7:12: undefined: pointer (and 3 more)"},
		{"a replayed failure carries its errors beside a plain cause",
			&govulncheckError{buildDir: buildDir, cause: exit, perrs: netbird.Errors},
			"github.com/netbirdio/wails/v3/pkg/application/menu_linux.go:7:12: undefined: pointer (and 3 more)"},
		{"a single load error has no count",
			&govulncheckError{buildDir: buildDir, cause: &loadFailure{Errors: []packages.Error{{Pos: buildDir + "/cmd/x/main.go:3:8", Msg: "could not import C"}}}},
			"cmd/x/main.go:3:8: could not import C"},
		{"a build directory under /tmp relativises /private/tmp paths",
			&govulncheckError{buildDir: "/tmp/x", cause: &loadFailure{Errors: []packages.Error{{Pos: "/private/tmp/x/a.go:1:1", Msg: "bad"}}}},
			"a.go:1:1: bad"},
		{"a pkg/mod directory outside the module cache is kept",
			&govulncheckError{buildDir: "/b", cause: &loadFailure{Errors: []packages.Error{{Pos: "/srv/other/pkg/mod/thing@v2/x.go:1:1", Msg: "bad"}}}},
			"/srv/other/pkg/mod/thing@v2/x.go:1:1: bad"},
		{"a version in the message is kept",
			&govulncheckError{buildDir: "/b", cause: &loadFailure{Errors: []packages.Error{{Pos: "/b/a.go:1:1", Msg: "cannot use x@v1/ value"}}}},
			"a.go:1:1: cannot use x@v1/ value"},
		{"the cause leads, not the stderr noise beside it",
			&govulncheckError{buildDir: "/b", cause: errors.New("signal: killed"), stderr: "go: downloading example.com/m v1.0.0\ngo: downloading example.com/n v1.0.0"},
			"govulncheck failed: signal: killed: go: downloading example.com/m v1.0.0; go: downloading example.com/n v1.0.0"},
		{"no stderr names the cause", &govulncheckError{buildDir: "/b", cause: context.DeadlineExceeded}, "govulncheck failed: context deadline exceeded"},
		{"the partial run's note follows the load error",
			&govulncheckError{buildDir: buildDir, cause: netbird, stderr: "no partial govulncheck run: every root imports a package govulncheck could not load (p)"},
			"github.com/netbirdio/wails/v3/pkg/application/menu_linux.go:7:12: undefined: pointer (and 3 more); no partial govulncheck run: every root imports a package govulncheck could not load (p)"},
		{"a note that is itself a failure is kept whole and never leads", outer,
			"y.go:2:2: outer bad; no partial govulncheck run: govulncheck failed (\"/b\"): govulncheck: loading packages: There are errors with the provided package patterns: " +
				"/b/x.go:1:1: inner bad For details on package patterns, see https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FailureText(tt.err); got != tt.want {
				t.Errorf("FailureText = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestFailureTextRowLeadsWithTheCause is the netbird row: the 200 runes a bounded report row keeps
// (trigger.assessErrorText, over the plugin's framing) hold the first load error and the count of the
// 130 after it. The 131 errors repeat the captured ones.
func TestFailureTextRowLeadsWithTheCause(t *testing.T) {
	t.Setenv("GOMODCACHE", "/Users/u/go/pkg/mod")
	captured := loadFailureFromText(t, netbirdLoadText).Errors
	netbird := &loadFailure{}
	for i := 0; i < 131; i++ {
		netbird.Errors = append(netbird.Errors, captured[i%len(captured)])
	}
	err := &govulncheckError{buildDir: "/private/tmp/claude-501/-Users-u-workspace/scratchpad/817/repos/netbird", cause: netbird}
	const framing = "plugin: reachability subprocess exited non-zero: exit status 1 (stderr: "
	row := []rune(framing + FailureText(err))
	if len(row) > 200 {
		row = row[:200]
	}
	for _, want := range []string{"menu_linux.go:7:12: undefined: pointer", "(and 130 more)"} {
		if !strings.Contains(string(row), want) {
			t.Errorf("first 200 runes %q lack %q", string(row), want)
		}
	}
}

// TestFailureTextLiveLoadFailure runs the construction path a scan uses over a module that cannot
// compile: the load errors arrive in the cause and stderr is empty.
func TestFailureTextLiveLoadFailure(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/broken\n\ngo 1.21\n")
	write("a/a.go", "package a\n\nvar A = undefinedA\n")
	write("b/b.go", "package b\n\nvar B = undefinedB\n")
	env := append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod", "GOTOOLCHAIN=local", "GOPROXY=off")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := govulncheckStream(ctx, dir, env, []string{"./..."})
	var failed *govulncheckError
	if !errors.As(err, &failed) {
		t.Fatalf("err = %v, want a govulncheck failure", err)
	}
	got := FailureText(err)
	want := regexp.MustCompile(`^a/a\.go:3:\d+: undefined: undefinedA \(and 1 more\)$`)
	if !want.MatchString(got) {
		t.Errorf("FailureText = %q (stderr %q, cause %q)", got, failed.stderr, failed.cause)
	}
}
