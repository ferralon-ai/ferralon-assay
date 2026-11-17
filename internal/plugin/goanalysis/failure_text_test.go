package goanalysis

import (
	"errors"
	"fmt"
	"testing"
)

func TestFailureText(t *testing.T) {
	const buildDir = "/tmp/scan/build"
	cause := errors.New("exit status 1")
	loadHeader := "govulncheck: loading packages: \nThere are errors with the provided package patterns:\n\n"
	wails := "/home/u/go/pkg/mod/github.com/netbirdio/wails/v3@v3.0.0-beta.3.0.20261028091752-cfa103160796/pkg/application/"
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"not a govulncheck failure is unchanged", errors.New("parse: bad"), "parse: bad"},
		{"wrapped failure keeps its own text", fmt.Errorf("outer: %w", &govulncheckError{buildDir: buildDir, cause: cause}),
			"outer: " + (&govulncheckError{buildDir: buildDir, cause: cause}).Error()},
		{"first load error leads, path trimmed to the module, the rest counted",
			&govulncheckError{buildDir: buildDir, cause: cause, stderr: loadHeader +
				wails + "menu_linux.go:7:12: undefined: pointer\n" + wails + "menuitem_linux.go:12:13: undefined: pointer\n" + wails + "screen_linux.go:9:10: undefined: linuxApp"},
			"github.com/netbirdio/wails/v3/pkg/application/menu_linux.go:7:12: undefined: pointer (and 2 more)"},
		{"a path under the build directory is made relative",
			&govulncheckError{buildDir: buildDir, cause: cause, stderr: loadHeader + buildDir + "/cmd/x/main.go:3:8: could not import C"},
			"cmd/x/main.go:3:8: could not import C"},
		{"the partial run's reason follows the cause",
			&govulncheckError{buildDir: buildDir, cause: cause, stderr: loadHeader + buildDir + "/a.go:1:1: bad\nno partial govulncheck run: every root imports a package govulncheck could not load (p)"},
			"a.go:1:1: bad; no partial govulncheck run: every root imports a package govulncheck could not load (p)"},
		{"no load error leaves the cause", &govulncheckError{buildDir: buildDir, cause: cause, stderr: "fetching vulnerabilities: i/o timeout"},
			"fetching vulnerabilities: i/o timeout"},
		{"no stderr names the exit", &govulncheckError{buildDir: buildDir, cause: cause}, "govulncheck failed: exit status 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FailureText(tt.err); got != tt.want {
				t.Errorf("FailureText = %q, want %q", got, tt.want)
			}
		})
	}
}
