package plugin

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Every constructor given no explicit binary reports an analyzer missing from PATH as a
// *NotInstalledError naming its own language and executable, and still reads as a lookup failure.
func TestConstructorsReportAMissingBinaryAsNotInstalled(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	cases := []struct {
		language string
		build    func() (LanguagePlugin, error)
	}{
		{"go", func() (LanguagePlugin, error) { return NewGoPlugin() }},
		{"java", func() (LanguagePlugin, error) { return NewJavaPlugin() }},
		{"kotlin", func() (LanguagePlugin, error) { return NewKotlinPlugin() }},
		{"js", func() (LanguagePlugin, error) { return NewJSPlugin() }},
		{"python", func() (LanguagePlugin, error) { return NewPythonPlugin() }},
		{"dotnet", func() (LanguagePlugin, error) { return NewDotNetPlugin() }},
		{"cfamily", func() (LanguagePlugin, error) { return NewCFamilyPlugin() }},
	}
	for _, tc := range cases {
		t.Run(tc.language, func(t *testing.T) {
			p, err := tc.build()
			if p != nil {
				t.Fatalf("constructed a plugin with no binary on PATH")
			}
			var missing *NotInstalledError
			if !errors.As(err, &missing) {
				t.Fatalf("err = %v (%T), want *NotInstalledError", err, err)
			}
			if missing.Language != tc.language || missing.Binary != BinaryName(tc.language) {
				t.Fatalf("NotInstalledError{Language: %q, Binary: %q}, want %q, %q", missing.Language, missing.Binary, tc.language, BinaryName(tc.language))
			}
			if !errors.Is(err, exec.ErrNotFound) {
				t.Fatalf("err = %v, does not wrap exec.ErrNotFound", err)
			}
		})
	}
}

func TestDiscoverBinary(t *testing.T) {
	installed := t.TempDir()
	bin := filepath.Join(installed, BinaryName("cfamily"))
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		path    string
		want    string
		missing bool
	}{
		{"on PATH", installed, bin, false},
		{"empty PATH", "", "", true},
		{"PATH without it", t.TempDir(), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PATH", tc.path)
			got, err := discoverBinary("cfamily")
			var missing *NotInstalledError
			if errors.As(err, &missing) != tc.missing {
				t.Fatalf("err = %v, want missing=%v", err, tc.missing)
			}
			if !tc.missing && err != nil {
				t.Fatalf("err = %v", err)
			}
			if got != tc.want {
				t.Fatalf("discoverBinary = %q, want %q", got, tc.want)
			}
		})
	}
}
