package pythonanalysis

import (
	"path/filepath"
	"slices"
	"testing"
)

// setuptoolsReading is what setuptools 84 reads from a setup.cfg (setuptools.config.setupcfg
// applied to a Distribution, each entry parsed by packaging's Requirement): the install_requires
// and extras_require entries, the setup_requires entries, or fails when either step raises.
type setuptoolsReading struct {
	specs, build []string
	fails        bool
}

// Every row is a configparser form, with setuptools' own reading of it recorded beside it
// (configparser behaves the same on Python 3.9, 3.13 and 3.14 for each). scanSetupCfg must
// either read exactly what setuptools reads or withhold (ok=false); it never reads a form
// differently, and it withholds wherever setuptools fails. withhold pins which of the two the
// reader does, so a rule that starts withholding a form setuptools reads is caught too.
func TestScanSetupCfg_ConfigparserForms(t *testing.T) {
	const opts = "[options]\n"
	pin := []string{"pyjwt==2.10.0"}
	none := setuptoolsReading{}
	fails := setuptoolsReading{fails: true}
	tests := []struct {
		name     string
		body     string
		st       setuptoolsReading
		withhold bool
	}{
		// A key line directly under a header opens an option at any indentation.
		{"indented first key", opts + "  install_requires =\n    pyjwt==2.10.0\n", setuptoolsReading{specs: pin}, false},
		{"indented dashed key", opts + "  install-requires = pyjwt==2.10.0\n", setuptoolsReading{specs: pin}, false},
		{"tab-indented setup_requires", opts + "\tsetup_requires = pyjwt==2.10.0\n", setuptoolsReading{build: pin}, false},
		{"indented key after a comment", opts + "# deps\n    install_requires = pyjwt==2.10.0\n", setuptoolsReading{specs: pin}, false},
		{"indented key after a blank line", opts + "\n    install_requires = pyjwt==2.10.0\n", setuptoolsReading{specs: pin}, false},
		{"indented key after another section", "[metadata]\nname = x\n" + opts + "    install_requires = pyjwt==2.10.0\n", setuptoolsReading{specs: pin}, false},
		// A line is a continuation only when indented deeper than the line that opened the option.
		{"indented line folds into the previous option", opts + "zip_safe = 0\n    install_requires = pyjwt==2.10.0\n", none, false},
		{"line no deeper than its key is an option", opts + "  install_requires =\n  pyjwt==2.10.0\n", none, false},
		{"tab is one column", opts + "    install_requires =\n\tpyjwt==2.10.0\n", none, false},
		{"tab indentation", opts + "install_requires =\n\tpyjwt==2.10.0\n", setuptoolsReading{specs: pin}, false},
		{"empty value then continuation", opts + "install_requires =\n    pyjwt==2.10.0\n    six\n", setuptoolsReading{specs: []string{"pyjwt==2.10.0", "six"}}, false},
		// Full-line comments change no state; blank lines stay inside a value.
		{"hash comment inside a value", opts + "install_requires =\n    six\n    # pinned\n    pyjwt==2.10.0\n", setuptoolsReading{specs: []string{"six", "pyjwt==2.10.0"}}, false},
		{"semicolon comment inside a value", opts + "install_requires =\n    six\n    ; pinned\n    pyjwt==2.10.0\n", setuptoolsReading{specs: []string{"six", "pyjwt==2.10.0"}}, false},
		{"blank line inside a value", opts + "install_requires =\n    six\n\n    pyjwt==2.10.0\n", setuptoolsReading{specs: []string{"six", "pyjwt==2.10.0"}}, false},
		// Delimiters and keys.
		{"colon delimiter", opts + "install_requires: pyjwt==2.10.0\n", setuptoolsReading{specs: pin}, false},
		{"first delimiter splits", opts + "install_requires : x = pyjwt==2.10.0\n", fails, true},
		{"key case", opts + "Install_Requires = pyjwt==2.10.0\n", setuptoolsReading{specs: pin}, false},
		{"dashed key", opts + "install-requires = pyjwt==2.10.0\n", setuptoolsReading{specs: pin}, false},
		{"non-ASCII key", opts + "İnstall_requires = pyjwt==2.10.0\n", none, true},
		{"empty key", opts + "= pyjwt==2.10.0\n", fails, true},
		{"line without a delimiter", opts + "install_requires = pyjwt==2.10.0\nzip_safe\n", fails, true},
		{"option before any section", "install_requires = pyjwt==2.10.0\n" + opts, fails, true},
		{"key repeated", opts + "install_requires = six\ninstall_requires = pyjwt==2.10.0\n", fails, true},
		{"key repeated in another case", opts + "install_requires = six\nINSTALL_REQUIRES = pyjwt==2.10.0\n", fails, true},
		{"key repeated dashed", opts + "install_requires = six\ninstall-requires = pyjwt==2.10.0\n", setuptoolsReading{specs: pin}, true},
		// Sections.
		{"key repeated across split sections", opts + "install_requires = six\n[metadata]\nname = x\n" + opts + "install_requires = pyjwt==2.10.0\n", fails, true},
		{"DEFAULT section", "[DEFAULT]\ninstall_requires = pyjwt==2.10.0\n" + opts, setuptoolsReading{specs: pin}, true},
		{"section case", "[Options]\ninstall_requires = pyjwt==2.10.0\n", none, true},
		{"dotted extras section", "[options..extras_require]\njwt = pyjwt==2.10.0\n", setuptoolsReading{specs: pin}, true},
		{"header with trailing text", "[options] # deps\ninstall_requires = pyjwt==2.10.0\n", setuptoolsReading{specs: pin}, true},
		{"empty header", "[]\n" + opts + "install_requires = pyjwt==2.10.0\n", fails, true},
		{"unterminated header", "[metadata]\n[options\ninstall_requires = pyjwt==2.10.0\n", fails, true},
		{"extras list", "[options.extras_require]\njwt =\n  pyjwt==2.10.0\n", setuptoolsReading{specs: pin}, false},
		{"extras dashed key", "[options.extras_require]\nJwt-Extra = pyjwt==2.10.0\n", setuptoolsReading{specs: pin}, false},
		// List values: lines when the value has a line break, else ';'-separated.
		{"inline semicolon after whitespace", opts + "install_requires = pyjwt==2.10.0 ; pinned\n", setuptoolsReading{specs: []string{"pyjwt==2.10.0", "pinned"}}, false},
		{"semicolon then hash entry", opts + "install_requires = pyjwt==2.10.0; # pinned\n", setuptoolsReading{specs: pin}, false},
		{"semicolon then hash in setup_requires", opts + "setup_requires = pyjwt==2.10.0; # pinned\n", fails, true},
		{"inline hash in a continuation", opts + "install_requires =\n    pyjwt==2.10.0  # pinned\n", fails, true},
		{"marker on its own line", opts + "install_requires =\n    pyjwt==2.10.0; python_version >= \"3.8\"\n", setuptoolsReading{specs: []string{"pyjwt==2.10.0; python_version >= \"3.8\""}}, false},
		{"marker on a single-line value", opts + "install_requires = pyjwt==2.10.0; python_version >= \"3.8\"\n", fails, true},
		{"second requirement after a semicolon", opts + "install_requires =\n    six;pyjwt==2\n", fails, true},
		// Interpolation.
		{"interpolation", opts + "install_requires =\n    pyjwt==2.10.0; os_name == \"%(os)s\"\nos = posix\n", setuptoolsReading{specs: []string{"pyjwt==2.10.0; os_name == \"posix\""}}, true},
		{"escaped percent", opts + "install_requires =\n    pyjwt==2.10.0; platform_release == \"5%%\"\n", setuptoolsReading{specs: []string{"pyjwt==2.10.0; platform_release == \"5%\""}}, true},
		{"lone percent", opts + "install_requires = pyjwt==2.10.0\nurl = https://x/%7E\n", fails, true},
		// Text: line breaks, whitespace and encoding.
		{"CRLF", "[options]\r\ninstall_requires =\r\n    pyjwt==2.10.0\r\n", setuptoolsReading{specs: pin}, false},
		{"lone CR", "[options]\rinstall_requires =\r    pyjwt==2.10.0\r", setuptoolsReading{specs: pin}, false},
		{"form feed", opts + "install_requires =\n\f    pyjwt==2.10.0\n", setuptoolsReading{specs: pin}, true},
		{"no-break space", opts + "install_requires =\n pyjwt==2.10.0\n", setuptoolsReading{specs: pin}, true},
		{"undecodable comment", "# \xff\n" + opts + "install_requires = pyjwt==2.10.0\n", fails, true},
	}
	path := filepath.Join(t.TempDir(), "setup.cfg")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.st.fails && !tt.withhold {
				t.Fatal("a form setuptools fails on must be withheld")
			}
			scan := scanSetupCfg(path, []byte(tt.body))
			if scan.ok == tt.withhold {
				t.Fatalf("ok = %v, want %v (specs %q, build %q)", scan.ok, !tt.withhold, scan.specs, scan.buildSpecs)
			}
			if scan.ok && (!slices.Equal(scan.specs, tt.st.specs) || !slices.Equal(scan.buildSpecs, tt.st.build)) {
				t.Fatalf("read specs %q build %q; setuptools reads specs %q build %q", scan.specs, scan.buildSpecs, tt.st.specs, tt.st.build)
			}
		})
	}
}

// R6-B1: a key line indented directly under a section header is an option setuptools reads,
// so its pin at another version leaves the root pin unresolved. The control row's indented line
// folds into zip_safe's value, as setuptools reads it, and the root pin resolves.
func TestResolveVersions_SetupCfgIndentedKeys(t *testing.T) {
	for name, body := range map[string]string{
		"indented first key":              "[options]\n  install_requires =\n    pyjwt==2.10.0\n",
		"indented dashed key":             "[options]\n  install-requires = pyjwt==2.10.0\n",
		"tab-indented setup_requires":     "[options]\n\tsetup_requires = pyjwt==2.10.0\n",
		"indented key after a comment":    "[options]\n# deps\n    install_requires = pyjwt==2.10.0\n",
		"indented key after a blank line": "[options]\n\n    install_requires = pyjwt==2.10.0\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"requirements.txt": "pyjwt==2.8.0\n", "svc/setup.cfg": body})
			for i := 0; i < resolveRuns; i++ {
				mustUnresolvedPy(t, resolveVersion(t, dir, "pyjwt"))
			}
		})
	}
	t.Run("control: indented line folds into zip_safe", func(t *testing.T) {
		dir := writeTree(t, map[string]string{
			"requirements.txt": "pyjwt==2.8.0\n",
			"svc/setup.cfg":    "[options]\nzip_safe = 0\n    install_requires = pyjwt==2.10.0\n",
		})
		mustResolvedCompletePy(t, dir, "pyjwt", "2.8.0")
	})
}
