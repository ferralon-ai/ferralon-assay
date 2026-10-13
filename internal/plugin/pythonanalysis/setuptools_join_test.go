package pythonanalysis

import (
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Every setuptools requirement list goes through _reqs.parse, whose join_continuation joins an
// entry ending in a backslash to the next one after dropping the last two characters: "pyjw@\"
// then "t==2.10.0" installs pyjwt==2.10.0 (setuptools 84.0.0 egg_info on Python 3.14 reads
// exactly that for every form below). Each reader withholds the manifest rather than read the
// two halves. The control tree spells the joined requirement on one line, so a withheld tree
// differs from a readable one only by the continuation.
func TestResolveVersions_SetuptoolsJoinedEntryWithheld(t *testing.T) {
	const (
		splitFile = "pyjw@\\\nt==2.10.0\n"
		joinFile  = "pyjwt==2.10.0\n"
		splitList = `["pyjw@\\", "t==2.10.0"]`
		joinList  = `["pyjwt==2.10.0"]`
		project   = "[project]\nname = \"svc\"\nversion = \"1\"\n"
	)
	dynamicDeps := project + "dynamic = [\"dependencies\"]\n[tool.setuptools.dynamic]\ndependencies = {file = [\"rb.txt\"]}\n"
	dynamicExtra := project + "dynamic = [\"optional-dependencies\"]\n[tool.setuptools.dynamic]\noptional-dependencies.jwt = {file = [\"rb.txt\"]}\n"
	setupPy := func(kw, list string) string {
		return "from setuptools import setup\nsetup(name=\"svc\", " + kw + "=" + list + ")\n"
	}
	for _, tc := range []struct {
		name          string
		split, joined map[string]string
	}{
		{"pyproject dynamic dependencies file:",
			map[string]string{"svc/pyproject.toml": dynamicDeps, "svc/rb.txt": splitFile},
			map[string]string{"svc/pyproject.toml": dynamicDeps, "svc/rb.txt": joinFile}},
		{"pyproject dynamic optional-dependencies file:",
			map[string]string{"svc/pyproject.toml": dynamicExtra, "svc/rb.txt": splitFile},
			map[string]string{"svc/pyproject.toml": dynamicExtra, "svc/rb.txt": joinFile}},
		{"pyproject dependencies",
			map[string]string{"svc/pyproject.toml": project + "dependencies = " + splitList + "\n"},
			map[string]string{"svc/pyproject.toml": project + "dependencies = " + joinList + "\n"}},
		{"pyproject optional-dependencies",
			map[string]string{"svc/pyproject.toml": project + "[project.optional-dependencies]\njwt = " + splitList + "\n"},
			map[string]string{"svc/pyproject.toml": project + "[project.optional-dependencies]\njwt = " + joinList + "\n"}},
		{"setup.cfg install_requires file:",
			map[string]string{"svc/setup.cfg": "[options]\ninstall_requires = file: rb.txt\n", "svc/rb.txt": splitFile},
			map[string]string{"svc/setup.cfg": "[options]\ninstall_requires = file: rb.txt\n", "svc/rb.txt": joinFile}},
		{"setup.cfg extras_require file:",
			map[string]string{"svc/setup.cfg": "[options.extras_require]\njwt = file: rb.txt\n", "svc/rb.txt": splitFile},
			map[string]string{"svc/setup.cfg": "[options.extras_require]\njwt = file: rb.txt\n", "svc/rb.txt": joinFile}},
		{"setup.py install_requires",
			map[string]string{"svc/setup.py": setupPy("install_requires", splitList)},
			map[string]string{"svc/setup.py": setupPy("install_requires", joinList)}},
		{"setup.py extras_require",
			map[string]string{"svc/setup.py": setupPy("extras_require", `{"jwt": `+splitList+`}`)},
			map[string]string{"svc/setup.py": setupPy("extras_require", `{"jwt": `+joinList+`}`)}},
		{"setup.py setup_requires",
			map[string]string{"svc/setup.py": setupPy("setup_requires", splitList)},
			map[string]string{"svc/setup.py": setupPy("setup_requires", joinList)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.split["requirements.txt"] = "pyjwt==2.8.0\n"
			tc.joined["requirements.txt"] = "pyjwt==2.8.0\n"
			control := resolveVersion(t, writeTree(t, tc.joined), "pyjwt")
			if !control.Partiality.Complete || !control.Found {
				t.Fatalf("control tree must read in full; partiality=%+v found=%v", control.Partiality, control.Found)
			}
			dir := writeTree(t, tc.split)
			for i := 0; i < resolveRuns; i++ {
				mustWithheldPy(t, resolveVersion(t, dir, "pyjwt"))
			}
		})
	}
}

// mustWithheldPy asserts a manifest was withheld: the coordinate is found, its match is
// UNRESOLVED, and the result is partial for exactly one reason, tool_failure.
func mustWithheldPy(t *testing.T, res plugin.DependencyVersionResult) {
	t.Helper()
	mustUnresolvedPy(t, res)
	if res.Partiality.Complete || !slices.Equal(res.Partiality.Reasons, []string{plugin.PartialReasonToolFailure}) {
		t.Fatalf("manifest must be withheld as tool_failure; partiality=%+v", res.Partiality)
	}
}

// readRequirementSpecs drops comment lines and cuts an inline comment before it looks for a
// continuation, as _reqs.parse does (yield_lines, drop_comment, then join_continuation).
func TestReadRequirementSpecs_Continuation(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       []string
		ok         bool
	}{
		{"entry ends in a backslash", "pyjw@\\\nt==2.10.0\n", nil, false},
		{"backslash before an inline comment", "pyjw@\\ # c\nt==2.10.0\n", nil, false},
		{"last entry ends in a backslash", "six\npyjwt==2.10.0 \\\n", []string{"six"}, false},
		{"comment line ends in a backslash", "# c \\\npyjwt==2.10.0\n", []string{"pyjwt==2.10.0"}, true},
		{"inline comment ends in a backslash", "pyjwt==2.10.0 # c \\\nsix\n", []string{"pyjwt==2.10.0", "six"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"rb.txt": tc.text})
			specs, _, ok := readRequirementSpecs(dir, "rb.txt")
			if ok != tc.ok || !slices.Equal(specs, tc.want) {
				t.Fatalf("readRequirementSpecs = %q, %v; want %q, %v", specs, ok, tc.want, tc.ok)
			}
		})
	}
}

// setuptools reads a setup.py list element line by line and cuts each line at " #" before
// parsing it (yield_lines, drop_comment): "six\npyjwt==2.10.0" installs six and pyjwt==2.10.0,
// so does "six\fpyjwt==2.10.0" (Python decodes the form feed, a line break to splitlines), and
// "pyjwt==2.10.0 # c" installs pyjwt==2.10.0 (setuptools 84.0.0 egg_info, Python 3.14). The
// reader reads an element only as the one requirement it spells, so each withholds setup.py.
func TestResolveVersions_SetupPyElementNotAsWritten(t *testing.T) {
	setupPy := func(list string) string {
		return "from setuptools import setup\nsetup(name=\"svc\", install_requires=" + list + ")\n"
	}
	for _, tc := range []struct{ name, split, joined string }{
		{"line break", `["six\npyjwt==2.10.0"]`, `["six", "pyjwt==2.10.0"]`},
		{"line break, form feed escape", `["six\fpyjwt==2.10.0"]`, `["six", "pyjwt==2.10.0"]`},
		{"line break, vertical tab escape", `["six\x0bpyjwt==2.10.0"]`, `["six", "pyjwt==2.10.0"]`},
		{"line break, literal form feed", "[\"six\fpyjwt==2.10.0\"]", `["six", "pyjwt==2.10.0"]`},
		{"inline comment", `["pyjwt==2.10.0 # c"]`, `["pyjwt==2.10.0"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			control := resolveVersion(t, writeTree(t, map[string]string{"requirements.txt": "pyjwt==2.8.0\n", "svc/setup.py": setupPy(tc.joined)}), "pyjwt")
			if !control.Partiality.Complete || !control.Found {
				t.Fatalf("control tree must read in full; partiality=%+v found=%v", control.Partiality, control.Found)
			}
			dir := writeTree(t, map[string]string{"requirements.txt": "pyjwt==2.8.0\n", "svc/setup.py": setupPy(tc.split)})
			for i := 0; i < resolveRuns; i++ {
				mustWithheldPy(t, resolveVersion(t, dir, "pyjwt"))
			}
		})
	}
}
