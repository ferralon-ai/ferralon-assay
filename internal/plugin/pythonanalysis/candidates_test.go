package pythonanalysis

import (
	"path/filepath"
	"reflect"
	"testing"
)

// TestManifestCandidates pins the classifier's contract: every file whose name or content looks
// like a Python install surface is a candidate, and FullyRead is true only for one the resolver
// discovers and reads in full (or reads through a fully read manifest's file directive).
func TestManifestCandidates(t *testing.T) {
	root := writeTree(t, map[string]string{
		"uv.lock":                exUVLock,
		"pyproject.toml":         exDynPyproject + "[tool.setuptools.dynamic]\ndependencies = {file = [\"deps.txt\"]}\n",
		"deps.txt":               "flask>=3\n",
		"requirements.txt":       "-r requirements-dev.txt\nflask==3.0.0\n",
		"requirements-dev.txt":   "-e ./local\n",
		"build/requirements.txt": "flask==3.0.0\n",
		"pylock.toml":            "lock-version = \"1.0\"\n",
		"deploy/prod.pins":       "flask==3.0.0 --hash=sha256:abc\n",
		"Cargo.lock":             "[[package]]\nname = \"serde\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
		"README.md":              "```toml\n[project]\ndependencies = [\"flask\"]\n```\n",
		"words.txt":              "apple\nbanana\n",
		"hatch_build.py":         "from hatchling.metadata.plugin.interface import MetadataHookInterface\n",
	})
	type row struct {
		Path      string
		FullyRead bool
	}
	var got []row
	for _, c := range ManifestCandidates(root) {
		rel, _ := filepath.Rel(root, c.Path)
		got = append(got, row{filepath.ToSlash(rel), c.FullyRead})
	}
	want := []row{
		{"build/requirements.txt", false}, // outside the directories the resolver discovers
		{"deploy/prod.pins", false},       // a requirement file by content, never parsed
		{"deps.txt", true},                // read through pyproject's dynamic file directive
		{"hatch_build.py", false},         // a build hook can add dependencies
		{"pylock.toml", false},            // a format the resolver never parses
		{"pyproject.toml", true},
		{"requirements-dev.txt", false}, // an editable line
		{"requirements.txt", false},     // includes a file that is not fully read
		{"uv.lock", true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("candidates:\n%v\nwant:\n%v", got, want)
	}
}
