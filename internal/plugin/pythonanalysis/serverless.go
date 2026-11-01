package pythonanalysis

import (
	"bytes"
	"io/fs"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// serverless-python-requirements installs the requirements file custom.pythonRequirements.fileName
// names, for a Serverless service and for each function module, with pip install -r and so with
// dependencies. It finds the file at path.join(servicePath, modulePath, fileName), and nothing
// keeps a module path inside the service, so the file may be anywhere whose path ends with the
// name.

// slsNames is what the Serverless configs under a root name.
type slsNames struct {
	names []string // the tail each path.join of a fileName ends with
	any   bool     // a config or fragment this cannot resolve, so any file may be named
}

// named reports whether a config may name the requirements file f.
func (s *slsNames) named(f string) bool {
	if s.any {
		return true
	}
	for _, n := range s.names {
		if strings.HasSuffix(f, string(filepath.Separator)+n) {
			return true
		}
	}
	return false
}

// slsScriptExts are the extensions of Serverless configs and ${file()} fragments written in
// code, which this does not evaluate.
var slsScriptExts = map[string]bool{".js": true, ".cjs": true, ".mjs": true, ".ts": true}

// serverlessNames walks root (all but its own .git and every node_modules) for the fileNames
// Serverless configs set. A config passed with --config may have any name, and custom or any
// part of it may be a ${file()} fragment, so every YAML, JSON or code file that mentions
// pythonRequirements is read. A YAML or JSON file names what its custom.pythonRequirements.fileName
// holds; any other file that mentions it, or a walk or read error, makes any file named.
func serverlessNames(root string) *slsNames {
	s := &slsNames{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			s.any = true
			return filepath.SkipAll
		}
		if d.IsDir() {
			if d.Name() == "node_modules" || d.Name() == ".git" && filepath.Dir(path) == filepath.Clean(root) {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		script := slsScriptExts[ext]
		if !script && ext != ".yml" && ext != ".yaml" && ext != ".json" {
			return nil
		}
		data, err := readRegular(path)
		if err != nil {
			s.any = true
			return filepath.SkipAll
		}
		if !bytes.Contains(data, []byte("pythonRequirements")) {
			return nil
		}
		name, ok := slsFileName(data)
		if script || !ok {
			s.any = true
			return filepath.SkipAll
		}
		if name != "" {
			s.names = append(s.names, name)
		}
		return nil
	})
	if err != nil {
		s.any = true
	}
	return s
}

// slsFileName reads custom.pythonRequirements.fileName from a YAML or JSON config, as the tail
// every path.join of it ends with: cleaned as if rooted, which drops a leading / and any ..
// that climbs past the start, so relative and with no .. element. It returns "" when the
// config sets none, which leaves the plugin's requirements.txt, or names no file, and false
// when the value cannot be resolved here: a document without custom or
// custom.pythonRequirements as a map (a fragment, or a reference to one), a variable, or a
// fileName that is not a string.
func slsFileName(data []byte) (string, bool) {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return "", false
	}
	custom, ok := doc["custom"].(map[string]any)
	if !ok {
		return "", false
	}
	pr, ok := custom["pythonRequirements"].(map[string]any)
	if !ok {
		return "", false
	}
	v, ok := pr["fileName"]
	if !ok || v == nil {
		return "", true
	}
	name, ok := v.(string)
	if !ok || strings.Contains(name, "${") {
		return "", false
	}
	sep := string(filepath.Separator)
	return strings.TrimPrefix(filepath.Clean(sep+filepath.FromSlash(name)), sep), true
}
