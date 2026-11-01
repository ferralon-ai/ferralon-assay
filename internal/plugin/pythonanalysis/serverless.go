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
	root  string
	names []string // the tail each path.join of a fileName ends with
	any   bool     // a config or fragment this cannot resolve, so any file may be named
}

// named reports whether a config may name the requirements file f. A tail that climbs above
// the root matches any f it ends with, since the directories above the root cannot be checked.
func (s *slsNames) named(f string) bool {
	if s.any {
		return true
	}
	sep := string(filepath.Separator)
	r, err := filepath.Rel(s.root, f)
	if err != nil {
		return true
	}
	r = sep + r
	for _, n := range s.names {
		if strings.HasSuffix(r, sep+n) || strings.HasSuffix(sep+n, r) {
			return true
		}
	}
	return false
}

// slsScriptExts are the extensions of Serverless configs and ${file()} fragments written in
// code, which this does not evaluate.
var slsScriptExts = map[string]bool{".js": true, ".cjs": true, ".mjs": true, ".ts": true}

// serverlessNames walks root (all but its own .git and .serverless output and every
// node_modules) for the fileNames Serverless configs set. A config passed with --config may have
// any name, and custom or any part of it may be a ${file()} fragment, so every YAML, JSON or code
// file that mentions pythonRequirements or the plugin is read. A YAML or JSON file names what its
// custom.pythonRequirements.fileName holds; any other file that mentions either, or a walk or
// read error, makes any file named.
func serverlessNames(root string) *slsNames {
	s := &slsNames{root: root}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			s.any = true
			return filepath.SkipAll
		}
		if d.IsDir() {
			if d.Name() == "node_modules" || (d.Name() == ".git" || d.Name() == ".serverless") && filepath.Dir(path) == filepath.Clean(root) {
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
		mentioned := bytes.Contains(data, []byte("pythonRequirements"))
		if !mentioned && !bytes.Contains(data, []byte("serverless-python-requirements")) {
			return nil
		}
		name, ok := slsFileName(data, mentioned)
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
// when the value cannot be resolved here: a custom or custom.pythonRequirements that is not a
// map (a variable), a variable, or a fileName that is not a string. A document that mentions
// pythonRequirements (mentioned) without holding it under custom is a fragment, or a reference
// to one, and cannot be resolved either; one that only loads the plugin sets none.
func slsFileName(data []byte, mentioned bool) (string, bool) {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return "", false
	}
	c, ok := doc["custom"]
	if !ok || c == nil {
		return "", !mentioned
	}
	custom, ok := c.(map[string]any)
	if !ok {
		return "", false
	}
	p, ok := custom["pythonRequirements"]
	if !ok {
		return "", !mentioned
	}
	if p == nil {
		return "", true
	}
	pr, ok := p.(map[string]any)
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
