package pythonanalysis

import (
	"bytes"
	"io/fs"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// serverless-python-requirements installs, for a Serverless service and for each function
// module under it, the requirements file custom.pythonRequirements.fileName names, joined to
// the service directory and the module path, with pip install -r and so with dependencies.

// slsName is one fileName a Serverless config sets: name, relative to dir or to a function
// module under dir.
type slsName struct{ dir, name string }

// slsNames is what the Serverless configs under a root name.
type slsNames struct {
	names []slsName
	any   bool // a config this cannot resolve, so any file may be named
}

// named reports whether a config may name the requirements file f.
func (s *slsNames) named(f string) bool {
	if s.any {
		return true
	}
	sep := string(filepath.Separator)
	for _, n := range s.names {
		rel, err := filepath.Rel(n.dir, f)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+sep) {
			continue
		}
		if rel == n.name || strings.HasSuffix(rel, sep+n.name) {
			return true
		}
	}
	return false
}

// slsScriptConfigs are the Serverless config names written in code, which this does not
// evaluate.
var slsScriptConfigs = map[string]bool{
	"serverless.js": true, "serverless.cjs": true, "serverless.mjs": true, "serverless.ts": true,
}

// serverlessNames walks root (all but its own .git) for the fileNames Serverless configs set:
// every YAML file and serverless.json that mentions pythonRequirements is read, since a config
// passed with --config may have any name. A config in code that mentions it, a value that is
// not a plain string, a name that leaves the service directory, or a walk or read error makes
// any file named.
func serverlessNames(root string) *slsNames {
	s := &slsNames{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			s.any = true
			return filepath.SkipAll
		}
		if d.IsDir() {
			if d.Name() == ".git" && filepath.Dir(path) == filepath.Clean(root) {
				return filepath.SkipDir
			}
			return nil
		}
		base := strings.ToLower(d.Name())
		ext := filepath.Ext(base)
		script := slsScriptConfigs[base]
		if !script && ext != ".yml" && ext != ".yaml" && base != "serverless.json" {
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
			s.names = append(s.names, slsName{filepath.Dir(path), name})
		}
		return nil
	})
	if err != nil {
		s.any = true
	}
	return s
}

// slsFileName reads custom.pythonRequirements.fileName from a YAML or JSON config, cleaned
// and relative. It returns "" when the config sets none, which leaves the plugin's
// requirements.txt, and false when the value cannot be resolved here: a variable, a value that
// is not a string, or a path that leaves the directory it is joined to.
func slsFileName(data []byte) (string, bool) {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return "", false
	}
	custom, ok := doc["custom"]
	if !ok || custom == nil {
		return "", true
	}
	cm, ok := custom.(map[string]any)
	if !ok {
		return "", false
	}
	pr, ok := cm["pythonRequirements"]
	if !ok || pr == nil {
		return "", true
	}
	pm, ok := pr.(map[string]any)
	if !ok {
		return "", false
	}
	v, ok := pm["fileName"]
	if !ok || v == nil {
		return "", true
	}
	name, ok := v.(string)
	if !ok || strings.Contains(name, "${") {
		return "", false
	}
	name = filepath.Clean(filepath.FromSlash(name))
	if name == "." {
		return "", true
	}
	if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
		return "", false
	}
	return name, true
}
