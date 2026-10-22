package scriptsurface

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// gitlabCI are the names GitLab reads a pipeline from.
var gitlabCI = map[string]bool{".gitlab-ci.yml": true, ".gitlab-ci.yaml": true}

// maxIncludeDepth bounds how deep GitLab includes are followed; GitLab's own limit is lower
// than any real chain this would cut.
const maxIncludeDepth = 16

// gitlabIncludes returns the text of every file a GitLab pipeline file includes, followed
// through nested includes, as units read with the pipeline's own; or why it withholds. Only a
// local include of a literal, in-tree, regular file can be read here. A remote, template,
// project or component include, a glob or variable in a local path, a path outside the build
// root or not there, and an include this cannot decode each run jobs this does not read.
func (v *Veto) gitlabIncludes(path, src string, seen map[string]bool, depth int) ([]unit, string) {
	// A file with a spec: header keeps its include: in a later document, so every document is
	// read.
	var incs []yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader([]byte(src)))
	for {
		var doc struct {
			Include yaml.Node `yaml:"include"`
		}
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if strings.Contains(src, "include") {
				return nil, "GitLab pipeline whose includes cannot be decoded"
			}
			return nil, ""
		}
		incs = append(incs, doc.Include)
	}
	var locals []string
	add := func(n *yaml.Node) string {
		switch n.Kind {
		case yaml.ScalarNode:
			if strings.Contains(n.Value, "://") {
				return "GitLab remote include: " + n.Value
			}
			locals = append(locals, n.Value)
			return ""
		case yaml.MappingNode:
			local := ""
			for i := 0; i+1 < len(n.Content); i += 2 {
				switch k, val := n.Content[i].Value, n.Content[i+1]; k {
				case "local":
					if val.Kind != yaml.ScalarNode {
						return "GitLab local include that is not a path"
					}
					local = val.Value
				case "rules", "inputs":
				default:
					return "GitLab include read from outside the tree: " + k
				}
			}
			if local == "" {
				return "GitLab include with no local path"
			}
			locals = append(locals, local)
			return ""
		}
		return "GitLab include of an unknown form"
	}
	for i := range incs {
		switch inc := &incs[i]; inc.Kind {
		case 0:
		case yaml.SequenceNode:
			for _, n := range inc.Content {
				if why := add(n); why != "" {
					return nil, why
				}
			}
		default:
			if why := add(inc); why != "" {
				return nil, why
			}
		}
	}
	if len(locals) > 0 && depth >= maxIncludeDepth {
		return nil, "GitLab includes nested past the bound"
	}
	var units []unit
	for _, l := range locals {
		rel := strings.TrimPrefix(l, "/")
		p := filepath.Join(v.root, filepath.FromSlash(rel))
		if rel == "" || strings.ContainsAny(rel, "*?[{$~") || !v.inRoot(p) {
			return nil, "GitLab local include outside the tree: " + l
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		data, err := v.spec.ReadRegular(p)
		if err != nil {
			return nil, "GitLab local include unreadable: " + l
		}
		if v.spec.Env.Match(data) {
			return nil, "GitLab local include sets an installer variable"
		}
		units = append(units, unit{text: string(data)})
		nested, why := v.gitlabIncludes(path, string(data), seen, depth+1)
		if why != "" {
			return nil, why
		}
		units = append(units, nested...)
	}
	return units, ""
}
