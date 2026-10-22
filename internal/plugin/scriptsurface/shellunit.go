package scriptsurface

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// shellUnit is CI text one shell runs from top to bottom: a GitHub step's run: scalar, or a
// GitLab job's before_script and then script. Its lines keep a directory and a venv mark from
// one to the next. dir, when not "", is the one directory the shell starts in.
type shellUnit struct {
	id  int
	dir string
}

// shellUnits maps the source line, from 0, of each scalar a shell unit is read from to its
// unit. Only a GitHub workflow and a GitLab pipeline or its include have units; any other
// file, or one that does not decode, has none, and its lines are each read on their own.
// included is true for a GitLab pipeline set with an include, where a job in one file may
// extend or reference a job in another.
func (v *Veto) shellUnits(path, src string, included bool) map[int]shellUnit {
	slash := "/" + strings.ToLower(filepath.ToSlash(path))
	github := strings.Contains(slash, "/.github/workflows/")
	gitlab := gitlabCI[strings.ToLower(filepath.Base(path))]
	if !github && !gitlab {
		return nil
	}
	units := map[int]shellUnit{}
	next := 0
	mark := func(n *yaml.Node, u shellUnit) {
		var walk func(*yaml.Node)
		walk = func(n *yaml.Node) {
			if n.Kind == yaml.ScalarNode {
				units[n.Line-1] = u
			}
			for _, c := range n.Content {
				walk(c)
			}
		}
		walk(n)
	}
	var tops []*yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader([]byte(src)))
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if !errors.Is(err, io.EOF) {
				return nil
			}
			break
		}
		if len(doc.Content) == 1 && doc.Content[0].Kind == yaml.MappingNode {
			tops = append(tops, doc.Content[0])
		}
	}
	var reused map[string]bool
	indirect := false
	if gitlab {
		reused = reusedJobs(tops)
		for _, top := range tops {
			indirect = indirect || aliasOrMerge(top)
		}
	}
	for _, top := range tops {
		if gitlab {
			for i := 0; i+1 < len(top.Content); i += 2 {
				job := top.Content[i+1]
				if job.Kind != yaml.MappingNode {
					continue
				}
				// before_script and script run in one shell, before_script first; a script
				// written above its before_script is read as a shell of its own. So is each of
				// a job another job may take them from (a hidden, extended, referenced or
				// anchored one) or one that takes keys from another (by extends or a << merge),
				// as what runs with its script may be another job's before_script. In a set of
				// files joined by include, that is any job: another file may extend it. GitLab
				// keeps the last of a repeated key, so a job that repeats one is read alone too.
				// An alias or a << merge anywhere in the file may stand for any key, value or
				// job name the join reads, so a file with one has every job read alone.
				name := top.Content[i].Value
				alone := included || strings.HasPrefix(name, ".") || reused[name] || anchored(job) || mapValue(job, "extends") != nil || mapValue(job, "<<") != nil || repeatsKey(job) || indirect
				pre := 0
				for j := 0; j+1 < len(job.Content); j += 2 {
					switch job.Content[j].Value {
					case "before_script":
						next++
						if !alone {
							pre = next
						}
						mark(job.Content[j+1], shellUnit{id: next, dir: v.root})
					case "script":
						id := pre
						if id == 0 {
							next++
							id = next
						}
						pre = 0
						mark(job.Content[j+1], shellUnit{id: id, dir: v.root})
					case "after_script":
						next++
						mark(job.Content[j+1], shellUnit{id: next, dir: v.root})
					}
				}
			}
			continue
		}
		wd, ok := v.runDir(top, v.root)
		if !ok {
			wd = ""
		}
		jobs := mapValue(top, "jobs")
		if jobs == nil || jobs.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(jobs.Content); i += 2 {
			job := jobs.Content[i+1]
			if job.Kind != yaml.MappingNode {
				continue
			}
			jwd, ok := v.runDir(job, wd)
			if !ok {
				jwd = ""
			}
			steps := mapValue(job, "steps")
			if steps == nil || steps.Kind != yaml.SequenceNode {
				continue
			}
			for _, step := range steps.Content {
				run := mapValue(step, "run")
				if run == nil || run.Kind != yaml.ScalarNode {
					continue
				}
				dir := jwd
				if n := mapValue(step, "working-directory"); n != nil {
					dir, _ = v.literalDir(n)
				}
				next++
				mark(run, shellUnit{id: next, dir: dir})
			}
		}
	}
	return units
}

// gitlabIncluded reports whether path is a GitLab pipeline and any of its units, the pipeline
// and the files it includes, may have an include: key: one written out, or one a << merge or
// a key that is not plain text may bring in, since GitLab resolves both.
func gitlabIncluded(path string, units []unit) bool {
	if !gitlabCI[strings.ToLower(filepath.Base(path))] {
		return false
	}
	for _, u := range units {
		dec := yaml.NewDecoder(bytes.NewReader([]byte(u.text)))
		for {
			var doc yaml.Node
			if err := dec.Decode(&doc); err != nil {
				if !errors.Is(err, io.EOF) {
					return true
				}
				break
			}
			if len(doc.Content) == 1 && mayInclude(doc.Content[0]) {
				return true
			}
		}
	}
	return false
}

// mayInclude reports whether a top-level mapping has an include: key or a key that may stand
// for one.
func mayInclude(top *yaml.Node) bool {
	for i := 0; i+1 < len(top.Content); i += 2 {
		k := top.Content[i]
		if k.Kind != yaml.ScalarNode || k.Value == "include" || k.Value == "<<" {
			return true
		}
	}
	return false
}

// aliasOrMerge reports whether n or anything in it is an alias or a << merge key.
func aliasOrMerge(n *yaml.Node) bool {
	if n.Kind == yaml.AliasNode {
		return true
	}
	for i, c := range n.Content {
		if n.Kind == yaml.MappingNode && i%2 == 0 && c.Value == "<<" {
			return true
		}
		if aliasOrMerge(c) {
			return true
		}
	}
	return false
}

// repeatsKey reports whether a mapping has the same key more than once.
func repeatsKey(n *yaml.Node) bool {
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i].Value
		if seen[k] {
			return true
		}
		seen[k] = true
	}
	return false
}

// reusedJobs returns the name of each GitLab job another job in the file extends or takes a
// key from with !reference.
func reusedJobs(tops []*yaml.Node) map[string]bool {
	reused := map[string]bool{}
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.SequenceNode && n.Tag == "!reference" && len(n.Content) > 0 {
			reused[n.Content[0].Value] = true
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	for _, top := range tops {
		for i := 0; i+1 < len(top.Content); i += 2 {
			ext := mapValue(top.Content[i+1], "extends")
			if ext != nil {
				reused[ext.Value] = true
				for _, c := range ext.Content {
					reused[c.Value] = true
				}
			}
			walk(top.Content[i+1])
		}
	}
	return reused
}

// anchored reports whether n or anything in it carries a YAML anchor, which another job may
// alias.
func anchored(n *yaml.Node) bool {
	if n.Anchor != "" {
		return true
	}
	for _, c := range n.Content {
		if anchored(c) {
			return true
		}
	}
	return false
}

// runDir returns the directory a GitHub workflow or job's defaults.run.working-directory sets,
// or inherit when it sets none; false when it sets one that is not a literal in-tree directory.
func (v *Veto) runDir(m *yaml.Node, inherit string) (string, bool) {
	n := mapValue(mapValue(mapValue(m, "defaults"), "run"), "working-directory")
	if n == nil {
		return inherit, true
	}
	return v.literalDir(n)
}

// literalDir returns the in-tree directory a working-directory value names from the build
// root; false when it is not a literal one.
func (v *Veto) literalDir(n *yaml.Node) (string, bool) {
	val := n.Value
	d := filepath.Join(v.root, val)
	if n.Kind != yaml.ScalarNode || val == "" || filepath.IsAbs(val) || strings.ContainsAny(val, "$`{~*") || !v.inRoot(d) || !isDir(d) {
		return "", false
	}
	return d, true
}

// mapValue returns the value of key in mapping m, or nil.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}
