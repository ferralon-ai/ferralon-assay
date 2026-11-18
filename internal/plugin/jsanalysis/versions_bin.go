package jsanalysis

import (
	"bytes"
	"encoding/json"
	"io"
	"path"
	"path/filepath"
	"strings"
)

// laneLinked is the lane's Spec.Linked: a package.json's bin names the files npm, yarn and
// pnpm link into node_modules/.bin of whoever installs the package, or of a workspace that
// holds it, by command name; installing the package's own dependencies links none. It
// returns data with the bin value blanked (rest), that also with the name value blanked
// (bare), and each linked file, as npm reads it (normalize-package-bin: the path joined to
// the package root, backslashes as slashes), with its command names: an object bin's key and
// that key's base name, or for a string bin the package name and its unscoped part.
//
// ok is false for any other file, a package.json that does not decode as an object, one with
// no bin or a repeated top-level key, a bin that is not a string or an object of strings, or
// a string bin without a string name.
func laneLinked(p string, data []byte) (rest, bare []byte, links map[string][]string, ok bool) {
	if filepath.Base(p) != "package.json" {
		return nil, nil, nil, false
	}
	spans, ok := topLevelValues(data)
	if !ok {
		return nil, nil, nil, false
	}
	bin, has := spans["bin"]
	if !has {
		return nil, nil, nil, false
	}
	raw := data[bin[0]:bin[1]]
	links = map[string][]string{}
	var one string
	var many map[string]string
	switch {
	case raw[0] == '"' && json.Unmarshal(raw, &one) == nil:
		nameAt, has := spans["name"]
		var name string
		if !has || json.Unmarshal(data[nameAt[0]:nameAt[1]], &name) != nil || name == "" {
			return nil, nil, nil, false
		}
		cmds := []string{name}
		if _, unscoped, scoped := strings.Cut(name, "/"); scoped && strings.HasPrefix(name, "@") {
			cmds = append(cmds, unscoped)
		}
		links[binTarget(one)] = cmds
	case raw[0] == '{' && json.Unmarshal(raw, &many) == nil:
		for key, target := range many {
			t := binTarget(target)
			links[t] = append(links[t], key, path.Base(strings.ReplaceAll(key, `\`, "/")))
		}
	default:
		return nil, nil, nil, false
	}
	rest = blank(data, bin)
	bare = rest
	if nameAt, has := spans["name"]; has {
		bare = blank(rest, nameAt)
	}
	return rest, bare, links, true
}

// binTarget is a bin value as npm links it: its backslashes as slashes, joined to the package
// root so no .. leaves it.
func binTarget(v string) string {
	return strings.TrimPrefix(path.Join("/", strings.ReplaceAll(v, `\`, "/")), "/")
}

// topLevelValues returns the byte span of each top-level value in data, a JSON object; ok is
// false when data is not one or repeats a key.
func topLevelValues(data []byte) (map[string][2]int64, bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, false
	}
	spans := map[string][2]int64{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, false
		}
		key, _ := t.(string)
		if _, dup := spans[key]; dup {
			return nil, false
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, false
		}
		end := dec.InputOffset()
		start := end - int64(len(raw))
		if start < 0 || !bytes.Equal(data[start:end], raw) {
			return nil, false
		}
		spans[key] = [2]int64{start, end}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return spans, true
}

// blank returns a copy of data with every byte in span but a line break as a space, so it
// names nothing a match could find and keeps its lines.
func blank(data []byte, span [2]int64) []byte {
	out := bytes.Clone(data)
	for i := span[0]; i < span[1]; i++ {
		if out[i] != '\n' && out[i] != '\r' {
			out[i] = ' '
		}
	}
	return out
}
