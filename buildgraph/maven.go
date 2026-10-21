package buildgraph

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Plugin goals are pinned, so a step's output format is the one these parsers read whatever
// plugin versions the repository manages.
const (
	mavenHelp       = "org.apache.maven.plugins:maven-help-plugin:3.5.1"
	mavenDependency = "org.apache.maven.plugins:maven-dependency-plugin:3.8.1"
)

// Maven steps, as they appear in commands[] and in tool_failed:<step>.
const (
	stepVersion        = "version"
	stepActiveProfiles = "active-profiles"
	stepEffectivePOM   = "effective-pom"
	stepTree           = "tree"
	stepReactorPaths   = "reactor_paths"
	stepList           = "list"
)

// mavenBase is the batch-mode argv prefix every Maven step shares: the stated profiles and
// properties, passed verbatim.
func mavenBase(c Conditions) []string {
	args := []string{"-B"}
	if len(c.Profiles) > 0 {
		args = append(args, "-P", strings.Join(c.Profiles, ","))
	}
	keys := make([]string, 0, len(c.Properties))
	for k := range c.Properties {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "-D"+k+"="+c.Properties[k])
	}
	return args
}

func resolveMaven(ctx context.Context, r *runner, c Conditions) (*Graph, error) {
	if err := treeShapingOverride(c, r.env, r.dir); err != nil {
		return nil, err
	}
	base := mavenBase(c)
	g := &Graph{Tool: Tool{Name: "maven"}}

	out, err := r.run(ctx, stepVersion, append(base, "-v")...)
	if err != nil {
		return nil, err
	}
	if g.Tool.Version, g.JVM, err = parseMavenVersion(out); err != nil {
		return nil, err
	}
	if f := checkJDK(c.JDK, g.JVM.Version); f != nil {
		return nil, f
	}

	apFile := filepath.Join(r.work, "active-profiles.txt")
	if _, err := r.run(ctx, stepActiveProfiles, append(base, mavenHelp+":active-profiles", "-Doutput="+apFile)...); err != nil {
		return nil, err
	}
	profiles, err := readOutput(stepActiveProfiles, apFile, parseActiveProfiles)
	if err != nil {
		return nil, err
	}

	epFile := filepath.Join(r.work, "effective-pom.xml")
	if _, err := r.run(ctx, stepEffectivePOM, append(base, mavenHelp+":effective-pom", "-Doutput="+epFile)...); err != nil {
		return nil, err
	}
	effective, err := readOutput(stepEffectivePOM, epFile, parseEffectivePOM)
	if err != nil {
		return nil, err
	}
	if err := treeShapingInPOM(effective); err != nil {
		return nil, err
	}

	treeFile := filepath.Join(r.work, "tree.json")
	treeLog, err := r.run(ctx, stepTree, append(base, mavenDependency+":tree", "-DoutputType=json", "-DoutputFile="+treeFile, "-DappendOutput=true", "-Dverbose=false")...)
	if err != nil {
		return nil, err
	}
	reactor, err := parseReactor(treeLog)
	if err != nil {
		return nil, err
	}
	if reactor[0].file == "" {
		if reactor, err = reactorPaths(ctx, r, base, reactor); err != nil {
			return nil, err
		}
	}
	trees, err := readOutput(stepTree, treeFile, parseTrees)
	if err != nil {
		return nil, err
	}

	modules, err := mavenModules(reactor, trees, profiles)
	if err != nil {
		return nil, err
	}
	if err := resolveMavenFiles(ctx, r, base, modules, effective); err != nil {
		return nil, err
	}
	toolchains, err := mavenToolchains(effective)
	if err != nil {
		return nil, err
	}
	for i := range modules {
		modules[i].JDKToolchains = toolchains[modules[i].ID]
	}
	g.Modules = modules

	sum, err := sha256File(epFile)
	if err != nil {
		return nil, &Failure{Kind: KindToolFailed, Detail: stepEffectivePOM, Log: err.Error()}
	}
	g.Sidecars = []Sidecar{{Name: "effective-pom", Path: "effective-pom.xml", SHA256: sum}}

	g.Subject.Inputs, err = collectInputs(r.dir, mavenInput(reactor))
	if err != nil {
		return nil, err
	}
	poms := make([]string, 0, len(reactor))
	for _, rp := range reactor {
		poms = append(poms, rp.file)
	}
	if g.Subject.Inputs, err = withInputs(r.dir, g.Subject.Inputs, poms); err != nil {
		return nil, err
	}
	return g, nil
}

// treeShapingParams are dependency:tree's parameters that change which nodes it reports.
var treeShapingParams = map[string]bool{"verbose": true, "scope": true, "includes": true, "excludes": true}

// treeShaping finds one of treeShapingParams set as a property on a command or JVM option line,
// in any of Maven's spellings: -Dk, -D k, --define k, --define=k.
var treeShaping = regexp.MustCompile(`(?:^|\s)(?:-D\s*|--define[=\s]\s*)(verbose|scope|includes|excludes)(?:[=\s]|$)`)

// treeShapingEnv are the variables whose options reach Maven's command line or its JVM.
var treeShapingEnv = map[string]bool{"MAVEN_ARGS": true, "MAVEN_OPTS": true, "JAVA_TOOL_OPTIONS": true, "JDK_JAVA_OPTIONS": true}

// treeShapingOverride fails a resolution whose stated properties, Maven or JVM options, or .mvn
// configuration would set one of treeShapingParams: the tree would then not be the build's graph.
// A setting that happens to match the build's default still fails; that red is the safe side.
func treeShapingOverride(c Conditions, env []string, dir string) error {
	fail := func(where, key string) error {
		return &Failure{Kind: KindToolFailed, Detail: stepConditions, Log: where + " sets -D" + key + ", which reshapes dependency:tree"}
	}
	for k := range c.Properties {
		if m := treeShaping.FindStringSubmatch("-D" + k); m != nil {
			return fail("the stated properties", m[1])
		}
	}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		if !treeShapingEnv[k] {
			continue
		}
		if m := treeShaping.FindStringSubmatch(v); m != nil {
			return fail(k, m[1])
		}
	}
	for _, name := range []string{"maven.config", "jvm.config"} {
		if b, err := os.ReadFile(filepath.Join(dir, ".mvn", name)); err == nil {
			if m := treeShaping.FindStringSubmatch(string(b)); m != nil {
				return fail(".mvn/"+name, m[1])
			}
		}
	}
	return nil
}

// treeShapingInPOM fails when a module's effective POM sets one of treeShapingParams: as a
// project property, which a mojo parameter's expression reads, or in the maven-dependency-plugin
// configuration a command-line goal takes (plugin-wide or the default-cli execution, in plugins
// or pluginManagement), which -D does not override. Other executions never reach the tree goal.
func treeShapingInPOM(effective []effectiveProject) error {
	fail := func(p effectiveProject, where, key string) error {
		return &Failure{Kind: KindToolFailed, Detail: stepConditions, Log: p.GroupID + ":" + p.ArtifactID + " sets " + key + " in " + where + ", which reshapes dependency:tree"}
	}
	for _, p := range effective {
		for _, e := range p.Properties.Any {
			if treeShapingParams[e.XMLName.Local] {
				return fail(p, "<properties>", e.XMLName.Local)
			}
		}
		for _, pl := range append(append([]effectivePlugin{}, p.Build.Plugins.Plugin...), p.Build.PluginManagement.Plugins.Plugin...) {
			if pl.ArtifactID != "maven-dependency-plugin" {
				continue
			}
			configs := []xmlChildren{pl.Configuration}
			for _, ex := range pl.Executions.Execution {
				if ex.ID == "default-cli" {
					configs = append(configs, ex.Configuration)
				}
			}
			for _, c := range configs {
				for _, e := range c.Any {
					if treeShapingParams[e.XMLName.Local] {
						return fail(p, "maven-dependency-plugin configuration", e.XMLName.Local)
					}
				}
			}
		}
	}
	return nil
}

// toolchainConfig is the part of a plugin's configuration that selects a JDK toolchain: the
// maven-toolchains-plugin's <toolchains><jdk>, or a toolchain-aware plugin's own <jdkToolchain>.
type toolchainConfig struct {
	Toolchains struct {
		JDK []struct {
			Version string `xml:"version"`
		} `xml:"jdk"`
	} `xml:"toolchains"`
	JDKToolchain *struct {
		Version string `xml:"version"`
	} `xml:"jdkToolchain"`
}

// toolchainUnstated stands for a toolchain selected by vendor or other requirements alone, whose
// version the build does not state.
const toolchainUnstated = "unstated"

// mavenToolchains reads the JDK toolchains each module's build plugins select, by
// groupId:artifactId, from the plugin-wide and every execution's configuration.
func mavenToolchains(effective []effectiveProject) (map[string][]string, error) {
	out := map[string][]string{}
	for _, p := range effective {
		key := p.GroupID + ":" + p.ArtifactID
		for _, pl := range p.Build.Plugins.Plugin {
			configs := []xmlChildren{pl.Configuration}
			for _, ex := range pl.Executions.Execution {
				configs = append(configs, ex.Configuration)
			}
			for _, c := range configs {
				var tc toolchainConfig
				if err := xml.Unmarshal([]byte("<configuration>"+c.Inner+"</configuration>"), &tc); err != nil {
					return nil, &Failure{Kind: KindToolFailed, Detail: stepEffectivePOM, Log: key + " " + pl.ArtifactID + " configuration: " + err.Error()}
				}
				var versions []string
				if pl.ArtifactID == "maven-toolchains-plugin" {
					for _, j := range tc.Toolchains.JDK {
						versions = append(versions, j.Version)
					}
				}
				if tc.JDKToolchain != nil {
					versions = append(versions, tc.JDKToolchain.Version)
				}
				for _, v := range versions {
					if v = strings.TrimSpace(v); v == "" {
						v = toolchainUnstated
					}
					if !slices.Contains(out[key], v) {
						out[key] = append(out[key], v)
					}
				}
			}
		}
	}
	return out, nil
}

// readOutput parses a step's output file; a missing or unparseable file fails that step.
func readOutput[T any](step, file string, parse func([]byte) (T, error)) (T, error) {
	var zero T
	b, err := os.ReadFile(file)
	if err != nil {
		return zero, &Failure{Kind: KindToolFailed, Detail: step, Log: err.Error()}
	}
	v, err := parse(b)
	if err != nil {
		return zero, &Failure{Kind: KindToolFailed, Detail: step, Log: err.Error()}
	}
	return v, nil
}

var (
	mavenVersionLine = regexp.MustCompile(`(?m)^Apache Maven (\S+)`)
	mavenJavaLine    = regexp.MustCompile(`(?m)^Java version: ([^,\s]+), vendor: ([^,]+),`)
)

func parseMavenVersion(out []byte) (string, JVM, error) {
	v := mavenVersionLine.FindSubmatch(out)
	j := mavenJavaLine.FindSubmatch(out)
	if v == nil || j == nil {
		return "", JVM{}, &Failure{Kind: KindToolFailed, Detail: stepVersion, Log: tail(out)}
	}
	return string(v[1]), JVM{Version: string(j[1]), Vendor: strings.TrimSpace(string(j[2]))}, nil
}

var (
	activeProject = regexp.MustCompile(`^Active Profiles for Project '([^':]+):([^':]+):[^']*':$`)
	activeProfile = regexp.MustCompile(`^ - (\S+) \(source: [^)]*\)$`)
)

// parseActiveProfiles maps each project's g:a to the ids of its active profiles, in the order
// the help plugin lists them.
func parseActiveProfiles(b []byte) (map[string][]string, error) {
	out := map[string][]string{}
	current := ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if m := activeProject.FindStringSubmatch(line); m != nil {
			current = m[1] + ":" + m[2]
			if _, dup := out[current]; dup {
				return nil, fmt.Errorf("project %s listed twice", current)
			}
			out[current] = nil
			continue
		}
		if m := activeProfile.FindStringSubmatch(line); m != nil {
			if current == "" {
				return nil, fmt.Errorf("profile %s before any project", m[1])
			}
			out[current] = append(out[current], m[1])
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no projects")
	}
	return out, sc.Err()
}

// xmlChildren holds an element's child element names, and its content verbatim.
type xmlChildren struct {
	Any []struct {
		XMLName xml.Name
	} `xml:",any"`
	Inner string `xml:",innerxml"`
}

// effectivePlugin is a plugin's configuration as an effective POM gives it.
type effectivePlugin struct {
	ArtifactID    string      `xml:"artifactId"`
	Configuration xmlChildren `xml:"configuration"`
	Executions    struct {
		Execution []struct {
			ID            string      `xml:"id"`
			Configuration xmlChildren `xml:"configuration"`
		} `xml:"execution"`
	} `xml:"executions"`
}

// effectiveProject is what the producer reads from one effective POM: its identity, its
// repositories verbatim, its system-scoped dependencies' paths, and the properties and plugin
// configuration treeShapingInPOM checks.
type effectiveProject struct {
	GroupID    string      `xml:"groupId"`
	ArtifactID string      `xml:"artifactId"`
	Properties xmlChildren `xml:"properties"`
	Build      struct {
		Plugins struct {
			Plugin []effectivePlugin `xml:"plugin"`
		} `xml:"plugins"`
		PluginManagement struct {
			Plugins struct {
				Plugin []effectivePlugin `xml:"plugin"`
			} `xml:"plugins"`
		} `xml:"pluginManagement"`
	} `xml:"build"`
	Repositories struct {
		Repository []struct {
			ID    string `xml:"id"`
			Inner string `xml:",innerxml"`
		} `xml:"repository"`
	} `xml:"repositories"`
	Dependencies struct {
		Dependency []struct {
			GroupID    string `xml:"groupId"`
			ArtifactID string `xml:"artifactId"`
			Scope      string `xml:"scope"`
			SystemPath string `xml:"systemPath"`
		} `xml:"dependency"`
	} `xml:"dependencies"`
}

// parseEffectivePOM reads help:effective-pom output: a <projects> list for a reactor, a single
// <project> otherwise.
func parseEffectivePOM(b []byte) ([]effectiveProject, error) {
	var many struct {
		XMLName  xml.Name           `xml:"projects"`
		Projects []effectiveProject `xml:"project"`
	}
	if err := xml.Unmarshal(b, &many); err == nil {
		return many.Projects, nil
	}
	var one effectiveProject
	if err := xml.Unmarshal(b, &one); err != nil {
		return nil, err
	}
	return []effectiveProject{one}, nil
}

// reactorProject is one module as Maven's reactor log announced it.
type reactorProject struct {
	key  string // g:a
	file string // the module's POM, slash path from the repository root
}

var (
	reactorHeader = regexp.MustCompile(`^\[INFO\] -+< ([^:\s]+):([^:\s]+) >-+$`)
	reactorFrom   = regexp.MustCompile(`^\[INFO\]   from (.+)$`)
)

// parseReactor reads the module list from a step's batch log: each "--< g:a >--" header and the
// "from <pom>" line newer Mavens print beneath it. Older ones print no "from" line, which leaves
// every file empty for reactorPaths to fill; a log naming some POMs and not others fails.
func parseReactor(log []byte) ([]reactorProject, error) {
	var out []reactorProject
	pending, named := -1, 0
	sc := bufio.NewScanner(bytes.NewReader(log))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if m := reactorHeader.FindStringSubmatch(line); m != nil {
			out = append(out, reactorProject{key: m[1] + ":" + m[2]})
			pending = len(out) - 1
			continue
		}
		if m := reactorFrom.FindStringSubmatch(line); m != nil && pending >= 0 {
			file := filepath.ToSlash(strings.TrimSpace(m[1]))
			if path.IsAbs(file) || file == ".." || strings.HasPrefix(file, "../") {
				return nil, &Failure{Kind: KindToolFailed, Detail: stepTree, Log: "module POM outside the repository: " + file}
			}
			out[pending].file = file
			pending = -1
			named++
		}
	}
	switch {
	case len(out) == 0:
		return nil, &Failure{Kind: KindToolFailed, Detail: stepTree, Log: "no reactor modules in the log\n" + tail(log)}
	case named != 0 && named != len(out):
		return nil, &Failure{Kind: KindToolFailed, Detail: stepTree, Log: fmt.Sprintf("the log names POMs for %d of %d modules", named, len(out))}
	}
	return out, nil
}

// evaluateNull is what help:evaluate writes for an expression with no value.
const evaluateNull = "null object or invalid expression"

// reactorPaths asks Maven for each module's POM when its log does not name them. help:evaluate is
// an aggregator, so it reads session.projects one index at a time, with the tree step's
// arguments: the id must be a module the log announced, the file must be inside the repository,
// and the index past the last module must be empty.
func reactorPaths(ctx context.Context, r *runner, base []string, headers []reactorProject) ([]reactorProject, error) {
	fail := func(format string, a ...any) error {
		return &Failure{Kind: KindToolFailed, Detail: stepReactorPaths, Log: fmt.Sprintf(format, a...)}
	}
	eval := func(i int, prop string) (string, error) {
		out := filepath.Join(r.work, "reactor", fmt.Sprintf("%d.%s", i, prop))
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return "", fail("%v", err)
		}
		args := append(append([]string{}, base...), mavenHelp+":evaluate", fmt.Sprintf("-Dexpression=session.projects[%d].%s", i, prop), "-Doutput="+out)
		if _, err := r.run(ctx, stepReactorPaths, args...); err != nil {
			return "", err
		}
		b, err := os.ReadFile(out)
		if err != nil {
			return "", fail("%v", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	pending := map[string]bool{}
	for _, h := range headers {
		pending[h.key] = true
	}
	out := make([]reactorProject, 0, len(headers))
	for i := range headers {
		id, err := eval(i, "id")
		if err != nil {
			return nil, err
		}
		f := strings.Split(id, ":")
		if len(f) != 4 || !pending[f[0]+":"+f[1]] {
			return nil, fail("project %d is %q, not a module the log announced", i, id)
		}
		key := f[0] + ":" + f[1]
		delete(pending, key)
		file, err := eval(i, "file")
		if err != nil {
			return nil, err
		}
		if !filepath.IsAbs(file) {
			return nil, fail("project %s has POM %q", key, file)
		}
		real, ok := realRel(r.dir, file)
		if !ok || real == "" {
			return nil, fail("module POM outside the repository: %s", file)
		}
		// The path as Maven names it, as a "from" line would give it, unless only the resolved
		// one is under the repository.
		rel, ok := relPath(r.dir, filepath.Clean(file))
		if !ok {
			rel = real
		}
		out = append(out, reactorProject{key: key, file: rel})
	}
	if extra, err := eval(len(headers), "id"); err != nil {
		return nil, err
	} else if extra != evaluateNull {
		return nil, fail("Maven has a project the log did not announce: %s", extra)
	}
	return out, nil
}

// treeNode is one node of dependency:tree's JSON output. optional is a string in that output.
type treeNode struct {
	GroupID    string     `json:"groupId"`
	ArtifactID string     `json:"artifactId"`
	Version    string     `json:"version"`
	Type       string     `json:"type"`
	Scope      string     `json:"scope"`
	Classifier string     `json:"classifier"`
	Optional   any        `json:"optional"`
	Children   []treeNode `json:"children"`
}

// parseTrees reads the concatenated JSON documents dependency:tree appends, one per module.
func parseTrees(b []byte) ([]treeNode, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	var out []treeNode
	for {
		var t treeNode
		err := dec.Decode(&t)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty tree output")
	}
	return out, nil
}

func (t treeNode) optional() bool {
	switch v := t.Optional.(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

func (t treeNode) node() Node {
	typ := t.Type
	if typ == "" {
		typ = "jar"
	}
	return Node{
		ID:         NodeID(t.GroupID, t.ArtifactID, typ, t.Classifier, t.Version),
		Group:      t.GroupID,
		Artifact:   t.ArtifactID,
		Version:    t.Version,
		Type:       typ,
		Classifier: t.Classifier,
		Scope:      t.Scope,
		Optional:   t.optional(),
	}
}

// mavenModules pairs each reactor module with its tree, one each, and flattens the tree into
// nodes and edges. A node the tree reaches twice is kept once.
func mavenModules(reactor []reactorProject, trees []treeNode, profiles map[string][]string) ([]Module, error) {
	byKey := map[string]treeNode{}
	for _, t := range trees {
		k := t.GroupID + ":" + t.ArtifactID
		if _, dup := byKey[k]; dup {
			return nil, &Failure{Kind: KindToolFailed, Detail: stepTree, Log: "two trees for " + k}
		}
		byKey[k] = t
	}
	if len(byKey) != len(reactor) {
		return nil, &Failure{Kind: KindToolFailed, Detail: stepTree, Log: fmt.Sprintf("%d trees for %d reactor modules", len(byKey), len(reactor))}
	}
	var modules []Module
	for _, rp := range reactor {
		t, ok := byKey[rp.key]
		if !ok {
			return nil, &Failure{Kind: KindToolFailed, Detail: stepTree, Log: "no tree for " + rp.key}
		}
		ap, ok := profiles[rp.key]
		if !ok {
			return nil, &Failure{Kind: KindToolFailed, Detail: stepActiveProfiles, Log: "no active-profiles entry for " + rp.key}
		}
		root := t.node()
		m := Module{ID: rp.key, Path: path.Dir(rp.file), Root: root.ID, ActiveProfiles: ap}
		seen := map[string]bool{}
		// A mediated tree holds one version of a coordinate; two mean it is not the build's graph.
		versions := map[string]string{}
		var walk func(n treeNode, id string) error
		walk = func(n treeNode, id string) error {
			for _, c := range n.Children {
				cn := c.node()
				coord := cn.Group + ":" + cn.Artifact + ":" + cn.Type + ":" + cn.Classifier
				if v, ok := versions[coord]; ok && v != cn.Version {
					return &Failure{Kind: KindToolFailed, Detail: stepTree, Log: rp.key + " holds " + coord + " at " + v + " and " + cn.Version}
				}
				versions[coord] = cn.Version
				m.Edges = append(m.Edges, Edge{From: id, To: cn.ID})
				if !seen[cn.ID] {
					seen[cn.ID] = true
					m.Nodes = append(m.Nodes, cn)
					if err := walk(c, cn.ID); err != nil {
						return err
					}
				}
			}
			return nil
		}
		seen[root.ID] = true
		m.Nodes = append(m.Nodes, root)
		if err := walk(t, root.ID); err != nil {
			return nil, err
		}
		modules = append(modules, m)
	}
	return modules, nil
}

// fileKey is how dependency:list names an artifact: g:a:type[:classifier]:version.
type fileKey = string

// resolveMavenFiles fills each external node's file. dependency:list on the reactor itself
// needs its modules built, so the external nodes are listed through a generated reactor that
// declares exactly them, by full coordinate and scope, with every transitive excluded, against
// the repositories the effective POMs name. Reactor modules, at the version the reactor builds,
// have no file. A system-scoped node's file is the systemPath its module's effective POM gives
// it, which Maven reads in place; one only a dependency declares fails closed.
func resolveMavenFiles(ctx context.Context, r *runner, base []string, modules []Module, effective []effectiveProject) error {
	reactor := map[string]bool{}
	for _, m := range modules {
		for _, n := range m.Nodes {
			if n.ID == m.Root {
				reactor[n.Group+":"+n.Artifact+":"+n.Version] = true
			}
		}
	}
	sibling := func(n Node) bool { return reactor[n.Group+":"+n.Artifact+":"+n.Version] }
	system := map[string]map[string]string{} // module g:a → dependency g:a → systemPath
	for _, p := range effective {
		k := p.GroupID + ":" + p.ArtifactID
		for _, d := range p.Dependencies.Dependency {
			if d.Scope == "system" {
				if system[k] == nil {
					system[k] = map[string]string{}
				}
				system[k][d.GroupID+":"+d.ArtifactID] = d.SystemPath
			}
		}
	}

	var want []Node
	seen := map[Node]bool{}
	for _, m := range modules {
		for _, n := range m.Nodes {
			if n.ID == m.Root || sibling(n) || n.Scope == "system" {
				continue
			}
			n.File = nil
			if !seen[n] {
				seen[n] = true
				want = append(want, n)
			}
		}
	}
	files := map[fileKey]string{}
	if len(want) > 0 {
		var err error
		if files, err = listFiles(ctx, r, base, want, effective); err != nil {
			return err
		}
	}

	for mi := range modules {
		m := &modules[mi]
		for ni := range m.Nodes {
			n := &m.Nodes[ni]
			if n.ID == m.Root || sibling(*n) {
				continue
			}
			p := files[n.ID]
			if n.Scope == "system" {
				if p = system[m.ID][n.Group+":"+n.Artifact]; p == "" || !filepath.IsAbs(p) {
					return &Failure{Kind: KindToolFailed, Detail: stepList, Log: "no absolute systemPath in " + m.ID + " for system-scoped " + n.ID}
				}
				p = filepath.Clean(p)
			}
			if p == "" {
				return &Failure{Kind: KindToolFailed, Detail: stepList, Log: "no file listed for " + n.ID}
			}
			sum, err := sha256File(p)
			if err != nil {
				return &Failure{Kind: KindToolFailed, Detail: stepList, Log: err.Error()}
			}
			n.File = &File{Path: p, SHA256: sum}
		}
	}
	return nil
}

// listFiles writes the generated reactor and runs dependency:list over it. A coordinate held at
// several versions goes into several layers, since one POM declares a coordinate once.
func listFiles(ctx context.Context, r *runner, base []string, want []Node, effective []effectiveProject) (map[fileKey]string, error) {
	dir := filepath.Join(r.work, "resolve")
	var layers [][]Node
	for _, n := range want {
		k := n.Group + ":" + n.Artifact + ":" + n.Type + ":" + n.Classifier
		placed := false
		for i := range layers {
			clash := false
			for _, o := range layers[i] {
				if o.Group+":"+o.Artifact+":"+o.Type+":"+o.Classifier == k {
					clash = true
					break
				}
			}
			if !clash {
				layers[i] = append(layers[i], n)
				placed = true
				break
			}
		}
		if !placed {
			layers = append(layers, []Node{n})
		}
	}
	repos := mavenRepositories(effective)
	var modules strings.Builder
	for i, layer := range layers {
		name := fmt.Sprintf("layer-%d", i)
		modules.WriteString("    <module>" + name + "</module>\n")
		if err := writeFile(filepath.Join(dir, name, "pom.xml"), layerPOM(name, repos, layer)); err != nil {
			return nil, err
		}
	}
	if err := writeFile(filepath.Join(dir, "pom.xml"), aggregatorPOM(repos, modules.String())); err != nil {
		return nil, err
	}
	if err := copyMavenConfig(r.dir, dir); err != nil {
		return nil, err
	}
	listFile := filepath.Join(r.work, "list.txt")
	args := append(append([]string{}, base...), "-f", filepath.Join(dir, "pom.xml"), mavenDependency+":list",
		"-DoutputAbsoluteArtifactFilename=true", "-DoutputFile="+listFile, "-DappendOutput=true")
	if _, err := r.run(ctx, stepList, args...); err != nil {
		return nil, err
	}
	return readOutput(stepList, listFile, parseList)
}

func writeFile(p, body string) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return &Failure{Kind: KindToolFailed, Detail: stepList, Log: err.Error()}
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		return &Failure{Kind: KindToolFailed, Detail: stepList, Log: err.Error()}
	}
	return nil
}

// copyMavenConfig carries the repository's .mvn configuration (maven.config, jvm.config,
// extensions.xml) to the generated reactor, so it resolves with the same transports and options.
func copyMavenConfig(repo, dir string) error {
	for _, name := range []string{"maven.config", "jvm.config", "extensions.xml"} {
		src := filepath.Join(repo, ".mvn", name)
		fi, err := os.Lstat(src)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		b, err := os.ReadFile(src)
		if err != nil {
			return &Failure{Kind: KindToolFailed, Detail: stepList, Log: err.Error()}
		}
		if err := writeFile(filepath.Join(dir, ".mvn", name), string(b)); err != nil {
			return err
		}
	}
	return nil
}

// mavenRepositories is every repository the effective POMs declare, first declaration of an id
// kept, verbatim.
func mavenRepositories(effective []effectiveProject) string {
	var b strings.Builder
	seen := map[string]bool{}
	for _, p := range effective {
		for _, repo := range p.Repositories.Repository {
			if seen[repo.ID] {
				continue
			}
			seen[repo.ID] = true
			b.WriteString("    <repository>" + repo.Inner + "</repository>\n")
		}
	}
	return b.String()
}

const pomHead = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>assay.buildgraph</groupId>
`

func aggregatorPOM(repos, modules string) string {
	return pomHead + "  <artifactId>resolve</artifactId>\n  <version>0</version>\n  <packaging>pom</packaging>\n" +
		"  <modules>\n" + modules + "  </modules>\n" +
		"  <repositories>\n" + repos + "  </repositories>\n</project>\n"
}

func layerPOM(name, repos string, nodes []Node) string {
	var b strings.Builder
	b.WriteString(pomHead + "  <artifactId>" + name + "</artifactId>\n  <version>0</version>\n  <packaging>pom</packaging>\n")
	b.WriteString("  <repositories>\n" + repos + "  </repositories>\n  <dependencies>\n")
	for _, n := range nodes {
		b.WriteString("    <dependency>\n")
		for _, f := range [][2]string{{"groupId", n.Group}, {"artifactId", n.Artifact}, {"version", n.Version}, {"type", n.Type}, {"classifier", n.Classifier}, {"scope", n.Scope}} {
			if f[1] != "" {
				b.WriteString("      <" + f[0] + ">" + xmlText(f[1]) + "</" + f[0] + ">\n")
			}
		}
		b.WriteString("      <exclusions><exclusion><groupId>*</groupId><artifactId>*</artifactId></exclusion></exclusions>\n")
		b.WriteString("    </dependency>\n")
	}
	b.WriteString("  </dependencies>\n</project>\n")
	return b.String()
}

func xmlText(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

var (
	// The coordinate holds no slash and the path is absolute, so a coordinate part spelled like
	// a scope cannot split the line early.
	listScope  = regexp.MustCompile(`^([^/]+):(compile|provided|runtime|test|system):(/.*)$`)
	listModule = regexp.MustCompile(` -- module \S+(?: \[auto\]| \(auto\))?$`)
)

// parseList reads dependency:list's "g:a:type[:classifier]:version:scope:/path" lines into the
// file each coordinate resolved to. A coordinate listed with two different files fails.
func parseList(b []byte) (map[fileKey]string, error) {
	out := map[fileKey]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r"))
		if line == "" || line == "none" || strings.HasPrefix(line, "The following files have been resolved") {
			continue
		}
		line = listModule.ReplaceAllString(line, "")
		m := listScope.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("unreadable list line %q", line)
		}
		f := strings.Split(m[1], ":")
		var key string
		switch len(f) {
		case 4:
			key = NodeID(f[0], f[1], f[2], "", f[3])
		case 5:
			key = NodeID(f[0], f[1], f[2], f[3], f[4])
		default:
			return nil, fmt.Errorf("unreadable coordinate %q", m[1])
		}
		if prev, ok := out[key]; ok && prev != m[3] {
			return nil, fmt.Errorf("%s listed at %s and %s", key, prev, m[3])
		}
		out[key] = m[3]
	}
	return out, sc.Err()
}

// mavenInput accepts every POM in the tree, each reactor module's POM whatever its name, and
// the .mvn configuration Maven reads.
func mavenInput(reactor []reactorProject) func(rel, name string) bool {
	files := map[string]bool{}
	for _, rp := range reactor {
		files[rp.file] = true
	}
	return func(rel, name string) bool {
		switch rel {
		case ".mvn/maven.config", ".mvn/jvm.config", ".mvn/extensions.xml", ".mvn/wrapper/maven-wrapper.properties":
			return true
		}
		return name == "pom.xml" || files[rel]
	}
}
