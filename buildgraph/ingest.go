package buildgraph

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
)

// Ingest checks, as they appear in graph_rejected:<check> beside Validate's.
const (
	CheckDecode        = "decode"
	CheckConditions    = "conditions"
	CheckSubjectInputs = "subject_inputs"
	CheckModulePath    = "module_path"
	CheckDuplicateKey  = "duplicate_key"
	CheckScope         = "scope"
	CheckNodeFile      = "node_file"
)

// scopes are the scopes a non-root node may carry: Maven's, and the ones the Gradle producer folds
// its classpaths into. ScopeOther is a dependency the build resolves on no classpath: one a
// distribution copies in, or a tool's.
var scopes = map[string]bool{"compile": true, "runtime": true, "provided": true, "system": true, "test": true, ScopeOther: true}

// ScopeOther is the scope of a node the build resolves on a configuration that is no classpath.
const ScopeOther = "other"

// Load reads the graph at file and checks it against the checkout at dir and the conditions the
// scan states. On top of Validate it requires that:
//   - the graph was resolved under exactly the stated conditions;
//   - every build input it names still has its recorded sha256, and the checkout holds no build
//     input it does not name;
//   - every module path is a clean relative path to a directory inside dir;
//   - each module holds one node per group:artifact:type:classifier, every non-root node at a
//     known scope;
//   - every file is absolute and still has its recorded sha256, and a node without one is the
//     module root, a reactor sibling, or a pom.
//
// Any failure is a *Failure of kind graph_rejected naming the check.
func Load(file, dir string, stated Conditions) (*Graph, error) {
	g, err := Decode(file)
	if err != nil {
		return nil, err
	}
	if check := g.Validate(); check != "" {
		log := ""
		if check == "schema" && g.Schema == schemaV1 {
			log = "graph written by an older resolve-graph; re-run resolve-graph"
		}
		return nil, reject(check, log)
	}
	if !sameConditions(g.Conditions, stated) {
		return nil, reject(CheckConditions, "graph resolved under other conditions than the scan states")
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, reject(CheckSubjectInputs, err.Error())
	}
	if err := checkInputs(g, dir); err != nil {
		return nil, err
	}
	siblings := map[string]bool{}
	for _, m := range g.Modules {
		siblings[m.Root] = true
	}
	for _, m := range g.Modules {
		if err := checkModule(m, dir, siblings); err != nil {
			return nil, err
		}
	}
	return g, nil
}

// Decode reads the graph at file without checking it. Only a reader handed a file that Load has
// already accepted in this run uses it.
func Decode(file string) (*Graph, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, reject(CheckDecode, err.Error())
	}
	var g Graph
	if err := json.Unmarshal(b, &g); err != nil {
		return nil, reject(CheckDecode, err.Error())
	}
	return &g, nil
}

func reject(check, log string) *Failure {
	return &Failure{Kind: KindGraphRejected, Detail: check, Log: log}
}

// sameConditions compares conditions with an absent list or map equal to an empty one.
func sameConditions(a, b Conditions) bool {
	norm := func(c Conditions) Conditions {
		if len(c.Profiles) == 0 {
			c.Profiles = nil
		}
		if len(c.Properties) == 0 {
			c.Properties = nil
		}
		if len(c.Env) == 0 {
			c.Env = nil
		}
		return c
	}
	return reflect.DeepEqual(norm(a), norm(b))
}

// checkInputs re-hashes every recorded input and walks the checkout for inputs the graph does not
// name, with the producer's own rule for what the tool reads.
func checkInputs(g *Graph, dir string) error {
	recorded := map[string]bool{}
	for _, in := range g.Subject.Inputs {
		if !cleanRel(in.Path) {
			return reject(CheckSubjectInputs, "input path "+in.Path)
		}
		p := filepath.Join(dir, filepath.FromSlash(in.Path))
		if _, ok := realRel(dir, p); !ok {
			return reject(CheckSubjectInputs, "input outside the checkout: "+in.Path)
		}
		sum, err := sha256File(p)
		if err != nil {
			return reject(CheckSubjectInputs, err.Error())
		}
		if sum != in.SHA256 {
			return reject(CheckSubjectInputs, in.Path+" changed since the graph was resolved")
		}
		recorded[in.Path] = true
	}
	match := gradleInput
	switch g.Tool.Name {
	case "maven":
		match = mavenInput(nil)
	case "gradle":
	default:
		return reject(CheckSubjectInputs, "unknown tool "+g.Tool.Name)
	}
	found, err := collectInputs(dir, match)
	if err != nil {
		return reject(CheckSubjectInputs, err.Error())
	}
	for _, in := range found {
		if !recorded[in.Path] {
			return reject(CheckSubjectInputs, in.Path+" is a build input the graph does not name")
		}
	}
	return nil
}

// OtherToolInputs lists dir's build inputs of the tool that did not resolve a tool graph: a
// Gradle build beside a Maven graph, or a POM beside a Gradle one. The graph is sound for its own
// build and says nothing about that one, which can resolve other versions; a repository shipping
// both (spring-petclinic does) is common and is not a reason to refuse the graph.
func OtherToolInputs(dir, tool string) ([]Input, error) {
	switch tool {
	case "maven":
		return collectInputs(dir, gradleInput)
	case "gradle":
		return collectInputs(dir, mavenInput(nil))
	}
	return nil, fmt.Errorf("unknown tool %q", tool)
}

func checkModule(m Module, dir string, siblings map[string]bool) error {
	if m.Path != "." && !cleanRel(m.Path) {
		return reject(CheckModulePath, m.ID+" at "+m.Path)
	}
	p := filepath.Join(dir, filepath.FromSlash(m.Path))
	if _, ok := realRel(dir, p); !ok {
		return reject(CheckModulePath, m.ID+" outside the checkout")
	}
	if fi, err := os.Stat(p); err != nil || !fi.IsDir() {
		return reject(CheckModulePath, m.ID+": "+m.Path+" is not a directory")
	}
	keys := map[string]bool{}
	for _, n := range m.Nodes {
		if keys[n.Key()] {
			return reject(CheckDuplicateKey, m.ID+": "+n.Key())
		}
		keys[n.Key()] = true
		if n.ID == m.Root {
			continue
		}
		if !scopes[n.Scope] {
			return reject(CheckScope, m.ID+": "+n.ID+" scope "+n.Scope)
		}
		if n.File == nil {
			if !siblings[n.ID] && n.Type != "pom" {
				return reject(CheckNodeFile, m.ID+": "+n.ID+" has no file")
			}
			continue
		}
		if !filepath.IsAbs(n.File.Path) {
			return reject(CheckNodeFile, m.ID+": "+n.ID+" file "+n.File.Path)
		}
		sum, err := sha256File(n.File.Path)
		if err != nil {
			return reject(CheckNodeFile, m.ID+": "+err.Error())
		}
		if sum != n.File.SHA256 {
			return reject(CheckNodeFile, m.ID+": "+n.File.Path+" changed since the graph was resolved")
		}
	}
	return nil
}

// cleanRel reports whether p is a clean, relative, slash-separated path that stays below its root.
func cleanRel(p string) bool {
	return p != "" && p != "." && p != ".." && !path.IsAbs(p) && path.Clean(p) == p && !strings.HasPrefix(p, "../")
}
