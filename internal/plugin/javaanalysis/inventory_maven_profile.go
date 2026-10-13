package javaanalysis

// inventory_maven_profile.go — Maven profile activation, evaluated three-valued: a profile is
// active, inactive, or undecided. Only facts the build actually fixes are used:
//   - <jdk> against the Java version the caller provides (TargetEnv "java.version"); Assay never
//     looks the version up itself, so without one every <jdk> condition is undecided;
//   - <file> against the reactor module's directory, for paths inside it; a dependency's POM has
//     no project directory, so its <file> conditions stay undecided;
//   - <property> against the values the caller states in TargetEnv; a property it doesn't state
//     is undecided, never assumed absent, since a -D on the command line or a settings.xml
//     profile can set it;
//   - <os> and any activation element this reader does not know are always undecided.
//
// An undecided profile is never applied, and a dependency it could re-version is left with an
// unresolved version rather than the one it has without the profile. It costs a profile_activation reason only when it could
// change the resolved graph: it declares a dependency or managed version the graph consumes, or
// sets a property such a declaration's coordinates reference. The reason is scoped to the
// dependencies the profile can add or re-version plus their closure, and to first-party code and
// its closure, since code nobody loaded can call back into the build (unbounded when any of that
// cannot be read from the cache). It is mirrored run-wide.

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// targetEnvJavaVersion is the TargetEnv key carrying the subject build's Java version, named
// after the JVM system property Maven's <jdk> activation reads.
const targetEnvJavaVersion = "java.version"

type tri int8

const (
	triFalse tri = iota
	triTrue
	triUnknown
)

func triAnd(a, b tri) tri {
	switch {
	case a == triFalse || b == triFalse:
		return triFalse
	case a == triUnknown || b == triUnknown:
		return triUnknown
	}
	return triTrue
}

func triOr(a, b tri) tri {
	switch {
	case a == triTrue || b == triTrue:
		return triTrue
	case a == triUnknown || b == triUnknown:
		return triUnknown
	}
	return triFalse
}

func triNot(a tri) tri {
	switch a {
	case triTrue:
		return triFalse
	case triFalse:
		return triTrue
	}
	return triUnknown
}

func triOf(b bool) tri {
	if b {
		return triTrue
	}
	return triFalse
}

// activationEnv is what profile activation is evaluated against.
type activationEnv struct {
	targetEnv map[string]string
	// basedir is the reactor module directory whose model is being built, "" for a POM read
	// from the cache. A reactor module's parents are evaluated against the module's directory,
	// as Maven does.
	basedir string
}

// evalProfiles returns the activation state of each profile of one POM. A profile with no
// activation condition is inactive; activeByDefault applies only when no other profile of the
// same POM is activated by its conditions.
func evalProfiles(profiles []mvnProfile, env activationEnv) []tri {
	out := make([]tri, len(profiles))
	anyActive := triFalse
	for i, pr := range profiles {
		out[i] = evalConditions(pr.Activation, env)
		anyActive = triOr(anyActive, out[i])
	}
	for i, pr := range profiles {
		if out[i] == triFalse && pr.Activation.ActiveByDefault {
			out[i] = triNot(anyActive)
		}
	}
	return out
}

// evalConditions ANDs every condition present (Maven 3.2.2+). No condition at all is inactive.
func evalConditions(a mvnActivation, env activationEnv) tri {
	present := false
	res := triTrue
	add := func(t tri) {
		present = true
		res = triAnd(res, t)
	}
	if a.JDK != "" {
		add(evalJDK(a.JDK, env.targetEnv[targetEnvJavaVersion]))
	}
	if a.OS || a.Other {
		add(triUnknown)
	}
	if a.PropName != "" {
		add(evalProperty(a.PropName, a.PropValue, env.targetEnv))
	}
	if a.FileExists != "" || a.FileMissing != "" {
		add(evalFile(a.FileExists, a.FileMissing, env))
	}
	if !present {
		return triFalse
	}
	return res
}

// evalProperty follows Maven's PropertyProfileActivator against caller-stated values: "!name"
// activates when the property is unset, a value activates on equality ("!value" on inequality).
// A property the caller doesn't state is undecided.
func evalProperty(name, value string, env map[string]string) tri {
	negName := strings.HasPrefix(name, "!")
	name = strings.TrimPrefix(name, "!")
	if name == "" {
		return triFalse
	}
	got, present := env[name]
	if !present {
		return triUnknown
	}
	if value != "" {
		negValue := strings.HasPrefix(value, "!")
		eq := triOf(got == strings.TrimPrefix(value, "!"))
		if negValue {
			return triNot(eq)
		}
		return eq
	}
	set := triOf(got != "")
	if negName {
		return triNot(set)
	}
	return set
}

// evalFile decides <file><exists>/<missing> for a path inside the module directory. A path that
// leaves it, references anything but the module directory, or points into the build output
// (which the build itself may create) is undecided.
func evalFile(exists, missing string, env activationEnv) tri {
	if env.basedir == "" {
		return triUnknown
	}
	path, wantMissing := exists, false
	if path == "" {
		path, wantMissing = missing, true
	}
	path = strings.NewReplacer("${basedir}", env.basedir, "${project.basedir}", env.basedir).Replace(path)
	if strings.Contains(path, "${") {
		return triUnknown
	}
	path = filepath.FromSlash(strings.ReplaceAll(path, "\\", "/"))
	if !filepath.IsAbs(path) {
		path = filepath.Join(env.basedir, path)
	}
	path = filepath.Clean(path)
	rel, err := filepath.Rel(env.basedir, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return triUnknown
	}
	if first := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]; first == "target" || first == "build" {
		return triUnknown
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		if os.IsNotExist(err) {
			return triOf(wantMissing)
		}
		return triUnknown
	}
	root, err := filepath.EvalSymlinks(env.basedir)
	if err != nil {
		return triUnknown
	}
	if r, err := filepath.Rel(root, real); err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return triUnknown
	}
	return triOf(!wantMissing)
}

// evalJDK follows Maven's JdkVersionProfileActivator against the provided java.version: a
// prefix ("11", "1.8"), a negated prefix ("!1.8"), or a range ("[11,)", "(,1.8]") compared on
// the first three numeric components. A provided version with fewer than three components
// ("11") stands for every version it prefixes, so a condition that differs across them is
// undecided.
func evalJDK(spec, version string) tri {
	version = strings.TrimSpace(version)
	if i := strings.IndexByte(version, '+'); i >= 0 {
		version = version[:i] // build metadata ("11.0.24+8"), not part of java.version
	}
	if numericTokens(version) == nil {
		return triUnknown // nothing the conditions can be compared against
	}
	partial := len(numericTokens(version)) < 3
	if neg, ok := strings.CutPrefix(spec, "!"); ok {
		return triNot(jdkPrefix(neg, version, partial))
	}
	if strings.HasPrefix(spec, "[") || strings.HasPrefix(spec, "(") {
		return jdkRange(spec, version, partial)
	}
	return jdkPrefix(spec, version, partial)
}

func jdkPrefix(spec, version string, partial bool) tri {
	switch {
	case strings.HasPrefix(version, spec):
		return triTrue
	case partial && strings.HasPrefix(spec, version):
		return triUnknown
	}
	return triFalse
}

type jdkBound struct {
	value  []int // nil = unbounded
	closed bool
}

func jdkRange(spec, version string, partial bool) tri {
	parts := strings.Split(spec, ",")
	if len(parts) > 2 {
		return triUnknown
	}
	var bounds []jdkBound
	for _, p := range parts {
		p = strings.TrimSpace(p)
		closed := strings.HasPrefix(p, "[") || strings.HasSuffix(p, "]")
		v := strings.Trim(p, "[]()")
		b := jdkBound{closed: closed}
		if v != "" {
			toks := numericTokens(v)
			if toks == nil {
				return triUnknown
			}
			b.value = pad3(toks, 0)
		}
		bounds = append(bounds, b)
	}
	if len(bounds) < 2 {
		bounds = append(bounds, jdkBound{value: []int{99999999, 0, 0}})
	}
	toks := numericTokens(version)
	if toks == nil {
		return triUnknown
	}
	lo := inJDKRange(pad3(toks, 0), bounds[0], bounds[1])
	if !partial {
		return triOf(lo)
	}
	if hi := inJDKRange(pad3(toks, 1<<30), bounds[0], bounds[1]); hi != lo {
		return triUnknown
	}
	return triOf(lo)
}

func inJDKRange(v []int, lower, upper jdkBound) bool {
	left := jdkRelation(v, lower, true)
	if left == 0 {
		return true
	}
	if left < 0 {
		return false
	}
	return jdkRelation(v, upper, false) <= 0
}

func jdkRelation(v []int, b jdkBound, isLeft bool) int {
	if b.value == nil {
		if isLeft {
			return 1
		}
		return -1
	}
	for i := 0; i < 3; i++ {
		if v[i] < b.value[i] {
			return -1
		}
		if v[i] > b.value[i] {
			return 1
		}
	}
	if !b.closed {
		if isLeft {
			return -1
		}
		return 1
	}
	return 0
}

// numericTokens splits a version on . _ - and returns its leading numeric components; nil when
// the first is not a number.
func numericTokens(v string) []int {
	var out []int
	for _, t := range strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '_' || r == '-' }) {
		n, err := strconv.Atoi(t)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

func pad3(t []int, fill int) []int {
	out := make([]int, 3)
	for i := range out {
		if i < len(t) {
			out[i] = t[i]
		} else {
			out[i] = fill
		}
	}
	return out
}

// --- what an undecided profile can change ------------------------------------

// undecidedProfile is a profile whose activation could not be decided and that can change the
// graph. touched lists the dependency declarations it can add or re-version, with every
// version it can resolve to; bounded is false when some of that cannot be pinned down.
type undecidedProfile struct {
	path    string // disclosure: the declaring POM and profile id
	touched []mvnDep
	bounded bool
}

// declEntry is one dependency or managed-version declaration of a POM chain. owner is the
// index of the profile declaring it in profileList order, -1 for a POM body.
type declEntry struct {
	dep   mvnDep
	mgmt  bool
	owner int
}

// profileScope is what profileTouches reads about the POM chain being modelled.
type profileScope struct {
	entries []declEntry
	// defs maps each property name to every raw value any POM body or profile of the chain
	// gives it, for following references transitively.
	defs map[string][]string
	// forDependency is true for a POM read from the cache: only declarations that reach a
	// consumer's graph (non-optional compile/runtime deps, managed versions of those) count.
	forDependency bool
}

func newProfileScope(chain []*mvnPOM, profileList []mvnProfile, forDependency bool) profileScope {
	ps := profileScope{defs: map[string][]string{}, forDependency: forDependency}
	idx := 0
	for _, anc := range chain {
		for _, d := range anc.Deps {
			ps.entries = append(ps.entries, declEntry{dep: d, owner: -1})
		}
		for _, d := range anc.DepMgmt {
			ps.entries = append(ps.entries, declEntry{dep: d, mgmt: true, owner: -1})
		}
		for k, v := range anc.Properties {
			ps.defs[k] = append(ps.defs[k], v)
		}
		for range anc.Profiles {
			pr := profileList[idx]
			for _, d := range pr.Deps {
				ps.entries = append(ps.entries, declEntry{dep: d, owner: idx})
			}
			for _, d := range pr.DepMgmt {
				ps.entries = append(ps.entries, declEntry{dep: d, mgmt: true, owner: idx})
			}
			for k, v := range pr.Properties {
				ps.defs[k] = append(ps.defs[k], v)
			}
			idx++
		}
	}
	return ps
}

func isImportBOM(d mvnDep) bool {
	return strings.EqualFold(d.Scope, "import") && strings.EqualFold(defaultType(d.Type), "pom")
}

// propagatesToConsumer reports whether a dependency declared in a cached POM lands on a
// consumer's graph. An unresolved scope or optional flag counts as propagating.
func propagatesToConsumer(d mvnDep) bool {
	if strings.EqualFold(strings.TrimSpace(d.Optional), "true") {
		return false
	}
	switch defaultScope(d.Scope) {
	case "test", "provided", "system", "import":
		return false
	}
	return true
}

// consequential reports which entries can affect the resolved graph.
func (ps profileScope) consequential() []bool {
	out := make([]bool, len(ps.entries))
	versionless := map[string]bool{}
	for _, e := range ps.entries {
		if !e.mgmt && strings.TrimSpace(e.dep.Version) == "" && (!ps.forDependency || propagatesToConsumer(e.dep)) {
			versionless[e.dep.ga()] = true
		}
	}
	for i, e := range ps.entries {
		switch {
		case !ps.forDependency:
			out[i] = true
		case e.mgmt:
			out[i] = isImportBOM(e.dep) || versionless[e.dep.ga()]
		default:
			out[i] = propagatesToConsumer(e.dep)
		}
	}
	return out
}

// referencedProps returns every property name raw refers to, following definitions.
func (ps profileScope) referencedProps(raws ...string) map[string]bool {
	seen := map[string]bool{}
	queue := append([]string{}, raws...)
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		for {
			start := strings.Index(s, "${")
			if start < 0 {
				break
			}
			end := strings.IndexByte(s[start:], '}')
			if end < 0 {
				break
			}
			name := s[start+2 : start+end]
			s = s[start+end+1:]
			if !seen[name] {
				seen[name] = true
				queue = append(queue, ps.defs[name]...)
			}
		}
	}
	return seen
}

// profileTouches returns what profile idx can change: its own consequential declarations, and
// every consequential declaration whose coordinates reference a property it sets. Each is
// resolved under the model without the profile and with it; a declaration that resolves to no
// literal coordinate in either, or an imported BOM, leaves the result unbounded.
func profileTouches(ps profileScope, idx int, pr mvnProfile, em *effectiveModel, rawProps map[string]string) (touched []mvnDep, bounded bool) {
	cons := ps.consequential()
	var picked []declEntry
	for i, e := range ps.entries {
		if !cons[i] {
			continue
		}
		if e.owner == idx {
			picked = append(picked, e)
			continue
		}
		if len(pr.Properties) == 0 {
			continue
		}
		refs := ps.referencedProps(e.dep.GroupID, e.dep.ArtifactID, e.dep.Version, e.dep.Scope, e.dep.Type, e.dep.Optional)
		for k := range pr.Properties {
			if refs[k] {
				picked = append(picked, e)
				break
			}
		}
	}
	if len(picked) == 0 {
		return nil, true
	}

	overlay := make(map[string]string, len(rawProps)+len(pr.Properties))
	for k, v := range rawProps {
		overlay[k] = v
	}
	for k, v := range pr.Properties {
		overlay[k] = v
	}
	interpProps(overlay)
	overlayManaged := map[string]string{}
	for _, m := range pr.DepMgmt {
		if v, ok := interp(m.Version, overlay); ok {
			overlayManaged[m.ga()] = v
		}
	}

	bounded = true
	for _, e := range picked {
		if e.mgmt && isImportBOM(e.dep) {
			return nil, false
		}
		seen := map[string]bool{}
		for _, props := range []map[string]string{em.props, overlay} {
			g, okG := interp(e.dep.GroupID, props)
			a, okA := interp(e.dep.ArtifactID, props)
			if !okG || !okA {
				continue
			}
			var versions []string
			if v, ok := interp(e.dep.Version, props); ok {
				versions = append(versions, v)
			} else if strings.TrimSpace(e.dep.Version) == "" {
				if v, ok := em.managed[g+":"+a]; ok {
					versions = append(versions, v)
				}
				if v, ok := overlayManaged[g+":"+a]; ok {
					versions = append(versions, v)
				}
			}
			for _, v := range versions {
				if !isLiteralVersion(v) {
					continue
				}
				d := e.dep
				d.GroupID, d.ArtifactID, d.Version = g, a, v
				if k := gavKey(g, a, v); !seen[k] {
					seen[k] = true
					touched = append(touched, d)
				}
			}
		}
		if len(seen) == 0 {
			bounded = false
		}
	}
	return touched, bounded
}

// mavenPackage renders a version-less Maven PURL, the form ScopedReason Package and Targets use.
func mavenPackage(group, artifact string) string {
	return "pkg:maven/" + group + "/" + artifact
}

// closureLimit caps how many POMs one Targets closure reads before it gives up as unbounded.
const closureLimit = 2000

// profileScoped turns a model's undecided profiles into scoped reasons. pkg is the package whose
// dependency list the profiles belong to ("" for a reactor module). rootManaged is the reactor
// module's dependencyManagement, which also pins the versions of transitive dependencies.
func profileScoped(em effectiveModel, pkg string, rootManaged map[string]string, reactor map[string]*mvnPOM, cache *mavenCache, targetEnv map[string]string) []plugin.ScopedReason {
	var out []plugin.ScopedReason
	for _, u := range em.undecided {
		sr := plugin.ScopedReason{Reason: reasonProfileActivation, Package: pkg, Path: u.path}
		if u.bounded {
			if t, ok := cache.closure(reactor, targetEnv, u.touched, rootManaged); ok {
				sr.Targets = t
			}
		}
		out = append(out, sr)
	}
	return out
}

// withFirstPartyBound widens every bounded scoped reason by first-party code (contract §4, the
// callback amendment). A profile-added package is a JAR nobody loaded: it can hold first-party
// objects and call them through its own or platform interfaces, or by reflection, and those calls
// reach whatever first-party code reaches. So each bound gains "" and the closure of the module's
// own dependencies outside test scope, plus whatever the module's undecided profiles could add.
// When that closure cannot be read in full, no bound holds and every Targets becomes nil.
func withFirstPartyBound(scoped []plugin.ScopedReason, em effectiveModel, reactor map[string]*mvnPOM, cache *mavenCache, targetEnv map[string]string) []plugin.ScopedReason {
	var firstParty []string
	computed, ok := false, false
	for i := range scoped {
		if scoped[i].Targets == nil {
			continue
		}
		if !computed {
			firstParty, ok = firstPartyClosure(em, reactor, cache, targetEnv)
			computed = true
		}
		if !ok {
			scoped[i].Targets = nil
			continue
		}
		set := map[string]bool{"": true}
		for _, t := range scoped[i].Targets {
			set[t] = true
		}
		for _, t := range firstParty {
			set[t] = true
		}
		targets := make([]string, 0, len(set))
		for t := range set {
			targets = append(targets, t)
		}
		sort.Strings(targets)
		scoped[i].Targets = targets
	}
	return scoped
}

// firstPartyClosure returns every package the module's code can reach through its dependencies.
// ok is false when that set is not a bound.
func firstPartyClosure(em effectiveModel, reactor map[string]*mvnPOM, cache *mavenCache, targetEnv map[string]string) ([]string, bool) {
	var roots []mvnDep
	for _, d := range em.deps {
		if !strings.EqualFold(strings.TrimSpace(d.Scope), "test") {
			roots = append(roots, d)
		}
	}
	for _, u := range em.undecided {
		if !u.bounded {
			return nil, false
		}
		roots = append(roots, u.touched...)
	}
	return cache.closure(reactor, targetEnv, roots, em.managed)
}

// closure returns every package reachable from roots over the cached POMs, roots included,
// counting the dependencies undecided profiles can add along the way. ok is false when some
// POM, version or profile on the way cannot be read, so the set is not a bound. managed is the
// reactor module's dependencyManagement: Maven resolves a transitive dependency it names at the
// managed version, so that version's POM is walked as well as the declared one.
func (c *mavenCache) closure(reactor map[string]*mvnPOM, targetEnv map[string]string, roots []mvnDep, managed map[string]string) ([]string, bool) {
	pkgs := map[string]bool{}
	seen := map[string]bool{}
	queue := append([]mvnDep{}, roots...)
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if !isLiteralVersion(d.GroupID) || !isLiteralVersion(d.ArtifactID) || !isLiteralVersion(d.Version) {
			return nil, false
		}
		pkgs[mavenPackage(d.GroupID, d.ArtifactID)] = true
		if mv, ok := managed[d.GroupID+":"+d.ArtifactID]; ok && mv != d.Version {
			md := d
			md.Version = mv
			queue = append(queue, md)
		}
		key := gavKey(d.GroupID, d.ArtifactID, d.Version)
		if seen[key] {
			continue
		}
		seen[key] = true
		if len(seen) > closureLimit {
			return nil, false
		}
		pom, ok := c.get(d.GroupID, d.ArtifactID, d.Version)
		if !ok {
			return nil, false
		}
		m := buildEffectiveModel(pom, reactor, c, targetEnv, 1)
		for _, r := range m.residue {
			if r != reasonProfileActivation {
				return nil, false
			}
		}
		for _, u := range m.undecided {
			if !u.bounded {
				return nil, false
			}
			queue = append(queue, u.touched...)
		}
		for _, cd := range m.deps {
			if propagatesToConsumer(cd) {
				queue = append(queue, cd)
			}
		}
	}
	out := make([]string, 0, len(pkgs))
	for p := range pkgs {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, true
}

// dedupScoped drops repeated scoped reasons and sorts the rest.
func dedupScoped(in []plugin.ScopedReason) []plugin.ScopedReason {
	seen := map[string]bool{}
	var out []plugin.ScopedReason
	for _, s := range in {
		k := s.Reason + "\x00" + s.Package + "\x00" + s.Path + "\x00" + strings.Join(s.Targets, ",")
		if s.Targets == nil {
			k += "\x00nil"
		}
		if !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		return out[i].Path < out[j].Path
	})
	return out
}
