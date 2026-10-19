package javaanalysis

// inventory_maven.go — Part A: the Maven effective-POM engine (PLAN-140). A pure function over
// an on-disk read model (reactor pom.xml closure + the warm ~/.m2/repository POM tree). Composable
// passes 1-8; each declares its own honest-absent residue so partiality is monotonically
// non-decreasing. NEVER invokes mvn/java/docker, NEVER touches the network (C2/C5).

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// --- cache reader (test-overridable) -----------------------------------------

// mavenCache resolves a GAV to its cached POM under the local Maven repositories, in priority
// order: a project-local .m2/repository (the per-build zero-egress CI shape), then ~/.m2
// (depcache.go:77 precedence). It is injected so a test can point `roots` at a fixture m2/ tree
// — the reader never reads os.UserHomeDir at resolution time. Parsed POMs are memoized; a GAV
// whose POM is absent is a recorded cache-miss (nil), never assumed edgeless.
type mavenCache struct {
	roots   []string
	memo    map[string]*mvnPOM // "g:a:v" -> parsed POM (nil sentinel via miss set)
	miss    map[string]bool
	escaped bool // the build's own repository links out of the checkout: every lookup misses
}

// newMavenCache builds the default reader for a build dir (project-local .m2 first, then the
// user ~/.m2). A blank home is harmless — that root simply resolves nothing. A project-local
// repository that resolves outside the build is an escape in the first root, so nothing is read
// past it.
func newMavenCache(buildDir string) *mavenCache {
	local := filepath.Join(buildDir, ".m2", "repository")
	roots := []string{local}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		roots = append(roots, filepath.Join(home, ".m2", "repository"))
	}
	c := newMavenCacheAt(roots...)
	c.escaped = rootLeavesCheckout(buildDir, local)
	return c
}

// newMavenCacheAt builds a reader over explicit repository roots (the S4/test injection point).
func newMavenCacheAt(roots ...string) *mavenCache {
	return &mavenCache{roots: roots, memo: map[string]*mvnPOM{}, miss: map[string]bool{}}
}

func gavKey(g, a, v string) string { return g + ":" + a + ":" + v }

// pomRelPath renders the Maven local-repo relative path of a POM:
// <group as path>/<artifact>/<version>/<artifact>-<version>.pom.
func pomRelPath(g, a, v string) string {
	return filepath.Join(strings.ReplaceAll(g, ".", "/"), a, v, a+"-"+v+".pom")
}

// get returns the cached POM for a GAV, or (nil, false) on a cache-miss. Roots are searched in
// order; the first hit wins. A GAV that cannot name a cache path, or whose POM resolves outside
// its root, is a miss in every root: what sits there is not the cached POM.
func (c *mavenCache) get(g, a, v string) (*mvnPOM, bool) {
	if c.escaped || !validGAV(g, a, v) {
		return nil, false
	}
	key := gavKey(g, a, v)
	if p, ok := c.memo[key]; ok {
		return p, true
	}
	if c.miss[key] {
		return nil, false
	}
	rel := pomRelPath(g, a, v)
	for _, root := range c.roots {
		path, st := inCache(root, rel)
		if st == cacheEscape {
			break
		}
		if st != cacheHit {
			continue
		}
		if p, ok := parseMavenPOM(path); ok {
			p.path = "" // a cached POM has no project directory
			c.memo[key] = p
			return p, true
		}
	}
	c.miss[key] = true
	return nil, false
}

// digestFor reads the on-disk .sha1 sidecar of a cached artifact (jar preferred, else pom) as a
// declared digest — no fetch, no compute (verified digest is PLAN-200). "" when absent.
func (c *mavenCache) digestFor(g, a, v string) string {
	if c.escaped || !validGAV(g, a, v) {
		return ""
	}
	for _, ext := range []string{".jar.sha1", ".pom.sha1"} {
		rel := filepath.Join(strings.ReplaceAll(g, ".", "/"), a, v, a+"-"+v+ext)
		for _, root := range c.roots {
			path, st := inCache(root, rel)
			if st == cacheEscape {
				return ""
			}
			if st != cacheHit {
				continue
			}
			if data, err := readRegular(path); err == nil {
				if h := strings.TrimSpace(string(data)); h != "" {
					return "sha1:" + strings.Fields(h)[0]
				}
			}
		}
	}
	return ""
}

// --- POM read model ----------------------------------------------------------

type mvnPOM struct {
	path       string // reactor path, "" for a cached POM
	GroupID    string
	ArtifactID string
	Version    string
	Packaging  string
	Parent     mvnParent
	Properties map[string]string
	DepMgmt    []mvnDep
	Deps       []mvnDep
	Modules    []string
	Profiles   []mvnProfile
}

type mvnParent struct{ GroupID, ArtifactID, Version, RelativePath string }

type mvnGA struct{ GroupID, ArtifactID string }

type mvnDep struct {
	GroupID, ArtifactID, Version string
	Scope, Type, Optional        string
	Classifier                   string
	Exclusions                   []mvnGA
	// unresolvedBy, when set, makes the graph emit this dependency with no version, for that
	// reason. Version keeps the value without the profile, for closures that walk every candidate.
	unresolvedBy string
	// variantSibling is set when the same POM also declares another file of this GA (a
	// classifier or non-jar type) that GA dedup dropped.
	variantSibling bool
}

// variant reports whether the declaration selects an artifact file other than the GA's main
// JAR: a classifier (sources, tests, jdk15, linux-x86_64, ...) or a non-jar type.
func (d mvnDep) variant() bool {
	if d.Classifier != "" || d.variantSibling {
		return true
	}
	switch defaultType(d.Type) {
	case "jar", "bundle":
		return false
	}
	return true
}

func (d mvnDep) ga() string { return d.GroupID + ":" + d.ArtifactID }

type mvnProfile struct {
	ID         string
	Activation mvnActivation
	Properties map[string]string
	DepMgmt    []mvnDep
	Deps       []mvnDep
	// Build is set when the profile has a <build> section with anything in it.
	Build bool
	// Modules are the profile's <module> entries, as written.
	Modules []string
	// Repositories is set when the profile declares a repository or plugin repository.
	Repositories bool
	// Elements are the local names of the profile's child elements, in document order. An
	// undecided profile is bounded only when each is on profileElements' allow-list.
	Elements []string
}

// mvnActivation is a profile's <activation> block. Every condition present must hold (Maven
// 3.2.2+); activeByDefault is not a condition but a fallback (see evalProfiles).
type mvnActivation struct {
	ActiveByDefault     bool
	JDK                 string
	OS                  bool // any <os> element, an empty one included: never evaluated, the runner's OS is not the subject's
	PropName, PropValue string
	File                bool // any <file> element, an empty one included: the tree Maven saw isn't the one read here
	// Other is a present condition no modelled rule decides: an element this reader does not know
	// (Maven 4 <packaging>, <condition>, ...), a child of <property> it does not know, or an empty
	// or padded <jdk>. It is undecided and ANDed with the rest.
	Other bool
	// Undecidable is an activation whose meaning depends on which of several elements Maven reads,
	// or on its version: a second <activation>, a repeated child, a <property> without exactly one
	// non-empty name or with more than one value, or a <jdk> or <property> value holding an
	// interpolation expression. No condition beside it decides the profile.
	Undecidable bool
}

// --- XML binding -------------------------------------------------------------

type xmlPOM struct {
	GroupID    string       `xml:"groupId"`
	ArtifactID string       `xml:"artifactId"`
	Version    string       `xml:"version"`
	Packaging  string       `xml:"packaging"`
	Parent     xmlParent    `xml:"parent"`
	Properties invProps     `xml:"properties"`
	DepMgmt    []xmlDep     `xml:"dependencyManagement>dependencies>dependency"`
	Deps       []xmlDep     `xml:"dependencies>dependency"`
	Modules    []string     `xml:"modules>module"`
	Profiles   []xmlProfile `xml:"profiles>profile"`
}

type xmlParent struct {
	GroupID      string `xml:"groupId"`
	ArtifactID   string `xml:"artifactId"`
	Version      string `xml:"version"`
	RelativePath string `xml:"relativePath"`
}

type xmlDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Type       string `xml:"type"`
	Classifier string `xml:"classifier"`
	Optional   string `xml:"optional"`
	Exclusions []struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
	} `xml:"exclusions>exclusion"`
}

type xmlProfile struct {
	ID         string          `xml:"id"`
	Activation []xmlActivation `xml:"activation"`
	Properties invProps        `xml:"properties"`
	DepMgmt    []xmlDep        `xml:"dependencyManagement>dependencies>dependency"`
	Deps       []xmlDep        `xml:"dependencies>dependency"`
	Build      struct {
		Children []struct {
			XMLName xml.Name
		} `xml:",any"`
	} `xml:"build"`
	Modules            []string   `xml:"modules>module"`
	Repositories       []struct{} `xml:"repositories>repository"`
	PluginRepositories []struct{} `xml:"pluginRepositories>pluginRepository"`
}

// xmlActivation binds every child as a slice, so an element that is present but empty, or
// repeated, is seen rather than read as absent.
type xmlActivation struct {
	ActiveByDefault []string     `xml:"activeByDefault"`
	JDK             []string     `xml:"jdk"`
	OS              []struct{}   `xml:"os"`
	Property        []xmlActProp `xml:"property"`
	File            []struct{}   `xml:"file"`
	Other           []struct {
		XMLName xml.Name
	} `xml:",any"`
}

type xmlActProp struct {
	Name  []string `xml:"name"`
	Value []string `xml:"value"`
	Other []struct {
		XMLName xml.Name
	} `xml:",any"`
}

// xmlProfileElements reads the local name of every child of each <profile>, in the same order
// xmlPOM binds the profiles.
type xmlProfileElements struct {
	Profiles []struct {
		Children []struct {
			XMLName xml.Name
		} `xml:",any"`
	} `xml:"profiles>profile"`
}

// invProps captures the arbitrary child elements of a <properties> block as name→value pairs.
type invProps struct{ Entries map[string]string }

func (p *invProps) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) error {
	p.Entries = map[string]string{}
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			var val string
			if err := d.DecodeElement(&val, &t); err != nil {
				return err
			}
			p.Entries[t.Name.Local] = javaTrim(val)
		case xml.EndElement:
			return nil
		}
	}
}

// javaTrim trims s as Java's String.trim does, which is how Maven's model reader trims element
// text: only characters at or below U+0020 go, so a no-break or other Unicode space stays part of
// the value Maven compares.
func javaTrim(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return r <= ' ' })
}

func convDeps(in []xmlDep) []mvnDep {
	var out []mvnDep
	for _, d := range in {
		md := mvnDep{
			GroupID:    javaTrim(d.GroupID),
			ArtifactID: javaTrim(d.ArtifactID),
			Version:    javaTrim(d.Version),
			Scope:      javaTrim(d.Scope),
			Type:       javaTrim(d.Type),
			Classifier: javaTrim(d.Classifier),
			Optional:   javaTrim(d.Optional),
		}
		for _, e := range d.Exclusions {
			md.Exclusions = append(md.Exclusions, mvnGA{javaTrim(e.GroupID), javaTrim(e.ArtifactID)})
		}
		out = append(out, md)
	}
	return out
}

// parseMavenPOM reads and binds one pom.xml. ok is false only when the file is unreadable or the
// XML is structurally unparseable (the caller records a cache-miss/residue, never a guess).
func parseMavenPOM(path string) (*mvnPOM, bool) {
	data, err := readRegular(path)
	if err != nil {
		return nil, false
	}
	var xp xmlPOM
	if err := unmarshalPOM(data, &xp); err != nil {
		return nil, false
	}
	p := &mvnPOM{
		path:       path,
		GroupID:    javaTrim(xp.GroupID),
		ArtifactID: javaTrim(xp.ArtifactID),
		Version:    javaTrim(xp.Version),
		Packaging:  javaTrim(xp.Packaging),
		Parent: mvnParent{
			GroupID:      javaTrim(xp.Parent.GroupID),
			ArtifactID:   javaTrim(xp.Parent.ArtifactID),
			Version:      javaTrim(xp.Parent.Version),
			RelativePath: javaTrim(xp.Parent.RelativePath),
		},
		Properties: xp.Properties.Entries,
		DepMgmt:    convDeps(xp.DepMgmt),
		Deps:       convDeps(xp.Deps),
	}
	if p.Properties == nil {
		p.Properties = map[string]string{}
	}
	for _, m := range xp.Modules {
		if m = javaTrim(m); m != "" {
			p.Modules = append(p.Modules, m)
		}
	}
	// Effective coordinate falls back to the parent's (Maven inheritance of groupId/version).
	if p.GroupID == "" {
		p.GroupID = p.Parent.GroupID
	}
	if p.Version == "" {
		p.Version = p.Parent.Version
	}
	var elems xmlProfileElements
	if len(xp.Profiles) > 0 {
		if err := unmarshalPOM(data, &elems); err != nil || len(elems.Profiles) != len(xp.Profiles) {
			return nil, false
		}
	}
	for i, pr := range xp.Profiles {
		mp := mvnProfile{
			ID:           javaTrim(pr.ID),
			Activation:   convActivation(pr.Activation),
			Properties:   pr.Properties.Entries,
			DepMgmt:      convDeps(pr.DepMgmt),
			Deps:         convDeps(pr.Deps),
			Build:        len(pr.Build.Children) > 0,
			Repositories: len(pr.Repositories)+len(pr.PluginRepositories) > 0,
		}
		for _, c := range elems.Profiles[i].Children {
			mp.Elements = append(mp.Elements, c.XMLName.Local)
		}
		for _, m := range pr.Modules {
			if m = javaTrim(m); m != "" {
				mp.Modules = append(mp.Modules, m)
			}
		}
		if mp.Properties == nil {
			mp.Properties = map[string]string{}
		}
		p.Profiles = append(p.Profiles, mp)
	}
	return p, true
}

// convActivation reads a profile's <activation> elements. Maven counts a condition whenever its
// element is present, so an empty one is still a condition; a shape this reader can't map onto
// one Maven reading is undecided.
func convActivation(acts []xmlActivation) mvnActivation {
	var m mvnActivation
	if len(acts) == 0 {
		return m
	}
	if len(acts) > 1 {
		m.Undecidable = true
	}
	a := acts[0]
	once := func(n int) bool {
		if n > 1 {
			m.Undecidable = true
		}
		return n > 0
	}
	if once(len(a.ActiveByDefault)) {
		m.ActiveByDefault = strings.EqualFold(javaTrim(a.ActiveByDefault[0]), "true")
	}
	if once(len(a.JDK)) {
		m.JDK = javaTrim(a.JDK[0])
		if m.JDK == "" || m.JDK != a.JDK[0] {
			// Empty, or padded: padding can only be known not to make the condition true.
			m.Other = true
		}
		if strings.Contains(m.JDK, "${") {
			m.Undecidable = true // whether activation values are interpolated depends on the Maven version
		}
	}
	m.OS = once(len(a.OS))
	m.File = once(len(a.File))
	if once(len(a.Property)) {
		p := a.Property[0]
		if len(p.Name) != 1 || len(p.Value) > 1 {
			m.Undecidable = true
		}
		if len(p.Name) > 0 {
			m.PropName = javaTrim(p.Name[0])
		}
		if len(p.Value) > 0 {
			m.PropValue = javaTrim(p.Value[0])
		}
		if strings.TrimPrefix(m.PropName, "!") == "" {
			m.Undecidable = true
		}
		if len(p.Other) > 0 {
			m.Other = true
		}
		if strings.Contains(m.PropName+m.PropValue, "${") {
			m.Undecidable = true
		}
	}
	if len(a.Other) > 0 {
		m.Other = true
	}
	return m
}

// --- effective model ---------------------------------------------------------

// effectiveModel is the flattened result of passes 1-4 for one POM: interpolated properties, the
// managed-version map (dependencyManagement + imported BOMs), and the effective direct
// dependency list. residue accumulates the honest-absent reasons hit while building it.
type effectiveModel struct {
	group, artifact, version string
	props                    map[string]string
	managed                  map[string]string // "g:a" -> version, "" when it doesn't interpolate
	deps                     []mvnDep
	residue                  []string
	undecided                []undecidedProfile // each also listed in residue as reasonProfileActivation
}

// buildEffectiveModel runs passes 1-4 over `pom`, resolving parents from the reactor (by GA) or
// the cache. `reactor` maps "g:a" -> reactor POM so a reactor-local parent is found without the
// cache. Recursion is depth-bounded to guard against a malformed cyclic parent chain.
func buildEffectiveModel(pom *mvnPOM, reactor map[string]*mvnPOM, cache *mavenCache, targetEnv map[string]string, depth int) effectiveModel {
	return buildModel(pom, reactor, cache, targetEnv, depth, false)
}

// buildImportedModel is buildEffectiveModel for a BOM a consumer imports: the BOM's whole
// managed set is what the import contributes, so every managed version in its lineage counts.
func buildImportedModel(bom *mvnPOM, reactor map[string]*mvnPOM, cache *mavenCache, targetEnv map[string]string, depth int) effectiveModel {
	return buildModel(bom, reactor, cache, targetEnv, depth, true)
}

func buildModel(pom *mvnPOM, reactor map[string]*mvnPOM, cache *mavenCache, targetEnv map[string]string, depth int, imported bool) effectiveModel {
	em := effectiveModel{
		group:    pom.GroupID,
		artifact: pom.ArtifactID,
		version:  pom.Version,
		props:    map[string]string{},
		managed:  map[string]string{},
	}

	// Pass 1: parent-chain inheritance (properties, depMgmt, deps merged child-wins). Each POM's
	// active profiles are injected into it before inheritance, so a profile overrides its own
	// POM's body and a child overrides both of an ancestor's.
	chain := parentChain(pom, reactor, cache, depth)
	if chain.parentMissing {
		em.residue = append(em.residue, reasonParentUncached)
	}

	// Pass 4 (folded in before interpolation so profile props/deps participate): profile eval
	// (inventory_maven_profile.go). Active profiles contribute properties/depMgmt/deps; an
	// undecided one is never applied, and is residue unless it provably changes nothing. The
	// invocation's explicit selection reaches a reactor module's whole lineage, never a
	// dependency's POM.
	env := activationEnv{targetEnv: targetEnv}
	if pom.path != "" {
		env.selection = selectionOf(targetEnv)
	}
	// mgmtSrc and depSrc list declarations in precedence order, highest first: self before its
	// ancestors, and within a POM its active profiles (last-declared first) before its body.
	var mgmtSrc []mvnDep
	var depSrc []mvnDep
	var profileList []mvnProfile
	var profileOwner []*mvnPOM
	var undecided []int
	for _, anc := range chain.poms { // root ... self
		for k, v := range anc.Properties {
			em.props[k] = v
		}
		var mgmt, deps []mvnDep
		states := evalProfiles(anc.Profiles, env)
		for i, pr := range anc.Profiles {
			profileList = append(profileList, pr)
			profileOwner = append(profileOwner, anc)
			switch states[i] {
			case triTrue:
				for k, v := range pr.Properties {
					em.props[k] = v
				}
				mgmt = append(append([]mvnDep{}, pr.DepMgmt...), mgmt...)
				deps = append(append([]mvnDep{}, pr.Deps...), deps...)
			case triUnknown:
				undecided = append(undecided, len(profileList)-1)
			}
		}
		mgmt = append(mgmt, anc.DepMgmt...)
		deps = append(deps, anc.Deps...)
		mgmtSrc = append(mgmt, mgmtSrc...)
		depSrc = append(deps, depSrc...)
	}
	// Implicit project.* properties (literal only).
	if isLiteralVersion(pom.Version) {
		em.props["project.version"] = pom.Version
		em.props["pom.version"] = pom.Version
	}
	em.props["project.groupId"] = pom.GroupID
	em.props["project.artifactId"] = pom.ArtifactID
	rawProps := make(map[string]string, len(em.props))
	for k, v := range em.props {
		rawProps[k] = v
	}

	// Pass 2: property fixpoint interpolation.
	interpProps(em.props)

	// Pass 3: dependencyManagement + imported BOMs → managed-version map (first declaration
	// wins per GA, Maven precedence). A declared entry beats any import; imports then fill in
	// order. BOMs are fetched from the cache recursively. A winning entry whose version doesn't
	// interpolate is kept as "" (managed, version unknown), so no lower-precedence entry fills it.
	for _, m := range mgmtSrc {
		if isImportBOM(m) {
			continue
		}
		key := m.ga()
		if _, seen := em.managed[key]; seen {
			continue
		}
		ver, _ := interp(m.Version, em.props)
		em.managed[key] = ver
	}
	for _, m := range mgmtSrc {
		if isImportBOM(m) {
			importBOM(m, &em, reactor, cache, targetEnv, depth)
		}
	}

	// Effective direct deps: interpolate versions, fall back to the managed map, dedup by GA
	// (first declaration wins). A dropped declaration that names another file of the GA marks
	// the kept one, since both files can reach the classpath.
	seen := map[string]int{}
	for _, d := range depSrc {
		if i, dup := seen[d.ga()]; dup {
			if d.variant() {
				em.deps[i].variantSibling = true
			}
			continue
		}
		seen[d.ga()] = len(em.deps)
		ed := d
		if v, ok := interp(d.Version, em.props); ok {
			ed.Version = v
		} else if mv, ok := em.managed[d.ga()]; ok {
			ed.Version = mv
		} else {
			ed.Version = "" // present-but-unresolved; recorded at node emit.
		}
		em.deps = append(em.deps, ed)
	}

	if len(undecided) > 0 {
		ps := newProfileScope(chain.poms, profileList, pom.path == "", imported)
		for _, idx := range undecided {
			touched, bounded := profileTouches(ps, idx, profileList[idx], &em, rawProps, reactor, cache, targetEnv, depth)
			// What an unbounded profile re-versions is unknown, so every dependency it could
			// reach is: each transitive of a reactor module, each dependency of a cached POM.
			anyVersion := !bounded || chain.parentMissing || profileUnlisted(profileList[idx], pom.path == "")
			if anyVersion || profileExtras(profileList[idx], profileOwner[idx], pom, reactor) {
				bounded = false // what it changes can't be read, or reaches past the dependency graph
			}
			if len(profileList[idx].Properties) > 0 {
				bounded = false // a property can reach plugin configuration or a repository, which this reader doesn't follow
			}
			if bounded && len(touched) == 0 {
				continue // cannot change the graph either way
			}
			owner := profileOwner[idx]
			em.residue = append(em.residue, reasonProfileActivation)
			em.undecided = append(em.undecided, undecidedProfile{
				path:       gavKey(owner.GroupID, owner.ArtifactID, owner.Version) + " profile " + profileList[idx].ID,
				touched:    touched,
				bounded:    bounded,
				anyVersion: anyVersion,
			})
		}
	}
	// An imported BOM's undecided profiles arrive in em.undecided too, and can re-version what
	// this POM's dependencies take from its management.
	if len(em.undecided) > 0 {
		unresolveReversioned(&em, pom.path == "")
	}
	return em
}

// unresolveReversioned marks every dependency an undecided profile could re-version as
// unresolved. The build may run either version, so the one without the profile isn't taken. A
// cached POM's dependencies are transitives of the build, so a profile whose versions are
// unknown unresolves all of them.
func unresolveReversioned(em *effectiveModel, cached bool) {
	alt := reversions(*em)
	for i, d := range em.deps {
		if d.Version != "" && (alt.reversioned(d.ga(), d.Version) || cached && alt.anyVersion) {
			em.deps[i].unresolvedBy = reasonProfileActivation
		}
	}
}

// profileVersions maps each "g:a" an undecided profile can add or re-version to every version it
// can resolve to under the profile.
// anyVersion is set when some undecided profile's versions are unknown.
type profileVersions struct {
	versions   map[string][]string
	anyVersion bool
}

func reversions(em effectiveModel) profileVersions {
	alt := profileVersions{versions: map[string][]string{}}
	for _, u := range em.undecided {
		alt.anyVersion = alt.anyVersion || u.anyVersion
		for _, d := range u.touched {
			alt.versions[d.ga()] = append(alt.versions[d.ga()], d.Version)
		}
	}
	return alt
}

// reversioned reports whether some undecided profile can put ga at a version other than version.
func (alt profileVersions) reversioned(ga, version string) bool {
	for _, v := range alt.versions[ga] {
		if v != version {
			return true
		}
	}
	return false
}

type chainResult struct {
	poms          []*mvnPOM // root ancestor ... self
	parentMissing bool
}

func parentChain(pom *mvnPOM, reactor map[string]*mvnPOM, cache *mavenCache, depth int) chainResult {
	var chain []*mvnPOM
	cur := pom
	missing := false
	for i := 0; i < 20 && cur != nil; i++ {
		chain = append(chain, cur)
		p := cur.Parent
		if p.ArtifactID == "" {
			break
		}
		if rp, ok := reactor[p.GroupID+":"+p.ArtifactID]; ok {
			cur = rp
			continue
		}
		if cp, ok := cache.get(p.GroupID, p.ArtifactID, p.Version); ok {
			cur = cp
			continue
		}
		missing = true
		break
	}
	// Reverse to root-first.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	_ = depth
	return chainResult{poms: chain, parentMissing: missing}
}

// importBOM folds an imported BOM's effective dependencyManagement into em.managed (existing keys
// untouched — first-declared wins). A cache-miss is residue, never assumed empty. em is a pointer
// so the BOM-cache-miss and nested-BOM residue actually reach the caller's model (a value receiver
// silently drops the residue slice reassignment — the managed map still merges either way).
func importBOM(m mvnDep, em *effectiveModel, reactor map[string]*mvnPOM, cache *mavenCache, targetEnv map[string]string, depth int) {
	ver, ok := interp(m.Version, em.props)
	if !ok {
		em.residue = append(em.residue, reasonBOMUncached)
		return
	}
	bom, ok := cache.get(m.GroupID, m.ArtifactID, ver)
	if !ok {
		em.residue = append(em.residue, reasonBOMUncached)
		return
	}
	if depth > 10 {
		return
	}
	sub := buildImportedModel(bom, reactor, cache, targetEnv, depth+1)
	for k, v := range sub.managed {
		if _, seen := em.managed[k]; !seen {
			em.managed[k] = v
		}
	}
	em.residue = append(em.residue, sub.residue...)
	em.undecided = append(em.undecided, sub.undecided...)
}

func defaultType(t string) string {
	if t == "" {
		return "jar"
	}
	return t
}

// --- property interpolation (pass 2) -----------------------------------------

// interpProps iterates the property map to a fixpoint so nested/compound references resolve.
func interpProps(props map[string]string) {
	for i := 0; i < 10; i++ {
		changed := false
		keys := make([]string, 0, len(props))
		for k := range props {
			keys = append(keys, k)
		}
		sort.Strings(keys) // deterministic (values are order-independent at fixpoint anyway)
		for _, k := range keys {
			if nv, ok := interp(props[k], props); ok && nv != props[k] {
				props[k] = nv
				changed = true
			}
		}
		if !changed {
			return
		}
	}
}

// interp resolves every ${name} in raw against props, to a fixpoint (compound "${a}-${b}" and
// nested supported). ok is false when raw is empty or ANY ${...} remains unresolvable
// (env.*/settings.*/unknown) — never a guess (extends versions.go:213 conservatism).
func interp(raw string, props map[string]string) (string, bool) {
	s := javaTrim(raw)
	if s == "" {
		return "", false
	}
	for i := 0; i < 15 && strings.Contains(s, "${"); i++ {
		start := strings.Index(s, "${")
		end := strings.Index(s[start:], "}")
		if end < 0 {
			break
		}
		name := s[start+2 : start+end]
		val, ok := props[name]
		if !ok {
			return "", false // env.*/settings.*/unknown property.
		}
		s = s[:start] + val + s[start+end+1:]
	}
	if strings.Contains(s, "${") {
		return "", false
	}
	return s, true
}
