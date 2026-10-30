package javaanalysis

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
)

// launchpom.go — the POM read model the launch-entry reader walks: a reactor POM and the parents
// it inherits from the local Maven cache, for the launch class and the properties naming it.
// Nothing reads dependencies from it; the dependency graph is the build tool's (buildgraph).

// mavenCache resolves a GAV to its cached POM under the local Maven repositories, in priority
// order: a project-local .m2/repository, then ~/.m2. Parsed POMs are memoized; an absent POM is a
// recorded miss.
type mavenCache struct {
	roots   []string
	memo    map[string]*mvnPOM
	miss    map[string]bool
	escaped bool // the build's own repository links out of the checkout: every lookup misses
}

// newMavenCache builds the reader for a build dir. A project-local repository that resolves
// outside the build is an escape in the first root, so nothing is read past it.
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

// newMavenCacheAt builds a reader over explicit repository roots.
func newMavenCacheAt(roots ...string) *mavenCache {
	return &mavenCache{roots: roots, memo: map[string]*mvnPOM{}, miss: map[string]bool{}}
}

func gavKey(g, a, v string) string { return g + ":" + a + ":" + v }

// pomRelPath renders the Maven local-repo relative path of a POM:
// <group as path>/<artifact>/<version>/<artifact>-<version>.pom.
func pomRelPath(g, a, v string) string {
	return filepath.Join(strings.ReplaceAll(g, ".", "/"), a, v, a+"-"+v+".pom")
}

// get returns the cached POM for a GAV, or (nil, false) on a miss. Roots are searched in order;
// the first hit wins. A GAV that cannot name a cache path, or whose POM resolves outside its
// root, is a miss in every root.
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

type mvnPOM struct {
	path       string // reactor path, "" for a cached POM
	GroupID    string
	ArtifactID string
	Version    string
	Packaging  string
	Parent     mvnParent
	Properties map[string]string
	Profiles   []mvnProfile
}

type mvnParent struct{ GroupID, ArtifactID, Version, RelativePath string }

type mvnProfile struct {
	ID         string
	Properties map[string]string
}

type xmlPOM struct {
	GroupID    string    `xml:"groupId"`
	ArtifactID string    `xml:"artifactId"`
	Version    string    `xml:"version"`
	Packaging  string    `xml:"packaging"`
	Parent     xmlParent `xml:"parent"`
	Properties pomProps  `xml:"properties"`
	Profiles   []struct {
		ID         string   `xml:"id"`
		Properties pomProps `xml:"properties"`
	} `xml:"profiles>profile"`
}

type xmlParent struct {
	GroupID      string `xml:"groupId"`
	ArtifactID   string `xml:"artifactId"`
	Version      string `xml:"version"`
	RelativePath string `xml:"relativePath"`
}

// pomProps captures the child elements of a <properties> block as name→value pairs.
type pomProps struct{ Entries map[string]string }

func (p *pomProps) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) error {
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
// text: only characters at or below U+0020 go.
func javaTrim(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return r <= ' ' })
}

// parseMavenPOM reads and binds one pom.xml. ok is false when the file is unreadable or the XML
// does not parse.
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
	}
	if p.Properties == nil {
		p.Properties = map[string]string{}
	}
	// The coordinate falls back to the parent's, as Maven inherits groupId and version.
	if p.GroupID == "" {
		p.GroupID = p.Parent.GroupID
	}
	if p.Version == "" {
		p.Version = p.Parent.Version
	}
	for _, pr := range xp.Profiles {
		mp := mvnProfile{ID: javaTrim(pr.ID), Properties: pr.Properties.Entries}
		if mp.Properties == nil {
			mp.Properties = map[string]string{}
		}
		p.Profiles = append(p.Profiles, mp)
	}
	return p, true
}
