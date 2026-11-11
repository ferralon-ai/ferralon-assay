package javaanalysis

import (
	"bytes"
	"encoding/xml"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/net/html/charset"
)

// effectivepom.go — the launch evidence a Maven module's POM chain carries, read once over the
// chain as Maven merges it, so the module's own POM and every parent it inherits from are held to
// one rule. Every launch-entry check (entryReader.maven, bootMaven, launchSignal through them)
// reads this view, never a single POM's text.
//
// A launch-naming element (mainClass, start-class, Main-Class, Start-Class, Main-Verticle) in any
// POM of the chain applies to the module when it sits in:
//   - a plugin the chain applies in <build><plugins> (inherited by every child);
//   - a <pluginManagement> entry for a plugin the module applies, in its chain's <build><plugins>
//     or by its packaging's default lifecycle (maven-jar-plugin for jar, and so on);
//   - a <profile>, whatever its activation, since -P or settings.xml can switch it on: it names a
//     launch class and also withholds (launch_entry_profile_plugin);
//   - anywhere else but <properties> and an unapplied plugin's <pluginManagement> entry, read as
//     applying, since the reader does not know what consumes it.
//
// The start-class property is spring-boot-maven-plugin's default main: it names one when the
// module applies the Boot plugin. Otherwise it names one only through an entry that reads it, so a
// module under a parent that sets it (a coverage aggregator under a Boot parent) names none.
// ${...} resolves against the chain's merged properties, the nearest POM's value winning and an
// active-by-default profile's over its own POM's. A value that is only ${start-class} or
// ${spring-boot.run.main-class} with the property unset is spring-boot-starter-parent's wiring
// handing the main to the Boot plugin: it names nothing.

// pomEffective is the merged launch view of one module's POM chain.
type pomEffective struct {
	chain []*mvnPOM
	files []string
	// texts holds each chain file's text with comments removed, "" where it could not be re-read.
	texts    []string
	complete bool // every parent in the chain was read
	unread   bool // a chain file could not be re-read or did not parse as XML
	// props is every property the chain sets, merged as Maven inherits them; profileProps the
	// keys any profile in the chain sets, whatever its activation.
	props        map[string]string
	profileProps map[string]bool
	// profileLaunch is set when a profile in the chain carries a launch-naming element.
	profileLaunch bool
	// applied holds the groupId:artifactId of every plugin the module runs.
	applied map[string]bool
	// entries are the launch-naming elements that apply to the module, nearest POM first.
	entries []pomEntry
}

// pomEntry is one launch-naming element: its element name and raw value.
type pomEntry struct{ elem, value string }

const (
	bootPluginKey   = "org.springframework.boot:spring-boot-maven-plugin"
	mavenPluginsGrp = "org.apache.maven.plugins"
)

// packagingPlugins are the plugins a packaging's default lifecycle runs that can carry a launch
// class in their configuration.
var packagingPlugins = map[string][]string{
	"":    {mavenPluginsGrp + ":maven-jar-plugin"},
	"jar": {mavenPluginsGrp + ":maven-jar-plugin"},
	"war": {mavenPluginsGrp + ":maven-war-plugin"},
	"ear": {mavenPluginsGrp + ":maven-ear-plugin"},
}

// pluginPaths are where a POM declares a plugin walkPOM reads: applied, managed, and applied by
// a profile.
var pluginPaths = [][]string{
	{"project", "build", "plugins", "plugin"},
	{"project", "build", "pluginManagement", "plugins", "plugin"},
	{"project", "profiles", "profile", "build", "plugins", "plugin"},
}

// launchElements are the element names that can name a launch class.
var launchElements = map[string]bool{
	"mainClass": true, "start-class": true, "Main-Class": true, "Start-Class": true, "Main-Verticle": true,
}

// pomWalk is what one POM file says, located by section.
type pomWalk struct {
	plugins  []pomPlugin // build>plugins
	managed  []pomPlugin // build>pluginManagement>plugins
	profiles []pomProfile
	other    []pomEntry // launch elements outside plugins, profiles and properties
}

type pomPlugin struct {
	key     string
	entries []pomEntry
}

type pomProfile struct {
	activeByDefault bool
	props           map[string]string
	entries         []pomEntry
	plugins         []string // the groupId:artifactId of each plugin in its <build><plugins>
}

// effective reads the chain of pom, read from path, into its merged launch view.
func (r *entryReader) effective(pom *mvnPOM, path string) *pomEffective {
	chain, files, complete := r.pomChain(pom, path)
	eff := &pomEffective{chain: chain, files: files, complete: complete, texts: make([]string, len(chain)),
		props: map[string]string{}, profileProps: map[string]bool{}, applied: map[string]bool{}}
	walks := make([]pomWalk, len(chain))
	for i := range chain {
		data, err := readRegular(files[i])
		if err != nil {
			eff.unread = true
			continue
		}
		eff.texts[i] = xmlComment.ReplaceAllString(string(data), "")
		w, ok := walkPOM(data)
		if !ok {
			eff.unread = true
			continue
		}
		walks[i] = w
	}
	for _, k := range packagingPlugins[pom.Packaging] {
		eff.applied[k] = true
	}
	// Properties: the farthest parent first, so a nearer POM overwrites what it inherits.
	for i := len(chain) - 1; i >= 0; i-- {
		for k, v := range chain[i].Properties {
			eff.props[k] = v
		}
		for _, pr := range walks[i].profiles {
			for k, v := range pr.props {
				eff.profileProps[k] = true
				if pr.activeByDefault {
					eff.props[k] = v
				}
			}
		}
		for _, pl := range walks[i].plugins {
			eff.applied[pl.key] = true
		}
	}
	for i := range chain {
		w := walks[i]
		for _, pl := range w.plugins {
			eff.entries = append(eff.entries, pl.entries...)
		}
		for _, pl := range w.managed {
			if eff.applied[pl.key] {
				eff.entries = append(eff.entries, pl.entries...)
			}
		}
		for _, pr := range w.profiles {
			if len(pr.entries) > 0 {
				eff.profileLaunch = true
				eff.entries = append(eff.entries, pr.entries...)
			}
		}
		eff.entries = append(eff.entries, w.other...)
	}
	return eff
}

// startClass reports the start-class property the chain sets, if any.
func (e *pomEffective) startClass() (string, bool) {
	v, ok := e.props["start-class"]
	return v, ok
}

// resolve replaces each ${key} in v whose merged property is set, through properties that name
// others, calling used for each key it reads. A reference to an unset property stays as it is.
func (e *pomEffective) resolve(v string, used func(key string)) string {
	for range 8 {
		changed := false
		v = pomPropertyRef.ReplaceAllStringFunc(v, func(ref string) string {
			key := ref[2 : len(ref)-1]
			val, ok := e.props[key]
			if !ok {
				return ref
			}
			used(key)
			changed = true
			return val
		})
		if !changed || !strings.Contains(v, "${") {
			return v
		}
	}
	return v
}

// walkPOM locates the launch-naming elements of one POM by section, with each profile's
// properties and activation. ok is false when the XML does not parse.
func walkPOM(data []byte) (pomWalk, bool) {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.CharsetReader = charset.NewReaderLabel
	var (
		w       pomWalk
		stack   []string
		text    strings.Builder
		plugin  *pomPlugin
		group   string
		profile *pomProfile
	)
	at := func(path ...string) bool { return slices.Equal(stack, path) }
	atPlugin := func(child ...string) bool {
		for _, p := range pluginPaths {
			if at(append(slices.Clip(p), child...)...) {
				return true
			}
		}
		return false
	}
	under := func(path ...string) bool {
		return len(stack) > len(path) && slices.Equal(stack[:len(path)], path)
	}
	for {
		tok, err := d.Token()
		if err != nil {
			return w, err == io.EOF
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			text.Reset()
			switch {
			case atPlugin():
				plugin, group = &pomPlugin{}, ""
			case at("project", "profiles", "profile"):
				profile = &pomProfile{props: map[string]string{}}
			}
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			name, val := t.Name.Local, javaTrim(text.String())
			switch {
			case plugin != nil && atPlugin("groupId"):
				group = val
			case plugin != nil && atPlugin("artifactId"):
				plugin.key = val
			case profile != nil && at("project", "profiles", "profile", "activation", "activeByDefault"):
				profile.activeByDefault = val == "true"
			case profile != nil && len(stack) == 5 && slices.Equal(stack[:4], []string{"project", "profiles", "profile", "properties"}):
				profile.props[name] = val
				if launchElements[name] {
					profile.entries = append(profile.entries, pomEntry{name, val})
				}
			case launchElements[name] && profile != nil && under("project", "profiles", "profile"):
				profile.entries = append(profile.entries, pomEntry{name, val})
			case launchElements[name] && plugin != nil:
				plugin.entries = append(plugin.entries, pomEntry{name, val})
			case launchElements[name] && under("project", "properties"):
				// The Boot plugin's start-class is read from the merged properties (startClass).
			case launchElements[name]:
				w.other = append(w.other, pomEntry{name, val})
			}
			switch {
			case atPlugin():
				if group == "" {
					group = mavenPluginsGrp
				}
				plugin.key = group + ":" + plugin.key
				switch {
				case stack[1] == "profiles":
					profile.plugins = append(profile.plugins, plugin.key)
				case stack[2] == "plugins":
					w.plugins = append(w.plugins, *plugin)
				default:
					w.managed = append(w.managed, *plugin)
				}
				plugin = nil
			case at("project", "profiles", "profile"):
				w.profiles = append(w.profiles, *profile)
				profile = nil
			}
			stack = stack[:len(stack)-1]
			text.Reset()
		}
	}
}

// repackagers are the plugins, by artifactId, that can build a module's artifact with other
// artifacts' classes inside it: shading, assembly, Boot's repackage, unpacking dependencies into
// the class output, one-jar and jarjar builds, and an OSGi bundle's embedded dependencies.
var repackagers = map[string]bool{
	"maven-shade-plugin": true, "maven-assembly-plugin": true, "spring-boot-maven-plugin": true,
	"maven-dependency-plugin": true, "onejar-maven-plugin": true, "jarjar-maven-plugin": true,
	"maven-jarjar-plugin": true, "maven-bundle-plugin": true,
}

// mavenRepackages reports whether the Maven module at dir, inside the checkout buildDir, may
// publish an artifact that carries classes besides its own: its POM chain applies a repackaging
// plugin in <build><plugins> or in any profile, its packaging is other than jar or pom, or its
// POM or a parent cannot be read.
func mavenRepackages(buildDir, dir string) bool {
	path := filepath.Join(dir, "pom.xml")
	pom, ok := parseMavenPOM(path)
	if !ok {
		return true
	}
	if pom.Packaging != "" && pom.Packaging != "jar" && pom.Packaging != "pom" {
		return true
	}
	r := &entryReader{cache: newMavenCache(buildDir), checkout: buildDir}
	chain, files, complete := r.pomChain(pom, path)
	if !complete {
		return true
	}
	for i := range chain {
		data, err := readRegular(files[i])
		if err != nil {
			return true
		}
		w, ok := walkPOM(data)
		if !ok {
			return true
		}
		keys := []string{}
		for _, pl := range w.plugins {
			keys = append(keys, pl.key)
		}
		for _, pr := range w.profiles {
			keys = append(keys, pr.plugins...)
		}
		for _, k := range keys {
			if repackagers[k[strings.LastIndex(k, ":")+1:]] {
				return true
			}
		}
	}
	return false
}
