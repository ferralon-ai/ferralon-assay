package javaanalysis

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// writePOMs writes each module path's POM under a fresh checkout and returns its root.
func writePOMs(t *testing.T, poms map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for dir, body := range poms {
		d := filepath.Join(root, filepath.FromSlash(dir))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(modulePOM(d), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const (
	effParent = `<project><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>`
	effChild  = `<project><parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1</version></parent><artifactId>app</artifactId>`
)

// effective merges the chain as Maven does: the nearest POM's property wins, an active-by-default
// profile's over its own POM's, ${...} resolves through properties naming others, and every
// launch-naming element that applies is read, profiles and unplaced elements included.
func TestEffectivePOM(t *testing.T) {
	cases := map[string]struct {
		parent, child string
		startClass    string   // "" when the chain sets none
		entries       []string // the values of the elements that apply
		profileLaunch bool
		complete      bool
		unread        bool
		resolve       string // what ${main} resolves to
	}{
		"the child's start-class over the parent's": {
			parent:     effParent + `<properties><start-class>com.acme.Parent</start-class></properties></project>`,
			child:      effChild + `<properties><start-class>com.acme.Child</start-class></properties></project>`,
			startClass: "com.acme.Child", complete: true, resolve: "${main}",
		},
		"an active-by-default profile over its own POM's property": {
			parent:     effParent + `<properties><start-class>com.acme.Plain</start-class></properties><profiles><profile><id>p</id><activation><activeByDefault>true</activeByDefault></activation><properties><start-class>com.acme.Profiled</start-class></properties></profile></profiles></project>`,
			child:      effChild + `</project>`,
			startClass: "com.acme.Profiled", entries: []string{"com.acme.Profiled"}, profileLaunch: true, complete: true, resolve: "${main}",
		},
		"a profile not active by default leaves the property": {
			parent:     effParent + `<properties><start-class>com.acme.Plain</start-class></properties><profiles><profile><id>p</id><properties><start-class>com.acme.Profiled</start-class></properties></profile></profiles></project>`,
			child:      effChild + `</project>`,
			startClass: "com.acme.Plain", entries: []string{"com.acme.Profiled"}, profileLaunch: true, complete: true, resolve: "${main}",
		},
		"a parent profile's plugin main": {
			parent:  effParent + `<profiles><profile><id>p</id><build><plugins><plugin><artifactId>exec-maven-plugin</artifactId><configuration><mainClass>com.acme.Tool</mainClass></configuration></plugin></plugins></build></profile></profiles></project>`,
			child:   effChild + `</project>`,
			entries: []string{"com.acme.Tool"}, profileLaunch: true, complete: true, resolve: "${main}",
		},
		"a main outside plugins, profiles and properties": {
			parent:  effParent + `<reporting><mainClass>com.acme.Elsewhere</mainClass></reporting></project>`,
			child:   effChild + `</project>`,
			entries: []string{"com.acme.Elsewhere"}, complete: true, resolve: "${main}",
		},
		"a property naming others resolves through them": {
			parent:   effParent + `<properties><main>${inner}</main><inner>${leaf}</inner><leaf>com.acme.Leaf</leaf></properties></project>`,
			child:    effChild + `</project>`,
			complete: true, resolve: "com.acme.Leaf",
		},
		"a parent not there": {
			child:   effChild + `</project>`,
			resolve: "${main}",
		},
		"a parent that parses only as a document prefix": {
			parent:   effParent + `</project><`,
			child:    effChild + `</project>`,
			complete: true, unread: true, resolve: "${main}",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			poms := map[string]string{"app": c.child}
			if c.parent != "" {
				poms["."] = c.parent
			}
			root := writePOMs(t, poms)
			path := modulePOM(filepath.Join(root, "app"))
			pom, ok := parseMavenPOM(path)
			if !ok {
				t.Fatal("child POM did not parse")
			}
			r := &entryReader{reasons: map[string]bool{}, named: map[string]bool{}, propKeys: map[string]bool{}, cache: newMavenCacheAt(filepath.Join(root, "no-cache")), checkout: root}
			eff := r.effective(pom, path)
			sc, _ := eff.startClass()
			var entries []string
			for _, e := range eff.entries {
				entries = append(entries, e.value)
			}
			if sc != c.startClass || !slices.Equal(entries, c.entries) || eff.profileLaunch != c.profileLaunch || eff.complete != c.complete || eff.unread != c.unread {
				t.Errorf("start-class %q entries %q profileLaunch %v complete %v unread %v, want %q %q %v %v %v",
					sc, entries, eff.profileLaunch, eff.complete, eff.unread, c.startClass, c.entries, c.profileLaunch, c.complete, c.unread)
			}
			if got := eff.resolve("${main}", func(string) {}); got != c.resolve {
				t.Errorf("${main} resolves to %q, want %q", got, c.resolve)
			}
		})
	}
}

// A code-free module whose POM chain cannot be read in full may name a launch class in what is
// missing: it carries launch evidence, unless it is an aggregator.
func TestLaunchSignal_CodeFreeChainNotRead(t *testing.T) {
	cases := map[string]struct {
		parent, child string
		want          bool
	}{
		"a parent read in full":                   {parent: effParent + `</project>`, child: effChild + `</project>`},
		"a parent not there":                      {child: effChild + `</project>`, want: true},
		"an aggregator, no parent":                {child: effChild + `<packaging>pom</packaging></project>`},
		"a parent that does not parse to the end": {parent: effParent + `</project><`, child: effChild + `</project>`, want: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			poms := map[string]string{"app": c.child}
			if c.parent != "" {
				poms["."] = c.parent
			}
			root := writePOMs(t, poms)
			if got := launchSignal(root, filepath.Join(root, "app"), nil, false); got != c.want {
				t.Errorf("launchSignal = %v, want %v", got, c.want)
			}
		})
	}
}

// mavenRepackages: a sibling may publish other artifacts' classes when its chain applies a
// repackaging plugin, in <build><plugins> or a profile, when its packaging is other than jar or
// pom, or when its POM or a parent cannot be read.
func TestMavenRepackages(t *testing.T) {
	plugin := func(a string) string { return `<plugin><artifactId>` + a + `</artifactId></plugin>` }
	build := func(p string) string { return `<build><plugins>` + p + `</plugins></build>` }
	cases := map[string]struct {
		parent, child string // child "" writes no POM for the module
		want          bool
	}{
		"a plain jar":                     {parent: effParent + `</project>`, child: effChild + `</project>`},
		"a plain aggregator":              {parent: effParent + `</project>`, child: effChild + `<packaging>pom</packaging></project>`},
		"a managed shade, not applied":    {parent: effParent + `<build><pluginManagement><plugins>` + plugin("maven-shade-plugin") + `</plugins></pluginManagement></build></project>`, child: effChild + `</project>`},
		"no POM":                          {parent: effParent + `</project>`, want: true},
		"bundle packaging":                {parent: effParent + `</project>`, child: effChild + `<packaging>bundle</packaging></project>`, want: true},
		"a parent not there":              {child: effChild + `</project>`, want: true},
		"a parent that does not parse":    {parent: effParent + `</project><`, child: effChild + `</project>`, want: true},
		"shade applied":                   {parent: effParent + `</project>`, child: effChild + build(plugin("maven-shade-plugin")) + `</project>`, want: true},
		"Boot repackage applied":          {parent: effParent + `</project>`, child: effChild + build(`<plugin><groupId>org.springframework.boot</groupId><artifactId>spring-boot-maven-plugin</artifactId></plugin>`) + `</project>`, want: true},
		"assembly in a profile":           {parent: effParent + `</project>`, child: effChild + `<profiles><profile><id>p</id>` + build(plugin("maven-assembly-plugin")) + `</profile></profiles></project>`, want: true},
		"dependency unpack in the parent": {parent: effParent + build(plugin("maven-dependency-plugin")) + `</project>`, child: effChild + `</project>`, want: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			poms := map[string]string{}
			if c.parent != "" {
				poms["."] = c.parent
			}
			if c.child != "" {
				poms["app"] = c.child
			}
			root := writePOMs(t, poms)
			if c.child == "" {
				if err := os.MkdirAll(filepath.Join(root, "app"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if got := mavenRepackages(root, filepath.Join(root, "app")); got != c.want {
				t.Errorf("mavenRepackages = %v, want %v", got, c.want)
			}
		})
	}
}
