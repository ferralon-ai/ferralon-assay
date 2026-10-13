package javaanalysis

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// stated returns a TargetEnv carrying the given explicit selection and Java version ("" leaves
// either out).
func stated(selection, javaVersion string) map[string]string {
	env := map[string]string{}
	if selection != "" {
		env[targetEnvMavenProfiles] = selection
	}
	if javaVersion != "" {
		env[targetEnvJavaVersion] = javaVersion
	}
	return env
}

// Until the invocation's selection is stated, -P or settings.xml could switch any reactor profile
// on or off, so none is decided: not one without activation, not activeByDefault, not a <jdk>
// profile the stated Java version satisfies.
func TestMavenProfile_SelectionUnstatedLeavesProfilesUndecided(t *testing.T) {
	for _, tt := range []struct {
		name, activation, selection string
		applied, disclosed          bool
	}{
		{"no activation, unstated", ``, "", false, true},
		{"activeByDefault, unstated", `<activeByDefault>true</activeByDefault>`, "", false, true},
		{"jdk satisfied, unstated", `<jdk>11</jdk>`, "", false, true},
		{"no activation, stated empty", ``, ",", false, false},
		{"activeByDefault, stated empty", `<activeByDefault>true</activeByDefault>`, ",", true, false},
		{"jdk satisfied, stated empty", `<jdk>11</jdk>`, ",", true, false},
		{"blank statement is unstated", `<jdk>11</jdk>`, " ", false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir, m2 := profileFixture(t, tt.activation, false)
			inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), stated(tt.selection, "11.0.2")))
			if got := findNode(t, inv, "pkg:maven/org.p/p@1.0") != nil; got != tt.applied {
				t.Errorf("profile applied = %v, want %v", got, tt.applied)
			}
			if got := hasStr(inv.Partiality.Reasons, reasonProfileActivation); got != tt.disclosed {
				t.Errorf("profile_activation listed = %v, want %v; got %+v", got, tt.disclosed, inv.Partiality)
			}
		})
	}
}

// A stated selection decides before any condition, and deactivation wins (DefaultProfileSelector).
func TestMavenProfile_StatedSelectionDecidesFirst(t *testing.T) {
	for _, tt := range []struct {
		name, activation, selection, java string
		applied                           bool
	}{
		{"selected without activation", ``, "p", "", true},
		{"selected though jdk is false", `<jdk>11</jdk>`, "p", "17.0.1", true},
		{"selected though jdk is undecided", `<jdk>11</jdk>`, "p", "", true},
		{"deselected though jdk is true", `<jdk>11</jdk>`, "!p", "11.0.2", false},
		{"deselected with -", `<jdk>11</jdk>`, "-p", "11.0.2", false},
		{"deselection wins", ``, "p,!p", "", false},
		{"selected with +", ``, "+p", "", true},
		{"optional selection", ``, "?p", "", true},
		{"optional deselection", `<jdk>11</jdk>`, "!?p", "11.0.2", false},
		{"selection with spaces", ``, "other, p", "", true},
		{"another id leaves conditions to decide", `<jdk>11</jdk>`, "other", "11.0.2", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir, m2 := profileFixture(t, tt.activation, false)
			inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), stated(tt.selection, tt.java)))
			if got := findNode(t, inv, "pkg:maven/org.p/p@1.0") != nil; got != tt.applied {
				t.Errorf("profile applied = %v, want %v", got, tt.applied)
			}
			if !inv.Partiality.Complete {
				t.Errorf("an explicitly decided profile costs no reason; got %+v", inv.Partiality)
			}
		})
	}
}

// activeByDefault turns off when any profile of the same POM is active, an explicitly selected
// sibling included.
func TestMavenProfile_SelectedSiblingTurnsOffActiveByDefault(t *testing.T) {
	for _, tt := range []struct {
		selection string
		applied   bool
	}{
		{",", true},
		{"sib", false},
		{"!def", false},
		{"elsewhere", true},
	} {
		t.Run(tt.selection, func(t *testing.T) {
			dir, m2 := t.TempDir(), t.TempDir()
			writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></dependency></dependencies>
<profiles><profile><id>def</id><activation><activeByDefault>true</activeByDefault></activation>
<dependencies><dependency><groupId>org.p</groupId><artifactId>p</artifactId><version>1.0</version></dependency></dependencies></profile>
<profile><id>sib</id></profile></profiles></project>`)
			writeCachePOM(t, m2, "org.base", "base", "1.0", `<project><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></project>`)
			writeCachePOM(t, m2, "org.p", "p", "1.0", `<project><groupId>org.p</groupId><artifactId>p</artifactId><version>1.0</version></project>`)
			inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), stated(tt.selection, "")))
			if got := findNode(t, inv, "pkg:maven/org.p/p@1.0") != nil; got != tt.applied {
				t.Errorf("activeByDefault applied = %v, want %v", got, tt.applied)
			}
			if !inv.Partiality.Complete {
				t.Errorf("want complete; got %+v", inv.Partiality)
			}
		})
	}
}

// .mvn/maven.config is part of the checkout: a profile it selects or deselects is undecided,
// since the caller's statement may or may not have accounted for it, and when the file can't be
// read in full every profile is.
func TestMavenProfile_MavenConfigSelection(t *testing.T) {
	for _, tt := range []struct {
		name, config string
		disclosed    bool
	}{
		{"-P selects", "-Pp\n", true},
		{"-P deselects", "-P!p\n", true},
		{"separate -P", "-P p\n", true},
		{"long form", "--activate-profiles=other,p\n", true},
		{"long form, separate", "--activate-profiles p\n", true},
		{"list continued after a comma", "-P other, p\n", true},
		{"interpolated list", "-P${env.PROFILES}\n", true},
		{"short-option cluster", "-UPp\n", true},
		{"-P with nothing after it", "-P\n", true},
		{"-P= selects", "-P=p\n", true},
		{"-P= deselects with !", "-P=!p\n", true},
		{"-P= deselects with -", "-P=-p\n", true},
		{"-P= with nothing after it", "-P=\n", true},
		{"long form with nothing after it", "--activate-profiles=\n", true},
		{"list ending in a comma", "-P other,\n  p\n", true},
		{"list with an empty element", "-Pother,,p\n", true},
		{"quoted value", "-P\"p\"\n", true},
		{"quoted value, separate", "-P \"p\"\n", true},
		{"quoted option", "\"-Pp\"\n", true},
		{"an id holding =", "-P p=1\n", true},
		{"abbreviated long form", "--activate-profile p\n", true},
		{"abbreviated long form with =", "--activate-prof=p\n", true},
		// R3-B1: Maven takes a line as one argument, so these select p. Any shape the reader
		// doesn't model withholds, whether or not p is visibly named.
		{"R3-B1 a list continued after whitespace", "-P a ,p\n", true},
		{"R3-B1 spaces either side of the comma", "-P a , p\n", true},
		{"R3-B1 attached, then continued after whitespace", "-Pa ,p\n", true},
		{"R3-B1 a second token before the list goes on", "-P a b,p\n", true},
		{"R3-B1 deselection continued after whitespace", "-P a ,!p\n", true},
		{"two options on one line", "-Pa -Pother\n", true},
		{"a selection after another option", "-DskipTests -Pother\n", true},
		{"a byte-order mark", "\ufeff-Pother\n", true},
		{"control, a list continued after a comma, p not named", "-P a, other\n", false},
		{"another profile only", "-Pother\n", false},
		{"another profile only, -P=", "-P=other\n", false},
		{"another profile only, long form with =", "--activate-profiles=other\n", false},
		{"another long option", "--also-make --fail-at-end\n", false},
		{"no selection", "-DskipTests -T 1C\n", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir, m2 := profileFixture(t, `<jdk>11</jdk>`, false)
			writeFile(t, filepath.Join(dir, ".mvn", "maven.config"), tt.config)
			inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), stated(",", "11.0.2")))
			if got := hasStr(inv.Partiality.Reasons, reasonProfileActivation); got != tt.disclosed {
				t.Errorf("profile_activation listed = %v, want %v; got %+v", got, tt.disclosed, inv.Partiality)
			}
			if got := findNode(t, inv, "pkg:maven/org.p/p@1.0") != nil; got == tt.disclosed {
				t.Errorf("profile applied = %v with disclosed = %v", got, tt.disclosed)
			}
		})
	}

	t.Run("unreadable", func(t *testing.T) {
		dir, m2 := profileFixture(t, `<jdk>11</jdk>`, false)
		cfg := filepath.Join(dir, ".mvn", "maven.config")
		writeFile(t, cfg, "-Pother\n")
		if err := os.Chmod(cfg, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(cfg, 0o644) })
		inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), stated(",", "11.0.2")))
		if !hasStr(inv.Partiality.Reasons, reasonProfileActivation) {
			t.Errorf("an unreadable maven.config leaves every profile undecided; got %+v", inv.Partiality)
		}
	})

	t.Run("a FIFO", func(t *testing.T) {
		dir, m2 := profileFixture(t, `<jdk>11</jdk>`, false)
		if err := os.MkdirAll(filepath.Join(dir, ".mvn"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(filepath.Join(dir, ".mvn", "maven.config"), 0o644); err != nil {
			t.Fatal(err)
		}
		poms, cache := findPOMs(dir), newMavenCacheAt(m2)
		done := make(chan plugin.DependencyInventory, 1)
		go func() { done <- resolveMaven(dir, poms, cache, stated(",", "11.0.2")) }()
		select {
		case got := <-done:
			if inv := toJSON(t, got); !hasStr(inv.Partiality.Reasons, reasonProfileActivation) {
				t.Errorf("a maven.config that is not a regular file leaves every profile undecided; got %+v", inv.Partiality)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("reading a FIFO maven.config did not return: it was opened for reading")
		}
	})
}

// A <file> condition is decided by the tree Maven saw when it started, which the build may have
// changed since, so it stays undecided whatever the scan sees.
func TestMavenProfile_FileActivationIsUndecided(t *testing.T) {
	for _, present := range []bool{true, false} {
		for _, activation := range []string{`<file><exists>marker</exists></file>`, `<file><missing>marker</missing></file>`} {
			dir, m2 := profileFixture(t, activation, false)
			if present {
				writeFile(t, filepath.Join(dir, "marker"), "")
			}
			inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), stated(",", "11.0.2")))
			if findNode(t, inv, "pkg:maven/org.p/p@1.0") != nil {
				t.Errorf("%s, marker present=%v: a <file> profile must not be applied", activation, present)
			}
			if !hasStr(inv.Partiality.Reasons, reasonProfileActivation) {
				t.Errorf("%s, marker present=%v: want profile_activation; got %+v", activation, present, inv.Partiality)
			}
		}
	}
}

// Explicit selection never reaches a dependency's POM.
func TestMavenProfile_SelectionSkipsDependencyPOMs(t *testing.T) {
	dir, m2 := depProfileFixture(t, `<activeByDefault>true</activeByDefault>`, `<dependency><groupId>org.x</groupId><artifactId>x</artifactId><version>3.0</version></dependency>`)
	inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), stated("!tp", "")))
	if findNode(t, inv, "pkg:maven/org.x/x@3.0") == nil || !inv.Partiality.Complete {
		t.Errorf("a dependency's activeByDefault profile applies whatever -P says; got %+v", inv)
	}
}

// An undecided profile that adds a build section, a module outside the reactor, or a repository
// can change what runs in ways the dependency graph doesn't show, so its reason has no bound.
func TestMavenProfile_NonDependencyContributionsAreUnbounded(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		unbounded  bool
	}{
		{"dependency unpack", `<build><plugins><plugin><artifactId>maven-dependency-plugin</artifactId>
<executions><execution><goals><goal>unpack</goal></goals><configuration><artifactItems><artifactItem><groupId>org.evil</groupId><artifactId>x</artifactId><version>1.0</version><outputDirectory>${project.build.outputDirectory}</outputDirectory></artifactItem></artifactItems></configuration></execution></executions></plugin></plugins></build>`, true},
		{"shade", `<build><plugins><plugin><artifactId>maven-shade-plugin</artifactId></plugin></plugins></build>`, true},
		{"outside module", `<modules><module>../other</module></modules>`, true},
		{"interpolated module", `<modules><module>${mod}</module></modules>`, true},
		{"interpolated module naming a directory as written", `<modules><module>${lit}</module></modules>`, true},
		{"repository", `<repositories><repository><id>r</id><url>https://repo.example/</url></repository></repositories>`, true},
		{"plugin repository", `<pluginRepositories><pluginRepository><id>r</id><url>https://repo.example/</url></pluginRepository></pluginRepositories>`, true},
		{"empty build", `<build></build>`, false},
		{"module in the reactor", `<modules><module>sub</module></modules>`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir, m2 := t.TempDir(), t.TempDir()
			writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<profiles><profile><id>p</id><activation><jdk>11</jdk></activation>`+tt.body+`</profile></profiles></project>`)
			writeFile(t, filepath.Join(dir, "sub", "pom.xml"), `<project><groupId>com.example</groupId><artifactId>sub</artifactId><version>1.0.0</version></project>`)
			writeFile(t, filepath.Join(dir, "${lit}", "pom.xml"), `<project><groupId>com.example</groupId><artifactId>lit</artifactId><version>1.0.0</version></project>`)
			raw := resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil)
			if !tt.unbounded {
				if hasStr(raw.Partiality.Reasons, reasonProfileActivation) || len(raw.Partiality.Scoped) != 0 {
					t.Errorf("a profile that changes nothing costs no reason; got %+v", raw.Partiality)
				}
				return
			}
			if len(raw.Partiality.Scoped) != 1 || raw.Partiality.Scoped[0].Targets != nil || raw.Partiality.Complete {
				t.Errorf("want one unbounded profile_activation; got %+v", raw.Partiality)
			}
		})
	}

	// A dependency's build section never runs in this build; its repositories can still serve
	// what it resolves.
	for name, tc := range map[string]struct {
		body     string
		complete bool
	}{
		"dependency build":      {`<build><plugins><plugin><artifactId>maven-shade-plugin</artifactId></plugin></plugins></build>`, true},
		"dependency repository": {`<repositories><repository><id>r</id><url>https://repo.example/</url></repository></repositories>`, false},
	} {
		t.Run(name, func(t *testing.T) {
			dir, m2 := t.TempDir(), t.TempDir()
			writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version></dependency></dependencies></project>`)
			writeCachePOM(t, m2, "org.top", "top", "1.0", `<project><groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version>
<profiles><profile><id>tp</id><activation><jdk>1.8</jdk></activation>`+tc.body+`</profile></profiles></project>`)
			raw := resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil)
			if raw.Partiality.Complete != tc.complete {
				t.Errorf("complete = %v, want %v; got %+v", raw.Partiality.Complete, tc.complete, raw.Partiality)
			}
			for _, s := range raw.Partiality.Scoped {
				if s.Targets != nil {
					t.Errorf("want nil Targets; got %+v", s)
				}
			}
		})
	}
}

// A transitive dependency an undecided profile of the module manages to another version is left
// unresolved, the same as a direct one: Maven resolves it at the managed version whenever the
// profile is on.
func TestMavenProfile_UndecidedManagementLeavesTransitiveUnresolved(t *testing.T) {
	setup := func(t *testing.T) (string, string) {
		dir, m2 := t.TempDir(), t.TempDir()
		writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></dependency></dependencies>
<profiles><profile><id>p</id><activation><jdk>11</jdk></activation>
<dependencyManagement><dependencies><dependency><groupId>org.t</groupId><artifactId>t</artifactId><version>2.0</version></dependency></dependencies></dependencyManagement>
</profile></profiles></project>`)
		writeCachePOM(t, m2, "org.base", "base", "1.0", `<project><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version>
<dependencies><dependency><groupId>org.t</groupId><artifactId>t</artifactId><version>1.0</version></dependency></dependencies></project>`)
		writeCachePOM(t, m2, "org.t", "t", "1.0", `<project><groupId>org.t</groupId><artifactId>t</artifactId><version>1.0</version></project>`)
		writeCachePOM(t, m2, "org.t", "t", "2.0", `<project><groupId>org.t</groupId><artifactId>t</artifactId><version>2.0</version></project>`)
		return dir, m2
	}

	dir, m2 := setup(t)
	inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil))
	if findNode(t, inv, "pkg:maven/org.t/t@1.0") != nil {
		t.Error("org.t:t must not take the version it has without the undecided profile")
	}
	if n := findNode(t, inv, "pkg:maven/org.t/t@"); n == nil || n.Version != "" || !hasStr(n.Partiality.Reasons, reasonProfileActivation) {
		t.Errorf("org.t:t must be emitted unresolved for profile_activation; got %+v", n)
	}

	dir, m2 = setup(t)
	off := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), stated(",", "17.0.1")))
	if findNode(t, off, "pkg:maven/org.t/t@1.0") == nil || !off.Partiality.Complete {
		t.Errorf("with the profile decided off, org.t:t resolves at 1.0; got %+v", off)
	}
}

// A profile in a parent POM read from the cache is bounded only because that POM was read and
// parsed; when the parent can't be read, nothing the module's profiles change has a bound.
func TestMavenProfile_OutOfRepoParent(t *testing.T) {
	child := `<project><parent><groupId>org.par</groupId><artifactId>par</artifactId><version>1</version></parent>
<artifactId>app</artifactId>
<profiles><profile><id>own</id><activation><jdk>11</jdk></activation>
<dependencies><dependency><groupId>org.o</groupId><artifactId>o</artifactId><version>1.0</version></dependency></dependencies></profile></profiles></project>`
	parent := `<project><groupId>org.par</groupId><artifactId>par</artifactId><version>1</version><packaging>pom</packaging>
<profiles><profile><id>pp</id><activation><jdk>11</jdk></activation>
<dependencies><dependency><groupId>org.p</groupId><artifactId>p</artifactId><version>1.0</version></dependency></dependencies></profile></profiles></project>`
	setup := func(t *testing.T, withParent bool) (string, string) {
		dir, m2 := t.TempDir(), t.TempDir()
		writeFile(t, filepath.Join(dir, "pom.xml"), child)
		if withParent {
			writeCachePOM(t, m2, "org.par", "par", "1", parent)
		}
		writeCachePOM(t, m2, "org.p", "p", "1.0", `<project><groupId>org.p</groupId><artifactId>p</artifactId><version>1.0</version></project>`)
		writeCachePOM(t, m2, "org.o", "o", "1.0", `<project><groupId>org.o</groupId><artifactId>o</artifactId><version>1.0</version></project>`)
		return dir, m2
	}

	t.Run("parsed", func(t *testing.T) {
		dir, m2 := setup(t, true)
		raw := resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil)
		if len(raw.Partiality.Scoped) != 2 {
			t.Fatalf("want a reason for each profile; got %+v", raw.Partiality.Scoped)
		}
		for _, s := range raw.Partiality.Scoped {
			if s.Targets == nil {
				t.Errorf("a parsed parent's profile is bounded; got %+v", s)
			}
		}
	})
	t.Run("selection reaches the cached parent", func(t *testing.T) {
		dir, m2 := setup(t, true)
		inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), stated("pp,!own", "")))
		if findNode(t, inv, "pkg:maven/org.p/p@1.0") == nil || !inv.Partiality.Complete {
			t.Errorf("-P pp applies the parent's profile; got %+v", inv)
		}
	})
	for _, name := range []string{"missing", "unreadable"} {
		t.Run(name, func(t *testing.T) {
			dir, m2 := setup(t, name == "unreadable")
			if name == "unreadable" {
				p := filepath.Join(m2, pomRelPath("org.par", "par", "1"))
				if err := os.Chmod(p, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
			}
			raw := resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil)
			if len(raw.Partiality.Scoped) == 0 {
				t.Fatalf("want the module's profile disclosed; got %+v", raw.Partiality)
			}
			for _, s := range raw.Partiality.Scoped {
				if s.Targets != nil {
					t.Errorf("with the parent unread, no profile is bounded; got %+v", s)
				}
			}
		})
	}
}

// A profile that declares no id is Maven's "default", and -P selects or deselects it by that name.
func TestMavenProfile_ProfileWithoutIDIsDefault(t *testing.T) {
	for _, tt := range []struct {
		selection, java string
		applied         bool
	}{
		{"!default", "11.0.2", false},
		{"default", "17.0.1", true},
	} {
		t.Run(tt.selection, func(t *testing.T) {
			dir, m2 := t.TempDir(), t.TempDir()
			writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<profiles><profile><activation><jdk>11</jdk></activation>
<dependencies><dependency><groupId>org.p</groupId><artifactId>p</artifactId><version>1.0</version></dependency></dependencies></profile></profiles></project>`)
			writeCachePOM(t, m2, "org.p", "p", "1.0", `<project><groupId>org.p</groupId><artifactId>p</artifactId><version>1.0</version></project>`)
			inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), stated(tt.selection, tt.java)))
			if got := findNode(t, inv, "pkg:maven/org.p/p@1.0") != nil; got != tt.applied {
				t.Errorf("profile applied = %v, want %v", got, tt.applied)
			}
		})
	}
}

// An undecided profile that declares a dependency at the version the build already has can't
// re-version it, so the dependency keeps that version.
func TestMavenProfile_SameVersionIsNotReversioned(t *testing.T) {
	dir, m2 := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></dependency></dependencies>
<profiles><profile><id>p</id><activation><jdk>11</jdk></activation>
<dependencies><dependency><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></dependency></dependencies></profile></profiles></project>`)
	writeCachePOM(t, m2, "org.base", "base", "1.0", `<project><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></project>`)
	inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil))
	if findNode(t, inv, "pkg:maven/org.base/base@1.0") == nil {
		t.Errorf("org.base:base keeps 1.0, the only version any profile gives it; got %+v", inv.Nodes)
	}
}

// A parent's profile modules belong to the parent's build. A child that inherits the profile
// doesn't resolve them against its own directory.
func TestMavenProfile_InheritedProfileModulesStayWithTheParent(t *testing.T) {
	dir, m2 := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>root</artifactId><version>1.0.0</version><packaging>pom</packaging>
<profiles><profile><id>p</id><activation><jdk>11</jdk></activation>
<modules><module>child</module></modules>
<dependencies><dependency><groupId>org.p</groupId><artifactId>p</artifactId><version>1.0</version></dependency></dependencies></profile></profiles></project>`)
	writeFile(t, filepath.Join(dir, "child", "pom.xml"), `<project>
<parent><groupId>com.example</groupId><artifactId>root</artifactId><version>1.0.0</version></parent>
<artifactId>child</artifactId></project>`)
	writeCachePOM(t, m2, "org.p", "p", "1.0", `<project><groupId>org.p</groupId><artifactId>p</artifactId><version>1.0</version></project>`)
	raw := resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil)
	if len(raw.Partiality.Scoped) == 0 {
		t.Fatalf("want a profile_activation reason; got %+v", raw.Partiality)
	}
	for _, s := range raw.Partiality.Scoped {
		if s.Targets == nil {
			t.Errorf("the profile's only module is in the reactor, so its reason is bounded; got %+v", s)
		}
	}
}

// The pipeline declares these TargetEnv keys on its own side (pipeline/inventory.go), so they are
// pinned here by their literal text: a rename on one side only goes red.
func TestTargetEnvKeys_MatchThePipeline(t *testing.T) {
	s := selectionOf(map[string]string{"maven.profiles": "release,!docs"})
	if s.explicit("release") != explicitOn || s.explicit("docs") != explicitOff {
		t.Errorf(`"maven.profiles" not read as the selection: release %v, docs %v`, s.explicit("release"), s.explicit("docs"))
	}
	if got := evalJDK("[11,)", map[string]string{"java.version": "17"}[targetEnvJavaVersion]); got != triTrue {
		t.Errorf(`"java.version" not read as the Java version: evalJDK = %v`, got)
	}
}

// R3-B2: a build started in a nested reactor reads that reactor's .mvn/maven.config, not the
// scan root's. Here it selects p, which moves base to 2.0. That file isn't parsed, so its
// presence (or a .mvn that can't be searched) withholds; a nested .mvn without one doesn't.
func TestMavenProfile_NestedReactorMavenConfig(t *testing.T) {
	for _, tt := range []struct {
		name     string
		setup    func(t *testing.T, sub string)
		deep     bool // the module's POM sits one directory below sub
		withheld bool
	}{
		{"a nested maven.config selecting the profile", func(t *testing.T, sub string) {
			writeFile(t, filepath.Join(sub, ".mvn", "maven.config"), "-Pp\n")
		}, false, true},
		{"a nested maven.config naming no profile", func(t *testing.T, sub string) {
			writeFile(t, filepath.Join(sub, ".mvn", "maven.config"), "-T 1C\n")
		}, false, true},
		{"a maven.config between the root and a deeper module", func(t *testing.T, sub string) {
			writeFile(t, filepath.Join(sub, ".mvn", "maven.config"), "-Pp\n")
		}, true, true},
		{"a nested .mvn that can't be searched", func(t *testing.T, sub string) {
			if os.Geteuid() == 0 {
				t.Skip("root ignores directory permissions")
			}
			mvn := filepath.Join(sub, ".mvn")
			if err := os.MkdirAll(mvn, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(mvn, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(mvn, 0o755) })
		}, false, true},
		{"control, no nested maven.config", func(t *testing.T, sub string) {}, false, false},
		{"control, no maven.config above a deeper module", func(t *testing.T, sub string) {}, true, false},
		{"control, a nested .mvn with only jvm.config", func(t *testing.T, sub string) {
			writeFile(t, filepath.Join(sub, ".mvn", "jvm.config"), "-Xmx1g\n")
		}, false, false},
		{"control, a nested .mvn that is a file", func(t *testing.T, sub string) {
			writeFile(t, filepath.Join(sub, ".mvn"), "")
		}, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir, m2 := t.TempDir(), t.TempDir()
			writeFile(t, filepath.Join(dir, "pom.xml"), `<project><groupId>com.example</groupId><artifactId>app</artifactId><version>1</version></project>`)
			sub := filepath.Join(dir, "sub")
			modDir := sub
			if tt.deep {
				modDir = filepath.Join(sub, "inner")
			}
			writeFile(t, filepath.Join(modDir, "pom.xml"), `<project><groupId>com.example</groupId><artifactId>sub</artifactId><version>1</version>
<dependencies><dependency><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></dependency></dependencies>
<profiles><profile><id>p</id>
<dependencies><dependency><groupId>org.base</groupId><artifactId>base</artifactId><version>2.0</version></dependency></dependencies>
</profile></profiles></project>`)
			for _, v := range []string{"1.0", "2.0"} {
				writeCachePOM(t, m2, "org.base", "base", v, `<project><groupId>org.base</groupId><artifactId>base</artifactId><version>`+v+`</version></project>`)
			}
			tt.setup(t, sub)
			inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), stated(",", "")))
			withheld := !inv.Partiality.Complete && hasStr(inv.Partiality.Reasons, reasonProfileActivation)
			if withheld != tt.withheld {
				t.Errorf("withheld = %v, want %v; got %+v", withheld, tt.withheld, inv.Partiality)
			}
			if !tt.withheld && findNode(t, inv, "pkg:maven/org.base/base@1.0") == nil {
				t.Error("control: base must resolve at 1.0")
			}
		})
	}
}
