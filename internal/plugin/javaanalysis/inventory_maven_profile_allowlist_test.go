package javaanalysis

import (
	"path/filepath"
	"testing"
)

// Every .mvn reader is an allow-list: an option, file or token it doesn't model withholds, as
// does a property definition that an activation condition reads. The fixture's profile is
// activated by <jdk>11</jdk> or by the given activation, under a stated java.version 11.0.2.
func TestMavenProfile_MvnDirAllowList(t *testing.T) {
	for _, tt := range []struct {
		name, file, content, activation string
		disclosed                       bool
	}{
		// java.version and a property an activation reads, set by the build itself.
		{"-D sets java.version", "maven.config", "-Djava.version=1.8\n", "", true},
		{"-D k=v sets java.version", "maven.config", "-D java.version=1.8\n", "", true},
		{"--define= sets java.version", "maven.config", "--define=java.version=1.8\n", "", true},
		{"-D sets the activation property", "maven.config", "-Drelease=true\n", `<property><name>release</name></property>`, true},
		{"-D sets the negated activation property", "maven.config", "-Drelease\n", `<property><name>!release</name></property>`, true},
		{"jvm.config sets java.version", "jvm.config", "-Xmx1g -Djava.version=1.8\n", "", true},
		// Settings and an alternate POM: what they select isn't read.
		{"-s", "maven.config", "-s .mvn/settings.xml\n", "", true},
		{"-s attached", "maven.config", "-s.mvn/settings.xml\n", "", true},
		{"--settings=", "maven.config", "--settings=.mvn/settings.xml\n", "", true},
		{"-gs", "maven.config", "-gs .mvn/settings.xml\n", "", true},
		{"--global-settings=", "maven.config", "--global-settings=.mvn/settings.xml\n", "", true},
		{"-f", "maven.config", "-f other/pom.xml\n", "", true},
		// Inversion: options and tokens on no list withhold.
		{"an option on no list", "maven.config", "--some-future-option\n", "", true},
		{"-llr, which -l's prefix would take", "maven.config", "-llr\n", "", true},
		{"an abbreviated long option", "maven.config", "--thr=4\n", "", true},
		{"two options on one line", "maven.config", "-B -q\n", "", true},
		{"a value option without its value", "maven.config", "-T\n", "", true},
		{"a value option with two values", "maven.config", "-T 1C 2\n", "", true},
		{"a define with a trailing token", "maven.config", "-Dfoo=a b\n", "", true},
		{"a separate define with a trailing token", "maven.config", "-D foo=1 bar\n", "", true},
		{"a value option after = with a trailing token", "maven.config", "--threads=4 x\n", "", true},
		{"an attached value option with a trailing token", "maven.config", "-T4 x\n", "", true},
		{"an interpolated define", "maven.config", "-D${name}=1\n", "", true},
		{"maven.ext.class.path", "maven.config", "-Dmaven.ext.class.path=ext.jar\n", "", true},
		{"an option on a comment line", "maven.config", "# -Djava.version=1.8\n", "", true},
		{"a bare goal", "maven.config", "verify\n", "", true},
		{"a JVM option on no list", "jvm.config", "-javaagent:agent.jar\n", "", true},
		{"a JVM argument file", "jvm.config", "@args\n", "", true},
		{"a trailing comment in jvm.config", "jvm.config", "-Xmx1g # -Djava.version=1.8\n", "", true},
		{"a # inside a jvm.config token", "jvm.config", "-Djava.version#=1.8\n", "", true},
		{"jvm.config defines maven.ext.class.path", "jvm.config", "-Dmaven.ext.class.path=ext.jar\n", "", true},
		{"a JVM module option without its value on the line", "jvm.config", "--add-opens\n", "", true},
		{"a JVM option prefix without a value", "jvm.config", "-Xmx\n", "", true},
		{"a JVM options file", "jvm.config", "-XX:VMOptionsFile=.mvn/vm.options\n", "", true},
		{"a HotSpot flags file", "jvm.config", "-XX:Flags=.hotspotrc\n", "", true},
		{"a -XX: flag on no list", "jvm.config", "-XX:+UseG1GC -XX:CompileCommandFile=cc.txt\n", "", true},
		{"a listed -XX: flag with a value that isn't a size", "jvm.config", "-XX:MaxMetaspaceSize=a.txt\n", "", true},
		{"a core extension", "extensions.xml", "<extensions/>\n", "", true},
		{"unknown leaves property conditions undecided", "maven.config", "--some-future-option\n", `<property><name>release</name></property>`, true},
		// Controls: options on the lists decide nothing away.
		{"batch mode", "maven.config", "-B\n--batch-mode\n", "", false},
		{"threads, each form", "maven.config", "-T 1C\n-T4\n-T=4\n--threads=4\n--threads 4\n", "", false},
		{"log file and projects", "maven.config", "-l build.log\n-pl app\n--projects=app\n", "", false},
		{"defines no condition reads", "maven.config", "-DskipTests\n-Dfoo=bar\n-D other=1\n--define=x=y\n", "", false},
		{"a comment", "maven.config", "# faster builds\n\n", "", false},
		{"inert JVM options", "jvm.config", "-Xmx2g -Xss4m -XX:+UseG1GC\n--add-opens java.base/java.lang=ALL-UNNAMED\n-Dfile.encoding=UTF-8\n# memory\n", "", false},
		{"listed -XX: flags", "jvm.config", "-XX:-TieredCompilation -XX:TieredStopAtLevel=1 -XX:MaxMetaspaceSize=512m -XX:MaxRAMPercentage=75.0\n", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			activation := tt.activation
			if activation == "" {
				activation = `<jdk>11</jdk>`
			}
			dir, m2 := profileFixture(t, activation, false)
			writeFile(t, filepath.Join(dir, ".mvn", tt.file), tt.content)
			env := stated(",", "11.0.2")
			env["release"] = "false"
			inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), env))
			if got := hasStr(inv.Partiality.Reasons, reasonProfileActivation); got != tt.disclosed {
				t.Errorf("profile_activation listed = %v, want %v; got %+v", got, tt.disclosed, inv.Partiality)
			}
		})
	}
}

// A nested .mvn's jvm.config is read like the top one's; its extensions.xml withholds.
func TestMavenProfile_NestedMvnAllowList(t *testing.T) {
	for _, tt := range []struct {
		name, file, content string
		disclosed           bool
	}{
		{"nested jvm.config sets java.version", "jvm.config", "-Djava.version=1.8\n", true},
		{"nested jvm.config with an unlisted option", "jvm.config", "-javaagent:a.jar\n", true},
		{"nested extensions.xml", "extensions.xml", "<extensions/>\n", true},
		{"control, nested jvm.config with inert options", "jvm.config", "-Xmx1g\n", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir, m2 := profileFixture(t, `<jdk>11</jdk>`, false)
			writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>root</artifactId><version>1.0.0</version><packaging>pom</packaging>
<modules><module>app</module></modules></project>`)
			writeFile(t, filepath.Join(dir, "app", "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></dependency></dependencies>
<profiles><profile><id>p</id><activation><jdk>11</jdk></activation>
<dependencies><dependency><groupId>org.p</groupId><artifactId>p</artifactId><version>1.0</version></dependency></dependencies>
</profile></profiles></project>`)
			writeFile(t, filepath.Join(dir, "app", ".mvn", tt.file), tt.content)
			inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), stated(",", "11.0.2")))
			if got := hasStr(inv.Partiality.Reasons, reasonProfileActivation); got != tt.disclosed {
				t.Errorf("profile_activation listed = %v, want %v; got %+v", got, tt.disclosed, inv.Partiality)
			}
		})
	}
}

// Maven counts an activation condition when its element is present, empty or not. Beside a true
// <jdk>, each of these leaves the profile undecided rather than applied. The property a is stated
// as 1, so a condition on it would decide.
func TestMavenProfile_ActivationPresenceAllowList(t *testing.T) {
	for _, tt := range []struct {
		name, activation string
		disclosed        bool
	}{
		{"empty os", `<jdk>11</jdk><os/>`, true},
		{"empty os, open and closed", `<jdk>11</jdk><os></os>`, true},
		{"empty file", `<jdk>11</jdk><file/>`, true},
		{"file with an empty exists", `<jdk>11</jdk><file><exists></exists></file>`, true},
		{"empty property", `<jdk>11</jdk><property/>`, true},
		{"property with an empty name", `<jdk>11</jdk><property><name></name></property>`, true},
		{"property named !", `<jdk>11</jdk><property><name>!</name></property>`, true},
		{"property with two names", `<jdk>11</jdk><property><name>a</name><name>b</name></property>`, true},
		{"property with two values", `<jdk>11</jdk><property><name>a</name><value>1</value><value>2</value></property>`, true},
		{"property with an unknown child", `<jdk>11</jdk><property><name>a</name><regex>x</regex></property>`, true},
		{"empty jdk", `<jdk/>`, true},
		{"blank jdk", `<jdk>  </jdk>`, true},
		{"interpolated jdk", `<jdk>${jdk.spec}</jdk>`, true},
		{"repeated jdk, the first false", `<jdk>17</jdk><jdk>11</jdk>`, true},
		{"interpolated property beside a false jdk", `<jdk>17</jdk><property><name>${p}</name></property>`, true},
		{"interpolated jdk beside a false property", `<jdk>${jdk.spec}</jdk><property><name>a</name><value>2</value></property>`, true},
		// Inversion: an activation child on no list.
		{"an activation element on no list", `<jdk>11</jdk><packaging>jar</packaging>`, true},
		{"control, jdk alone", `<jdk>11</jdk>`, false},
		{"control, a stated property beside the jdk", `<jdk>11</jdk><property><name>a</name><value>1</value></property>`, false},
		{"control, undecided element beside a false one", `<jdk>17</jdk><os/>`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir, m2 := profileFixture(t, tt.activation, false)
			env := stated(",", "11.0.2")
			env["a"] = "1"
			inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), env))
			if got := hasStr(inv.Partiality.Reasons, reasonProfileActivation); got != tt.disclosed {
				t.Errorf("profile_activation listed = %v, want %v; got %+v", got, tt.disclosed, inv.Partiality)
			}
		})
	}

	t.Run("a second activation", func(t *testing.T) {
		dir, m2 := profileFixture(t, `<jdk>17</jdk></activation><activation><jdk>11</jdk>`, false)
		inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), stated(",", "11.0.2")))
		if !hasStr(inv.Partiality.Reasons, reasonProfileActivation) {
			t.Errorf("want profile_activation; got %+v", inv.Partiality)
		}
	})
}

// An undecided profile's child elements must each be on profileElements' allow-list for its POM.
// The profile here adds nothing to the graph, so only the element itself can cost a reason.
func TestMavenProfile_ProfileElementAllowList(t *testing.T) {
	for _, tt := range []struct {
		name, element string
		cached        bool
		disclosed     bool
	}{
		{"an element on no list, dependency POM", `<parent><groupId>g</groupId><artifactId>a</artifactId><version>1</version></parent>`, true, true},
		{"an element on no list, reactor POM", `<futureElement/>`, false, true},
		{"distributionManagement, dependency POM", `<distributionManagement><relocation><groupId>org.moved</groupId></relocation></distributionManagement>`, true, true},
		{"control, distributionManagement, reactor POM", `<distributionManagement><site><id>s</id></site></distributionManagement>`, false, false},
		{"control, reporting, dependency POM", `<reporting><plugins/></reporting>`, true, false},
		{"control, build, dependency POM", `<build><plugins><plugin><artifactId>maven-dependency-plugin</artifactId></plugin></plugins></build>`, true, false},
		{"control, modules, dependency POM", `<modules><module>m</module></modules>`, true, false},
		{"control, empty dependencies, dependency POM", `<dependencies/>`, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir, m2 := t.TempDir(), t.TempDir()
			profile := `<profiles><profile><id>tp</id><activation><jdk>1.8</jdk></activation>` + tt.element + `</profile></profiles>`
			rootProfile, topProfile := "", ""
			if tt.cached {
				topProfile = profile
			} else {
				rootProfile = profile
			}
			writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version></dependency></dependencies>`+rootProfile+`</project>`)
			writeCachePOM(t, m2, "org.top", "top", "1.0", `<project><groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version>
<dependencies><dependency><groupId>org.x</groupId><artifactId>x</artifactId><version>3.0</version></dependency></dependencies>`+topProfile+`</project>`)
			writeCachePOM(t, m2, "org.x", "x", "3.0", `<project><groupId>org.x</groupId><artifactId>x</artifactId><version>3.0</version></project>`)
			inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), stated(",", "")))
			if got := hasStr(inv.Partiality.Reasons, reasonProfileActivation); got != tt.disclosed {
				t.Errorf("profile_activation listed = %v, want %v; got %+v", got, tt.disclosed, inv.Partiality)
			}
		})
	}
}

// An unknown .mvn leaves <jdk> and <property> conditions undecided in dependency POMs too, which
// no -P reaches: the unknown option may define what they read.
func TestMavenProfile_MvnUnknownReachesDependencyPOMs(t *testing.T) {
	for _, tt := range []struct {
		name, activation, config string
		complete                 bool
	}{
		{"jdk", `<jdk>1.8</jdk>`, "--some-future-option\n", false},
		{"property", `<property><name>release</name></property>`, "--some-future-option\n", false},
		{"control, jdk under inert options", `<jdk>1.8</jdk>`, "-B\n", true},
		{"control, property under inert options", `<property><name>release</name></property>`, "-B\n", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir, m2 := depProfileFixture(t, tt.activation, `<dependency><groupId>org.x</groupId><artifactId>x</artifactId><version>3.0</version></dependency>`)
			writeFile(t, filepath.Join(dir, ".mvn", "maven.config"), tt.config)
			env := stated(",", "11.0.2")
			env["release"] = "false"
			inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), env))
			if inv.Partiality.Complete != tt.complete {
				t.Errorf("complete = %v, want %v; got %+v", inv.Partiality.Complete, tt.complete, inv.Partiality)
			}
		})
	}
}

// A dependency's undecided profile managing a version costs nothing only when nothing in the chain
// declares that coordinate: below the consumer only the consumer's own management applies, but the
// dependency's own declarations take it.
func TestMavenProfile_DependencyPOMProfileManagementAllowList(t *testing.T) {
	const mgmt = `<dependencyManagement><dependencies><dependency><groupId>org.x</groupId><artifactId>x</artifactId><version>3.0</version></dependency></dependencies></dependencyManagement>`
	for _, tt := range []struct {
		name, body string
		complete   bool
	}{
		{"declared in the body", `<dependencies><dependency><groupId>org.x</groupId><artifactId>x</artifactId><version>2.0</version></dependency></dependencies>`, false},
		{"declared nowhere", ``, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir, m2 := depProfileFixture(t, `<jdk>1.8</jdk>`, ``)
			writeCachePOM(t, m2, "org.top", "top", "1.0", `<project><groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version>
`+tt.body+`<profiles><profile><id>tp</id><activation><jdk>1.8</jdk></activation>`+mgmt+`</profile></profiles></project>`)
			writeCachePOM(t, m2, "org.x", "x", "2.0", `<project><groupId>org.x</groupId><artifactId>x</artifactId><version>2.0</version></project>`)
			inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil))
			if inv.Partiality.Complete != tt.complete {
				t.Errorf("complete = %v, want %v; got %+v", inv.Partiality.Complete, tt.complete, inv.Partiality)
			}
		})
	}
}
