package javaanalysis

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func TestEvalJDK(t *testing.T) {
	tests := []struct {
		spec, version string
		want          tri
	}{
		{"11", "", triUnknown},
		{"11", "abc", triUnknown},
		{"!11", "openjdk", triUnknown},
		{"11", "11.0.24", triTrue},
		{"11", "11.0.24+8", triTrue},
		{"11", "17.0.1", triFalse},
		{"1.8", "1.8.0_382", triTrue},
		{"1.8", "11", triFalse},
		{"!1.8", "11.0.2", triTrue},
		{"!1.8", "1.8.0_382", triFalse},
		{"!11.0.2", "11", triUnknown},
		{"11.0", "11", triUnknown},
		{"[11,)", "11.0.2", triTrue},
		{"[11,)", "1.8.0_382", triFalse},
		{"[11,)", "17", triTrue},
		{"(11,)", "11.0.0", triFalse},
		{"(11,)", "11.0.1", triTrue},
		{"(,1.8]", "1.8.0", triTrue},
		{"(,1.8]", "1.8.0_382", triTrue},
		{"(,1.8]", "1.8.1", triFalse},
		{"(,1.8]", "11", triFalse},
		{"[1.8,11)", "9.0.4", triTrue},
		{"[1.8,11)", "11.0.0", triFalse},
		{"[11.0.5,12)", "11", triUnknown},
		{"[17.0.5,)", "17.0", triUnknown},
		{"[11,12)", "11", triTrue},
		{"[11", "11.0.2", triTrue},
		{"[11", "1.8.0", triFalse},
		{"[a,b)", "11", triUnknown},
		{"[1,2,3]", "1", triUnknown},
		// JDK 8 and earlier report java.version as 1.N.0_U, so a stated "8" is "1.8".
		{"1.8", "8", triTrue},
		{"!1.8", "8", triFalse},
		{"8", "8", triFalse},
		{"1.8", "8.0.382", triTrue},
		{"1.8.0", "8", triUnknown},
		{"[1.8,)", "8", triTrue},
		{"[1.8,11)", "8", triTrue},
		{"[9,)", "8", triFalse},
		{"!1.8", "11", triTrue},
		{"11", "11.0.2", triTrue},
	}
	for _, tt := range tests {
		if got := evalJDK(tt.spec, tt.version); got != tt.want {
			t.Errorf("evalJDK(%q, %q) = %d, want %d", tt.spec, tt.version, got, tt.want)
		}
	}
}

func TestEvalProperty(t *testing.T) {
	env := map[string]string{"release": "true", "java.version": "11", "empty": "", "maven.profiles": "a"}
	tests := []struct {
		name, value string
		want        tri
	}{
		{"release", "", triTrue},
		{"release", "true", triTrue},
		{"release", "false", triFalse},
		{"release", "!false", triTrue},
		{"release", "!true", triFalse},
		{"!release", "", triFalse},
		{"!skip", "", triUnknown},
		{"skip", "", triUnknown},
		{"skip", "!x", triUnknown},
		{"empty", "", triFalse},
		{"java.version", "11", triUnknown},
		{"maven.profiles", "", triUnknown},
		{"java.vendor", "", triUnknown},
		{"!os.name", "", triUnknown},
		{"env.CI", "true", triUnknown},
		{"!empty", "", triTrue},
		{"user.home", "!x", triUnknown},
		{"!", "", triFalse},
	}
	for _, tt := range tests {
		if got := evalProperty(tt.name, tt.value, env); got != tt.want {
			t.Errorf("evalProperty(%q, %q) = %d, want %d", tt.name, tt.value, got, tt.want)
		}
	}
}

// A <property> condition on java.version compares against the stated version in the form Maven's
// JVM reports it. A stated version with fewer than three components stands for every version it
// prefixes, so it can't decide equality with one of them.
func TestEvalProperty_JavaVersion(t *testing.T) {
	tests := []struct {
		stated, value string
		want          tri
	}{
		{"17.0.2", "17.0.2", triTrue},
		{"17.0.2+8", "17.0.2", triTrue},
		{"17", "17.0.2", triUnknown},
		{"17", "17", triUnknown},
		{"17", "!17.0.2", triUnknown},
		{"17.0.2", "17", triFalse},
		{"17", "11.0.2", triFalse},
		{"8", "1.8.0_382", triUnknown},
		{"1.8.0_382", "1.8.0_382", triTrue},
		{"8.0.382", "1.8.0_382", triTrue},
		{"openjdk", "17", triUnknown},
	}
	for _, tt := range tests {
		if got := evalProperty(targetEnvJavaVersion, tt.value, map[string]string{targetEnvJavaVersion: tt.stated}); got != tt.want {
			t.Errorf("evalProperty(java.version, %q) against stated %q = %d, want %d", tt.value, tt.stated, got, tt.want)
		}
	}
}

func TestEvalProfiles_ActiveByDefault(t *testing.T) {
	def := mvnProfile{ID: "def", Activation: mvnActivation{ActiveByDefault: true}}
	jdk := mvnProfile{ID: "jdk", Activation: mvnActivation{JDK: "11"}}
	none := mvnProfile{ID: "none"}
	tests := []struct {
		name    string
		version string
		want    []tri
	}{
		{"other profile undecided", "", []tri{triUnknown, triUnknown, triFalse}},
		{"other profile inactive", "17", []tri{triTrue, triFalse, triFalse}},
		{"other profile active", "11.0.2", []tri{triFalse, triTrue, triFalse}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := activationEnv{targetEnv: map[string]string{targetEnvJavaVersion: tt.version}, selection: selectionOf(map[string]string{targetEnvMavenProfiles: ","})}
			if tt.version == "" {
				env.targetEnv = nil
			}
			if got := evalProfiles([]mvnProfile{def, jdk, none}, env); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("evalProfiles = %v, want %v", got, tt.want)
			}
		})
	}
}

// A profile whose own condition holds is active whether or not it is also activeByDefault.
func TestEvalProfiles_ActiveByDefaultWithAConditionThatHolds(t *testing.T) {
	both := mvnProfile{ID: "both", Activation: mvnActivation{ActiveByDefault: true, JDK: "11"}}
	env := activationEnv{targetEnv: map[string]string{targetEnvJavaVersion: "11.0.2"}, selection: selectionOf(map[string]string{targetEnvMavenProfiles: ","})}
	if got := evalProfiles([]mvnProfile{both}, env); !reflect.DeepEqual(got, []tri{triTrue}) {
		t.Errorf("evalProfiles = %v, want [%d]", got, triTrue)
	}
}

func TestEvalConditions_AndAndUnknownElements(t *testing.T) {
	env := activationEnv{targetEnv: map[string]string{targetEnvJavaVersion: "11.0.2", "release": "true"}}
	tests := []struct {
		name string
		a    mvnActivation
		want tri
	}{
		{"all true", mvnActivation{JDK: "11", PropName: "release"}, triTrue},
		{"one false", mvnActivation{JDK: "17", PropName: "release"}, triFalse},
		{"os undecided", mvnActivation{OS: true}, triUnknown},
		{"os undecided and false", mvnActivation{OS: true, JDK: "17"}, triFalse},
		{"unknown element", mvnActivation{Other: true, JDK: "11"}, triUnknown},
		{"file undecided", mvnActivation{FileExists: "pom.xml"}, triUnknown},
		{"missing file undecided", mvnActivation{FileMissing: "absent"}, triUnknown},
		{"file undecided and false", mvnActivation{FileExists: "pom.xml", JDK: "17"}, triFalse},
		{"no condition", mvnActivation{}, triFalse},
	}
	for _, tt := range tests {
		if got := evalConditions(tt.a, env); got != tt.want {
			t.Errorf("%s: evalConditions = %d, want %d", tt.name, got, tt.want)
		}
	}
}

// profileFixture is a module depending on org.base:base:1.0 whose only profile adds
// org.p:p:1.0; org.p:p:1.0 depends on org.q:q:2.0. All are cached unless dropQ.
func profileFixture(t *testing.T, activation string, dropQ bool) (dir, m2 string) {
	t.Helper()
	dir, m2 = t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></dependency></dependencies>
<profiles><profile><id>p</id><activation>`+activation+`</activation>
<dependencies><dependency><groupId>org.p</groupId><artifactId>p</artifactId><version>1.0</version></dependency></dependencies>
</profile></profiles></project>`)
	writeCachePOM(t, m2, "org.base", "base", "1.0", `<project><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></project>`)
	writeCachePOM(t, m2, "org.p", "p", "1.0", `<project><groupId>org.p</groupId><artifactId>p</artifactId><version>1.0</version>
<dependencies><dependency><groupId>org.q</groupId><artifactId>q</artifactId><version>2.0</version></dependency></dependencies></project>`)
	if !dropQ {
		writeCachePOM(t, m2, "org.q", "q", "2.0", `<project><groupId>org.q</groupId><artifactId>q</artifactId><version>2.0</version></project>`)
	}
	return dir, m2
}

func TestMavenProfile_JDKWithoutVersionIsScopedAndMirrored(t *testing.T) {
	dir, m2 := profileFixture(t, `<jdk>11</jdk>`, false)
	raw := resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil)
	inv := toJSON(t, raw)
	if findNode(t, inv, "pkg:maven/org.p/p@1.0") != nil {
		t.Fatal("an undecided profile must not be applied")
	}
	if !hasStr(inv.Partiality.Reasons, reasonProfileActivation) {
		t.Errorf("profile_activation must be listed run-wide; got %+v", inv.Partiality)
	}
	want := []plugin.ScopedReason{{
		Reason:  reasonProfileActivation,
		Package: "",
		Path:    "com.example:app:1.0.0 profile p",
		Targets: []string{"", "pkg:maven/org.base/base", "pkg:maven/org.p/p", "pkg:maven/org.q/q"},
	}}
	if !reflect.DeepEqual(raw.Partiality.Scoped, want) {
		t.Errorf("Scoped = %+v, want %+v", raw.Partiality.Scoped, want)
	}
}

func TestMavenProfile_UncachedClosureIsUnbounded(t *testing.T) {
	dir, m2 := profileFixture(t, `<jdk>11</jdk>`, true)
	raw := resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil)
	if len(raw.Partiality.Scoped) != 1 {
		t.Fatalf("want one scoped reason, got %+v", raw.Partiality.Scoped)
	}
	if got := raw.Partiality.Scoped[0].Targets; got != nil {
		t.Errorf("a closure through an uncached POM is no bound; want nil Targets, got %v", got)
	}
}

func TestMavenProfile_ProvidedJavaVersionDecides(t *testing.T) {
	tests := []struct {
		version string
		applied bool
	}{
		{"11.0.24", true},
		{"11", true},
		{"17.0.1", false},
		{"1.8.0_382", false},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			dir, m2 := profileFixture(t, `<jdk>11</jdk>`, false)
			raw := resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), stated(",", tt.version))
			inv := toJSON(t, raw)
			if got := findNode(t, inv, "pkg:maven/org.p/p@1.0") != nil; got != tt.applied {
				t.Errorf("profile applied = %v, want %v", got, tt.applied)
			}
			if !inv.Partiality.Complete || len(raw.Partiality.Scoped) != 0 {
				t.Errorf("a decided profile costs no reason; got %+v scoped %+v", inv.Partiality, raw.Partiality.Scoped)
			}
		})
	}
}

func TestMavenProfile_OSFamilyIsUndecided(t *testing.T) {
	dir, m2 := profileFixture(t, `<os><family>unix</family></os>`, false)
	inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), map[string]string{targetEnvJavaVersion: "11"}))
	if findNode(t, inv, "pkg:maven/org.p/p@1.0") != nil {
		t.Error("an <os> profile must not be applied")
	}
	if !hasStr(inv.Partiality.Reasons, reasonProfileActivation) {
		t.Errorf("an <os> profile that adds a dependency must be disclosed; got %+v", inv.Partiality)
	}
}

func TestMavenProfile_PropertyActivationNeedsAStatedValue(t *testing.T) {
	tests := []struct {
		name      string
		env       map[string]string
		applied   bool
		disclosed bool
	}{
		{"not stated", stated(",", "11"), false, true},
		{"stated set", map[string]string{targetEnvMavenProfiles: ",", "skipP": "true"}, false, false},
		{"stated empty", map[string]string{targetEnvMavenProfiles: ",", "skipP": ""}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, m2 := profileFixture(t, `<property><name>!skipP</name></property>`, false)
			inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), tt.env))
			if got := findNode(t, inv, "pkg:maven/org.p/p@1.0") != nil; got != tt.applied {
				t.Errorf("profile applied = %v, want %v", got, tt.applied)
			}
			if got := hasStr(inv.Partiality.Reasons, reasonProfileActivation); got != tt.disclosed {
				t.Errorf("profile_activation listed = %v, want %v; got %+v", got, tt.disclosed, inv.Partiality)
			}
		})
	}
}

func TestMavenProfile_NonContributingProfileCostsNothing(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></dependency></dependencies>
<profiles><profile><id>p</id><activation><jdk>11</jdk></activation></profile></profiles></project>`)
	m2 := t.TempDir()
	writeCachePOM(t, m2, "org.base", "base", "1.0", `<project><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></project>`)
	inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil))
	if !inv.Partiality.Complete {
		t.Errorf("a profile that changes nothing costs no reason; got %+v", inv.Partiality)
	}
}

// A property an undecided profile sets can reach plugin configuration or a repository URL, which
// this reader doesn't follow, so the profile is unbounded whatever else it holds.
func TestMavenProfile_PropertiesMakeAProfileUnbounded(t *testing.T) {
	for _, tt := range []struct{ name, body, profile string }{
		{"a property nothing reads", "", `<properties><unused.prop>x</unused.prop></properties>`},
		{"a property a body plugin reads", `<properties><skip.unpack>true</skip.unpack></properties>
<build><plugins><plugin><artifactId>maven-dependency-plugin</artifactId><configuration><skip>${skip.unpack}</skip></configuration></plugin></plugins></build>`,
			`<properties><skip.unpack>false</skip.unpack></properties>`},
		{"a property a body repository reads", `<properties><repo.url>https://good.example/</repo.url></properties>
<repositories><repository><id>r</id><url>${repo.url}</url></repository></repositories>`,
			`<properties><repo.url>https://other.example/</repo.url></properties>`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir, m2 := t.TempDir(), t.TempDir()
			writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></dependency></dependencies>`+tt.body+`
<profiles><profile><id>p</id><activation><jdk>11</jdk></activation>`+tt.profile+`</profile></profiles></project>`)
			writeCachePOM(t, m2, "org.base", "base", "1.0", `<project><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></project>`)
			raw := resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), stated(",", ""))
			if raw.Partiality.Complete || len(raw.Partiality.Scoped) != 1 || raw.Partiality.Scoped[0].Targets != nil {
				t.Errorf("want one unbounded profile_activation; got %+v", raw.Partiality)
			}
		})
	}
}

// What an undecided profile's imported BOM manages is read from the cache: a transitive it
// manages to another version is unresolved. A BOM that can't be read unresolves every transitive.
func TestMavenProfile_ProfileBOMReversionsTransitives(t *testing.T) {
	for _, tt := range []struct {
		name, bom   string // bom: the version org.bom:bom:1.0 manages org.t:t to, "" when uncached
		tUnresolved bool
		bounded     bool
	}{
		{"manages the transitive to another version", "2.0", true, true},
		{"manages the transitive to its version", "1.0", false, true},
		{"isn't cached", "", true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir, m2 := t.TempDir(), t.TempDir()
			writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></dependency></dependencies>
<profiles><profile><id>p</id><activation><jdk>11</jdk></activation>
<dependencyManagement><dependencies><dependency><groupId>org.bom</groupId><artifactId>bom</artifactId><version>1.0</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement></profile></profiles></project>`)
			writeCachePOM(t, m2, "org.base", "base", "1.0", `<project><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version>
<dependencies><dependency><groupId>org.t</groupId><artifactId>t</artifactId><version>1.0</version></dependency></dependencies></project>`)
			writeCachePOM(t, m2, "org.t", "t", "1.0", `<project><groupId>org.t</groupId><artifactId>t</artifactId><version>1.0</version></project>`)
			writeCachePOM(t, m2, "org.t", "t", "2.0", `<project><groupId>org.t</groupId><artifactId>t</artifactId><version>2.0</version></project>`)
			if tt.bom != "" {
				writeCachePOM(t, m2, "org.bom", "bom", "1.0", `<project><groupId>org.bom</groupId><artifactId>bom</artifactId><version>1.0</version><packaging>pom</packaging>
<dependencyManagement><dependencies><dependency><groupId>org.t</groupId><artifactId>t</artifactId><version>`+tt.bom+`</version></dependency></dependencies></dependencyManagement></project>`)
			}
			raw := resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), stated(",", ""))
			inv := toJSON(t, raw)
			if got := findNode(t, inv, "pkg:maven/org.t/t@1.0") == nil; got != tt.tUnresolved {
				t.Errorf("org.t:t unresolved = %v, want %v", got, tt.tUnresolved)
			}
			if findNode(t, inv, "pkg:maven/org.base/base@1.0") == nil {
				t.Error("a direct dependency with its own version stays resolved")
			}
			if len(raw.Partiality.Scoped) != 1 || (raw.Partiality.Scoped[0].Targets != nil) != tt.bounded {
				t.Errorf("want one profile_activation, bounded = %v; got %+v", tt.bounded, raw.Partiality)
			}
		})
	}
}

// A cached POM's undecided profile whose versions are unknown unresolves that POM's dependencies.
func TestMavenProfile_DependencyPOMUnboundedProfileUnresolvesItsDependencies(t *testing.T) {
	dir, m2 := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version></dependency></dependencies></project>`)
	writeCachePOM(t, m2, "org.top", "top", "1.0", `<project><groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version>
<dependencies><dependency><groupId>org.x</groupId><artifactId>x</artifactId><version>3.0</version></dependency></dependencies>
<profiles><profile><id>tp</id><activation><jdk>1.8</jdk></activation>
<dependencyManagement><dependencies><dependency><groupId>org.bom</groupId><artifactId>bom</artifactId><version>1.0</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement></profile></profiles></project>`)
	writeCachePOM(t, m2, "org.x", "x", "3.0", `<project><groupId>org.x</groupId><artifactId>x</artifactId><version>3.0</version></project>`)
	inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil))
	if findNode(t, inv, "pkg:maven/org.x/x@3.0") != nil {
		t.Error("x must not keep the version it has without the profile")
	}
	if findNode(t, inv, "pkg:maven/org.top/top@1.0") == nil {
		t.Error("the module's direct dependency stays resolved")
	}
}

// depProfileFixture is a module depending on org.top:top:1.0, whose cached POM has one
// profile with the given activation and dependency.
func depProfileFixture(t *testing.T, activation, dep string) (dir, m2 string) {
	t.Helper()
	dir, m2 = t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version></dependency></dependencies></project>`)
	writeCachePOM(t, m2, "org.top", "top", "1.0", `<project><groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version>
<profiles><profile><id>tp</id><activation>`+activation+`</activation>
<dependencies>`+dep+`</dependencies></profile></profiles></project>`)
	writeCachePOM(t, m2, "org.x", "x", "3.0", `<project><groupId>org.x</groupId><artifactId>x</artifactId><version>3.0</version></project>`)
	return dir, m2
}

func TestMavenProfile_DependencyPOMNonPropagatingDepCostsNothing(t *testing.T) {
	for name, dep := range map[string]string{
		"system":   `<dependency><groupId>com.sun</groupId><artifactId>tools</artifactId><version>1.8</version><scope>system</scope><systemPath>${java.home}/../lib/tools.jar</systemPath></dependency>`,
		"optional": `<dependency><groupId>org.x</groupId><artifactId>x</artifactId><version>3.0</version><optional>true</optional></dependency>`,
		"test":     `<dependency><groupId>org.x</groupId><artifactId>x</artifactId><version>3.0</version><scope>test</scope></dependency>`,
	} {
		t.Run(name, func(t *testing.T) {
			dir, m2 := depProfileFixture(t, `<jdk>1.8</jdk>`, dep)
			inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil))
			if !inv.Partiality.Complete {
				t.Errorf("a dependency's profile adding a %s dep cannot reach this graph; got %+v", name, inv.Partiality)
			}
		})
	}
}

func TestMavenProfile_DependencyPOMCompileDepIsScopedToThatPackage(t *testing.T) {
	dir, m2 := depProfileFixture(t, `<jdk>1.8</jdk>`, `<dependency><groupId>org.x</groupId><artifactId>x</artifactId><version>3.0</version></dependency>`)
	raw := resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil)
	want := []plugin.ScopedReason{{
		Reason:  reasonProfileActivation,
		Package: "pkg:maven/org.top/top",
		Path:    "org.top:top:1.0 profile tp",
		Targets: []string{"", "pkg:maven/org.top/top", "pkg:maven/org.x/x"},
	}}
	if !reflect.DeepEqual(raw.Partiality.Scoped, want) {
		t.Errorf("Scoped = %+v, want %+v", raw.Partiality.Scoped, want)
	}
	if !hasStr(raw.Partiality.Reasons, reasonProfileActivation) {
		t.Errorf("profile_activation must be listed run-wide; got %+v", raw.Partiality.Reasons)
	}
}

// A cached POM has no project directory: its <file> conditions must stay undecided rather than
// be checked against the cache directory the POM happens to sit in.
func TestMavenProfile_DependencyPOMFileIsUndecided(t *testing.T) {
	dir, m2 := depProfileFixture(t, `<file><exists>top-1.0.pom</exists></file>`, `<dependency><groupId>org.x</groupId><artifactId>x</artifactId><version>3.0</version></dependency>`)
	inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil))
	if findNode(t, inv, "pkg:maven/org.x/x@3.0") != nil {
		t.Error("a dependency POM's <file> profile must not be applied")
	}
	if !hasStr(inv.Partiality.Reasons, reasonProfileActivation) {
		t.Errorf("want profile_activation; got %+v", inv.Partiality)
	}
}

func TestMavenProfile_PropertyReferencedVersionIsTouched(t *testing.T) {
	dir, m2 := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<properties><x.version>3.0</x.version><ver.alias>${x.version}</ver.alias></properties>
<dependencies><dependency><groupId>org.x</groupId><artifactId>x</artifactId><version>${ver.alias}</version></dependency></dependencies>
<profiles><profile><id>p</id><activation><jdk>11</jdk></activation>
<properties><x.version>4.0</x.version></properties></profile></profiles></project>`)
	writeCachePOM(t, m2, "org.x", "x", "3.0", `<project><groupId>org.x</groupId><artifactId>x</artifactId><version>3.0</version></project>`)
	writeCachePOM(t, m2, "org.x", "x", "4.0", `<project><groupId>org.x</groupId><artifactId>x</artifactId><version>4.0</version>
<dependencies><dependency><groupId>org.y</groupId><artifactId>y</artifactId><version>1.0</version></dependency></dependencies></project>`)
	writeCachePOM(t, m2, "org.y", "y", "1.0", `<project><groupId>org.y</groupId><artifactId>y</artifactId><version>1.0</version></project>`)

	raw := resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil)
	if len(raw.Partiality.Scoped) != 1 {
		t.Fatalf("a profile re-versioning a dependency through a property must be disclosed; got %+v", raw.Partiality)
	}
	if got := raw.Partiality.Scoped[0].Targets; got != nil {
		t.Errorf("Targets = %v, want nil: a profile setting a property is unbounded", got)
	}

	undecided := toJSON(t, raw)
	if findNode(t, undecided, "pkg:maven/org.x/x@3.0") != nil {
		t.Error("x must not take the version it has without the undecided profile")
	}
	if n := findNode(t, undecided, "pkg:maven/org.x/x@"); n == nil || n.Version != "" || !hasStr(n.Partiality.Reasons, reasonProfileActivation) {
		t.Errorf("x must be emitted unresolved for profile_activation; got %+v", n)
	}

	decided := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), stated(",", "11.0.2")))
	if findNode(t, decided, "pkg:maven/org.x/x@4.0") == nil || !decided.Partiality.Complete {
		t.Errorf("with java 11 the profile applies and re-versions x to 4.0; got %+v", decided)
	}
}

func TestMavenProfile_UnboundedTouches(t *testing.T) {
	tests := []struct {
		name, profile string
		extra         func(t *testing.T, m2 string)
	}{
		{
			name:    "non-literal version",
			profile: `<dependencies><dependency><groupId>org.z</groupId><artifactId>z</artifactId><version>${nope}</version></dependency></dependencies>`,
		},
		{
			name:    "import BOM not cached",
			profile: `<dependencyManagement><dependencies><dependency><groupId>org.bom</groupId><artifactId>bom</artifactId><version>1.0</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement>`,
		},
		{
			name:    "import BOM with an undecided profile of its own",
			profile: `<dependencyManagement><dependencies><dependency><groupId>org.bom</groupId><artifactId>bom</artifactId><version>1.0</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement>`,
			extra: func(t *testing.T, m2 string) {
				writeCachePOM(t, m2, "org.bom", "bom", "1.0", `<project><groupId>org.bom</groupId><artifactId>bom</artifactId><version>1.0</version><packaging>pom</packaging>
<profiles><profile><id>bp</id><activation><jdk>11</jdk></activation>
<dependencyManagement><dependencies><dependency><groupId>org.q</groupId><artifactId>q</artifactId><version>${nope}</version></dependency></dependencies></dependencyManagement></profile></profiles></project>`)
			},
		},
		{
			name:    "closure through an unbounded profile",
			profile: `<dependencies><dependency><groupId>org.n</groupId><artifactId>n</artifactId><version>1.0</version></dependency></dependencies>`,
			extra: func(t *testing.T, m2 string) {
				writeCachePOM(t, m2, "org.n", "n", "1.0", `<project><groupId>org.n</groupId><artifactId>n</artifactId><version>1.0</version>
<profiles><profile><id>np</id><activation><jdk>11</jdk></activation>
<dependencies><dependency><groupId>org.z</groupId><artifactId>z</artifactId><version>${nope}</version></dependency></dependencies></profile></profiles></project>`)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, m2 := t.TempDir(), t.TempDir()
			writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></dependency></dependencies>
<profiles><profile><id>p</id><activation><jdk>11</jdk></activation>`+tt.profile+`</profile></profiles></project>`)
			writeCachePOM(t, m2, "org.base", "base", "1.0", `<project><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></project>`)
			if tt.extra != nil {
				tt.extra(t, m2)
			}
			raw := resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil)
			if !hasStr(raw.Partiality.Reasons, reasonProfileActivation) {
				t.Fatalf("want profile_activation run-wide; got %+v", raw.Partiality.Reasons)
			}
			var mine *plugin.ScopedReason
			for i := range raw.Partiality.Scoped {
				if raw.Partiality.Scoped[i].Package == "" {
					mine = &raw.Partiality.Scoped[i]
				}
			}
			if mine == nil || mine.Targets != nil {
				t.Errorf("want the module's scoped reason with nil Targets; got %+v", raw.Partiality.Scoped)
			}
		})
	}
}

// A test-scoped dependency's POM sits outside first-party reach, so nothing else voids the bound of
// its profile. A profile that adds one literal dependency beside one it can't resolve has no
// bound at all: the literal one alone would be a partial closure.
func TestMavenProfile_PartlyResolvableProfileIsUnbounded(t *testing.T) {
	dir, m2 := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></dependency>
<dependency><groupId>org.t</groupId><artifactId>t</artifactId><version>1.0</version><scope>test</scope></dependency></dependencies></project>`)
	writeCachePOM(t, m2, "org.base", "base", "1.0", `<project><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></project>`)
	writeCachePOM(t, m2, "org.t", "t", "1.0", `<project><groupId>org.t</groupId><artifactId>t</artifactId><version>1.0</version>
<profiles><profile><id>tp</id><activation><jdk>11</jdk></activation>
<dependencies><dependency><groupId>org.y</groupId><artifactId>y</artifactId><version>1.0</version></dependency>
<dependency><groupId>org.z</groupId><artifactId>z</artifactId><version>${nope}</version></dependency></dependencies></profile></profiles></project>`)
	writeCachePOM(t, m2, "org.y", "y", "1.0", `<project><groupId>org.y</groupId><artifactId>y</artifactId><version>1.0</version></project>`)

	raw := resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil)
	var mine *plugin.ScopedReason
	for i := range raw.Partiality.Scoped {
		if raw.Partiality.Scoped[i].Package == "pkg:maven/org.t/t" {
			mine = &raw.Partiality.Scoped[i]
		}
	}
	if mine == nil || mine.Targets != nil {
		t.Errorf("want org.t's scoped reason with nil Targets; got %+v", raw.Partiality.Scoped)
	}
}

// The module's dependencyManagement pins a transitive dependency's version, so the closure walks
// the managed version's POM too: org.x 2.0 brings org.w, which the declared org.x 1.0 doesn't.
func TestMavenProfile_ClosureFollowsRootManagedVersions(t *testing.T) {
	dir, m2 := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencyManagement><dependencies><dependency><groupId>org.x</groupId><artifactId>x</artifactId><version>2.0</version></dependency></dependencies></dependencyManagement>
<dependencies><dependency><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></dependency></dependencies>
<profiles><profile><id>p</id><activation><jdk>11</jdk></activation>
<dependencies><dependency><groupId>org.p</groupId><artifactId>p</artifactId><version>1.0</version></dependency></dependencies>
</profile></profiles></project>`)
	writeCachePOM(t, m2, "org.base", "base", "1.0", `<project><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version>
<dependencies><dependency><groupId>org.x</groupId><artifactId>x</artifactId><version>1.0</version></dependency></dependencies></project>`)
	writeCachePOM(t, m2, "org.x", "x", "1.0", `<project><groupId>org.x</groupId><artifactId>x</artifactId><version>1.0</version></project>`)
	writeCachePOM(t, m2, "org.x", "x", "2.0", `<project><groupId>org.x</groupId><artifactId>x</artifactId><version>2.0</version>
<dependencies><dependency><groupId>org.w</groupId><artifactId>w</artifactId><version>1.0</version></dependency></dependencies></project>`)
	writeCachePOM(t, m2, "org.w", "w", "1.0", `<project><groupId>org.w</groupId><artifactId>w</artifactId><version>1.0</version></project>`)
	writeCachePOM(t, m2, "org.p", "p", "1.0", `<project><groupId>org.p</groupId><artifactId>p</artifactId><version>1.0</version></project>`)

	raw := resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil)
	var mine *plugin.ScopedReason
	for i := range raw.Partiality.Scoped {
		if raw.Partiality.Scoped[i].Path == "com.example:app:1.0.0 profile p" {
			mine = &raw.Partiality.Scoped[i]
		}
	}
	if mine == nil {
		t.Fatalf("want a scoped reason for profile p; got %+v", raw.Partiality.Scoped)
	}
	want := []string{"", "pkg:maven/org.base/base", "pkg:maven/org.p/p", "pkg:maven/org.w/w", "pkg:maven/org.x/x"}
	if !reflect.DeepEqual(mine.Targets, want) {
		t.Errorf("Targets = %q, want %q", mine.Targets, want)
	}
}

// A test-scoped dependency's profile is bounded by its own closure, outside first-party reach, and
// that closure follows the module's managed versions too: org.v 2.0 brings org.u.
func TestMavenProfile_TestScopedProfileFollowsRootManagedVersions(t *testing.T) {
	dir, m2 := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencyManagement><dependencies><dependency><groupId>org.v</groupId><artifactId>v</artifactId><version>2.0</version></dependency></dependencies></dependencyManagement>
<dependencies><dependency><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></dependency>
<dependency><groupId>org.t</groupId><artifactId>t</artifactId><version>1.0</version><scope>test</scope></dependency></dependencies></project>`)
	writeCachePOM(t, m2, "org.base", "base", "1.0", `<project><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></project>`)
	writeCachePOM(t, m2, "org.t", "t", "1.0", `<project><groupId>org.t</groupId><artifactId>t</artifactId><version>1.0</version>
<profiles><profile><id>tp</id><activation><jdk>11</jdk></activation>
<dependencies><dependency><groupId>org.y</groupId><artifactId>y</artifactId><version>1.0</version></dependency></dependencies></profile></profiles></project>`)
	writeCachePOM(t, m2, "org.y", "y", "1.0", `<project><groupId>org.y</groupId><artifactId>y</artifactId><version>1.0</version>
<dependencies><dependency><groupId>org.v</groupId><artifactId>v</artifactId><version>1.0</version></dependency></dependencies></project>`)
	writeCachePOM(t, m2, "org.v", "v", "1.0", `<project><groupId>org.v</groupId><artifactId>v</artifactId><version>1.0</version></project>`)
	writeCachePOM(t, m2, "org.v", "v", "2.0", `<project><groupId>org.v</groupId><artifactId>v</artifactId><version>2.0</version>
<dependencies><dependency><groupId>org.u</groupId><artifactId>u</artifactId><version>1.0</version></dependency></dependencies></project>`)
	writeCachePOM(t, m2, "org.u", "u", "1.0", `<project><groupId>org.u</groupId><artifactId>u</artifactId><version>1.0</version></project>`)

	raw := resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil)
	var mine *plugin.ScopedReason
	for i := range raw.Partiality.Scoped {
		if raw.Partiality.Scoped[i].Package == "pkg:maven/org.t/t" {
			mine = &raw.Partiality.Scoped[i]
		}
	}
	if mine == nil {
		t.Fatalf("want a scoped reason for org.t's profile; got %+v", raw.Partiality.Scoped)
	}
	want := []string{"", "pkg:maven/org.base/base", "pkg:maven/org.u/u", "pkg:maven/org.v/v", "pkg:maven/org.y/y"}
	if !reflect.DeepEqual(mine.Targets, want) {
		t.Errorf("Targets = %q, want %q", mine.Targets, want)
	}
}

// A dependency's profile that supplies the managed version of a versionless dependency its
// body declares can change the consumer's graph. Without that profile x has no version, so
// first-party code's closure cannot be read and the reason has no bound.
func TestMavenProfile_DependencyPOMManagedVersionIsTouched(t *testing.T) {
	dir, m2 := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version></dependency></dependencies></project>`)
	writeCachePOM(t, m2, "org.top", "top", "1.0", `<project><groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version>
<dependencies><dependency><groupId>org.x</groupId><artifactId>x</artifactId></dependency></dependencies>
<profiles><profile><id>tp</id><activation><jdk>11</jdk></activation>
<dependencyManagement><dependencies><dependency><groupId>org.x</groupId><artifactId>x</artifactId><version>3.0</version></dependency></dependencies></dependencyManagement>
</profile></profiles></project>`)
	writeCachePOM(t, m2, "org.x", "x", "3.0", `<project><groupId>org.x</groupId><artifactId>x</artifactId><version>3.0</version></project>`)

	raw := resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil)
	want := []plugin.ScopedReason{{
		Reason:  reasonProfileActivation,
		Package: "pkg:maven/org.top/top",
		Path:    "org.top:top:1.0 profile tp",
		Targets: nil,
	}}
	if !reflect.DeepEqual(raw.Partiality.Scoped, want) {
		t.Errorf("Scoped = %+v, want %+v", raw.Partiality.Scoped, want)
	}
}

// A profile-added JAR can call back into first-party code, so a bound also needs first-party
// code's own closure; when that closure cannot be read, no bound holds.
func TestMavenProfile_FirstPartyClosureBound(t *testing.T) {
	tests := []struct {
		name     string
		deps     string // the module's own <dependencies>
		profiles string // extra profiles beside p, which adds org.p:p:1.0
		cacheDep bool   // whether org.base:base:1.0 is cached
		want     []string
	}{
		{
			name:     "first-party closure known",
			deps:     `<dependency><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></dependency>`,
			cacheDep: true,
			want:     []string{"", "pkg:maven/org.base/base", "pkg:maven/org.p/p"},
		},
		{
			name: "test-scoped dependency is not first-party reach",
			deps: `<dependency><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></dependency>` +
				`<dependency><groupId>org.t</groupId><artifactId>t</artifactId><version>1.0</version><scope>test</scope></dependency>`,
			cacheDep: true,
			want:     []string{"", "pkg:maven/org.base/base", "pkg:maven/org.p/p"},
		},
		{
			name: "first-party dependency uncached",
			deps: `<dependency><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></dependency>`,
			want: nil,
		},
		{
			name:     "another module profile is unbounded",
			deps:     `<dependency><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></dependency>`,
			profiles: `<profile><id>u</id><activation><jdk>11</jdk></activation><dependencies><dependency><groupId>org.z</groupId><artifactId>z</artifactId><version>${nope}</version></dependency></dependencies></profile>`,
			cacheDep: true,
			want:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, m2 := t.TempDir(), t.TempDir()
			writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies>`+tt.deps+`</dependencies>
<profiles><profile><id>p</id><activation><jdk>11</jdk></activation>
<dependencies><dependency><groupId>org.p</groupId><artifactId>p</artifactId><version>1.0</version></dependency></dependencies>
</profile>`+tt.profiles+`</profiles></project>`)
			writeCachePOM(t, m2, "org.p", "p", "1.0", `<project><groupId>org.p</groupId><artifactId>p</artifactId><version>1.0</version></project>`)
			if tt.cacheDep {
				writeCachePOM(t, m2, "org.base", "base", "1.0", `<project><groupId>org.base</groupId><artifactId>base</artifactId><version>1.0</version></project>`)
			}
			raw := resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil)
			var mine *plugin.ScopedReason
			for i := range raw.Partiality.Scoped {
				if raw.Partiality.Scoped[i].Path == "com.example:app:1.0.0 profile p" {
					mine = &raw.Partiality.Scoped[i]
				}
			}
			if mine == nil {
				t.Fatalf("want a scoped reason for profile p; got %+v", raw.Partiality.Scoped)
			}
			if !reflect.DeepEqual(mine.Targets, tt.want) {
				t.Errorf("Targets = %q, want %q", mine.Targets, tt.want)
			}
			if !hasStr(raw.Partiality.Reasons, reasonProfileActivation) {
				t.Errorf("profile_activation must be listed run-wide; got %+v", raw.Partiality.Reasons)
			}
		})
	}
}
