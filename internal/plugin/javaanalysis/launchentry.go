package javaanalysis

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/depreach"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// launchentry.go — what the build says starts the program, for the bytecode search's
// Searched licence. An empty search from a main says nothing about code the runtime starts
// some other way, so a main licenses Searched only when the build names it as the launch
// entry, and only when no other entry shape is in the build.
//
// This is an allow-list. A main is licensed only when it is named by one of the forms
// below and resolves to a first-party class declaring main(String[]); every other launch
// shape withholds Searched with a named reason, because an entry the reader does not know is
// not an entry that is absent:
//   - Maven: a <mainClass>, <start-class>, <Main-Class> or <Start-Class> element that applies
//     to the module over its effective POM (effectivepom.go: the module's pom.xml and every
//     parent it inherits from, a parent's <pluginManagement> entry counting for a plugin the
//     module applies, start-class for the Boot plugin), with ${...} resolved through the chain's
//     merged properties; packaging jar (or none);
//   - Gradle: mainClass = / mainClass.set(...) / mainClassName = and a 'Main-Class' manifest
//     attribute in the project's build.gradle(.kts), with no war plugin;
//   - a manifest the project ships or built (src/main/resources/META-INF/MANIFEST.MF, the
//     class output's META-INF/MANIFEST.MF, a JAR under target/ or build/libs/): Main-Class
//     naming a first-party class, or Spring Boot's JarLauncher/WarLauncher with a Start-Class;
//   - with none of the above, the main spring-boot-maven-plugin finds itself (bootMain,
//     BootMainClass).
//
// Withheld, each with its reason: no named entry and no main the Boot plugin finds
// (launch_entry_unnamed); a named entry that is not a first-party main, a dependency launcher such as Vert.x's (Main-Class outside the
// build, a Main-Verticle attribute), an unresolved ${...}, or packaging other than jar
// (launch_entry_unmapped); a ${...} entry whose property a <profile> sets, in the POM or any
// POM it inherits from, or whose parent chain is not all read (launch_entry_profile_property);
// a ${...} entry whose property a -D<key> or --define <key> sets anywhere in the checkout the
// launch-option scan reads (a CI workflow's mvn command, .mvn/maven.config, a script), or with a
// file in that scan that cannot be read (launch_entry_cli_property); a <profile> in that chain that names a launch class itself (launch_entry_profile_plugin); war
// packaging or a built .war (war_packaging); and a first-party
// class a container calls back without any call the search can see (container_callback):
// one whose ancestors include a servlet Filter, listener, GenericServlet, Servlet,
// ServletContainerInitializer, JMS MessageListener, MessageDrivenBean or WebSocket Endpoint,
// or that carries @WebFilter, @WebListener, @WebServlet, @MessageDriven, @Startup or
// @ServerEndpoint, under javax. or jakarta. HttpServlet subclasses are the one container
// shape the ingress recognizers map, so the ancestor walk stops there. A first-party class
// whose ancestry reaches a class neither loaded nor in the JDK cannot be classified and
// withholds the same way.

const (
	reasonLaunchEntryUnnamed  = plugin.PartialReasonRelationshipUnexpressed + ":launch_entry_unnamed"
	reasonLaunchEntryUnmapped = plugin.PartialReasonRelationshipUnexpressed + ":launch_entry_unmapped"
	reasonWarPackaging        = plugin.PartialReasonRelationshipUnexpressed + ":war_packaging"
	reasonContainerCallback   = plugin.PartialReasonRelationshipUnexpressed + ":container_callback"

	reasonLaunchEntryProfileProperty = plugin.PartialReasonRelationshipUnexpressed + ":launch_entry_profile_property"
	reasonLaunchEntryProfilePlugin   = plugin.PartialReasonRelationshipUnexpressed + ":launch_entry_profile_plugin"
	reasonLaunchEntryCLIProperty     = plugin.PartialReasonRelationshipUnexpressed + ":launch_entry_cli_property"
)

// launchEntry is the launch mains the build names and the reasons its entry shape withholds
// Searched.
type launchEntry struct {
	mains   []string // binary names, '/'-separated, sorted
	reasons []string // sorted, distinct
}

// licenses reports whether an empty search from the named mains may be Searched.
func (e launchEntry) licenses() bool { return len(e.mains) > 0 && len(e.reasons) == 0 }

// containerCallbackTypes are the container-invoked supertypes, without the javax./jakarta.
// root. servlet/http/HttpServlet is absent: the ingress recognizers map its overrides.
var containerCallbackTypes = []string{
	"servlet/Servlet", "servlet/GenericServlet", "servlet/Filter", "servlet/ServletContainerInitializer",
	"servlet/ServletContextListener", "servlet/ServletContextAttributeListener",
	"servlet/ServletRequestListener", "servlet/ServletRequestAttributeListener",
	"servlet/AsyncListener", "servlet/ReadListener", "servlet/WriteListener",
	"servlet/http/HttpSessionListener", "servlet/http/HttpSessionAttributeListener",
	"servlet/http/HttpSessionIdListener", "servlet/http/HttpSessionActivationListener",
	"servlet/http/HttpSessionBindingListener", "servlet/http/HttpUpgradeHandler",
	"jms/MessageListener", "ejb/MessageDrivenBean",
	"websocket/Endpoint", "websocket/server/ServerApplicationConfig",
}

// containerCallbackAnnotations are the class annotations that register a class with a
// container, without the javax./jakarta. root.
var containerCallbackAnnotations = []string{
	"servlet/annotation/WebFilter", "servlet/annotation/WebListener", "servlet/annotation/WebServlet",
	"ejb/MessageDriven", "ejb/Startup", "websocket/server/ServerEndpoint",
}

// mappedContainerTypes end the ancestor walk: a container shape the recognizers map.
var mappedContainerTypes = map[string]bool{
	"javax/servlet/http/HttpServlet":   true,
	"jakarta/servlet/http/HttpServlet": true,
}

func withRoots(names []string, prefix, suffix string) map[string]bool {
	out := map[string]bool{}
	for _, root := range []string{"javax/", "jakarta/"} {
		for _, n := range names {
			out[prefix+root+n+suffix] = true
		}
	}
	return out
}

var (
	callbackTypeSet       = withRoots(containerCallbackTypes, "", "")
	callbackAnnotationSet = withRoots(containerCallbackAnnotations, "L", ";")
)

// springBootLaunchers are the Main-Class values that start the manifest's Start-Class.
var springBootLaunchers = map[string]bool{
	"org.springframework.boot.loader.JarLauncher":        true,
	"org.springframework.boot.loader.WarLauncher":        true,
	"org.springframework.boot.loader.launch.JarLauncher": true,
	"org.springframework.boot.loader.launch.WarLauncher": true,
}

// findLaunchEntry reads the launch entry of the projects whose class output fp read; for a
// reactor unit, of the unit module alone, whose reactor parent POMs may be read from the
// checkout. lookup returns a loaded class (first-party or dependency) by binary name.
func findLaunchEntry(buildDir string, fp *firstPartyBytecode, lookup func(string) (*classfile.Class, bool)) launchEntry {
	r := &entryReader{reasons: map[string]bool{}, named: map[string]bool{}, propKeys: map[string]bool{}, cache: newMavenCache(buildDir)}
	dirs, roots, bootClasses := fp.projectDirs(), fp.roots, fp.classes
	if fp.unit != nil {
		dirs, roots, bootClasses = []string{fp.unit.dir}, fp.unit.roots, fp.unit.classes
		r.checkout = buildDir
	}
	for _, dir := range dirs {
		r.maven(filepath.Join(dir, "pom.xml"))
		for _, n := range []string{"build.gradle", "build.gradle.kts"} {
			r.gradle(filepath.Join(dir, n))
		}
		r.manifestFile(filepath.Join(dir, "src", "main", "resources", "META-INF", "MANIFEST.MF"))
		for _, out := range []string{"target", filepath.Join("build", "libs")} {
			r.archives(filepath.Join(dir, out))
		}
	}
	for _, root := range roots {
		r.manifestFile(filepath.Join(root, "META-INF", "MANIFEST.MF"))
	}
	if r.bootPlugin {
		// A -D for either key overrides the Boot plugin's main, found or configured.
		r.propKeys["start-class"] = true
		r.propKeys["spring-boot.run.main-class"] = true
	}
	if len(r.propKeys) > 0 && checkoutDefines(buildDir, r.propKeys) {
		r.reasons[reasonLaunchEntryCLIProperty] = true
	}

	firstParty := map[string]*classfile.Class{}
	for i := range fp.classes {
		firstParty[fp.classes[i].Name] = &fp.classes[i]
	}
	var e launchEntry
	for n := range r.named {
		bin := strings.ReplaceAll(n, ".", "/")
		c := firstParty[bin]
		if c == nil || !declaresMain(c) {
			r.reasons[reasonLaunchEntryUnmapped] = true
			continue
		}
		e.mains = append(e.mains, bin)
	}
	if len(r.named) == 0 {
		if main, ok := r.bootMain(bootClasses, roots); ok {
			e.mains = append(e.mains, main)
		} else {
			r.reasons[reasonLaunchEntryUnnamed] = true
		}
	}
	sort.Strings(e.mains)
	for i := range fp.classes {
		if containerCallback(&fp.classes[i], lookup) {
			r.reasons[reasonContainerCallback] = true
			break
		}
	}
	for k := range r.reasons {
		e.reasons = append(e.reasons, k)
	}
	sort.Strings(e.reasons)
	return e
}

// launchSignal reports whether the Maven module at dir carries launch evidence of its own, so it
// ships as a program and not only as a library another module loads. The evidence is what
// findLaunchEntry reads for a unit, met at all, whether or not it resolves: the Boot plugin
// applied by its POM or one it inherits; a launch class named in its POM, its source manifest, a
// JAR under its target/ or the manifest of one of its class output roots; war or ear packaging, or
// a built .war; a POM, manifest or built JAR that cannot be read; or a POM chain that may name
// what it does not show: a parent not read, or a profile naming a launch class or plugin.
//
// A module with no code of its own (code false) ships a program only by packaging other modules'
// classes: its evidence is a launch class it names, a launching packaging or archive, or a profile
// naming one. The Boot plugin alone, which finds its main among the module's own classes, is none.
func launchSignal(buildDir, dir string, roots []string, code bool) bool {
	r := &entryReader{reasons: map[string]bool{}, named: map[string]bool{}, propKeys: map[string]bool{}, cache: newMavenCache(buildDir), checkout: buildDir}
	r.maven(filepath.Join(dir, "pom.xml"))
	r.manifestFile(filepath.Join(dir, "src", "main", "resources", "META-INF", "MANIFEST.MF"))
	r.archives(filepath.Join(dir, "target"))
	for _, root := range roots {
		r.manifestFile(filepath.Join(root, "META-INF", "MANIFEST.MF"))
	}
	if !code {
		return r.launched || r.reasons[reasonLaunchEntryProfilePlugin]
	}
	return r.launched || r.bootPlugin || r.bootBlocked || r.reasons[reasonLaunchEntryProfilePlugin]
}

func declaresMain(c *classfile.Class) bool {
	for _, m := range c.Methods {
		if m.Ref.Name == "main" && m.Ref.Descriptor == mainDescriptor && !m.Abstract && !m.Native {
			return true
		}
	}
	return false
}

const springBootApplication = "Lorg/springframework/boot/autoconfigure/SpringBootApplication;"

// bootMain is the main spring-boot-maven-plugin finds when the build names none
// (BootMainClass), licensed only when the project applies the plugin and nothing in the build can
// name a main for it instead (bootBlocked).
//
// This lane reads the Maven plugin only. A Gradle build applying org.springframework.boot with no
// main named keeps launch_entry_unnamed here; the Kotlin lane reads the Gradle plugin.
func (r *entryReader) bootMain(classes []classfile.Class, roots []string) (string, bool) {
	if !r.bootPlugin || r.bootBlocked {
		return "", false
	}
	return BootMainClass(classes, roots)
}

// BootMainClass is the main Spring Boot's MainClassFinder picks from classes, the first-party
// classes read from the class output directories roots. The finder (spring-boot-loader-tools
// MainClassFinder.findSingleMainClass, used by both the Maven plugin and the Gradle plugin's
// resolveMainClassName) takes every class in a class output directory with a public static
// main(String[]), keeps those annotated @SpringBootApplication directly when there are any, and
// fails the build unless one is left. The main is returned only when:
//   - every main candidate sits in one of roots, the one directory the finder reads;
//   - the same single class is left whether a candidate is the finder's public static main or
//     any concrete main(String[]), so the answer does not rest on the access flags alone.
//
// The name is binary, '/'-separated.
func BootMainClass(classes []classfile.Class, roots []string) (string, bool) {
	strict := bootCandidates(classes, isBootMain)
	broad := bootCandidates(classes, declaresMain)
	if len(broad) != 1 || !slices.Equal(strict, broad) {
		return "", false
	}
	var all []string
	for i := range classes {
		if declaresMain(&classes[i]) || isBootMain(&classes[i]) {
			all = append(all, classes[i].Name)
		}
	}
	dirs := 0
	for _, root := range roots {
		for _, n := range all {
			if info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(n)+".class")); err == nil && info.Mode().IsRegular() {
				dirs++
				break
			}
		}
	}
	if dirs != 1 {
		return "", false
	}
	return strict[0], true
}

// MavenBootPlugin reads the POM at path and the parents it inherits from (from the Maven cache
// buildDir's build uses): plugin is whether one applies spring-boot-maven-plugin; blocked is
// whether the build can hand that plugin a main BootMainClass does not see (bootMaven), or the
// POM cannot be read; cliProperty is whether the checkout's launch-option scan sets start-class or
// spring-boot.run.main-class, which override the plugin's main, found or configured.
func MavenBootPlugin(buildDir, path string) (plugin, blocked, cliProperty bool) {
	pom, ok := parseMavenPOM(path)
	if !ok {
		return false, true, false
	}
	r := &entryReader{reasons: map[string]bool{}, named: map[string]bool{}, propKeys: map[string]bool{}, cache: newMavenCache(buildDir)}
	r.bootMaven(r.effective(pom, path))
	if !r.bootPlugin {
		return false, r.bootBlocked, false
	}
	return true, r.bootBlocked, checkoutDefines(buildDir, map[string]bool{"start-class": true, "spring-boot.run.main-class": true})
}

// isBootMain reports whether c declares the main MainClassFinder looks for.
func isBootMain(c *classfile.Class) bool {
	for _, m := range c.Methods {
		if m.Ref.Name == "main" && m.Ref.Descriptor == mainDescriptor && m.Public && m.Static {
			return true
		}
	}
	return false
}

// bootCandidates applies MainClassFinder's selection to the classes isMain accepts: the
// @SpringBootApplication ones when there are any, otherwise all of them.
func bootCandidates(classes []classfile.Class, isMain func(*classfile.Class) bool) []string {
	var all, annotated []string
	for i := range classes {
		c := &classes[i]
		if !isMain(c) {
			continue
		}
		all = append(all, c.Name)
		for _, a := range c.Annotations {
			if a.Type == springBootApplication {
				annotated = append(annotated, c.Name)
				break
			}
		}
	}
	if len(annotated) > 0 {
		return annotated
	}
	return all
}

// containerCallback reports whether a container may call c back with no call the search sees:
// c carries a registration annotation, or an ancestor is a container callback type or cannot
// be read.
func containerCallback(c *classfile.Class, lookup func(string) (*classfile.Class, bool)) bool {
	for _, a := range c.Annotations {
		if callbackAnnotationSet[a.Type] {
			return true
		}
	}
	seen := map[string]bool{}
	stack := append([]string{c.Super}, c.Interfaces...)
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n == "" || seen[n] || mappedContainerTypes[n] {
			continue
		}
		seen[n] = true
		if callbackTypeSet[n] {
			return true
		}
		ac, ok := lookup(n)
		if !ok {
			if depreach.IsPlatformClass(n) {
				continue
			}
			return true
		}
		stack = append(stack, ac.Super)
		stack = append(stack, ac.Interfaces...)
	}
	return false
}

type entryReader struct {
	reasons  map[string]bool
	named    map[string]bool
	propKeys map[string]bool // POM properties a launch entry resolved through
	cache    *mavenCache
	// checkout is the build dir a parent POM may be read from at its relativePath, "" for none.
	checkout string

	bootPlugin  bool // a POM in the chain applies spring-boot-maven-plugin
	bootBlocked bool // the build may hand the Boot plugin a main bootMain does not see
	// launched is set when the reader meets a launch-naming form, resolved or not, an
	// unreadable POM, manifest or built JAR, war or ear packaging, or a built .war (launchSignal).
	launched bool
}

var (
	xmlComment      = regexp.MustCompile(`(?s)<!--.*?-->`)
	pomEntryElement = regexp.MustCompile(`<(mainClass|start-class|Main-Class|Start-Class|Main-Verticle)>([^<]*)</`)
	pomPropertyRef  = regexp.MustCompile(`\$\{([^}]*)\}`)
	// pomEntryWord is any element that can name a launch class, whatever its form (a
	// manifestFile's Main-Class is the jar's, which the Boot plugin takes over finding one);
	// bootStartClassRef is the one form spring-boot-starter-parent uses, which leaves the main
	// to the Boot plugin while start-class is unset.
	pomEntryWord      = regexp.MustCompile(`<(mainClass|start-class|Main-Class|Start-Class|Main-Verticle|manifestFile)\b`)
	bootStartClassRef = regexp.MustCompile(`<mainClass>\$\{(start-class|spring-boot\.run\.main-class)\}</mainClass>`)
)

func (r *entryReader) name(v string) {
	r.launched = true
	v = strings.TrimSpace(v)
	if v == "" || !javaBinaryNamePattern.MatchString(v) {
		r.reasons[reasonLaunchEntryUnmapped] = true
		return
	}
	r.named[v] = true
}

var javaBinaryNamePattern = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*$`)

func (r *entryReader) maven(path string) {
	_, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			r.launched = true
			r.reasons[reasonLaunchEntryUnmapped] = true
		}
		return
	}
	pom, ok := parseMavenPOM(path)
	if !ok {
		r.launched = true
		r.reasons[reasonLaunchEntryUnmapped] = true
		return
	}
	// Every packaging but a plain jar or an aggregator ships the module as something of its own
	// (war, ear, an OSGi bundle, a plugin, or a value only a property resolves).
	if pom.Packaging != "" && pom.Packaging != "jar" && pom.Packaging != "pom" {
		r.launched = true
	}
	switch pom.Packaging {
	case "", "jar":
	case "war":
		r.reasons[reasonWarPackaging] = true
	default:
		r.reasons[reasonLaunchEntryUnmapped] = true
	}
	eff := r.effective(pom, path)
	if eff.profileLaunch {
		r.reasons[reasonLaunchEntryProfilePlugin] = true
	}
	if eff.unread {
		r.launched = true
		r.reasons[reasonLaunchEntryUnmapped] = true
	}
	// A parent not read may name a launch class for any plugin the module runs; an aggregator
	// runs none that packages a program.
	if !eff.complete && pom.Packaging != "pom" {
		r.launched = true
	}
	r.bootMaven(eff)
	for _, e := range eff.entries {
		r.entry(eff, e)
	}
	// The Boot plugin's main defaults to start-class; without the plugin the property launches
	// only through an entry that names it, read above.
	if v, ok := eff.startClass(); ok && r.bootPlugin {
		r.entry(eff, pomEntry{elem: "start-class", value: v})
	}
}

// entry records one launch-naming element of eff, its ${...} resolved against eff's merged
// properties.
func (r *entryReader) entry(eff *pomEffective, e pomEntry) {
	if e.elem == "Main-Verticle" {
		r.launched = true
		r.reasons[reasonLaunchEntryUnmapped] = true
		return
	}
	v := eff.resolve(e.value, func(key string) {
		if !eff.complete || eff.profileProps[key] {
			r.reasons[reasonLaunchEntryProfileProperty] = true
		}
		r.propKeys[key] = true
	})
	if m := pomWholeRef.FindStringSubmatch(v); m != nil && bootMainKeys[m[1]] {
		return
	}
	r.name(v)
}

// bootMainKeys are the properties spring-boot-starter-parent wires to the Boot plugin's main: a
// value that resolves to nothing but one of them, unset, leaves the main to the plugin.
var bootMainKeys = map[string]bool{"start-class": true, "spring-boot.run.main-class": true}

var pomWholeRef = regexp.MustCompile(`^\$\{([^}]*)\}$`)

// bootMaven records whether the module applies spring-boot-maven-plugin, and blocks bootMain when
// the chain is not all read, or when a POM in it names a launch class any way but starter-parent's
// ${start-class} wiring (a <start-class> property is one such way) or points
// spring-boot.run.main-class anywhere but ${start-class}.
func (r *entryReader) bootMaven(eff *pomEffective) {
	r.bootPlugin = r.bootPlugin || eff.applied[bootPluginKey]
	if !eff.complete || eff.unread {
		r.bootBlocked = true
	}
	for _, p := range eff.chain {
		props := []map[string]string{p.Properties}
		for _, pr := range p.Profiles {
			props = append(props, pr.Properties)
		}
		for _, m := range props {
			if v, ok := m["spring-boot.run.main-class"]; ok && strings.TrimSpace(v) != "${start-class}" {
				r.bootBlocked = true
			}
		}
	}
	for _, text := range eff.texts {
		if len(pomEntryWord.FindAllStringIndex(text, -1)) != len(bootStartClassRef.FindAllStringIndex(text, -1)) {
			r.bootBlocked = true
		}
	}
}

// pomChain returns pom (read from path) and the parents it inherits from, nearest first, with
// the file each was read from. complete is false when a parent is not there: its profiles are
// unknown, not absent. A parent comes from the Maven cache; when r reads a reactor unit, first
// from the checkout at its relativePath, as Maven takes it, when that POM's coordinate matches.
func (r *entryReader) pomChain(pom *mvnPOM, path string) ([]*mvnPOM, []string, bool) {
	chain, files := []*mvnPOM{pom}, []string{path}
	seen := map[string]bool{}
	for cur, curFile := pom, path; len(chain) <= 20; {
		p := cur.Parent
		if p.ArtifactID == "" {
			return chain, files, true
		}
		key := gavKey(p.GroupID, p.ArtifactID, p.Version)
		if seen[key] {
			return chain, files, false
		}
		next, file, ok := r.checkoutParent(curFile, p)
		parentFile := file
		if !ok {
			// A cached POM's relativePath points into the repository, never the checkout.
			next, ok = r.cache.get(p.GroupID, p.ArtifactID, p.Version)
			file, parentFile = r.cache.pomFile(p.GroupID, p.ArtifactID, p.Version), ""
		}
		if !ok {
			return chain, files, false
		}
		seen[key] = true
		chain, files = append(chain, next), append(files, file)
		cur, curFile = next, parentFile
	}
	return chain, files, false
}

// checkoutParent reads parent p of the checkout POM at child from the checkout, at p's
// relativePath, ../pom.xml when it names none; a directory names its pom.xml and an empty one
// turns the lookup off. It is found only when r has a checkout, the file lies inside it, and the
// POM there has p's coordinate.
func (r *entryReader) checkoutParent(child string, p mvnParent) (*mvnPOM, string, bool) {
	relPath := "../pom.xml"
	if p.RelativePath != nil {
		relPath = *p.RelativePath
	}
	if r.checkout == "" || relPath == "" || child == "" {
		return nil, "", false
	}
	candidate := filepath.Join(filepath.Dir(child), filepath.FromSlash(relPath))
	if !within(r.checkout, candidate) {
		return nil, "", false
	}
	if info, err := os.Stat(candidate); err == nil && info.IsDir() {
		candidate = filepath.Join(candidate, "pom.xml")
	}
	rel, err := filepath.Rel(r.checkout, candidate)
	if err != nil {
		return nil, "", false
	}
	if _, st := inCache(r.checkout, rel); st != cacheHit {
		return nil, "", false
	}
	pom, ok := parseMavenPOM(candidate)
	if !ok || pom.GroupID != p.GroupID || pom.ArtifactID != p.ArtifactID || pom.Version != p.Version {
		return nil, "", false
	}
	return pom, candidate, true
}

// pomFile returns the cache file mavenCache.get reads g:a:v's POM from, or "" when there is none;
// a cached POM's own path is blank.
func (c *mavenCache) pomFile(g, a, v string) string {
	if c.escaped || !validGAV(g, a, v) {
		return ""
	}
	rel := pomRelPath(g, a, v)
	for _, root := range c.roots {
		path, st := inCache(root, rel)
		if st == cacheEscape {
			break
		}
		if st == cacheHit {
			return path
		}
	}
	return ""
}

var (
	gradleMainClass    = regexp.MustCompile(`(?m)\bmainClass(?:Name)?\s*(?:=|\.set\s*\()\s*["']([^"']*)["']`)
	gradleManifestAttr = regexp.MustCompile(`["'](Main-Class|Start-Class|Main-Verticle)["']\s*(?::|to|,)\s*["']([^"']*)["']`)
	gradleWar          = regexp.MustCompile(`(?m)(\bid\s*\(?\s*["']war["']|apply\s*\(?\s*plugin\s*[:=]\s*["']war["']|^\s*war\s*$)`)
)

func (r *entryReader) gradle(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			r.reasons[reasonLaunchEntryUnmapped] = true
		}
		return
	}
	text := string(data)
	if gradleWar.MatchString(text) {
		r.reasons[reasonWarPackaging] = true
	}
	for _, m := range gradleMainClass.FindAllStringSubmatch(text, -1) {
		r.name(m[1])
	}
	for _, m := range gradleManifestAttr.FindAllStringSubmatch(text, -1) {
		if m[1] == "Main-Verticle" {
			r.reasons[reasonLaunchEntryUnmapped] = true
			continue
		}
		r.name(m[2])
	}
}

func (r *entryReader) manifestFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			r.launched = true
			r.reasons[reasonLaunchEntryUnmapped] = true
		}
		return
	}
	r.manifest(data)
}

// archives reads the manifest of every JAR directly under dir; a WAR there is war packaging.
func (r *entryReader) archives(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, d := range entries {
		lower := strings.ToLower(d.Name())
		switch {
		case d.IsDir():
		case strings.HasSuffix(lower, ".war"):
			r.launched = true
			r.reasons[reasonWarPackaging] = true
		case strings.HasSuffix(lower, ".jar"):
			r.archiveManifest(filepath.Join(dir, d.Name()))
		}
	}
}

func (r *entryReader) archiveManifest(path string) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		r.launched = true
		r.reasons[reasonLaunchEntryUnmapped] = true
		return
	}
	defer zr.Close()
	for _, f := range zr.File {
		if !strings.EqualFold(f.Name, "META-INF/MANIFEST.MF") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			r.launched = true
			r.reasons[reasonLaunchEntryUnmapped] = true
			return
		}
		data, err := io.ReadAll(io.LimitReader(rc, launchTextLimit))
		rc.Close()
		if err != nil {
			r.launched = true
			r.reasons[reasonLaunchEntryUnmapped] = true
			return
		}
		r.manifest(data)
	}
}

// manifest reads Main-Class, Start-Class and Main-Verticle from a MANIFEST.MF.
func (r *entryReader) manifest(data []byte) {
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n ", "")
	attrs := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok {
			attrs[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	if _, ok := attrs["main-verticle"]; ok {
		r.launched = true
		r.reasons[reasonLaunchEntryUnmapped] = true
	}
	main, hasMain := attrs["main-class"]
	start, hasStart := attrs["start-class"]
	switch {
	case hasMain && springBootLaunchers[main]:
		if !hasStart {
			r.reasons[reasonLaunchEntryUnmapped] = true
			return
		}
		r.name(start)
	case hasMain:
		r.name(main)
		if hasStart {
			r.name(start)
		}
	case hasStart:
		r.name(start)
	}
}
