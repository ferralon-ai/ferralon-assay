package javaanalysis

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"regexp"
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
//   - Maven: a <mainClass>, <start-class>, <Main-Class> or <Start-Class> element in a
//     project's pom.xml (jar/shade/assembly/exec/spring-boot plugin configuration, manifest
//     entries, the Boot property), with ${...} resolved from that POM's own <properties>;
//     packaging jar (or none);
//   - Gradle: mainClass = / mainClass.set(...) / mainClassName = and a 'Main-Class' manifest
//     attribute in the project's build.gradle(.kts), with no war plugin;
//   - a manifest the project ships or built (src/main/resources/META-INF/MANIFEST.MF, the
//     class output's META-INF/MANIFEST.MF, a JAR under target/ or build/libs/): Main-Class
//     naming a first-party class, or Spring Boot's JarLauncher/WarLauncher with a Start-Class.
//
// Withheld, each with its reason: no named entry (launch_entry_unnamed); a named entry that
// is not a first-party main, a dependency launcher such as Vert.x's (Main-Class outside the
// build, a Main-Verticle attribute), an unresolved ${...}, or packaging other than jar
// (launch_entry_unmapped); war packaging or a built .war (war_packaging); and a first-party
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

// findLaunchEntry reads the launch entry of the projects whose class output fp read.
// lookup returns a loaded class (first-party or dependency) by binary name.
func findLaunchEntry(fp *firstPartyBytecode, lookup func(string) (*classfile.Class, bool)) launchEntry {
	r := &entryReader{reasons: map[string]bool{}, named: map[string]bool{}}
	for _, dir := range fp.projectDirs() {
		r.maven(filepath.Join(dir, "pom.xml"))
		for _, n := range []string{"build.gradle", "build.gradle.kts"} {
			r.gradle(filepath.Join(dir, n))
		}
		r.manifestFile(filepath.Join(dir, "src", "main", "resources", "META-INF", "MANIFEST.MF"))
		for _, out := range []string{"target", filepath.Join("build", "libs")} {
			r.archives(filepath.Join(dir, out))
		}
	}
	for _, root := range fp.roots {
		r.manifestFile(filepath.Join(root, "META-INF", "MANIFEST.MF"))
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
	sort.Strings(e.mains)
	if len(r.named) == 0 {
		r.reasons[reasonLaunchEntryUnnamed] = true
	}
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

func declaresMain(c *classfile.Class) bool {
	for _, m := range c.Methods {
		if m.Ref.Name == "main" && m.Ref.Descriptor == mainDescriptor && !m.Abstract && !m.Native {
			return true
		}
	}
	return false
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
	reasons map[string]bool
	named   map[string]bool
}

var (
	xmlComment      = regexp.MustCompile(`(?s)<!--.*?-->`)
	pomEntryElement = regexp.MustCompile(`<(mainClass|start-class|Main-Class|Start-Class|Main-Verticle)>([^<]*)</`)
	pomPropertyRef  = regexp.MustCompile(`\$\{([^}]*)\}`)
)

func (r *entryReader) name(v string) {
	v = strings.TrimSpace(v)
	if v == "" || !javaBinaryNamePattern.MatchString(v) {
		r.reasons[reasonLaunchEntryUnmapped] = true
		return
	}
	r.named[v] = true
}

var javaBinaryNamePattern = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*$`)

func (r *entryReader) maven(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			r.reasons[reasonLaunchEntryUnmapped] = true
		}
		return
	}
	pom, ok := parseMavenPOM(path)
	if !ok {
		r.reasons[reasonLaunchEntryUnmapped] = true
		return
	}
	switch pom.Packaging {
	case "", "jar":
	case "war":
		r.reasons[reasonWarPackaging] = true
	default:
		r.reasons[reasonLaunchEntryUnmapped] = true
	}
	text := xmlComment.ReplaceAllString(string(data), "")
	for _, m := range pomEntryElement.FindAllStringSubmatch(text, -1) {
		if m[1] == "Main-Verticle" {
			r.reasons[reasonLaunchEntryUnmapped] = true
			continue
		}
		v := pomPropertyRef.ReplaceAllStringFunc(m[2], func(ref string) string {
			if val, ok := pom.Properties[ref[2:len(ref)-1]]; ok && !strings.Contains(val, "${") {
				return val
			}
			return ref
		})
		r.name(v)
	}
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
			r.reasons[reasonWarPackaging] = true
		case strings.HasSuffix(lower, ".jar"):
			r.archiveManifest(filepath.Join(dir, d.Name()))
		}
	}
}

func (r *entryReader) archiveManifest(path string) {
	zr, err := zip.OpenReader(path)
	if err != nil {
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
			r.reasons[reasonLaunchEntryUnmapped] = true
			return
		}
		data, err := io.ReadAll(io.LimitReader(rc, launchTextLimit))
		rc.Close()
		if err != nil {
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
