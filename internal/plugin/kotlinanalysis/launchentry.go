package kotlinanalysis

import (
	"archive/zip"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/depreach"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// launchentry.go — what the build says starts the program, for the Searched licence. An
// empty search from a main says nothing about code the runtime starts some other way, so an
// empty search is Searched only when the build names a first-party main as its launch entry
// and no other entry shape is in the build.
//
// This is an allow-list. The named forms are a Gradle start script's main class; a literal
// mainClass = / mainClass.set(...) / mainClassName = or 'Main-Class' attribute in the root
// build.gradle(.kts); a literal <mainClass>, <start-class>, <Main-Class> or <Start-Class> in
// the root pom.xml; and a Main-Class (or Spring Boot's JarLauncher/WarLauncher with a
// Start-Class) in a manifest the project ships or built (src/main/resources, a class root,
// a JAR under build/libs/ or target/). Each named class must be first-party and declare
// main(String[]). Every other shape withholds Searched with a named reason:
//   - no named entry: launch_entry_unnamed;
//   - a named class outside the first-party code (a dependency launcher such as Ktor's
//     EngineMain), a Main-Verticle attribute, a non-literal or unreadable entry, or a build
//     file that cannot be read: launch_entry_unmapped;
//   - the war or bootWar plugin, <packaging>war</packaging>, or a built .war: war_packaging;
//   - a first-party class a container calls back with no call the search can see: one whose
//     ancestors include a javax./jakarta. servlet Filter, listener, Servlet, GenericServlet,
//     ServletContainerInitializer, JMS MessageListener, MessageDrivenBean or WebSocket
//     Endpoint, or that carries @WebFilter, @WebListener, @WebServlet, @MessageDriven,
//     @Startup or @ServerEndpoint. HttpServlet ends the ancestor walk (the ingress
//     recognizers map it); an ancestor neither loaded nor in the JDK withholds the same way:
//     container_callback;
//   - a META-INF/versions/N/ class in a first-party class root, a first-party JAR or a loaded
//     dependency JAR, or one of those that cannot be read: multi_release_override_unread. A
//     JDK at release N runs the override, and this lane reads only the base class.
//
// This is the Kotlin lane's interim check. The Java lane's launch-entry allow-list
// (javaanalysis/launchentry.go) is richer and replaces it when the two lanes share it.

const (
	reasonLaunchEntryUnnamed  = plugin.PartialReasonRelationshipUnexpressed + ":launch_entry_unnamed"
	reasonLaunchEntryUnmapped = plugin.PartialReasonRelationshipUnexpressed + ":launch_entry_unmapped"
	reasonWarPackaging        = plugin.PartialReasonRelationshipUnexpressed + ":war_packaging"
	reasonContainerCallback   = plugin.PartialReasonRelationshipUnexpressed + ":container_callback"
	reasonMultiReleaseUnread  = plugin.PartialReasonToolFailure + ":multi_release_override_unread"
)

const launchTextLimit = 4 << 20

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

var (
	blockComment    = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineComment     = regexp.MustCompile(`(?m)^\s*//.*$`)
	gradleEntryWord = regexp.MustCompile(`\bmainClass(Name)?\b|Main-Class`)
	gradleEntry     = regexp.MustCompile(`\bmainClass(?:Name)?\s*(?:\.set\s*\(\s*|=\s*)["']([^"'$]*)["']|["']Main-Class["']\s*(?::|to|,)\s*["']([^"'$]*)["']`)
	gradleWar       = regexp.MustCompile("\\bid\\s*\\(?\\s*[\"']war[\"']|\\bapply\\s*\\(?\\s*plugin\\s*[:=]\\s*[\"']war[\"']|(?m)^\\s*`?war`?\\s*$|\\bbootWar\\b")
	pomEntryElement = regexp.MustCompile(`<(mainClass|start-class|Main-Class|Start-Class|Main-Verticle)>([^<]*)</`)
	pomWar          = regexp.MustCompile(`<packaging>\s*war\s*</packaging>`)
)

// javaBinaryName matches a dotted Java binary class name.
var javaBinaryName = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*$`)

type entryReader struct {
	reasons map[string]bool
	named   map[string]bool
}

// launchEntryReasons returns the reasons the build's launch shape withholds Searched, sorted;
// none means a named first-party main licenses an empty search. all is every loaded class,
// first-party and dependency, for the ancestor walk.
func launchEntryReasons(buildDir string, prog *program, deps *depClosure, all []classfile.Class) []string {
	r := &entryReader{reasons: map[string]bool{}, named: map[string]bool{}}
	for _, n := range []string{"build.gradle", "build.gradle.kts"} {
		r.gradle(filepath.Join(buildDir, n))
	}
	r.maven(filepath.Join(buildDir, "pom.xml"))
	r.startScripts(buildDir)
	r.manifestFile(filepath.Join(buildDir, "src", "main", "resources", "META-INF", "MANIFEST.MF"))
	for _, rel := range firstPartyClassRoots {
		r.manifestFile(filepath.Join(buildDir, rel, "META-INF", "MANIFEST.MF"))
		r.classRootReleases(filepath.Join(buildDir, rel))
	}
	for _, rel := range []string{firstPartyJarDir, "target"} {
		r.archives(filepath.Join(buildDir, rel))
	}
	loaded := make([]string, 0, len(deps.loaded))
	for _, p := range deps.loaded {
		loaded = append(loaded, p)
	}
	sort.Strings(loaded)
	for _, p := range loaded {
		r.jarReleases(p)
	}

	byName := make(map[string]*classfile.Class, len(all))
	for i := range all {
		if _, dup := byName[all[i].Name]; !dup {
			byName[all[i].Name] = &all[i]
		}
	}
	firstParty := make(map[string]*classfile.Class, len(prog.classes))
	for i := range prog.classes {
		firstParty[prog.classes[i].Name] = &prog.classes[i]
	}
	if len(r.named) == 0 {
		r.reasons[reasonLaunchEntryUnnamed] = true
	}
	for n := range r.named {
		c := firstParty[strings.ReplaceAll(n, ".", "/")]
		if c == nil || !declaresMain(c) {
			r.reasons[reasonLaunchEntryUnmapped] = true
		}
	}
	lookup := func(n string) (*classfile.Class, bool) { c, ok := byName[n]; return c, ok }
	for i := range prog.classes {
		if containerCallback(&prog.classes[i], lookup) {
			r.reasons[reasonContainerCallback] = true
			break
		}
	}

	out := make([]string, 0, len(r.reasons))
	for k := range r.reasons {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func declaresMain(c *classfile.Class) bool {
	for _, m := range c.Methods {
		if m.Ref.Name == "main" && m.Ref.Descriptor == "([Ljava/lang/String;)V" && !m.Abstract && !m.Native {
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

func (r *entryReader) name(v string) {
	v = strings.TrimSpace(v)
	if v == "" || !javaBinaryName.MatchString(v) {
		r.reasons[reasonLaunchEntryUnmapped] = true
		return
	}
	r.named[v] = true
}

// read returns a build file's text; ok is false when it is absent. A file that exists but is
// not a regular file (a FIFO would block the read) or cannot be read withholds: unread is never
// absent.
func (r *entryReader) read(path string) (string, bool) {
	if !r.regular(path) {
		return "", false
	}
	f, err := os.Open(path)
	if err != nil {
		r.reasons[reasonLaunchEntryUnmapped] = true
		return "", false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, launchTextLimit))
	if err != nil {
		r.reasons[reasonLaunchEntryUnmapped] = true
		return "", false
	}
	return string(data), true
}

// regular reports whether path is a regular file, withholding when it exists as anything else.
func (r *entryReader) regular(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			r.reasons[reasonLaunchEntryUnmapped] = true
		}
		return false
	}
	if !info.Mode().IsRegular() {
		r.reasons[reasonLaunchEntryUnmapped] = true
		return false
	}
	return true
}

// gradle reads the literal launch entries and the war plugin from a build script. A
// mainClass, mainClassName or Main-Class mention that is not one of the literal forms is an
// entry the reader cannot resolve.
func (r *entryReader) gradle(path string) {
	text, ok := r.read(path)
	if !ok {
		return
	}
	text = lineComment.ReplaceAllString(blockComment.ReplaceAllString(text, ""), "")
	if gradleWar.MatchString(text) {
		r.reasons[reasonWarPackaging] = true
	}
	literal := gradleEntry.FindAllStringSubmatchIndex(text, -1)
	for _, m := range literal {
		for g := 2; g < len(m); g += 2 {
			if m[g] >= 0 {
				r.name(text[m[g]:m[g+1]])
			}
		}
	}
	for _, w := range gradleEntryWord.FindAllStringIndex(text, -1) {
		covered := false
		for _, m := range literal {
			if w[0] >= m[0] && w[1] <= m[1] {
				covered = true
				break
			}
		}
		if !covered {
			r.reasons[reasonLaunchEntryUnmapped] = true
		}
	}
}

// startScriptDirs are where Gradle writes the start scripts it generates: `startScripts` (run
// by `assemble` for the application plugin) and `installDist`.
var startScriptDirs = []string{
	filepath.Join("build", "scripts"),
	filepath.Join("build", "install", "*", "bin"),
}

// startScripts names the class each Gradle unix start script launches: the line after
// `-classpath "$CLASSPATH" \`. A script that launches no plain class (a --module launch, a
// hand-edited script) is an entry the reader cannot resolve.
func (r *entryReader) startScripts(buildDir string) {
	for _, pattern := range startScriptDirs {
		dirs, _ := filepath.Glob(filepath.Join(buildDir, pattern))
		for _, d := range dirs {
			entries, err := os.ReadDir(d)
			if err != nil {
				r.reasons[reasonLaunchEntryUnmapped] = true
				continue
			}
			for _, e := range entries {
				if e.IsDir() || strings.HasSuffix(e.Name(), ".bat") {
					continue
				}
				text, ok := r.read(filepath.Join(d, e.Name()))
				if !ok {
					continue
				}
				lines := strings.Split(text, "\n")
				named := false
				for i, line := range lines {
					if strings.TrimSpace(line) == `-classpath "$CLASSPATH" \` && i+1 < len(lines) {
						r.name(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(lines[i+1]), `\`)))
						named = true
					}
				}
				if !named {
					r.reasons[reasonLaunchEntryUnmapped] = true
				}
			}
		}
	}
}

func (r *entryReader) maven(path string) {
	text, ok := r.read(path)
	if !ok {
		return
	}
	text = xmlComment.ReplaceAllString(text, "")
	if pomWar.MatchString(text) {
		r.reasons[reasonWarPackaging] = true
	}
	for _, m := range pomEntryElement.FindAllStringSubmatch(text, -1) {
		if m[1] == "Main-Verticle" || strings.Contains(m[2], "${") {
			r.reasons[reasonLaunchEntryUnmapped] = true
			continue
		}
		r.name(m[2])
	}
}

func (r *entryReader) manifestFile(path string) {
	if text, ok := r.read(path); ok {
		r.manifest(text)
	}
}

// archives reads the manifest of every JAR in dir and withholds on a built .war.
func (r *entryReader) archives(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			r.reasons[reasonLaunchEntryUnmapped] = true
		}
		return
	}
	for _, d := range entries {
		if d.IsDir() {
			continue
		}
		lower := strings.ToLower(d.Name())
		switch {
		case strings.HasSuffix(lower, ".war"):
			r.reasons[reasonWarPackaging] = true
		case strings.HasSuffix(lower, ".jar"):
			r.archive(filepath.Join(dir, d.Name()))
		}
	}
}

// archive reads a first-party JAR's manifest and its multi-release overrides.
func (r *entryReader) archive(path string) {
	if !r.regular(path) {
		r.reasons[reasonMultiReleaseUnread] = true
		return
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		r.reasons[reasonLaunchEntryUnmapped] = true
		r.reasons[reasonMultiReleaseUnread] = true
		return
	}
	defer zr.Close()
	r.zipReleases(&zr.Reader)
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
		r.manifest(string(data))
	}
}

// manifest reads Main-Class, Start-Class and Main-Verticle from a MANIFEST.MF.
func (r *entryReader) manifest(text string) {
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n ", "")
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

// classRootReleases withholds when a class root holds a META-INF/versions/N/ class.
func (r *entryReader) classRootReleases(root string) {
	dir := filepath.Join(root, "META-INF", "versions")
	if _, err := os.Lstat(dir); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			r.reasons[reasonMultiReleaseUnread] = true
		}
		return
	}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || (!d.IsDir() && isReleaseOverride(d.Name())) {
			r.reasons[reasonMultiReleaseUnread] = true
			return filepath.SkipAll
		}
		return nil
	})
}

// jarReleases withholds when a loaded dependency JAR holds a META-INF/versions/N/ class.
func (r *entryReader) jarReleases(path string) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		r.reasons[reasonMultiReleaseUnread] = true
		return
	}
	defer zr.Close()
	r.zipReleases(&zr.Reader)
}

func (r *entryReader) zipReleases(zr *zip.Reader) {
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "META-INF/versions/") && isReleaseOverride(f.Name[strings.LastIndexByte(f.Name, '/')+1:]) {
			r.reasons[reasonMultiReleaseUnread] = true
			return
		}
	}
}

func isReleaseOverride(base string) bool {
	return strings.HasSuffix(base, ".class") && base != "module-info.class"
}
