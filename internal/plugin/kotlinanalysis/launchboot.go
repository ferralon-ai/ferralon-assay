package kotlinanalysis

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis"
)

// launchboot.go — the main a Spring Boot build launches when it names none. The Boot plugins
// (Gradle's resolveMainClassName, the Maven plugin's repackage) take the main class configured
// for them and otherwise run spring-boot-loader-tools' MainClassFinder over the class output:
// javaanalysis.BootMainClass models that finder. A Kotlin top-level `fun main` compiles to a
// static main(String[]) in its <File>Kt facade, while @SpringBootApplication sits on the
// application class, which has no main: the finder prefers annotated mains only when there are
// any, so the facade is the one main it keeps.
//
// For Gradle, the build tool's own answer comes first: resolveMainClassName writes the main it
// resolved, configured or found, to build/resolvedMainClassName, and that file names the entry
// like any other named form (an empty one is the plugin finding none). Without it, the root build
// script is read. The finder's main is taken only when the script applies
// org.springframework.boot and nothing can configure a main where the reader cannot see it
// (bootBlocked): every plugin the root script or the settings script applies is one known not to
// set the Boot main, neither script runs build logic from elsewhere (apply from, a project hook,
// any apply that is not a literal plugin id), and the root script neither mentions a main class
// nor reconfigures the source sets whose output the plugin scans. A literal mainClass or
// Start-Class in the script is a named entry, read by gradle, and takes precedence.

// resolvedMainClassFile is where the Gradle plugin's resolveMainClassName writes its main.
var resolvedMainClassFile = filepath.Join("build", "resolvedMainClassName")

// bootInertPlugins are the plugin ids that leave the Boot main to the Boot plugin.
var bootInertPlugins = map[string]bool{
	"org.springframework.boot":            true,
	"io.spring.dependency-management":     true,
	"java":                                true,
	"java-library":                        true,
	"application":                         true,
	"base":                                true,
	"idea":                                true,
	"eclipse":                             true,
	"jacoco":                              true,
	"maven-publish":                       true,
	"org.jetbrains.kotlin.jvm":            true,
	"org.jetbrains.kotlin.kapt":           true,
	"org.jetbrains.kotlin.plugin.spring":  true,
	"org.jetbrains.kotlin.plugin.jpa":     true,
	"org.jetbrains.kotlin.plugin.allopen": true,
	"org.jetbrains.kotlin.plugin.noarg":   true,
	"org.jetbrains.kotlin.plugin.serialization": true,
}

// settingsInertPlugins are the settings plugin ids that configure no project.
var settingsInertPlugins = map[string]bool{
	"org.gradle.toolchains.foojay-resolver-convention": true,
	"org.gradle.toolchains.foojay-resolver":            true,
}

var (
	gradlePluginsBlock = regexp.MustCompile(`\bplugins\s*\{`)
	pluginByID         = regexp.MustCompile(`^id\s*\(?\s*["']([A-Za-z0-9_.\-]+)["']\s*\)?(?:\s+version\s*\(?\s*["'][^"'$]*["']\s*\)?)?$`)
	pluginByKotlin     = regexp.MustCompile(`^kotlin\s*\(\s*["']([A-Za-z0-9_.\-]+)["']\s*\)(?:\s+version\s*\(?\s*["'][^"'$]*["']\s*\)?)?$`)
	pluginByAccessor   = regexp.MustCompile("^`?([A-Za-z][A-Za-z0-9\\-]*)`?$")
	gradleApplyPlugin  = regexp.MustCompile(`(?:^|[^.\w])apply\s*\(?\s*plugin\s*[:=]\s*["']([A-Za-z0-9_.\-]+)["']\s*\)?`)
	gradleApplyWord    = regexp.MustCompile(`\bapply\b`)
	// gradleBootInput is a script mention that can change the main the Boot plugin finds: its
	// main-class settings (any not a literal named entry) and the class output it scans.
	gradleBootInput   = regexp.MustCompile(`(?i)mainclass|start-class|\bsourceSets\b`)
	gradleProjectHook = regexp.MustCompile(`\b(allprojects|subprojects|beforeProject|afterProject|projectsLoaded|projectsEvaluated|rootProject\s*[{(])`)
)

// gradleBoot reads the Boot plugin's resolved main, whether the root build script applies the
// plugin, and whether the build can configure its main unseen.
func (r *entryReader) gradleBoot(buildDir string) {
	if text, ok := r.read(filepath.Join(buildDir, resolvedMainClassFile)); ok {
		if strings.TrimSpace(text) == "" {
			r.reasons[reasonLaunchEntryUnmapped] = true
		} else {
			r.name(text)
		}
	}
	for _, n := range []string{"build.gradle", "build.gradle.kts"} {
		text, ok := r.bootScript(filepath.Join(buildDir, n))
		if !ok {
			continue
		}
		ids, ok := scriptPlugins(text)
		if !ok || gradleBootInput.MatchString(stripComments(text)) {
			r.bootBlocked = true
		}
		for _, id := range ids {
			if id == "org.springframework.boot" {
				r.bootPlugin = true
			}
			if !bootInertPlugins[id] {
				r.bootBlocked = true
			}
		}
	}
	for _, n := range []string{"settings.gradle", "settings.gradle.kts"} {
		text, ok := r.bootScript(filepath.Join(buildDir, n))
		if !ok {
			continue
		}
		ids, ok := scriptPlugins(text)
		if !ok || gradleProjectHook.MatchString(stripComments(text)) {
			r.bootBlocked = true
		}
		for _, id := range ids {
			if !settingsInertPlugins[id] {
				r.bootBlocked = true
			}
		}
	}
}

// bootScript reads a Gradle script for gradleBoot; ok is false when it is absent or unread, and
// an unread one blocks the plugin's main.
func (r *entryReader) bootScript(path string) (string, bool) {
	text, ok := r.read(path)
	if !ok {
		if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
			r.bootBlocked = true
		}
	}
	return text, ok
}

// bootMain reports whether the build, naming no main, applies a Boot plugin that finds one
// first-party main itself with nothing able to hand it another.
func (r *entryReader) bootMain(buildDir string, prog *program) bool {
	if !r.bootPlugin || r.bootBlocked {
		return false
	}
	roots := make([]string, 0, len(firstPartyClassRoots))
	for _, rel := range firstPartyClassRoots {
		roots = append(roots, filepath.Join(buildDir, rel))
	}
	_, ok := javaanalysis.BootMainClass(prog.classes, roots)
	return ok
}

func stripComments(text string) string {
	return lineComment.ReplaceAllString(blockComment.ReplaceAllString(text, ""), "")
}

// scriptPlugins returns the plugin ids a Gradle script applies: each statement of a plugins {}
// block, and each apply(plugin = "...") / apply plugin: '...' outside one. ok is false when the
// script applies anything else, or anything this way: a plugins {} statement of another form
// (a version-catalog alias, apply false, a non-literal id), an apply from, or an unbalanced block.
func scriptPlugins(text string) (ids []string, ok bool) {
	text = stripComments(text)
	ok = true
	var rest strings.Builder
	for {
		loc := gradlePluginsBlock.FindStringIndex(text)
		if loc == nil {
			rest.WriteString(text)
			break
		}
		rest.WriteString(text[:loc[0]])
		depth, end := 1, -1
		for i := loc[1]; i < len(text); i++ {
			switch text[i] {
			case '{':
				depth++
			case '}':
				depth--
			}
			if depth == 0 {
				end = i
				break
			}
		}
		if end < 0 {
			return ids, false
		}
		for _, st := range strings.FieldsFunc(text[loc[1]:end], func(c rune) bool { return c == '\n' || c == ';' }) {
			st = strings.TrimSpace(st)
			if st == "" {
				continue
			}
			if m := pluginByID.FindStringSubmatch(st); m != nil {
				ids = append(ids, m[1])
			} else if m := pluginByKotlin.FindStringSubmatch(st); m != nil {
				ids = append(ids, "org.jetbrains.kotlin."+m[1])
			} else if m := pluginByAccessor.FindStringSubmatch(st); m != nil {
				ids = append(ids, m[1])
			} else {
				ok = false
			}
		}
		text = text[end+1:]
	}
	outside := rest.String()
	for _, m := range gradleApplyPlugin.FindAllStringSubmatch(outside, -1) {
		ids = append(ids, m[1])
	}
	if len(gradleApplyWord.FindAllStringIndex(outside, -1)) != len(gradleApplyPlugin.FindAllStringIndex(outside, -1)) {
		ok = false
	}
	return ids, ok
}
