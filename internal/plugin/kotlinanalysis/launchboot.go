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
// For Gradle, the root build script must apply org.springframework.boot, and nothing may be able
// to configure the Boot main where the reader cannot see it (bootBlocked). The checks are
// allow-lists: every plugin the root or settings script applies is one known not to set the Boot
// main; every settings statement only names the root project or declares repositories; a
// buildscript {} block only puts the Boot, Kotlin or dependency-management plugin on the
// classpath; the root script has no import, applies nothing but literal plugin ids, and neither
// mentions a main class nor reconfigures the source sets the plugin scans; and there is no
// buildSrc. When all of that holds, the plugin's own answer comes first: resolveMainClassName
// writes the main it resolved to build/resolvedMainClassName, and that file names the entry (an
// empty one is the plugin finding none). Without it, the finder's main is taken. A literal
// mainClass or Start-Class in the script is a named entry, read by gradle, and takes precedence.
// Init scripts live outside the checkout and are not read.

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
	gradlePluginsBlock     = regexp.MustCompile(`\bplugins\s*\{`)
	gradleBuildscriptBlock = regexp.MustCompile(`\bbuildscript\s*\{`)
	pluginByID             = regexp.MustCompile(`^id\s*\(?\s*["']([A-Za-z0-9_.\-]+)["']\s*\)?(?:\s+version\s*\(?\s*["'][^"'$]*["']\s*\)?)?$`)
	pluginByKotlin         = regexp.MustCompile(`^kotlin\s*\(\s*["']([A-Za-z0-9_.\-]+)["']\s*\)(?:\s+version\s*\(?\s*["'][^"'$]*["']\s*\)?)?$`)
	pluginByAccessor       = regexp.MustCompile("^`?([A-Za-z][A-Za-z0-9\\-]*)`?$")
	gradleApplyPlugin      = regexp.MustCompile(`(?m)(?:^|[^.\w])apply\s*\(?\s*plugin\s*[:=]\s*["']([A-Za-z0-9_.\-]+)["'][ \t]*\)?`)
	gradleApplyWord        = regexp.MustCompile(`\bapply\b`)
	// gradleBootInput is a script mention that can change the main the Boot plugin finds: its
	// main-class settings (any not a literal named entry) and the class output it scans.
	gradleBootInput = regexp.MustCompile(`(?i)mainclass|start-class|\bsourceSets\b`)
	// gradleImport is an import in a build script: code beyond the Gradle API and applied plugins.
	gradleImport = regexp.MustCompile(`(?m)^\s*import\s`)
	// interpolation is a ${name} string template, whose braces are not blocks.
	interpolation = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
)

// repositoryStatements are the statements that only declare where Gradle downloads from.
var repositoryStatements = []*regexp.Regexp{
	regexp.MustCompile(`^(?:pluginManagement|dependencyResolutionManagement|repositories|maven)\s*\{$`),
	regexp.MustCompile(`^\}$`),
	regexp.MustCompile(`^(?:mavenCentral|gradlePluginPortal|google|mavenLocal)\s*\(\s*\)$`),
	regexp.MustCompile(`^maven\s*\(\s*["'][^"'$]*["']\s*\)$`),
	regexp.MustCompile(`^url\s*=?\s*(?:uri\s*\(\s*)?["'][^"'$]*["']\s*\)?$`),
	regexp.MustCompile(`^repositoriesMode\.set\s*\(\s*RepositoriesMode\.[A-Z_]+\s*\)$`),
}

// settingsStatements are the settings-script statements, besides a plugins {} block, that
// configure no project: the root project's name and repository declarations.
var settingsStatements = append([]*regexp.Regexp{
	regexp.MustCompile(`^rootProject\.name\s*=\s*["'][^"'$]*["']$`),
}, repositoryStatements...)

// buildscriptStatements are the statements of a buildscript {} block that put only the Boot,
// Kotlin and dependency-management Gradle plugins on the script classpath.
var buildscriptStatements = append([]*regexp.Regexp{
	regexp.MustCompile(`^dependencies\s*\{$`),
	regexp.MustCompile(`^classpath\s*\(?\s*["'](?:org\.springframework\.boot:spring-boot-gradle-plugin|io\.spring\.gradle:dependency-management-plugin|org\.jetbrains\.kotlin:kotlin-(?:gradle-plugin|allopen|noarg|serialization)):[^"':]*["']\s*\)?$`),
	regexp.MustCompile(`^ext\.[A-Za-z_][A-Za-z0-9_]*\s*=\s*["'][^"'$]*["']$`),
}, repositoryStatements...)

// gradleBoot reads whether the root build script applies the Boot plugin, and whether the build
// can configure its main unseen.
func (r *entryReader) gradleBoot(buildDir string) {
	for _, n := range []string{"build.gradle", "build.gradle.kts"} {
		text, ok := r.bootScript(filepath.Join(buildDir, n))
		if !ok {
			continue
		}
		text = stripComments(text)
		ids, ok := scriptPlugins(text)
		if !ok || gradleBootInput.MatchString(text) || gradleImport.MatchString(text) {
			r.bootBlocked = true
		}
		for _, id := range ids {
			if id == "org.springframework.boot" {
				r.bootPlugin = true
				r.gradleBootPlugin = true
			}
			if !bootInertPlugins[id] {
				r.bootBlocked = true
			}
		}
		bodies, _, ok := cutBlocks(text, gradleBuildscriptBlock)
		if !ok || !allStatements(strings.Join(bodies, "\n"), buildscriptStatements) {
			r.bootBlocked = true
		}
	}
	for _, n := range []string{"settings.gradle", "settings.gradle.kts"} {
		text, ok := r.bootScript(filepath.Join(buildDir, n))
		if !ok {
			continue
		}
		text = stripComments(text)
		ids, ok := scriptPlugins(text)
		_, rest, cut := cutBlocks(text, gradlePluginsBlock)
		if !ok || !cut || !allStatements(rest, settingsStatements) {
			r.bootBlocked = true
		}
		for _, id := range ids {
			if !settingsInertPlugins[id] {
				r.bootBlocked = true
			}
		}
	}
	// buildSrc is compiled onto every build script's classpath: code there can configure the
	// Boot tasks from a call the root script makes.
	if _, err := os.Lstat(filepath.Join(buildDir, "buildSrc")); !errors.Is(err, fs.ErrNotExist) {
		r.bootBlocked = true
	}
}

// resolvedMain names the main in build/resolvedMainClassName, the Gradle plugin's own answer, when
// the root script applies the plugin and nothing can configure the Boot main unseen. bootJar
// launches a manifest Start-Class or its own mainClass over that file, and either may be set where
// the reader cannot see it, so otherwise the file is not read.
func (r *entryReader) resolvedMain(buildDir string) {
	if !r.gradleBootPlugin || r.bootBlocked {
		return
	}
	if text, ok := r.read(filepath.Join(buildDir, resolvedMainClassFile)); ok {
		if strings.TrimSpace(text) == "" {
			r.reasons[reasonLaunchEntryUnmapped] = true
		} else {
			r.name(text)
		}
	}
}

// allStatements reports whether every statement of text, with each brace its own statement,
// matches one of allowed.
func allStatements(text string, allowed []*regexp.Regexp) bool {
	text = interpolation.ReplaceAllString(text, "$$$1")
	text = strings.NewReplacer("{", "{\n", "}", "\n}\n").Replace(text)
	for _, st := range strings.FieldsFunc(text, func(c rune) bool { return c == '\n' || c == ';' }) {
		st = strings.TrimSpace(st)
		if st == "" {
			continue
		}
		matched := false
		for _, re := range allowed {
			if re.MatchString(st) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// cutBlocks returns the bodies of every block open matches in text and the text outside them;
// ok is false when a block does not close.
func cutBlocks(text string, open *regexp.Regexp) (bodies []string, rest string, ok bool) {
	var out strings.Builder
	for {
		loc := open.FindStringIndex(text)
		if loc == nil {
			out.WriteString(text)
			return bodies, out.String(), true
		}
		out.WriteString(text[:loc[0]])
		depth, end := 1, -1
		for i := loc[1]; i < len(text) && end < 0; i++ {
			switch text[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = i
				}
			}
		}
		if end < 0 {
			return bodies, out.String(), false
		}
		bodies = append(bodies, text[loc[1]:end])
		text = text[end+1:]
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
	bodies, outside, ok := cutBlocks(stripComments(text), gradlePluginsBlock)
	for _, body := range bodies {
		for _, st := range strings.FieldsFunc(body, func(c rune) bool { return c == '\n' || c == ';' }) {
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
	}
	for _, m := range gradleApplyPlugin.FindAllStringSubmatch(outside, -1) {
		ids = append(ids, m[1])
	}
	if len(gradleApplyWord.FindAllStringIndex(outside, -1)) != len(gradleApplyPlugin.FindAllStringIndex(outside, -1)) {
		ok = false
	}
	return ids, ok
}
