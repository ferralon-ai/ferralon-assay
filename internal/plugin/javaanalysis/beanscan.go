package javaanalysis

import (
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

// #6 bean-existence configuration readers (spring-surface.md §2). These bound which
// beans/impls are LIVE — the scan scope, explicit imports, and auto-configuration that
// decide the registered bean set. All are on-disk reads (classfiles, jar resources,
// build files); no build is executed and no network is touched (§3.3, zero-egress).
//
// Soundness stance (inv.5): scan configuration is applied only in the ADDITIVE
// direction — a reader may ADD a bean source (an @Import'ed config, an auto-config
// class, an XML <bean>), which can only widen the candidate set and therefore only make
// a resolution MORE ambiguous (Partial), never fabricate or misdirect an edge.
// RESTRICTIVE application (excluding a first-party stereotype outside @ComponentScan's
// packages, or a bean behind an unsatisfied @Conditional/@Profile) is deliberately NOT
// performed here: a mis-judged exclusion would drop a live edge and risk a false
// not_exploitable. Those remain the irreducible residue — the scope is surfaced for a
// future precision pass, the beans stay in the set with their activation UNKNOWN.

// The readers below parse the four #6 bean-existence inputs — component-scan scope,
// explicit @Import/@Enable* config types, dependency auto-configuration, and (in
// beanconfig.go) legacy XML. They are the parsing primitives the additive integration
// (XML beans) and a future restrictive-scope precision pass consume; each is unit-tested
// against the on-disk formats it reads.

// autoConfigResourcePredicate selects the jar entries that declare auto-configuration:
// the classic META-INF/spring.factories and the Boot 2.7+
// META-INF/spring/*.AutoConfiguration.imports. Pass it to classfile.LoadJarWithResources.
func autoConfigResourcePredicate(name string) bool {
	return name == "META-INF/spring.factories" ||
		(strings.HasPrefix(name, "META-INF/spring/") && strings.HasSuffix(name, ".imports"))
}

// readAutoConfig extracts the auto-configuration class names from a jar's resource
// entries (as returned in classfile.JarResult.Resources). It reads two formats:
//
//   - META-INF/spring.factories: a Java properties file; the value of the
//     EnableAutoConfiguration key is a comma-separated, backslash-continued class list.
//   - META-INF/spring/*.AutoConfiguration.imports: one fully-qualified class per line,
//     '#'-comments and blanks ignored (Boot 2.7+).
//
// The result is sorted and deduplicated. A malformed line is skipped, never fatal — a
// resource we cannot parse is a bounded gap, not a crash.
func readAutoConfig(resources map[string][]byte) []string {
	set := map[string]bool{}
	for name, data := range resources {
		switch {
		case name == "META-INF/spring.factories":
			for _, c := range parseFactoriesAutoConfig(string(data)) {
				set[c] = true
			}
		case strings.HasPrefix(name, "META-INF/spring/") && strings.HasSuffix(name, ".imports"):
			for _, line := range strings.Split(string(data), "\n") {
				if c := strings.TrimSpace(line); c != "" && !strings.HasPrefix(c, "#") {
					set[c] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// parseFactoriesAutoConfig pulls the comma-separated class list that follows the
// EnableAutoConfiguration key in a spring.factories properties body, honoring the
// backslash line-continuations the format uses for long lists.
func parseFactoriesAutoConfig(body string) []string {
	const key = "org.springframework.boot.autoconfigure.EnableAutoConfiguration"
	idx := strings.Index(body, key)
	if idx < 0 {
		return nil
	}
	rest := body[idx+len(key):]
	rest = strings.TrimLeft(rest, " \t")
	if !strings.HasPrefix(rest, "=") {
		return nil
	}
	rest = rest[1:]
	// Join backslash-continued lines, then stop at the first line that does not continue.
	var b strings.Builder
	for _, line := range strings.Split(rest, "\n") {
		trimmed := strings.TrimRight(line, " \t\r")
		cont := strings.HasSuffix(trimmed, "\\")
		b.WriteString(strings.TrimSuffix(trimmed, "\\"))
		if !cont {
			break
		}
	}
	var out []string
	for _, c := range strings.Split(b.String(), ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// importedTypesFromClasses reads the @Import / @Enable* configuration references from a
// set of parsed classes, using 1a's class-valued annotation elements (Annotation.
// ClassElements). Each referenced type's internal name is returned — the configuration
// classes the module pulls in explicitly. Deduplicated and sorted.
func importedTypesFromClasses(classes []classfile.Class) []string {
	set := map[string]bool{}
	for i := range classes {
		for _, a := range classes[i].Annotations {
			name := simpleImportAnno(a.Type)
			if name != "Import" && !strings.HasPrefix(name, "Enable") {
				continue
			}
			for _, ce := range a.ClassElements {
				if ce.Value != "" {
					set[ce.Value] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// simpleImportAnno reduces an annotation descriptor to its simple name for the #6
// import/enable recognition (namespace-agnostic, like the rest of the lane).
func simpleImportAnno(desc string) string {
	s := desc
	if strings.HasPrefix(s, "L") && strings.HasSuffix(s, ";") {
		s = s[1 : len(s)-1]
	}
	if k := strings.LastIndexByte(s, '/'); k >= 0 {
		s = s[k+1:]
	}
	return s
}

// componentScanPackagesFromSource extracts declared @ComponentScan base packages from
// the scanned source classes (the value recoverable on the Java-source path is the first
// basePackages string, per 1a's annotation-value recovery). The scope is surfaced, not
// applied restrictively (see the soundness stance above).
func componentScanPackagesFromSource(pending []parsedAnno) []string {
	var pkgs []string
	for _, a := range pending {
		if (a.name == "ComponentScan" || a.name == "SpringBootApplication") && a.value != "" {
			pkgs = append(pkgs, a.value)
		}
	}
	return pkgs
}
