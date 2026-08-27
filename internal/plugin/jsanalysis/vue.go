package jsanalysis

import (
	"strings"
	"unicode"
)

// Vue single-file component (SFC) support.
//
// A `.vue` file is not JavaScript: it is an HTML-ish container of top-level blocks —
// `<template>` (markup with framework directives), one or two `<script>` blocks (the
// component's real JS/TS), and `<style>`. The pure-JS lexer cannot parse the raw file
// (its markup would be mis-scanned as operators and calls), so before this the whole
// SFC — including the `<script setup>` block, which IS ordinary JS/TS — was silently
// skipped: no nodes, no edges, no ingresses, and the graph still declared itself
// Complete (an entrypoint→sink path through a component was invisible AND unflagged).
//
// This file closes that gap in two sound, conservative moves that mirror the lane's
// existing model:
//
//   - Script ingestion: the concatenated `<script>` / `<script setup>` contents are
//     parsed as an ordinary JS/TS module (parseFile). Its functions become nodes and
//     its intra-/cross-module calls become edges, exactly as a `.ts` file's would.
//   - Template-event ingress: a `@evt="handler"` / `v-on:evt="handler"` binding whose
//     value is a bare method reference is recorded as a `handler` ingress naming that
//     method — the framework invokes it on user interaction, precisely analogous to an
//     Express route binding a named handler (calls.go routeIngress). An inline
//     expression or arrow (`@click="count++"`, `@click="() => f()"`) names no bare
//     method and records no ingress: honest absence, never a fabricated entry.
//
// Deliberately NOT modeled (documented known-absent, per honest-absent inv.5 — each
// only WEAKENS reachability, never fabricates): Options-API object-literal methods
// (`methods: { onSubmit() {} }`), reactivity callbacks (`watch`/`computed`/
// `watchEffect`), router route→component wiring, and Pinia/Vuex string-keyed
// `dispatch('action')`. Their presence still degrades partiality through the existing
// mechanisms (an unresolved/uninspectable call site on `watch`, `useRouter`, etc.).

// parseVueSFC parses one Vue single-file component. Its `<script>` block(s) are parsed
// as an ordinary JS/TS module (so module is the `.vue`-stripped path, identical to how
// a sibling `.ts` file would be indexed); its `<template>` event bindings contribute
// `handler` ingress markers. A component with no `<script>` block yields an empty parse
// plus whatever template ingresses it declares (which resolve to a symbol only if the
// named handler is a declared function the lexer can see — otherwise dropped honestly).
func parseVueSFC(module, src string) parseResult {
	script, template, _ := extractSFCBlocks(src)

	var res parseResult
	if strings.TrimSpace(script) != "" {
		res = parseFile(module, script)
	} else {
		res = parseResult{module: module}
	}
	res.ingresses = append(res.ingresses, vueTemplateIngresses(template)...)
	return res
}

// extractSFCBlocks pulls the concatenated `<script>` contents and the first top-level
// `<template>` content out of a Vue SFC. `<script>` is a raw-text element terminated by
// the first `</script>`; both a plain `<script>` and a `<script setup>` block (they may
// coexist) are collected. The `<template>` block is matched with nesting awareness —
// Vue permits nested `<template>` (e.g. `<template v-if>`) inside the root template.
// `<style>` is ignored. sawScript reports whether at least one `<script>` block existed.
func extractSFCBlocks(src string) (scriptSrc, templateSrc string, sawScript bool) {
	lower := strings.ToLower(src)

	var scripts []string
	for i := 0; ; {
		open := indexTag(lower, "<script", i)
		if open < 0 {
			break
		}
		gt := strings.IndexByte(src[open:], '>')
		if gt < 0 {
			break
		}
		contentStart := open + gt + 1
		rel := strings.Index(lower[contentStart:], "</script")
		if rel < 0 {
			scripts = append(scripts, src[contentStart:]) // unterminated: take the rest
			sawScript = true
			break
		}
		closeAt := contentStart + rel
		scripts = append(scripts, src[contentStart:closeAt])
		sawScript = true
		cgt := strings.IndexByte(src[closeAt:], '>')
		if cgt < 0 {
			break
		}
		i = closeAt + cgt + 1
	}
	scriptSrc = strings.Join(scripts, "\n")
	templateSrc = extractTemplate(src, lower)
	return scriptSrc, templateSrc, sawScript
}

// extractTemplate returns the inner content of the first top-level `<template>` block,
// matching `</template>` with nesting awareness. lower is a lowercased copy of src of
// identical length (ASCII tag names), so an index into lower is an index into src.
func extractTemplate(src, lower string) string {
	open := indexTag(lower, "<template", 0)
	if open < 0 {
		return ""
	}
	gt := strings.IndexByte(src[open:], '>')
	if gt < 0 {
		return ""
	}
	contentStart := open + gt + 1
	depth := 1
	i := contentStart
	for i < len(src) {
		nextOpen := indexTag(lower, "<template", i)
		rel := strings.Index(lower[i:], "</template")
		if rel < 0 {
			return src[contentStart:] // unterminated: take the rest
		}
		nextClose := i + rel
		if nextOpen >= 0 && nextOpen < nextClose {
			depth++
			ogt := strings.IndexByte(src[nextOpen:], '>')
			if ogt < 0 {
				return src[contentStart:]
			}
			i = nextOpen + ogt + 1
			continue
		}
		depth--
		if depth == 0 {
			return src[contentStart:nextClose]
		}
		cgt := strings.IndexByte(src[nextClose:], '>')
		if cgt < 0 {
			return src[contentStart:nextClose]
		}
		i = nextClose + cgt + 1
	}
	return src[contentStart:]
}

// indexTag finds the next occurrence of tag (e.g. "<script", "<template") at or after
// from in s, requiring the character following the tag name to be a tag delimiter
// (whitespace, '>', or '/') so "<template" does not match a hypothetical "<templatex".
// s is expected lowercased; tag is lowercase.
func indexTag(s, tag string, from int) int {
	for from < len(s) {
		idx := strings.Index(s[from:], tag)
		if idx < 0 {
			return -1
		}
		at := from + idx
		end := at + len(tag)
		if end >= len(s) {
			return -1
		}
		if c := s[end]; c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '>' || c == '/' {
			return at
		}
		from = end
	}
	return -1
}

// vueTemplateIngresses scans a Vue template for event bindings whose value is a bare
// method reference and returns one `handler` ingress marker per distinct method. It
// recognizes the two event-binding syntaxes:
//
//	@evt="handler"          (shorthand, with any .modifiers)
//	v-on:evt="handler"      (long form)
//
// The value qualifies only when it is a bare identifier ("onSubmit") or an explicit
// call of one ("onSubmit()"); an inline expression, an arrow, or a member access
// ("count++", "() => f()", "store.act") records nothing — honest absence, mirroring the
// anonymous-route-handler rule. Markers are de-duplicated per template; final ordering
// is imposed downstream (FindIngresses / CallGraph roots sort).
func vueTemplateIngresses(tmpl string) []ingressMarker {
	if tmpl == "" {
		return nil
	}
	r := []rune(tmpl)
	n := len(r)
	seen := map[string]bool{}
	var out []ingressMarker

	i := 0
	for i < n {
		evValStart := -1
		switch {
		case r[i] == '@':
			evValStart = i + 1
		case r[i] == 'v' && hasPrefixAt(r, i, "v-on:"):
			evValStart = i + len("v-on:")
		}
		if evValStart < 0 {
			i++
			continue
		}
		// Scan the event name (plus any ".modifiers") up to '=' or a boundary.
		j := evValStart
		for j < n && r[j] != '=' && !unicode.IsSpace(r[j]) && r[j] != '>' && r[j] != '"' && r[j] != '\'' {
			j++
		}
		k := skipSpace(r, j)
		if k >= n || r[k] != '=' {
			i = evValStart
			continue
		}
		k = skipSpace(r, k+1)
		if k >= n || (r[k] != '"' && r[k] != '\'') {
			i = k
			continue
		}
		quote := r[k]
		k++
		start := k
		for k < n && r[k] != quote {
			k++
		}
		val := strings.TrimSpace(string(r[start:k]))
		if ref := vueHandlerRef(val); ref != "" && !seen[ref] {
			seen[ref] = true
			out = append(out, ingressMarker{name: ref, kind: "handler"})
		}
		i = k + 1
	}
	return out
}

// vueHandlerRef returns the bare method name an event-binding value invokes, or "" when
// the value is not a bare method reference. "onSubmit" → "onSubmit"; "onSubmit()" →
// "onSubmit"; "onSubmit($event)" → "onSubmit". An expression, arrow, member access, or
// anything with intervening operators returns "" (conservative: no fabricated ingress).
func vueHandlerRef(val string) string {
	if val == "" {
		return ""
	}
	if isBareIdent(val) {
		return val
	}
	if p := strings.IndexByte(val, '('); p > 0 && strings.HasSuffix(strings.TrimSpace(val), ")") {
		head := strings.TrimSpace(val[:p])
		if isBareIdent(head) {
			return head
		}
	}
	return ""
}

// isBareIdent reports whether s is exactly one JS identifier (no dots, no spaces, no
// operators).
func isBareIdent(s string) bool {
	if s == "" {
		return false
	}
	for idx, c := range s {
		if idx == 0 {
			if !isIdentStart(c) {
				return false
			}
			continue
		}
		if !isIdentPart(c) {
			return false
		}
	}
	return true
}

// hasPrefixAt reports whether the runes of r starting at i match the ASCII prefix.
func hasPrefixAt(r []rune, i int, prefix string) bool {
	if i+len(prefix) > len(r) {
		return false
	}
	for k := 0; k < len(prefix); k++ {
		if r[i+k] != rune(prefix[k]) {
			return false
		}
	}
	return true
}
