package jsanalysis

import (
	"encoding/json"
	"strings"
	"unicode"
)

// npmrcEntry is one setting of a .npmrc as the ini parser behind npm and pnpm reads it.
type npmrcEntry struct {
	key    string
	val    string
	hasVal bool // false for a line with no "="; ini reads the value as true
	array  bool // the key ended in "[]"; ini collects the values into an array
	opaque bool // the value is not one the lane can read as text (a quoted non-string, a bad JSON string); val is the raw text
}

// parseNpmrc reads data the way npm's ini package does (decode and unsafe in ini/lib/ini.js; pnpm
// 10 bundles ini 1.x with the same decode and unsafe): lines end at \r or \n, a line whose first
// non-space character is ';' or '#' is a comment, the key is everything before the first '=',
// and key and value each go through unsafe. A line with no key is ignored, as ini ignores it. A
// "[section]" header is read as an ordinary line, so its settings are still returned although
// ini files them under the section; the caller can only withhold more.
//
// ok is false when a key is one the lane cannot read the way ini would: a quoted string that is
// not a JSON string, or a key that keeps "${" (environment substitution) or "\" after unsafe,
// unless npmrcKeyCarved exempts it. A value unsafe turns into something other than text sets
// opaque on its entry instead: a value decode cannot change the key, so the caller withholds
// only when the key is one it models.
func parseNpmrc(data []byte) ([]npmrcEntry, bool) {
	var out []npmrcEntry
	for _, line := range strings.FieldsFunc(string(data), func(r rune) bool { return r == '\n' || r == '\r' }) {
		if t := strings.TrimLeftFunc(line, isJSSpace); strings.HasPrefix(t, ";") || strings.HasPrefix(t, "#") {
			continue
		}
		rawKey, rawVal, hasVal := strings.Cut(line, "=")
		if rawKey == "" {
			continue
		}
		key, ok := iniUnsafe(rawKey)
		if !ok {
			return nil, false
		}
		e := npmrcEntry{key: key, hasVal: hasVal}
		if len(key) > 2 && strings.HasSuffix(key, "[]") {
			e.key, e.array = key[:len(key)-2], true
		}
		if (strings.Contains(e.key, "${") || strings.Contains(e.key, `\`)) && !npmrcKeyCarved(rawKey) {
			return nil, false
		}
		if hasVal {
			if e.val, ok = iniUnsafe(rawVal); !ok {
				e.opaque = true
				e.val = strings.TrimFunc(rawVal, isJSSpace)
			}
		}
		out = append(out, e)
	}
	return out, true
}

// npmrcKeyCarved reports whether a raw .npmrc key, after the BOM and surrounding space, begins
// with "//" (a registry's credentials, //${HOST}/:_authToken) or "@" (a scoped registry,
// @${SCOPE}:registry). pnpm expands ${...} in a key only after it cuts the line at the first "="
// and unquotes only a key that starts with a quote, so the resolved key keeps its first
// characters, and no pnpm 10 or 11 setting name starts with "/" or "@". The rule is literal: a
// quoted "//${X}" is not carved. Both parseNpmrc and npmrcKeyIndirect use it.
func npmrcKeyCarved(rawKey string) bool {
	k := strings.TrimFunc(rawKey, isJSSpace)
	return strings.HasPrefix(k, "//") || strings.HasPrefix(k, "@")
}

// npmrcFold is the key fold pnpm 10 applies to a workspace project's .npmrc (readLocalConfig runs
// camelcase-keys over it): the key lowercases and "-", "_", "." and space are one separator, so
// virtualStoreDir, VIRTUAL_STORE_DIR, "virtual store dir" and "-virtual-store-dir" all name
// virtual-store-dir. Folding every key, whether or not it sits in a workspace member, only
// over-approximates.
func npmrcFold(key string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || r == '.' || r == ' ' {
			return -1
		}
		return r
	}, strings.ToLower(key))
}

// iniUnsafe is ini's unsafe: trim, then either unquote a quoted string through JSON.parse or
// walk the text to its first unescaped ';' or '#'. ok is false where the result is not plain
// text: a double-quoted string JSON.parse rejects stays quoted, and a single-quoted string whose
// contents parse as JSON may yield a number, array or boolean.
func iniUnsafe(s string) (string, bool) {
	s = strings.TrimFunc(s, isJSSpace)
	if n := len(s); n > 0 && (s[0] == '"' || s[0] == '\'') && s[n-1] == s[0] {
		single := s[0] == '\''
		if single {
			s = s[1:max(1, n-1)]
		}
		var v any
		if json.Unmarshal([]byte(s), &v) == nil {
			str, isStr := v.(string)
			return str, isStr
		}
		return s, single
	}
	var b strings.Builder
	esc := false
walk:
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case esc:
			if c != '\\' && c != ';' && c != '#' {
				b.WriteByte('\\')
			}
			b.WriteByte(c)
			esc = false
		case c == ';' || c == '#':
			break walk
		case c == '\\':
			esc = true
		default:
			b.WriteByte(c)
		}
	}
	if esc {
		b.WriteByte('\\')
	}
	return strings.TrimFunc(b.String(), isJSSpace), true
}

// isJSSpace is JavaScript's String.prototype.trim whitespace, which ini trims with. It differs
// from unicode.IsSpace at U+FEFF, which JavaScript trims and Go does not, so a byte-order mark
// is dropped here as pnpm drops it; and at U+0085, which Go trims and JavaScript does not.
func isJSSpace(r rune) bool {
	return r == '\uFEFF' || r != '\u0085' && unicode.IsSpace(r)
}

// npmrcNamesAny reports whether the .npmrc in data holds a setting whose key, as ini reads it,
// contains any of words, or cannot be read. A quoted key can spell a word in an escape
// ("pnpmfile"), which a search of the raw bytes misses.
func npmrcNamesAny(data []byte, words []string) bool {
	entries, ok := parseNpmrc(data)
	if !ok {
		return true
	}
	for _, e := range entries {
		for _, w := range words {
			if strings.Contains(e.key, w) {
				return true
			}
		}
	}
	return false
}
