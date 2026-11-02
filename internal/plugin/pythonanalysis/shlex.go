package pythonanalysis

import "strings"

// shellSplit splits a requirements option line into words the way pip does, with Python's
// shlex.split in POSIX mode: ASCII space, tab, CR and LF separate words; inside '...' every
// character is literal; inside "..." a backslash escapes only '"' and '\'; elsewhere a
// backslash escapes the next character. Quoted and unquoted parts of one word join, and ""
// is an empty word. It reports false where shlex raises (an unclosed quote, a trailing
// backslash), as pip then rejects the whole file.
func shellSplit(line string) ([]string, bool) {
	var words []string
	var word strings.Builder
	inWord := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch c {
		case ' ', '\t', '\r', '\n':
			if inWord {
				words = append(words, word.String())
				word.Reset()
				inWord = false
			}
			continue
		case '\\':
			if i+1 == len(line) {
				return nil, false
			}
			i++
			word.WriteByte(line[i])
		case '\'':
			end := strings.IndexByte(line[i+1:], '\'')
			if end < 0 {
				return nil, false
			}
			word.WriteString(line[i+1 : i+1+end])
			i += end + 1
		case '"':
			i++
			for ; i < len(line) && line[i] != '"'; i++ {
				if line[i] == '\\' && i+1 < len(line) && (line[i+1] == '"' || line[i+1] == '\\') {
					i++
				}
				word.WriteByte(line[i])
			}
			if i == len(line) {
				return nil, false
			}
		default:
			word.WriteByte(c)
		}
		inWord = true
	}
	if inWord {
		words = append(words, word.String())
	}
	return words, true
}
