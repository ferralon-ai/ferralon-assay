package jsanalysis

import (
	"context"
	"errors"
	"path"
	"time"
)

// Per-file parse limits for dependency code. The parser's forward scans (a call's argument
// list, an arrow body, a bracket's close, a template's substitutions) each run to their
// terminator, so input that never terminates them costs quadratic time. A dependency file the
// estimate refuses is not parsed and surfaces as skipped: the run-wide unsupported_phase1
// limit. The refusal depends only on the file, so the same input always gets the same answer.
var (
	// depWorkPerRune and depWorkFloor bound depScanWork: a file whose estimate exceeds
	// depWorkPerRune runes visited per rune of source, plus depWorkFloor, is refused before it
	// is parsed.
	depWorkPerRune int64 = 64
	depWorkFloor   int64 = 1 << 24
	// depFileParseBackstop bounds one file's parse in wall time, for a shape the estimate does
	// not model. It sits far above any parse the estimate admits, so hitting it is a tool
	// failure, not a property of the input: the package is left unread and the run carries
	// tool_failure, scoped and run-wide, as when the read budget runs out.
	depFileParseBackstop = 2 * time.Minute
	// depRunSourceCap bounds the source bytes one run parses across every dependency package.
	// A package read past it is left unparsed with a scoped tool_failure.
	depRunSourceCap int64 = 256 << 20
	// depParser parses one dependency source file; tests replace it.
	depParser = parseDepFile
)

func parseDepFile(module string, f depFile) parseResult {
	if path.Ext(f.rel) == vueExtension {
		return parseVueSFC(module, string(f.data))
	}
	return parseFile(module, string(f.data))
}

// errParseBackstop reports a dependency file parse cut off at depFileParseBackstop.
var errParseBackstop = errors.New("dependency file parse ran past the backstop")

// parseDepSource parses one dependency file under the per-file limits. It returns
// errParseBackstop when the backstop cut the parse off, and ctx's error when ctx ended first.
func parseDepSource(ctx context.Context, module string, f depFile) (parseResult, error) {
	if !depWorkWithin(string(f.data)) {
		return parseResult{module: module, skipped: true}, nil
	}
	done := make(chan parseResult, 1)
	go func() { done <- depParser(module, f) }()
	t := time.NewTimer(depFileParseBackstop)
	defer t.Stop()
	select {
	case pr := <-done:
		return pr, nil
	case <-t.C:
		// The parse cannot be interrupted; it runs on until it returns or the plugin process
		// exits at the end of the op, and its result is dropped.
		return parseResult{}, errParseBackstop
	case <-ctx.Done():
		return parseResult{}, ctx.Err()
	}
}

func depWorkWithin(src string) bool {
	clean, _ := lexJS(src)
	n := int64(len(clean))
	return depScanWork(clean, []rune(src)) <= depWorkPerRune*n+depWorkFloor
}

// depScanWork estimates the runes the parser's forward scans visit on clean (lexJS output) and
// raw (the source, position-identical):
//   - a scan from each opening bracket to its close: the sum of the bracket depth at each rune;
//   - a scan from each "=>" to the ',', ';', ':', line break or closing bracket that ends the
//     body at its own depth;
//   - a scan from each template literal's opening backtick to its close. A template that never
//     closes is scanned again from every later template start, each to the end of the source.
func depScanWork(clean, raw []rune) int64 {
	n := len(clean)
	var work int64
	before := make([]int32, n)
	depth := int32(0)
	for p, c := range clean {
		before[p] = depth
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		}
		work += int64(depth)
	}

	stop := []int{n}
	at := func(level int32) int {
		for int(level) >= len(stop) {
			stop = append(stop, n)
		}
		return int(level)
	}
	for p := n - 1; p >= 0; p-- {
		switch c := clean[p]; c {
		case ')', ']', '}':
			if before[p] > 0 {
				stop[at(before[p])] = p
			}
		case '(', '[', '{':
			stop[at(before[p]+1)] = n
		case ',', ';', ':', '\n':
			stop[at(before[p])] = p
		case '=':
			if p+1 < n && clean[p+1] == '>' {
				work += int64(stop[at(before[p])] - p)
			}
		}
	}

	unclosed := false
	for i := 0; i < len(raw) && i < n; i++ {
		if raw[i] != '`' || clean[i] != '_' {
			continue
		}
		if unclosed {
			work += int64(len(raw) - i)
			continue
		}
		end, closed := templateEnd(raw, i)
		work += int64(end - i)
		if closed {
			i = end
		} else {
			unclosed = true
		}
	}
	return work
}

// templateEnd follows templateSubstitutionWords's walk from the backtick at i: it returns the
// closing backtick's index, or len(raw) and false when the template never closes.
func templateEnd(raw []rune, i int) (int, bool) {
	n := len(raw)
	depth := 0
	for j := i + 1; j < n; j++ {
		switch {
		case raw[j] == '\\' && j+1 < n:
			j++
		case depth == 0 && raw[j] == '`':
			return j, true
		case raw[j] == '$' && j+1 < n && raw[j+1] == '{':
			depth++
			j++
		case depth > 0 && raw[j] == '}':
			depth--
		}
	}
	return n, false
}
