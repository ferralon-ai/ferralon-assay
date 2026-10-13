// Package depreach builds a class-hierarchy (CHA) call graph over parsed
// dependency bytecode and answers the two-trace proof-of-non-exploitability that
// the free Assess tier rests on: is a vulnerable sink method reachable from an
// ingress, and if no path is found, is that a searched-and-empty result
// (not_exploitable) or a search a completeness hazard could have hidden a path from
// (undetermined). The verdict engine and honesty boundary are the language-agnostic
// core the other lanes reuse; only the bytecode reader is Java-specific.
package depreach

import "strings"

// parseParamRefTypes returns the internal names of every reference-type parameter
// in a JVM method descriptor, including reference element types of array
// parameters. Primitive parameters and the return type are ignored.
//
// It exists for the re-entry hazard rule: a parameter whose type an in-classpath
// application class implements is a callback that an out-of-classpath method could
// invoke, re-entering application code from a leaf the graph does not traverse.
// Descriptor grammar (JVMS §4.3.3): "(" ParameterType* ")" ReturnType, where a
// type is a primitive (BCDFIJSZ), "L" ClassName ";", or "[" Type.
func parseParamRefTypes(desc string) []string {
	i := 0
	// Advance to the parameter list.
	for i < len(desc) && desc[i] != '(' {
		i++
	}
	if i >= len(desc) {
		return nil
	}
	i++ // past '('

	var refs []string
	for i < len(desc) && desc[i] != ')' {
		// Skip array dimensions; the element type follows.
		for i < len(desc) && desc[i] == '[' {
			i++
		}
		if i >= len(desc) {
			break
		}
		switch desc[i] {
		case 'L':
			j := i + 1
			for j < len(desc) && desc[j] != ';' {
				j++
			}
			if j >= len(desc) {
				return refs // malformed: unterminated object type
			}
			refs = append(refs, desc[i+1:j])
			i = j + 1
		case 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z':
			i++
		default:
			// Unexpected character (malformed descriptor) — stop conservatively.
			return refs
		}
	}
	return refs
}

// paramTypes returns each reference-type parameter of a JVM method descriptor as
// the receiver type a call on that argument would name: the internal class name of
// an object parameter, or the whole descriptor ("[I", "[Ljava/lang/Object;") of an
// array parameter. Primitive parameters are skipped.
func paramTypes(desc string) []string {
	i := strings.IndexByte(desc, '(')
	if i < 0 {
		return nil
	}
	i++
	var out []string
	for i < len(desc) && desc[i] != ')' {
		start := i
		for i < len(desc) && desc[i] == '[' {
			i++
		}
		if i >= len(desc) {
			return out
		}
		switch desc[i] {
		case 'L':
			j := strings.IndexByte(desc[i:], ';')
			if j < 0 {
				return out // malformed: unterminated object type
			}
			i += j + 1
		case 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z':
			i++
			if i-start == 1 {
				continue
			}
		default:
			return out
		}
		if desc[start] == '[' {
			out = append(out, desc[start:i])
		} else {
			out = append(out, desc[start+1:i-1])
		}
	}
	return out
}
