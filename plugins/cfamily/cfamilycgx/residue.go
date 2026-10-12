package cfamilycgx

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Residue reasons: what the cgx call graph cannot show, named per kind. All are quiet
// (inherent to reading C/C++ source without compiling it), so they disclose without gating.
const (
	reasonFnPtr       = plugin.PartialReasonDynamicDispatch + ":fn_ptr"
	reasonVtable      = plugin.PartialReasonDynamicDispatch + ":vtable"
	reasonMacro       = plugin.PartialReasonMacroExpansion
	reasonLinkPrefix  = plugin.PartialReasonNativeLinkBoundary + ":"
	reasonLinkTrunc   = reasonLinkPrefix + "cgx_list_truncated"
	maxLinkBoundaries = 16
)

var (
	// A function-like macro definition: its call sites expand to code cgx never sees.
	fnMacroRE = regexp.MustCompile(`(?m)^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)\(`)
	// Any macro definition's name, so a macro call is never mistaken for an external function.
	macroNameRE = regexp.MustCompile(`(?m)^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)`)
	// A function-pointer declarator: (*name)( or (*)(.
	fnPtrDeclRE = regexp.MustCompile(`\(\s*\*\s*\w*\s*\)\s*\(`)
	// A call through a struct member, which in C can only be a function pointer.
	memberCallRE = regexp.MustCompile(`(?:->|\.)\s*[A-Za-z_]\w*\s*\(`)
	virtualRE    = regexp.MustCompile(`\bvirtual\b`)
	// A called name, optionally qualified (std::memcpy), and what precedes it.
	callRE  = regexp.MustCompile(`(->|\.|::)?\s*((?:[A-Za-z_]\w*\s*::\s*)*[A-Za-z_]\w*)\s*\(`)
	identRE = regexp.MustCompile(`[A-Za-z_]\w*`)
)

// notCallees are words followed by "(" that are not calls: statements, operators, casts and
// attribute syntax.
var notCallees = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`if while for switch return sizeof alignof _Alignof _Alignas alignas
		decltype typeof __typeof__ __typeof noexcept defined static_assert _Static_assert _Generic
		static_cast dynamic_cast reinterpret_cast const_cast typeid catch throw new delete operator
		template requires co_await co_return co_yield case do else goto
		__attribute__ __attribute __declspec __asm__ __asm asm __extension__ __builtin_expect
		int char void short long float double unsigned signed bool _Bool const volatile restrict
		__restrict auto register static extern inline __inline __inline__ struct union enum
		class typename using namespace public private protected virtual override final explicit
		constexpr consteval constinit thread_local _Thread_local __thread mutable friend
		wchar_t char8_t char16_t char32_t size_t this`) {
		notCallees[w] = true
	}
}

// residue scans the staged sources for what the graph cannot show: calls through function
// pointers and virtual slots, function-like macros, and calls to functions the tree does not
// define (a native link boundary, named per symbol). cgx's own edge kinds add the dispatch
// reasons they evidence.
func residue(work string, files []string, gv *graphView) map[string]bool {
	reasons := map[string]bool{}
	if gv.kinds[edgeCallback] || gv.kinds[edgeIndirect] {
		reasons[reasonFnPtr] = true
	}
	if gv.kinds[edgeVirtual] {
		reasons[reasonVtable] = true
	}

	known := map[string]bool{}
	for fqn, ns := range gv.nodes {
		for _, n := range ns {
			if n.Kind == "function" || n.Kind == "method" || n.Kind == "type" || n.Kind == "constant" || n.Kind == "macro" {
				known[fqn] = true
				known[shortName(fqn)] = true
			}
		}
	}

	texts := make([]string, len(files))
	for i, f := range files {
		b, err := os.ReadFile(filepath.Join(work, filepath.FromSlash(f)))
		if err != nil {
			continue
		}
		texts[i] = stripCommentsAndLiterals(string(b))
		for _, m := range macroNameRE.FindAllStringSubmatch(texts[i], -1) {
			known[m[1]] = true
		}
	}

	// A name used anywhere other than as a callee is a variable or a function used as a value;
	// a call through such a name that is not a function in the tree is a call through a pointer.
	valueUse := map[string]bool{}
	for _, t := range texts {
		for _, loc := range identRE.FindAllStringIndex(t, -1) {
			rest := strings.TrimLeft(t[loc[1]:], " \t\r\n")
			if !strings.HasPrefix(rest, "(") && !strings.HasPrefix(rest, "::") {
				valueUse[t[loc[0]:loc[1]]] = true
			}
		}
	}

	external := map[string]bool{}
	for i, f := range files {
		t := texts[i]
		if t == "" {
			continue
		}
		l := langOf(f)
		if fnMacroRE.MatchString(t) {
			reasons[reasonMacro] = true
		}
		if fnPtrDeclRE.MatchString(t) || (l.cSyntax() && memberCallRE.MatchString(t)) {
			reasons[reasonFnPtr] = true
		}
		if !l.cSyntax() && virtualRE.MatchString(t) {
			reasons[reasonVtable] = true
		}
		for _, m := range callRE.FindAllStringSubmatch(t, -1) {
			lead, name := m[1], strings.Join(strings.Fields(m[2]), "")
			short := shortName(name)
			switch {
			case notCallees[short] || known[name] || known[short]:
			case l.cSyntax() && (lead == "->" || lead == "."):
				// a struct member call in C: a function pointer, declared above
			case valueUse[short] && !strings.Contains(name, "::"):
				reasons[reasonFnPtr] = true
			default:
				external[name] = true
			}
		}
	}

	names := make([]string, 0, len(external))
	for n := range external {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) > maxLinkBoundaries {
		names = names[:maxLinkBoundaries]
		reasons[reasonLinkTrunc] = true
	}
	for _, n := range names {
		reasons[reasonLinkPrefix+n] = true
	}
	return reasons
}

// shortName is an FQN's last component: "util::checksum" -> "checksum".
func shortName(fqn string) string {
	if i := strings.LastIndex(fqn, "::"); i >= 0 {
		fqn = fqn[i+2:]
	}
	if i := strings.IndexAny(fqn, "#("); i >= 0 {
		fqn = fqn[:i]
	}
	return fqn
}

// stripCommentsAndLiterals blanks comments and string and character literals, keeping line
// structure, so the lexical scans see code only.
func stripCommentsAndLiterals(s string) string {
	b := []byte(s)
	out := make([]byte, len(b))
	copy(out, b)
	for i := 0; i < len(b); i++ {
		switch {
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '/':
			for ; i < len(b) && b[i] != '\n'; i++ {
				out[i] = ' '
			}
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '*':
			out[i], out[i+1] = ' ', ' '
			for i += 2; i < len(b) && !(b[i] == '*' && i+1 < len(b) && b[i+1] == '/'); i++ {
				if b[i] != '\n' {
					out[i] = ' '
				}
			}
			if i+1 < len(b) {
				out[i], out[i+1] = ' ', ' '
				i++
			}
		case b[i] == '"' || b[i] == '\'':
			q := b[i]
			for i++; i < len(b) && b[i] != q && b[i] != '\n'; i++ {
				if b[i] == '\\' && i+1 < len(b) {
					out[i] = ' '
					i++
				}
				out[i] = ' '
			}
		}
	}
	return string(out)
}

// static reports whether fqn is file-local: every definition of it is lexically static, with
// the keyword on its line or on the line before when that line holds only the declaration's
// leading part (a return type on its own line). A name with any non-static definition is
// exported.
func static(work string, ns []node, cache map[string][]string) bool {
	if len(ns) == 0 {
		return false
	}
	for _, n := range ns {
		lines, ok := cache[n.File]
		if !ok {
			b, err := os.ReadFile(filepath.Join(work, filepath.FromSlash(n.File)))
			if err == nil {
				lines = strings.Split(stripCommentsAndLiterals(string(b)), "\n")
			}
			cache[n.File] = lines
		}
		at := func(i int) string {
			if i >= 0 && i < len(lines) {
				return lines[i]
			}
			return ""
		}
		cur, prev := at(n.Line-1), at(n.Line-2)
		if staticRE.MatchString(cur) {
			continue
		}
		if staticRE.MatchString(prev) && !strings.ContainsAny(prev, ";{}") {
			continue
		}
		return false
	}
	return true
}

var staticRE = regexp.MustCompile(`\bstatic\b`)
