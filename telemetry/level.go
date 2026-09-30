package telemetry

import "strings"

// Level is the coverage tier selected by Config.Level.
// It is fixed ONCE at provider construction and realized as an SDK View set plus a trace
// sampler — never branched on at individual emit sites. The tiers are ordered
// essential < standard < full so a single ">" comparison decides whether an instrument's
// stream is dropped at a given level (see viewsForLevel).
type Level int

const (
	// LevelEssential counts every business action and meters the top COGS, bounded-enum
	// attributes only, metrics-only (AlwaysOff sampler → zero spans). The default.
	LevelEssential Level = iota
	// LevelStandard adds per-run cost breakdowns, durations, the basic span tree (which
	// lights up exemplars), and the cve.id/vuln_class/language/stage dimensions.
	LevelStandard
	// LevelFull adds fine-grained per-Trial span detail, vanity signals, high-cardinality
	// dimensions, and (behind secondary gates) content capture + the contributors probe.
	LevelFull
)

func (l Level) String() string {
	switch l {
	case LevelStandard:
		return "standard"
	case LevelFull:
		return "full"
	default:
		return "essential"
	}
}

// ParseLevel maps a coverage-tier name to a Level, for a host that takes the tier as a string. Empty or "essential" yields the
// safe default; an unrecognized value also yields essential but returns ok=false so the
// caller can surface the misconfiguration.
func ParseLevel(s string) (Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "essential":
		return LevelEssential, true
	case "standard":
		return LevelStandard, true
	case "full":
		return LevelFull, true
	default:
		return LevelEssential, false
	}
}
