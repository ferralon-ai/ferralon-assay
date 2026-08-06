package telemetry

import (
	"os"
	"strings"
)

// EnvLevel is the environment variable selecting the coverage tier. Internal-only (F-6 review):
// never printed to any output (no flag surface, no error/log line names it), set only by our own
// deployment/CI, never documented as an Action input or customer-facing config — so a hardcoded
// TEGRON_ literal here never reaches a customer surface. Left literal.
const EnvLevel = "TEGRON_OTEL_LEVEL"

// Level is the coverage tier selected by TEGRON_OTEL_LEVEL.
// It is read ONCE at provider construction and realized as an SDK View set plus a trace
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

// ParseLevel maps a TEGRON_OTEL_LEVEL string to a Level. Empty or "essential" yields the
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

// levelFromEnv reads TEGRON_OTEL_LEVEL, defaulting to essential.
func levelFromEnv() Level {
	lvl, _ := ParseLevel(os.Getenv(EnvLevel))
	return lvl
}
