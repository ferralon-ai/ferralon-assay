package cfamilycgx

import (
	"fmt"
	"strings"
	"time"
)

// Transport selects how the SDK runs cgx.
type Transport string

const (
	// TransportWasm runs cgx in-process as a WebAssembly module (the SDK default).
	TransportWasm Transport = "wasm"
	// TransportNative drives a native cgx binary as a long-lived subprocess.
	TransportNative Transport = "native"
)

// The cgx edge-confidence tiers, lowest to highest. A floor keeps the edges at or above it.
const (
	ConfidencePossible = "possible"
	ConfidenceProbable = "probable"
	ConfidenceCertain  = "certain"
)

// DefaultMinConfidence keeps every cgx call edge. C needs the lowest tier: cgx resolves a call
// to a function defined in another file at `possible` (a same-file call is `certain`), so any
// higher floor drops every cross-file call and a C program falls apart into its files.
const DefaultMinConfidence = ConfidencePossible

// confidenceRank orders the tiers; an unknown tier ranks lowest, so a floor never drops it.
func confidenceRank(c string) int {
	switch c {
	case ConfidenceCertain:
		return 2
	case ConfidenceProbable:
		return 1
	default:
		return 0
	}
}

// Config is the lane's configuration. cmd/assay-plugin-cfamily fills it from the environment;
// this package never reads the environment itself.
type Config struct {
	Transport     Transport
	CgxBin        string // native transport: absolute path of the cgx binary
	WasmModule    string // wasm transport: module file; required while the SDK embeds none
	CacheDir      string // root for index snapshots and the SDK's compile cache
	PoolSize      int    // extractor instances; 0 leaves the SDK default
	MinConfidence string // ConfidencePossible | ConfidenceProbable | ConfidenceCertain
	StatsFile     string // when set, one JSON line per operation is appended here
	// CgxBinSHA256 pins CgxBin (hex SHA-256); with no pin the binary is not run.
	CgxBinSHA256 string
	// WasmModuleSHA256, when set, must equal PinnedWasmSHA256: it names the module an operator
	// expects, and a module from another cgx commit is refused rather than run against this SDK.
	// The module file is checked against PinnedWasmSHA256 whether or not it is set.
	WasmModuleSHA256 string
	// Fallback, when set, is the transport an operation retries once on after the wasm engine
	// traps (the linear-memory limit included) while indexing. Only TransportNative is
	// accepted (ParseFallback); empty disables the retry.
	Fallback Transport
	// FailureTTL is how long an index failure that may not recur (EngineExit, EngineContext)
	// is replayed before the index is attempted again; 0 never replays one. Deterministic
	// failures (EngineMemoryLimit, EngineTrap) are replayed for as long as the tree, engine
	// build and options are unchanged. ParseFailureTTL gives the default.
	FailureTTL time.Duration
}

// ParseTransport reads a transport name. Empty selects TransportWasm; anything unrecognised
// is an error rather than a silent fallback to the other transport.
func ParseTransport(s string) (Transport, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(TransportWasm):
		return TransportWasm, nil
	case string(TransportNative):
		return TransportNative, nil
	default:
		return "", fmt.Errorf("cfamilycgx: unknown transport %q (want %q or %q)", s, TransportWasm, TransportNative)
	}
}

// ParseMinConfidence reads a confidence floor. Empty selects DefaultMinConfidence.
func ParseMinConfidence(s string) (string, error) {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "":
		return DefaultMinConfidence, nil
	case ConfidencePossible, ConfidenceProbable, ConfidenceCertain:
		return v, nil
	default:
		return "", fmt.Errorf("cfamilycgx: unknown confidence %q (want %s, %s or %s)", s, ConfidenceCertain, ConfidenceProbable, ConfidencePossible)
	}
}

// ParseFallback reads the fallback transport. Empty disables it; native is the only fallback,
// since it is the remedy for the wasm engine's memory ceiling.
func ParseFallback(s string) (Transport, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return "", nil
	case string(TransportNative):
		return TransportNative, nil
	default:
		return "", fmt.Errorf("cfamilycgx: unknown fallback %q (want %q or empty)", s, TransportNative)
	}
}

// ParseFailureTTL reads FailureTTL as a Go duration ("30m", "0s"). Empty selects
// DefaultFailureTTL; a negative duration is an error.
func ParseFailureTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return DefaultFailureTTL, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("cfamilycgx: failure TTL %q: %w", s, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("cfamilycgx: failure TTL %q is negative", s)
	}
	return d, nil
}
