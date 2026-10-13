package cfamilycgx

import (
	"fmt"
	"runtime/debug"
)

// The cgx engine this lane runs, pinned as one unit. The SDK (the host side of the engine ABI)
// and the wasm module (the guest side) must come from the same cgx commit: a module built from
// another commit can import host functions this SDK does not provide, or the reverse, and then
// fails at instantiation or, worse, mid-index. So the two are pinned together, here and nowhere
// else, and a re-pin changes both lines in one edit: PinnedSDKVersion must equal the require in
// plugins/cfamily/go.mod (a test checks it), and PinnedWasmSHA256 is the SHA-256 of the module
// built from that same commit. A module, or an SDK in the build, that does not match is refused
// as tool_failure:cgx_engine_mismatch before anything runs.
const (
	// SDKModule is the cgx Go SDK's module path.
	SDKModule = "github.com/ferralon-ai/cgx/sdk/go"
	// PinnedSDKVersion is the SDK pseudo-version, cgx commit 6eb2990f5280.
	PinnedSDKVersion = "v0.0.0-20261012234334-6eb2990f5280"
	// PinnedWasmSHA256 is the SHA-256 of cgx.wasm built from the same commit.
	PinnedWasmSHA256 = "af1f079fd5acaf7f21f56505fe0ca0d2f3a4a7660f0e8f4528b6b40df1b706c3"
)

// readBuildInfo is debug.ReadBuildInfo, swappable in tests.
var readBuildInfo = debug.ReadBuildInfo

// checkSDKBuild confirms the SDK linked into this binary is PinnedSDKVersion, unreplaced, so the
// module pinned beside it is the one it speaks to. A binary with no build info, or with the SDK
// missing from it, cannot show the coupling and is refused the same way.
func checkSDKBuild() error {
	info, ok := readBuildInfo()
	if !ok {
		return fmt.Errorf("%w: no build info to confirm the cgx SDK is %s", ErrEngineMismatch, PinnedSDKVersion)
	}
	for _, dep := range info.Deps {
		if dep.Path != SDKModule {
			continue
		}
		if dep.Replace != nil {
			return fmt.Errorf("%w: the cgx SDK is replaced by %s %s; the engine is pinned to SDK %s", ErrEngineMismatch, dep.Replace.Path, dep.Replace.Version, PinnedSDKVersion)
		}
		if dep.Version != PinnedSDKVersion {
			return fmt.Errorf("%w: the cgx SDK in this build is %s; the engine is pinned to SDK %s", ErrEngineMismatch, dep.Version, PinnedSDKVersion)
		}
		return nil
	}
	return fmt.Errorf("%w: the cgx SDK is not in this build's dependencies", ErrEngineMismatch)
}
