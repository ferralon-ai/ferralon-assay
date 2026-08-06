package verdict

import (
	"regexp"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

// TestPoEVersionAlignedWithRegistry catches drift between verdict.SchemaVersion and
// the artifact Registry's TypePoE entry. It lives in the verdict package (which may
// import artifact) so no artifact->verdict import cycle is introduced.
func TestPoEVersionAlignedWithRegistry(t *testing.T) {
	meta, ok := artifact.Lookup(artifact.TypePoE)
	if !ok {
		t.Fatal("TypePoE missing from artifact.Registry")
	}
	if meta.SchemaVersion != SchemaVersion {
		t.Fatalf("registry TypePoE version = %q, verdict.SchemaVersion = %q", meta.SchemaVersion, SchemaVersion)
	}
}

// TestPoEVersionFollowsConvention asserts the PoE version string follows the same
// tegron.<type>.v<N> convention the registry enforces for every other type.
func TestPoEVersionFollowsConvention(t *testing.T) {
	re := regexp.MustCompile(`^tegron\.[a-z_]+\.v\d+$`)
	if !re.MatchString(SchemaVersion) {
		t.Fatalf("verdict.SchemaVersion %q does not match %s", SchemaVersion, re)
	}
}
