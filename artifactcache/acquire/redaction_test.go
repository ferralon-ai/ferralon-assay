package acquire

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
	"github.com/ferralon-ai/ferralon-assay/checkout"
)

const secretTok = "REGISTRY_SECRET_TOKEN_v1_MUSTNOTLEAK"

// Test 3.1: RegistryCredentials (value) and a map-of-Credentials redact under every fmt verb —
// value receivers (security-gate change #2) mean formatting goes through the redacting String,
// never a raw map dump.
func TestRegistryCredentialsRedactUnderFmtVerbs(t *testing.T) {
	rc := NewRegistryCredentials(map[string]checkout.Credential{
		"registry.npmjs.org": checkout.NewCredential(secretTok),
		"nuget.pkg.test":     checkout.NewCredential(""),
	})
	rawMap := map[string]checkout.Credential{"h": checkout.NewCredential(secretTok)}

	for _, verb := range []string{"%v", "%s", "%#v", "%+v", "%q"} {
		if out := fmt.Sprintf(verb, rc); strings.Contains(out, secretTok) {
			t.Fatalf("RegistryCredentials leaked token under %s: %s", verb, out)
		}
		if out := fmt.Sprintf(verb, rawMap); strings.Contains(out, secretTok) {
			t.Fatalf("map-of-Credentials leaked token under %s: %s", verb, out)
		}
	}
}

// Test 3.2: a PolicyReason / IntegrityReason error that WRAPS a struct embedding a Credential
// never leaks the token under Error()/%v/%#v.
func TestReasonWrappingCredentialDoesNotLeak(t *testing.T) {
	cred := checkout.NewCredential(secretTok)
	// Emulate the worst case: a reason interpolated alongside a credential into a wrapped error.
	pr := &artifactcache.PolicyReason{PURL: "pkg:npm/x@1", Host: "registry.npmjs.org", Code: artifactcache.PolicyOffAllowlist}
	wrapped := fmt.Errorf("acquire refused (%w) while holding cred %v / %#v", pr, cred, cred)
	for _, s := range []string{wrapped.Error(), fmt.Sprintf("%v", wrapped), fmt.Sprintf("%#v", wrapped)} {
		if strings.Contains(s, secretTok) {
			t.Fatalf("wrapped reason leaked token: %s", s)
		}
	}
	// The reason itself is secret-free by construction (holds no credential).
	if strings.Contains(pr.Error(), secretTok) {
		t.Fatalf("PolicyReason.Error leaked token")
	}
}

// Test 3.3: AcquisitionRecord carries no token and its Source has no userinfo.
func TestAcquisitionRecordSecretFree(t *testing.T) {
	rec := AcquisitionRecord{
		PURL:       "pkg:nuget/Newtonsoft.Json@13.0.3",
		Source:     "https://registry.nuget.test/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg",
		Digest:     "sha512:abc",
		Canonical:  "sha512:deadbeef",
		AcquiredAt: time.Now(),
	}
	for _, verb := range []string{"%v", "%s", "%+v", "%#v"} {
		out := fmt.Sprintf(verb, rec)
		if strings.Contains(out, secretTok) {
			t.Fatalf("record leaked a token under %s", verb)
		}
		if strings.Contains(out, "@") && strings.Contains(out, "://") {
			// crude userinfo probe: no user:pass@host in the source
			if idx := indexUserinfo(rec.Source); idx >= 0 {
				t.Fatalf("record Source carries userinfo: %s", rec.Source)
			}
		}
	}
}
