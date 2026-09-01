package javaanalysis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// repoFixtureProgram parses a fixture module containing a Spring Data repository
// interface (a derived-query finder + an @Query method, both body-absent) alongside a
// non-repository service, and returns the loaded program.
func repoFixtureProgram(t *testing.T) *program {
	t.Helper()
	dir := t.TempDir()
	src := `package com.example;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

interface UserRepository extends JpaRepository<User, Long> {
	List<User> findByName(String name);

	@Query("SELECT u FROM User u WHERE u.email = ?1")
	User lookup(String email);

	interface Projection {
		String render(String raw);
	}
}

class UserService {
	User load(String name) {
		return null;
	}
}
`
	if err := os.WriteFile(filepath.Join(dir, "UserRepository.java"), []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	prog, err := loadProgram(dir)
	if err != nil {
		t.Fatalf("loadProgram: %v", err)
	}
	if !prog.repositoryTypes["UserRepository"] {
		t.Fatalf("fixture precondition: UserRepository not recognized as a repository type (%v)", prog.repositoryTypes)
	}
	return prog
}

// TestRepositorySinkClassifier flags a method declared directly on a Spring Data
// repository type (derived-query finder and @Query method alike) with
// repository_synthesized_sink, and leaves non-repository methods and methods on types
// nested inside the repository unflagged. Assertions are CONTAINS, never set-equality.
func TestRepositorySinkClassifier(t *testing.T) {
	prog := repoFixtureProgram(t)
	classify := newRepositorySinkClassifier(prog)

	tests := []struct {
		name     string
		sink     string
		wantRepo bool
	}{
		{
			name:     "derived-query finder is a synthesized sink",
			sink:     methodSCIP("com.example", []string{"UserRepository"}, "findByName", 1),
			wantRepo: true,
		},
		{
			name:     "@Query method is a synthesized sink",
			sink:     methodSCIP("com.example", []string{"UserRepository"}, "lookup", 1),
			wantRepo: true,
		},
		{
			name:     "non-repository service method is not a synthesized sink",
			sink:     methodSCIP("com.example", []string{"UserService"}, "load", 1),
			wantRepo: false,
		},
		{
			name:     "method on a type nested inside the repository is not the repo's sink",
			sink:     methodSCIP("com.example", []string{"UserRepository", "Projection"}, "render", 1),
			wantRepo: false,
		},
		{
			name:     "unrelated id is untouched",
			sink:     "not even a scip id",
			wantRepo: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reasons := classify(tt.sink)
			if got := containsReason(reasons, plugin.PartialReasonRepositorySynthesized); got != tt.wantRepo {
				t.Errorf("classify(%q) repository_synthesized_sink = %v, want %v (reasons=%v)", tt.sink, got, tt.wantRepo, reasons)
			}
		})
	}
}

// TestRepositorySinkThroughFirstPartyPaths proves the reason surfaces through the H3
// registry (init-registered) on the real firstPartyPaths path, independent of whether a
// path reaches the sink. CONTAINS, not set-equality: other partiality (e.g. no_known_ingress)
// legitimately coexists.
func TestRepositorySinkThroughFirstPartyPaths(t *testing.T) {
	prog := repoFixtureProgram(t)
	sink := methodSCIP("com.example", []string{"UserRepository"}, "findByName", 1)

	_, reasons := firstPartyPaths(prog, plugin.CallGraphResult{}, plugin.IngressResult{}, []string{sink})
	if !reasons[plugin.PartialReasonRepositorySynthesized] {
		t.Errorf("repository_synthesized_sink absent from firstPartyPaths reasons: %v", reasons)
	}

	// A non-repository sink draws no repository_synthesized_sink.
	nonRepo := methodSCIP("com.example", []string{"UserService"}, "load", 1)
	_, reasons = firstPartyPaths(prog, plugin.CallGraphResult{}, plugin.IngressResult{}, []string{nonRepo})
	if reasons[plugin.PartialReasonRepositorySynthesized] {
		t.Errorf("repository_synthesized_sink surfaced for a non-repository sink: %v", reasons)
	}
}

// TestRepositorySinkClassifierNoRepositories returns a no-op classifier when the program
// has no repository types, so the default behavior stays byte-identical.
func TestRepositorySinkClassifierNoRepositories(t *testing.T) {
	classify := newRepositorySinkClassifier(&program{})
	if r := classify("anything"); r != nil {
		t.Errorf("empty program classifier returned %v, want nil", r)
	}
	if r := newRepositorySinkClassifier(nil)("anything"); r != nil {
		t.Errorf("nil program classifier returned %v, want nil", r)
	}
}

func containsReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}
