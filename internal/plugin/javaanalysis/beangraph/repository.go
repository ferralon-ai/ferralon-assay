package beangraph

import "github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"

// This file is the repository TYPE-MODEL the #3 repo-sink overlay consumes: which types
// are Spring Data repositories (an interface transitively extending a *Repository base).
// Foundation exposes only the classifier INPUT — the set of repository types; the #3
// overlay owns the sink marking and raises PartialReasonRepositorySynthesized (edge-seam.md
// §4). A repository's methods are body-absent DB sinks (the impl is runtime-synthesized),
// so the overlay must not claim value-flow through them.

// repositoryBaseNames are the Spring Data base interfaces, matched by SIMPLE name
// (namespace-agnostic — Spring Data, JPA, Mongo, R2DBC, reactive variants all share this
// shape). A type transitively extending any of these is a repository whose methods are
// synthesized at runtime.
var repositoryBaseNames = map[string]bool{
	"Repository":                 true,
	"CrudRepository":             true,
	"PagingAndSortingRepository": true,
	"JpaRepository":              true,
	"ReactiveCrudRepository":     true,
	"ReactiveSortingRepository":  true,
	"RxJava3CrudRepository":      true,
	"MongoRepository":            true,
	"R2dbcRepository":            true,
	"ElasticsearchRepository":    true,
	"CassandraRepository":        true,
	"JpaSpecificationExecutor":   true,
	"QuerydslPredicateExecutor":  true,
	"CoroutineCrudRepository":    true,
	"CoroutineSortingRepository": true,
}

// IsRepositoryBaseName reports whether a simple type name is one of the Spring Data base
// repository interfaces. Exposed so a lane's own scanner (the Java source repo detector)
// can share the base set rather than re-declare it.
func IsRepositoryBaseName(simpleName string) bool { return repositoryBaseNames[simpleName] }

// RepositoryTypesFromClasses returns the internal names of every type in the class set
// that is a Spring Data repository — a type whose transitive supertype closure (over the
// classes provided) reaches a *Repository base, OR that directly extends one by simple
// name even when the base's own class is not in the set (the common case: a first-party
// FooRepository extends the dependency-declared JpaRepository). It is the classifier
// INPUT for the #3 overlay, which maps a resolved sink's owner type against this set.
func RepositoryTypesFromClasses(classes []classfile.Class) map[string]bool {
	byName := make(map[string]*classfile.Class, len(classes))
	for i := range classes {
		byName[classes[i].Name] = &classes[i]
	}
	out := map[string]bool{}
	for i := range classes {
		if reachesRepositoryBase(classes[i].Name, byName) {
			out[classes[i].Name] = true
		}
	}
	return out
}

// reachesRepositoryBase reports whether typeName transitively extends/implements a
// repository base. A supertype whose class is absent from the set is matched by its
// simple name (so `extends JpaRepository` is detected without Spring Data on the path).
func reachesRepositoryBase(typeName string, byName map[string]*classfile.Class) bool {
	seen := map[string]bool{}
	stack := []string{typeName}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if cur == "" || seen[cur] {
			continue
		}
		seen[cur] = true
		if cur != typeName && repositoryBaseNames[SimpleTypeName(cur)] {
			return true
		}
		c := byName[cur]
		if c == nil {
			// Out-of-set supertype: match by simple name (the dependency-declared base).
			if repositoryBaseNames[SimpleTypeName(cur)] && cur != typeName {
				return true
			}
			continue
		}
		if c.Super != "" {
			stack = append(stack, c.Super)
		}
		stack = append(stack, c.Interfaces...)
	}
	return false
}
