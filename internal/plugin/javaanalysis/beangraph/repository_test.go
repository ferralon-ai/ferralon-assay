package beangraph

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

func TestRepositoryTypesFromClasses(t *testing.T) {
	classes := []classfile.Class{
		// Directly extends the (dependency-declared, out-of-set) JpaRepository base.
		{Name: "com/ex/UserRepo", Interfaces: []string{"org/springframework/data/jpa/repository/JpaRepository"}},
		// Transitive through a first-party custom base repository.
		{Name: "com/ex/CustomBase", Interfaces: []string{"org/springframework/data/repository/CrudRepository"}},
		{Name: "com/ex/OrderRepo", Interfaces: []string{"com/ex/CustomBase"}},
		// Not a repository.
		{Name: "com/ex/UserService", Interfaces: []string{"com/ex/BaseService"}},
	}
	got := RepositoryTypesFromClasses(classes)
	for _, want := range []string{"com/ex/UserRepo", "com/ex/CustomBase", "com/ex/OrderRepo"} {
		if !got[want] {
			t.Errorf("%s not classified as a repository; got %v", want, got)
		}
	}
	if got["com/ex/UserService"] {
		t.Errorf("UserService wrongly classified as a repository")
	}
	if got["com/ex/BaseService"] {
		t.Errorf("BaseService (out of set, not a repo base) wrongly classified")
	}
}

func TestIsRepositoryBaseName(t *testing.T) {
	if !IsRepositoryBaseName("JpaRepository") || !IsRepositoryBaseName("CrudRepository") {
		t.Error("known Spring Data base not recognized")
	}
	if IsRepositoryBaseName("UserRepo") {
		t.Error("a concrete repo interface is not a base name")
	}
}
