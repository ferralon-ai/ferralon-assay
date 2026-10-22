module tegron.test/chimod

go 1.26

require (
	github.com/go-chi/chi v1.5.5
	github.com/go-chi/chi/v5 v5.0.0
	tegron.test/nethttp v0.0.0
)

// Hermetic stand-ins: the chi ingress detector matches the package PATHS
// github.com/go-chi/chi and github.com/go-chi/chi/v5; the local stubs supply those
// paths with no network fetch. tegron.test/nethttp stands in for the net/http types
// chi's API uses (see nethttpstub/http.go for why).
replace (
	github.com/go-chi/chi => ./chistub
	github.com/go-chi/chi/v5 => ./chiv5stub
	tegron.test/nethttp => ./nethttpstub
)
