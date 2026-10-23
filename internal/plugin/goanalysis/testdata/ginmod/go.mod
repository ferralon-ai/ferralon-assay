module tegron.test/ginmod

go 1.26

require (
	github.com/gin-gonic/gin v1.10.0
	tegron.test/nethttp v0.0.0
)

// Hermetic stand-ins: the gin ingress detector matches the package PATH
// github.com/gin-gonic/gin; the local stub supplies that path with no network fetch.
// tegron.test/nethttp stands in for the net/http types gin's API uses (see
// nethttpstub/http.go for why).
replace (
	github.com/gin-gonic/gin => ./ginstub
	tegron.test/nethttp => ./nethttpstub
)
