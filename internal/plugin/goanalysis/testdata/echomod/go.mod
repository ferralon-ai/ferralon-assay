module tegron.test/echomod

go 1.26

require (
	github.com/labstack/echo/v4 v4.12.0
	tegron.test/nethttp v0.0.0
)

// Hermetic stand-ins: the echo ingress detector matches the package PATH
// github.com/labstack/echo/v4; the local stub supplies that path with no network
// fetch. tegron.test/nethttp stands in for the net/http types echo's API uses (see
// nethttpstub/http.go for why).
replace (
	github.com/labstack/echo/v4 => ./echostub
	tegron.test/nethttp => ./nethttpstub
)
