module tegron.test/frameworkmod

go 1.26

require (
	github.com/beego/beego/v2 v2.3.8
	github.com/emicklei/go-restful/v3 v3.12.2
	github.com/gorilla/websocket v1.5.3
	google.golang.org/grpc v1.70.0
	tegron.test/nethttp v0.0.0
)

// Hermetic stand-ins: the framework ingress detector matches the package PATHS of
// beego, go-restful, gorilla/websocket and gRPC; the local stubs supply those paths
// with no network fetch. tegron.test/nethttp stands in for the net/http types their
// APIs use (see ../chimod/nethttpstub/http.go for why).
replace (
	github.com/beego/beego/v2 => ./beegostub
	github.com/emicklei/go-restful/v3 => ./restfulstub
	github.com/gorilla/websocket => ./wsstub
	google.golang.org/grpc => ./grpcstub
	tegron.test/nethttp => ../chimod/nethttpstub
)
