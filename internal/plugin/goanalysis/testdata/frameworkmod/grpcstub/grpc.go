// Package grpc mirrors the registrar types a generated Register<Service>Server takes.
package grpc

// ServiceDesc mirrors grpc.ServiceDesc.
type ServiceDesc struct{ ServiceName string }

// ServiceRegistrar mirrors grpc.ServiceRegistrar.
type ServiceRegistrar interface {
	RegisterService(desc *ServiceDesc, impl any)
}

// Server mirrors grpc.Server.
type Server struct{}

func NewServer() *Server                                      { return &Server{} }
func (s *Server) RegisterService(desc *ServiceDesc, impl any) {}
