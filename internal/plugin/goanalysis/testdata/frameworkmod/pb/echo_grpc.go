// Package pb mirrors what protoc-gen-go-grpc generates for a service: the server
// interface, the Unimplemented base an implementation embeds, and the registrar.
package pb

import (
	"context"

	"google.golang.org/grpc"
)

type Msg struct{ Body string }

// EchoServer is the service interface.
type EchoServer interface {
	Echo(context.Context, *Msg) (*Msg, error)
	Ping(context.Context, *Msg) (*Msg, error)
	mustEmbedUnimplementedEchoServer()
}

// UnimplementedEchoServer answers every method Unimplemented.
type UnimplementedEchoServer struct{}

func (UnimplementedEchoServer) Echo(context.Context, *Msg) (*Msg, error) { return nil, nil }
func (UnimplementedEchoServer) Ping(context.Context, *Msg) (*Msg, error) { return nil, nil }
func (UnimplementedEchoServer) mustEmbedUnimplementedEchoServer()        {}

// RegisterEchoServer is the generated registrar.
func RegisterEchoServer(s grpc.ServiceRegistrar, srv EchoServer) {
	s.RegisterService(&grpc.ServiceDesc{ServiceName: "pb.Echo"}, srv)
}

// LegacyServer is a service whose generated registrar takes the concrete *grpc.Server.
type LegacyServer interface {
	Old(context.Context, *Msg) (*Msg, error)
}

func RegisterLegacyServer(s *grpc.Server, srv LegacyServer) {
	s.RegisterService(&grpc.ServiceDesc{ServiceName: "pb.Legacy"}, srv)
}
