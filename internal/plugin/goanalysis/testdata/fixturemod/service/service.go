// Package service exposes a Service type whose Handle method calls util.Sink.
package service

import "tegron.test/fixturemod/util"

// Service is an exported struct type with an exported method.
type Service struct {
	Name string
}

// New constructs a Service.
func New(name string) *Service {
	return &Service{Name: name}
}

// Handle processes a request and forwards it to util.Sink.
func (s *Service) Handle(req string) string {
	return util.Sink(s.Name + ":" + req)
}
