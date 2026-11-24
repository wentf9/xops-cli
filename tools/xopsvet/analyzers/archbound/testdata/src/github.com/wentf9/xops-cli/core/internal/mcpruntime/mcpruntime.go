package mcpruntime

import (
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/usecase/session"
	"github.com/wentf9/xops-cli/core/ports"
)

type Server struct {
	FS ports.ScopedRootFS
	G  *gate.Gate
	S  *session.Service
}

func NewServer(s *session.Service) *Server {
	return &Server{S: s}
}
