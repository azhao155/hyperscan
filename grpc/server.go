package grpc

import (
	pb "azwaf/proto"
	"azwaf/waf"

	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// Server is an AzWaf gRPC server.
type Server interface {
	Serve() error
}

type serverImpl struct {
	ws waf.Server
}

// NewServer creates a new AzWaf gRPC server.
func NewServer(ws waf.Server) Server {
	return &serverImpl{ws}
}

func (s *serverImpl) EvalRequest(ctx context.Context, in *pb.WafHttpRequest) (d *pb.WafDecision, err error) {
	allow, err := s.ws.EvalRequest(&wafHTTPRequestPbWrapper{pb: in})
	if err != nil {
		return
	}

	d = &pb.WafDecision{Allow: allow}
	return
}

func (s *serverImpl) Serve() error {
	lis, err := net.Listen("tcp", ":37291")
	if err != nil {
		return fmt.Errorf("Failed to listen: %v", err)
	}

	gs := grpc.NewServer()
	pb.RegisterWafServiceServer(gs, s)
	reflection.Register(gs)
	if err := gs.Serve(lis); err != nil {
		return fmt.Errorf("Failed to serve: %v", err)
	}

	return nil
}
