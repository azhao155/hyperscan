package server

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "azwaf/proto"
)

type server struct{}

func (s *server) EvalRequest(ctx context.Context, in *pb.WafHttpRequest) (*pb.WafDecision, error) {
	log.Printf("Received: %v", in.Uri)
	return &pb.WafDecision{Allow: true}, nil
}

func Start() {
	lis, err := net.Listen("tcp", ":37291")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterWafServiceServer(s, &server{})
	reflection.Register(s)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
