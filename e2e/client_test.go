package e2e

import (
	pb "azwaf/proto"
	"context"
	"testing"

	"google.golang.org/grpc"
)

const address = "passthrough:///unix:///tmp/azwaf.sock"

func newWafServiceClient(t *testing.T) pb.WafServiceClient {
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	client := pb.NewWafServiceClient(conn)
	return client
}

func evalRequest(ctx context.Context, t *testing.T, c pb.WafServiceClient, r *pb.WafHttpRequest) (wafDecision *pb.WafDecision) {
	requests := []*pb.WafHttpRequest{ r }
	return evalMultiChunkRequest(ctx, t, c, requests) 
}

func evalMultiChunkRequest(ctx context.Context, t *testing.T, c pb.WafServiceClient, r []*pb.WafHttpRequest) (wafDecision *pb.WafDecision) {
	erStream, err := c.EvalRequest(ctx, grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	for i := 0; i < len(r); i++ {
		err = erStream.Send(r[i])
		if err != nil {
			t.Fatalf("Got unexpected error: %v", err)
		}
	}

	wafDecision, err = erStream.CloseAndRecv()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}
	return
}
