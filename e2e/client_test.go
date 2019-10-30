package e2e

import (
	pb "azwaf/proto"
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
