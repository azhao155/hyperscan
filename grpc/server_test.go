package grpc

import (
	pb "azwaf/proto"

	"testing"
)

type mockWafServer struct {
	evalRequestCalled int
}

func (m *mockWafServer) EvalRequest(req *pb.WafHttpRequest) (*pb.WafDecision, error) {
	m.evalRequestCalled++
	return &pb.WafDecision{Allow: true}, nil
}

func TestGrpcServerEvalRequest(t *testing.T) {
	// Arrange
	mw := &mockWafServer{}
	s := &serverImpl{mw}
	req := &pb.WafHttpRequest{}

	// Act
	s.EvalRequest(nil, req)

	// Assert
	if mw.evalRequestCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockWafServer.EvalRequest")
	}
}
