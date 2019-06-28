package grpc

import (
	pb "azwaf/proto"
	"azwaf/waf"
	"testing"
)

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

type mockWafServer struct {
	evalRequestCalled int
}

func (m *mockWafServer) EvalRequest(req waf.HTTPRequest) (bool, error) {
	m.evalRequestCalled++
	return true, nil
}
