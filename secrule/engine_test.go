package secrule

import (
	pb "azwaf/proto"

	"testing"
)

func TestSecRuleEngineEvalRequest(t *testing.T) {
	// Arrange
	e := &engineImpl{"site1"}
	req := &pb.WafHttpRequest{}

	// Act
	r := e.EvalRequest(req)

	// Assert
	if !r {
		t.Fatalf("EvalRequest did not return true")
	}
}
