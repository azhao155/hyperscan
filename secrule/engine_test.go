package secrule

import (
	pb "azwaf/proto"

	"testing"
)

func TestSecRuleEngineEvalRequest(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rl := newMockRuleLoader()
	ef := NewEngineFactory(rl, rsf)
	e, err := ef.NewEngine("some ruleset")
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	req := &pb.WafHttpRequest{Uri: "/hello.php?arg1=aaaaaaabccc"}

	// Act
	r := e.EvalRequest(req)

	// Assert
	if !r {
		t.Fatalf("EvalRequest did not return true")
	}
}
