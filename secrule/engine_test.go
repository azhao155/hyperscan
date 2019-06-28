package secrule

import (
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
	req := &mockWafHTTPRequest{}

	// Act
	r := e.EvalRequest(req)

	// Assert
	if !r {
		t.Fatalf("EvalRequest did not return true")
	}
}
