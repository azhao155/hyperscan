package secrule

import (
	"azwaf/waf"
	"testing"
)

func TestSecRuleEngineEvalRequest(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rl := newMockRuleLoader()
	re := NewRuleEvaluator()
	reslog := &mockResultsLogger{}
	ef := NewEngineFactory(rl, rsf, re, reslog)
	e, err := ef.NewEngine(&mockSecRuleConfig{})
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	req := &mockWafHTTPRequest{uri: "/hello.php?arg1=aaaaaaabccc"}

	// Act
	r := e.EvalRequest(req)

	// Assert
	if !r {
		t.Fatalf("EvalRequest did not return true")
	}
}

type mockSecRuleConfig struct{}

func (c *mockSecRuleConfig) ID() string        { return "SecRuleConfig1" }
func (c *mockSecRuleConfig) Enabled() bool     { return false }
func (c *mockSecRuleConfig) RuleSetID() string { return "some ruleset" }

type mockResultsLogger struct{}

func (l *mockResultsLogger) SecRuleTriggered(request waf.HTTPRequest, stmt Statement, action string, msg string, logData string) {
	return
}
