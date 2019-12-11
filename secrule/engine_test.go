package secrule

import (
	"azwaf/testutils"
	"azwaf/waf"
	"testing"

	"github.com/rs/zerolog"
)

func TestSecRuleEngineEvalRequest(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	rsf := &mockReqScannerFactory{}
	rl := newMockRuleLoader()
	ref := &mockRuleEvaluatorFactory{}
	reslog := &mockResultsLogger{}
	ef := NewEngineFactory(logger, rl, rsf, ref)
	e, err := ef.NewEngine(&mockSecRuleConfig{})
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	req := &mockWafHTTPRequest{}

	// Act
	ev := e.NewEvaluation(logger, reslog, req)
	err = ev.ScanHeaders()
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	r := ev.EvalRules(2)

	// Assert
	if r != waf.Pass {
		t.Fatalf("EvalRequest did not return pass")
	}
}

type mockSecRuleConfig struct{}

func (c *mockSecRuleConfig) Enabled() bool     { return false }
func (c *mockSecRuleConfig) RuleSetID() string { return "some ruleset" }

type mockResultsLogger struct {
}

func (l *mockResultsLogger) SecRuleTriggered(ruleID int, decision waf.Decision, msg string, logData string, ruleSetID waf.RuleSetID) {
	return
}

type mockReqScanner struct {
}

func (r *mockReqScanner) NewReqScannerEvaluation(scratchSpace *ReqScannerScratchSpace) ReqScannerEvaluation {
	return &mockReqScannerEvaluation{}
}

func (r *mockReqScanner) NewScratchSpace() (scratchSpace *ReqScannerScratchSpace, err error) {
	s := make(ReqScannerScratchSpace)
	scratchSpace = &s
	return
}

type mockReqScannerEvaluation struct {
}

func (r *mockReqScannerEvaluation) ScanHeaders(req waf.HTTPRequest, results *ScanResults) (err error) {
	return
}
func (r *mockReqScannerEvaluation) ScanBodyField(contentType waf.ContentType, fieldName string, data string, results *ScanResults) (err error) {
	return
}

type mockReqScannerFactory struct {
}

func (f *mockReqScannerFactory) NewReqScanner(statements []Statement) (r ReqScanner, err error) {
	r = &mockReqScanner{}
	return
}

type mockRuleEvaluatorFactory struct{}

func (r *mockRuleEvaluatorFactory) NewRuleEvaluator(logger zerolog.Logger, perRequestEnv *environment, statements []Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) RuleEvaluator {
	return &mockRuleEvaluator{}
}

type mockRuleEvaluator struct{}

func (r *mockRuleEvaluator) ProcessPhase(phase int) (decision waf.Decision) {
	decision = waf.Pass
	return
}

func (r *mockRuleEvaluator) IsForceRequestBodyScanning() bool {
	return false
}
