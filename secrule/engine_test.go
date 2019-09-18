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
	re := &mockRuleEvaluator{}
	reslog := &mockResultsLogger{}
	ef := NewEngineFactory(logger, rl, rsf, re, reslog)
	e, err := ef.NewEngine(&mockSecRuleConfig{})
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	req := &mockWafHTTPRequest{}

	// Act
	ev := e.NewEvaluation(logger, req)
	err = ev.ScanHeaders()
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	r := ev.EvalRules()

	// Assert
	if r != waf.Pass {
		t.Fatalf("EvalRequest did not return pass")
	}
}

type mockSecRuleConfig struct{}

func (c *mockSecRuleConfig) Enabled() bool     { return false }
func (c *mockSecRuleConfig) RuleSetID() string { return "some ruleset" }

type mockResultsLogger struct {
	cb func(request waf.HTTPRequest, stmt Statement, action string, msg string, logData string)
}

func (l *mockResultsLogger) SecRuleTriggered(request waf.HTTPRequest, stmt Statement, action string, msg string, logData string) {
	if l.cb != nil {
		l.cb(request, stmt, action, msg, logData)
	}

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

func (r *mockReqScannerEvaluation) ScanHeaders(req waf.HTTPRequest) (results *ScanResults, err error) {
	results = &ScanResults{}
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

type mockRuleEvaluator struct{}

func (r *mockRuleEvaluator) Process(logger zerolog.Logger, perRequestEnv envMap, statements []Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) (decision waf.Decision, statusCode int, err error) {
	decision = waf.Pass
	return
}
