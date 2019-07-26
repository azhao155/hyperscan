package secrule

import (
	"azwaf/testutils"
	"azwaf/waf"
	"github.com/rs/zerolog"
	"testing"
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
	if r != true {
		t.Fatalf("EvalRequest did not return true")
	}
}

type mockSecRuleConfig struct{}

func (c *mockSecRuleConfig) ID() string        { return "SecRuleConfig1" }
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

func (r *mockReqScanner) ScanHeaders(req waf.HTTPRequest) (results *ScanResults, err error) {
	results = &ScanResults{}
	return
}
func (r *mockReqScanner) ScanBodyField(contentType waf.ContentType, fieldName string, data string, results *ScanResults) (err error) {
	return
}

type mockReqScannerFactory struct {
}

func (f *mockReqScannerFactory) NewReqScanner(statements []Statement) (r ReqScanner, err error) {
	r = &mockReqScanner{}
	return
}

type mockRuleEvaluator struct{}

func (r *mockRuleEvaluator) Process(logger zerolog.Logger, perRequestEnv envMap, statements []Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) (allow bool, statusCode int, err error) {
	allow = true
	return
}
