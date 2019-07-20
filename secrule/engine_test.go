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
	r := e.EvalRequest(logger, req)

	// Assert
	if r != true {
		t.Fatalf("EvalRequest did not return true")
	}
}

func TestSecRuleEngineEvalRequestTooLongField(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	rsf := &mockReqScannerFactory{scanCb: func(req waf.HTTPRequest) (results *ScanResults, err error) {
		results = &ScanResults{}
		err = errFieldBytesLimitExceeded
		return
	}}
	rl := newMockRuleLoader()
	re := &mockRuleEvaluator{}
	wasResultsLoggerCalled := false
	reslog := &mockResultsLogger{cb: func(request waf.HTTPRequest, stmt Statement, action string, msg string, logData string) {
		wasResultsLoggerCalled = true
		if msg != "Request body contained a field longer than the limit (1000 bytes)" {
			t.Fatalf("Unexpected results logger msg: %v", msg)
		}
	}}
	ef := NewEngineFactory(logger, rl, rsf, re, reslog)
	e, err := ef.NewEngine(&mockSecRuleConfig{})
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	req := &mockWafHTTPRequest{}

	// Act
	r := e.EvalRequest(logger, req)

	// Assert
	if r != false {
		t.Fatalf("EvalRequest did not return false")
	}

	if !wasResultsLoggerCalled {
		t.Fatalf("Results logger was not called")
	}
}

func TestSecRuleEngineEvalRequestTooLongBodyExcludingFiles(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	rsf := &mockReqScannerFactory{scanCb: func(req waf.HTTPRequest) (results *ScanResults, err error) {
		results = &ScanResults{}
		err = errPausableBytesLimitExceeded
		return
	}}
	rl := newMockRuleLoader()
	re := &mockRuleEvaluator{}
	wasResultsLoggerCalled := false
	reslog := &mockResultsLogger{cb: func(request waf.HTTPRequest, stmt Statement, action string, msg string, logData string) {
		wasResultsLoggerCalled = true
		if msg != "Request body length (excluding file upload fields) exceeded the limit (2000 bytes)" {
			t.Fatalf("Unexpected results logger msg: %v", msg)
		}
	}}
	ef := NewEngineFactory(logger, rl, rsf, re, reslog)
	e, err := ef.NewEngine(&mockSecRuleConfig{})
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	req := &mockWafHTTPRequest{}

	// Act
	r := e.EvalRequest(logger, req)

	// Assert
	if r != false {
		t.Fatalf("EvalRequest did not return false")
	}

	if !wasResultsLoggerCalled {
		t.Fatalf("Results logger was not called")
	}
}

func TestSecRuleEngineEvalRequestTooLongTotal(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	rsf := &mockReqScannerFactory{scanCb: func(req waf.HTTPRequest) (results *ScanResults, err error) {
		results = &ScanResults{}
		err = errTotalBytesLimitExceeded
		return
	}}
	rl := newMockRuleLoader()
	re := &mockRuleEvaluator{}
	wasResultsLoggerCalled := false
	reslog := &mockResultsLogger{cb: func(request waf.HTTPRequest, stmt Statement, action string, msg string, logData string) {
		wasResultsLoggerCalled = true
		if msg != "Request body length exceeded the limit (3000 bytes)" {
			t.Fatalf("Unexpected results logger msg: %v", msg)
		}
	}}
	ef := NewEngineFactory(logger, rl, rsf, re, reslog)
	e, err := ef.NewEngine(&mockSecRuleConfig{})
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	req := &mockWafHTTPRequest{}

	// Act
	r := e.EvalRequest(logger, req)

	// Assert
	if r != false {
		t.Fatalf("EvalRequest did not return false")
	}

	if !wasResultsLoggerCalled {
		t.Fatalf("Results logger was not called")
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
	scanCb func(req waf.HTTPRequest) (results *ScanResults, err error)
}

func (r *mockReqScanner) Scan(req waf.HTTPRequest) (results *ScanResults, err error) {
	if r.scanCb != nil {
		return r.scanCb(req)
	}

	results = &ScanResults{}
	return
}

func (r *mockReqScanner) LengthLimits() LengthLimits {
	return LengthLimits{1000, 2000, 3000}
}

type mockReqScannerFactory struct {
	scanCb func(req waf.HTTPRequest) (results *ScanResults, err error)
}

func (f *mockReqScannerFactory) NewReqScanner(statements []Statement) (r ReqScanner, err error) {
	r = &mockReqScanner{scanCb: f.scanCb}
	return
}

type mockRuleEvaluator struct{}

func (r *mockRuleEvaluator) Process(logger zerolog.Logger, perRequestEnv envMap, statements []Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) (allow bool, statusCode int, err error) {
	allow = true
	return
}
