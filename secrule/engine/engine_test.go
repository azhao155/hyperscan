package engine

import (
	. "azwaf/secrule"
	. "azwaf/secrule/ast"

	"azwaf/testutils"
	"azwaf/waf"
	"io"
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
	ev := e.NewEvaluation(logger, reslog, req, waf.OtherBody)
	err = ev.ScanHeaders()
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	r1 := ev.EvalRulesPhase1()
	r2 := ev.EvalRulesPhase2to5(0)

	// Assert
	if r1 != waf.Pass || r2 != waf.Pass {
		t.Fatalf("EvalRequest did not return pass")
	}
}

func TestReqbodyProcessorValues(t *testing.T) {
	// If you change this number, make sure to add the corresponding test below as well.
	if len(reqbodyProcessorValues) != 5 {
		t.Fatalf("Unexpected len(reqbodyProcessorValues). You must update this test if you have changed reqbodyProcessorValues.")
	}

	s := reqbodyProcessorValues[waf.OtherBody].String()
	if s != "" {
		t.Fatalf("Unexpected reqbodyProcessorValues[waf.OtherBody]: %v", s)
	}

	s = reqbodyProcessorValues[waf.MultipartFormDataBody].String()
	if s != "MULTIPART" {
		t.Fatalf("Unexpected reqbodyProcessorValues[waf.MultipartFormDataBody]: %v", s)
	}

	s = reqbodyProcessorValues[waf.URLEncodedBody].String()
	if s != "URLENCODED" {
		t.Fatalf("Unexpected reqbodyProcessorValues[waf.URLEncodedBody]: %v", s)
	}

	s = reqbodyProcessorValues[waf.XMLBody].String()
	if s != "XML" {
		t.Fatalf("Unexpected reqbodyProcessorValues[waf.XMLBody]: %v", s)
	}

	s = reqbodyProcessorValues[waf.JSONBody].String()
	if s != "JSON" {
		t.Fatalf("Unexpected reqbodyProcessorValues[waf.JSONBody]: %v", s)
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
func (r *mockReqScannerEvaluation) ScanBodyField(contentType waf.FieldContentType, fieldName string, data string, results *ScanResults) (err error) {
	return
}

type mockReqScannerFactory struct {
}

func (f *mockReqScannerFactory) NewReqScanner(statements []Statement) (r ReqScanner, err error) {
	r = &mockReqScanner{}
	return
}

type mockRuleEvaluatorFactory struct{}

func (r *mockRuleEvaluatorFactory) NewRuleEvaluator(logger zerolog.Logger, perRequestEnv Environment, statements []Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) RuleEvaluator {
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

func newMockRuleLoader() RuleLoader {
	return &mockRuleLoader{}
}

type mockRuleLoader struct{}

func (m *mockRuleLoader) Rules(r waf.RuleSetID) (statements []Statement, err error) {
	statements = []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("ab+c")}},
				},
			},
		},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("abc+")}},
				},
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("xyz")}},
					Transformations: []Transformation{Lowercase},
				},
			},
		},
		&Rule{
			ID: 300,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: TargetRequestURIRaw}}, Op: Rx, Val: Value{StringToken("a+bc")}},
					Transformations: []Transformation{Lowercase, RemoveWhitespace},
				},
			},
		},
		&Rule{
			ID: 400,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetXML, Selector: "/*"}}, Op: Rx, Val: Value{StringToken("abc+")}},
				},
			},
		}}

	return
}

type mockWafHTTPRequest struct {
	uri        string
	bodyReader io.Reader
	headers    []waf.HeaderPair
}

func (r *mockWafHTTPRequest) Method() string                      { return "GET" }
func (r *mockWafHTTPRequest) URI() string                         { return r.uri }
func (r *mockWafHTTPRequest) Protocol() string                    { return "HTTP/1.1" }
func (r *mockWafHTTPRequest) RemoteAddr() string                  { return "0.0.0.0" }
func (r *mockWafHTTPRequest) ConfigID() string                    { return "SecRuleConfig1" }
func (r *mockWafHTTPRequest) Headers() []waf.HeaderPair           { return r.headers }
func (r *mockWafHTTPRequest) BodyReader() io.Reader               { return r.bodyReader }
func (r *mockWafHTTPRequest) LogMetaData() waf.RequestLogMetaData { return &mockLogMetaData{} }
func (r *mockWafHTTPRequest) TransactionID() string               { return "abc" }

type mockHeaderPair struct {
	k string
	v string
}

func (h *mockHeaderPair) Key() string   { return h.k }
func (h *mockHeaderPair) Value() string { return h.v }

type mockLogMetaData struct {
}

func (h *mockLogMetaData) Scope() string     { return "Global" }
func (h *mockLogMetaData) ScopeName() string { return "Default Policy" }
