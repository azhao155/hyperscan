package waf

import (
	"azwaf/testutils"
	"bytes"
	"io"
	"testing"

	"github.com/rs/zerolog"
)

func TestWafServerEvalRequest(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	mrl := &mockResultsLogger{}
	msrev := &mockSecRuleEvaluation{}
	msre := &mockSecRuleEngine{msrev: msrev}
	msref := &mockSecRuleEngineFactory{msre: msre}
	mcre := &mockCustomRuleEngine{}
	mcref := &mockCustomRuleEngineFactory{mcre: mcre}
	c := make(map[int]Config)
	c[0] = &mockConfig{}
	mrbp := &mockRequestBodyParser{}
	mcm := &mockConfigMgr{}
	s, err := NewServer(logger, mcm, c, msref, mrbp, mrl, mcref)
	if err != nil {
		t.Fatalf("Error from NewServer: %s", err)
	}
	req := &mockWafHTTPRequest{}

	// Act
	s.EvalRequest(req)

	// Assert
	if msref.newEngineCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockSecRuleEngineFactory.NewEngine: %v", msref.newEngineCalled)
	}

	if msre.newEvaluationCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockSecRuleEngine.NewEvaluation: %v", msre.newEvaluationCalled)
	}

	if msrev.scanHeadersCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockSecRuleEvaluation.ScanHeaders: %v", msrev.scanHeadersCalled)
	}

	if msrev.scanBodyFieldCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockSecRuleEvaluation.ScanBodyField: %v", msrev.scanBodyFieldCalled)
	}

	if msrev.evalRulesCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockSecRuleEvaluation.EvalRules: %v", msrev.evalRulesCalled)
	}

	if msrev.closeCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockSecRuleEvaluation.Close: %v", msrev.closeCalled)
	}
}

func TestSecRuleEngineEvalRequestTooLongField(t *testing.T) {
	testBytesLimit(t, ErrFieldBytesLimitExceeded, 1, 0, 0)
}

func TestSecRuleEngineEvalRequestTooLongBodyExcludingFiles(t *testing.T) {
	testBytesLimit(t, ErrPausableBytesLimitExceeded, 0, 1, 0)
}

func TestSecRuleEngineEvalRequestTooLongTotal(t *testing.T) {
	testBytesLimit(t, ErrTotalBytesLimitExceeded, 0, 0, 1)
}

func testBytesLimit(t *testing.T, expectedErr error, expectedFieldBytesLimitExceededCalled int, expectedPausableBytesLimitExceededCalled int, expectedTotalBytesLimitExceededCalled int) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	mrl := &mockResultsLogger{}
	msrev := &mockSecRuleEvaluation{}
	msre := &mockSecRuleEngine{msrev: msrev}
	msref := &mockSecRuleEngineFactory{msre: msre}
	mcre := &mockCustomRuleEngine{}
	mcref := &mockCustomRuleEngineFactory{mcre: mcre}
	c := make(map[int]Config)
	c[0] = &mockConfig{}
	mrbp := &mockRequestBodyParser{
		parseCb: func(logger zerolog.Logger, req HTTPRequest, cb ParsedBodyFieldCb) (err error) {
			err = expectedErr
			return
		},
	}
	mcm := &mockConfigMgr{}
	s, err := NewServer(logger, mcm, c, msref, mrbp, mrl, mcref)
	if err != nil {
		t.Fatalf("Unexpected error from NewServer: %s", err)
	}

	req := &mockWafHTTPRequest{}

	// Act
	r, err := s.EvalRequest(req)

	// Assert
	if err != expectedErr {
		t.Fatalf("Unexpected error from EvalRequest: %s", err)
	}

	if r != false {
		t.Fatalf("EvalRequest did not return false")
	}

	if mrl.fieldBytesLimitExceededCalled != expectedFieldBytesLimitExceededCalled {
		t.Fatalf("Unexpected number of calls to mockResultsLogger.FieldBytesLimitExceeded: %v", mrl.fieldBytesLimitExceededCalled)
	}

	if mrl.pausableBytesLimitExceededCalled != expectedPausableBytesLimitExceededCalled {
		t.Fatalf("Unexpected number of calls to mockResultsLogger.PausableBytesLimitExceeded: %v", mrl.pausableBytesLimitExceededCalled)
	}

	if mrl.totalBytesLimitExceededCalled != expectedTotalBytesLimitExceededCalled {
		t.Fatalf("Unexpected number of calls to mockResultsLogger.TotalBytesLimitExceeded: %v", mrl.totalBytesLimitExceededCalled)
	}

	if mrl.bodyParseErrorCalled != 0 {
		t.Fatalf("Unexpected number of calls to mockResultsLogger.BodyParseError: %v", mrl.bodyParseErrorCalled)
	}
}

type mockRequestBodyParser struct {
	parseCb func(logger zerolog.Logger, req HTTPRequest, cb ParsedBodyFieldCb) error
}

func (r *mockRequestBodyParser) Parse(logger zerolog.Logger, req HTTPRequest, cb ParsedBodyFieldCb) (err error) {
	if r.parseCb != nil {
		err = r.parseCb(logger, req, cb)
	} else {
		cb(MultipartFormDataContent, "somearg", "somevalue")
	}

	return
}

func (r *mockRequestBodyParser) LengthLimits() LengthLimits {
	return LengthLimits{1000, 2000, 3000}
}

type mockSecRuleEvaluation struct {
	scanHeadersCalled   int
	scanBodyFieldCalled int
	evalRulesCalled     int
	closeCalled         int
}

func (m *mockSecRuleEvaluation) ScanHeaders() (err error) {
	m.scanHeadersCalled++
	return
}
func (m *mockSecRuleEvaluation) ScanBodyField(contentType ContentType, fieldName string, data string) (err error) {
	m.scanBodyFieldCalled++
	return
}
func (m *mockSecRuleEvaluation) EvalRules() bool {
	m.evalRulesCalled++
	return true
}
func (m *mockSecRuleEvaluation) Close() {
	m.closeCalled++
}

type mockSecRuleEngine struct {
	newEvaluationCalled int
	msrev               *mockSecRuleEvaluation
}

func (m *mockSecRuleEngine) NewEvaluation(logger zerolog.Logger, req HTTPRequest) SecRuleEvaluation {
	m.newEvaluationCalled++
	return m.msrev
}

type mockSecRuleEngineFactory struct {
	msre            *mockSecRuleEngine
	newEngineCalled int
}

func (m *mockSecRuleEngineFactory) NewEngine(c SecRuleConfig) (engine SecRuleEngine, err error) {
	m.newEngineCalled++
	engine = m.msre
	return
}

type mockWafHTTPRequest struct{}

func (r *mockWafHTTPRequest) Method() string                  { return "GET" }
func (r *mockWafHTTPRequest) URI() string                     { return "/hello.php?arg1=aaaaaaabccc" }
func (r *mockWafHTTPRequest) Headers() []HeaderPair           { return nil }
func (r *mockWafHTTPRequest) ConfigID() string                { return "waf policy 1" }
func (r *mockWafHTTPRequest) Version() int64                  { return 0 }
func (r *mockWafHTTPRequest) BodyReader() io.Reader           { return &bytes.Buffer{} }
func (r *mockWafHTTPRequest) LogMetaData() RequestLogMetaData { return &mockLogMetaData{} }
func (r *mockWafHTTPRequest) TransactionID() string           { return "abc" }

type mockLogMetaData struct {
}

func (h *mockLogMetaData) Scope() string     { return "Global" }
func (h *mockLogMetaData) ScopeName() string { return "Default Policy" }

type mockResultsLogger struct {
	fieldBytesLimitExceededCalled    int
	pausableBytesLimitExceededCalled int
	totalBytesLimitExceededCalled    int
	bodyParseErrorCalled             int
}

func (r *mockResultsLogger) FieldBytesLimitExceeded(request HTTPRequest, limit int) {
	r.fieldBytesLimitExceededCalled++
}
func (r *mockResultsLogger) PausableBytesLimitExceeded(request HTTPRequest, limit int) {
	r.pausableBytesLimitExceededCalled++
}
func (r *mockResultsLogger) TotalBytesLimitExceeded(request HTTPRequest, limit int) {
	r.totalBytesLimitExceededCalled++
}
func (r *mockResultsLogger) BodyParseError(request HTTPRequest, err error) {
	r.bodyParseErrorCalled++
}

func (r *mockResultsLogger) SetLogMetaData(metaData ConfigLogMetaData) {
}

type mockConfigMgr struct {
	configMap map[int][]string
}

func (m *mockConfigMgr) PutConfig(c Config) error {
	if m.configMap == nil {
		m.configMap = make(map[int][]string)
	}

	v := int(c.ConfigVersion())
	m.configMap[v] = make([]string, 0)

	for _, l := range c.PolicyConfigs() {
		m.configMap[v] = append(m.configMap[v], l.ConfigID())
	}

	return nil
}

func (m *mockConfigMgr) DisposeConfig(version int) ([]string, error) {
	return m.configMap[version], nil
}

type mockCustomRuleEngine struct {
}

type mockCustomRuleEngineFactory struct {
	mcre            *mockCustomRuleEngine
	newEngineCalled int
}

func (m *mockCustomRuleEngineFactory) NewEngine(c CustomRuleConfig) (engine CustomRuleEngine, err error) {
	m.newEngineCalled++
	engine = m.mcre
	return
}

func (s *mockCustomRuleEngine) NewEvaluation(logger zerolog.Logger, req HTTPRequest) CustomRuleEvaluation {
	return &mockCustomRuleEvaluation{}
}

type mockCustomRuleEvaluation struct{}

func (s *mockCustomRuleEvaluation) ScanHeaders() error {
	return nil
}

func (s *mockCustomRuleEvaluation) ScanBodyField(contentType ContentType, fieldName string, data string) error {
	return nil
}

func (s *mockCustomRuleEvaluation) EvalRules() bool {
	return true
}
