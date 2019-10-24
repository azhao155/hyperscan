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
	mcrev := &mockCustomRuleEvaluation{}
	mcre := &mockCustomRuleEngine{mcrev: mcrev}
	mcref := &mockCustomRuleEngineFactory{mcre: mcre}
	c := make(map[int]Config)
	c[0] = &mockConfig{}
	mrbp := &mockRequestBodyParser{}
	mcm := &mockConfigMgr{}
	mire := &mockIPReputationEngine{}
	mgdb := &mockGeoDB{}
	s, err := NewServer(logger, mcm, c, msref, mrbp, mrl, mcref, mire, mgdb)
	if err != nil {
		t.Fatalf("Error from NewServer: %s", err)
	}
	req := &mockWafHTTPRequest{}

	// Act
	s.EvalRequest(req)

	// Assert

	if mcref.newEngineCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockCustomRuleEngineFactory.NewEngine: %v", mcref.newEngineCalled)
	}

	if mcre.newEvaluationCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockCustomRuleEngine.NewEvaluation: %v", mcre.newEvaluationCalled)
	}

	if mcrev.scanHeadersCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockCustomRuleEvaluation.ScanHeaders: %v", mcrev.scanHeadersCalled)
	}

	if mcrev.scanBodyFieldCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockCustomRuleEvaluation.ScanBodyField: %v", mcrev.scanBodyFieldCalled)
	}

	if mcrev.evalRulesCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockCustomRuleEvaluation.EvalRules: %v", mcrev.evalRulesCalled)
	}

	if mcrev.closeCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockCustomRuleEvaluation.Close: %v", mcrev.closeCalled)
	}

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

	if mire.evalRequestCount != 1 {
		t.Fatalf("Unexpected number of calls to mockIPReputationEngine.EvalRequest: %v", mire.evalRequestCount)
	}
}

func TestWafDetectionMode(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	mrl := &mockResultsLogger{}

	// Block request
	msrev := &mockSecRuleEvaluation{decision: Block}

	msre := &mockSecRuleEngine{msrev: msrev}
	msref := &mockSecRuleEngineFactory{msre: msre}
	mcrev := &mockCustomRuleEvaluation{}
	mcre := &mockCustomRuleEngine{mcrev: mcrev}
	mcref := &mockCustomRuleEngineFactory{mcre: mcre}
	c := make(map[int]Config)
	mc := &mockConfig{mpc: mockPolicyConfig{isDetectionMode: true}}
	c[0] = mc
	mrbp := &mockRequestBodyParser{}
	mcm := &mockConfigMgr{}
	mire := &mockIPReputationEngine{}
	mgdb := &mockGeoDB{}
	s, err := NewServer(logger, mcm, c, msref, mrbp, mrl, mcref, mire, mgdb)
	if err != nil {
		t.Fatalf("Error from NewServer: %s", err)
	}
	req := &mockWafHTTPRequest{}

	// Act
	d, err := s.EvalRequest(req)

	// Assert
	if d != Pass {
		t.Fatalf("Unexpected decision: %v", d)
	}
}

func TestWafServerPutIPReputationList(t *testing.T) {
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
	mire := &mockIPReputationEngine{}
	mgdb := &mockGeoDB{}
	s, err := NewServer(logger, mcm, c, msref, mrbp, mrl, mcref, mire, mgdb)
	if err != nil {
		t.Fatalf("Error from NewServer: %s", err)
	}

	// Act
	s.PutIPReputationList([]string{"0.0.0.0/32=bot:1", "255.255.255.255/32=bot:1", "115.213.87.34/32=bot:1"})

	// Assert
	if mire.putIPReputationListCount != 1 {
		t.Fatalf("Unexpected number of calls to mockIPReputationEngine.PutIPReputationList: %v", mire.putIPReputationListCount)
	}
}

func TestSanitizeIPList(t *testing.T) {
	validIPs := []string{"0.0.0.0/32=bot:1", "255.255.255.255", "1.2.3.4"}
	invalidIPs := []string{"256.256.256.256", "0.0.0.0/33", "abcd=bot:1"}
	unsanitizedList := append(validIPs, invalidIPs...)
	sanitizedList := sanitizeIPList(unsanitizedList)
	if len(sanitizedList) != 3 {
		t.Fatal("sanitizeIPList failed to filter out invalid IPs")
	}
}

func TestSecRuleEngineEvalRequestTooLongField(t *testing.T) {
	testBytesLimit(t, ErrFieldBytesLimitExceeded, 1, 0, 0, 0)
}

func TestSecRuleEngineEvalRequestTooLongBodyExcludingFiles(t *testing.T) {
	testBytesLimit(t, ErrPausableBytesLimitExceeded, 0, 1, 0, 0)
}

func TestSecRuleEngineEvalRequestTooLongTotal(t *testing.T) {
	testBytesLimit(t, ErrTotalBytesLimitExceeded, 0, 0, 1, 0)
}

func TestSecRuleEngineEvalRequestTooLongTotalFullRawRequestBody(t *testing.T) {
	testBytesLimit(t, ErrTotalFullRawRequestBodyExceeded, 0, 0, 0, 1)
}

func testBytesLimit(
	t *testing.T,
	errToSimulate error,
	expectedFieldBytesLimitExceededCalled int,
	expectedPausableBytesLimitExceededCalled int,
	expectedTotalBytesLimitExceededCalled int,
	expectedTotalFullRawRequestBodyLimitExceededCalled int,
) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	mrl := &mockResultsLogger{}
	msrev := &mockSecRuleEvaluation{}
	msre := &mockSecRuleEngine{msrev: msrev}
	msref := &mockSecRuleEngineFactory{msre: msre}
	mcrev := &mockCustomRuleEvaluation{}
	mcre := &mockCustomRuleEngine{mcrev: mcrev}
	mcref := &mockCustomRuleEngineFactory{mcre: mcre}
	c := make(map[int]Config)
	c[0] = &mockConfig{}
	mrbp := &mockRequestBodyParser{
		parseCb: func(logger zerolog.Logger, req RequestBodyParserHTTPRequest, cb ParsedBodyFieldCb) (err error) {
			err = errToSimulate
			return
		},
	}
	mcm := &mockConfigMgr{}
	mire := &mockIPReputationEngine{}
	mgdb := &mockGeoDB{}
	s, err := NewServer(logger, mcm, c, msref, mrbp, mrl, mcref, mire, mgdb)
	if err != nil {
		t.Fatalf("Unexpected error from NewServer: %s", err)
	}

	req := &mockWafHTTPRequest{}

	// Act
	r, err := s.EvalRequest(req)

	// Assert
	if err != errToSimulate {
		t.Fatalf("Unexpected error from EvalRequest: %s", err)
	}

	if r != Block {
		t.Fatalf("EvalRequest did not return block")
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

	if mrl.totalFullRawRequestBodyLimitExceededCalled != expectedTotalFullRawRequestBodyLimitExceededCalled {
		t.Fatalf("Unexpected number of calls to mockResultsLogger.TotalFullRawRequestBodyLimitExceeded: %v", mrl.totalFullRawRequestBodyLimitExceededCalled)
	}

	if mrl.bodyParseErrorCalled != 0 {
		t.Fatalf("Unexpected number of calls to mockResultsLogger.BodyParseError: %v", mrl.bodyParseErrorCalled)
	}
}

type mockRequestBodyParser struct {
	parseCb func(logger zerolog.Logger, req RequestBodyParserHTTPRequest, cb ParsedBodyFieldCb) error
}

func (r *mockRequestBodyParser) Parse(
	logger zerolog.Logger,
	req RequestBodyParserHTTPRequest,
	fieldCb ParsedBodyFieldCb,
	usesFullRawRequestBodyCb UsesFullRawRequestBodyCb,
) (err error) {
	if r.parseCb != nil {
		err = r.parseCb(logger, req, fieldCb)
	} else {
		fieldCb(MultipartFormDataContent, "somearg", "somevalue")
	}

	return
}

func (r *mockRequestBodyParser) LengthLimits() LengthLimits {
	return LengthLimits{1000, 2000, 3000, 1000}
}

type mockSecRuleEvaluation struct {
	scanHeadersCalled   int
	scanBodyFieldCalled int
	evalRulesCalled     int
	closeCalled         int
	decision            Decision
}

func (m *mockSecRuleEvaluation) ScanHeaders() (err error) {
	m.scanHeadersCalled++
	return
}
func (m *mockSecRuleEvaluation) ScanBodyField(contentType ContentType, fieldName string, data string) (err error) {
	m.scanBodyFieldCalled++
	return
}
func (m *mockSecRuleEvaluation) EvalRules() Decision {
	m.evalRulesCalled++
	return m.decision
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

func (m *mockSecRuleEngine) UsesFullRawRequestBody() bool {
	return false
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

type mockIPReputationEngine struct {
	evalRequestCount         int
	putIPReputationListCount int
}

func (m *mockIPReputationEngine) PutIPReputationList([]string) {
	m.putIPReputationListCount++
}

func (m *mockIPReputationEngine) EvalRequest(req IPReputationEngineHTTPRequest) Decision {
	m.evalRequestCount++
	return Pass
}

type mockWafHTTPRequest struct{}

func (r *mockWafHTTPRequest) Method() string                  { return "GET" }
func (r *mockWafHTTPRequest) URI() string                     { return "/hello.php?arg1=aaaaaaabccc" }
func (r *mockWafHTTPRequest) Protocol() string                { return "HTTP/1.1" }
func (r *mockWafHTTPRequest) RemoteAddr() string              { return "0.0.0.0" }
func (r *mockWafHTTPRequest) Headers() []HeaderPair           { return nil }
func (r *mockWafHTTPRequest) ConfigID() string                { return "waf policy 1" }
func (r *mockWafHTTPRequest) BodyReader() io.Reader           { return &bytes.Buffer{} }
func (r *mockWafHTTPRequest) LogMetaData() RequestLogMetaData { return &mockLogMetaData{} }
func (r *mockWafHTTPRequest) TransactionID() string           { return "abc" }

type mockLogMetaData struct {
}

func (h *mockLogMetaData) Scope() string     { return "Global" }
func (h *mockLogMetaData) ScopeName() string { return "Default Policy" }

type mockResultsLogger struct {
	fieldBytesLimitExceededCalled              int
	pausableBytesLimitExceededCalled           int
	totalBytesLimitExceededCalled              int
	totalFullRawRequestBodyLimitExceededCalled int
	bodyParseErrorCalled                       int
}

func (r *mockResultsLogger) FieldBytesLimitExceeded(request ResultsLoggerHTTPRequest, limit int) {
	r.fieldBytesLimitExceededCalled++
}
func (r *mockResultsLogger) PausableBytesLimitExceeded(request ResultsLoggerHTTPRequest, limit int) {
	r.pausableBytesLimitExceededCalled++
}
func (r *mockResultsLogger) TotalBytesLimitExceeded(request ResultsLoggerHTTPRequest, limit int) {
	r.totalBytesLimitExceededCalled++
}
func (r *mockResultsLogger) TotalFullRawRequestBodyLimitExceeded(request ResultsLoggerHTTPRequest, limit int) {
	r.totalFullRawRequestBodyLimitExceededCalled++
}
func (r *mockResultsLogger) BodyParseError(request ResultsLoggerHTTPRequest, err error) {
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
	newEvaluationCalled int
	mcrev               *mockCustomRuleEvaluation
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
	s.newEvaluationCalled++
	return s.mcrev
}

type mockCustomRuleEvaluation struct {
	scanHeadersCalled   int
	scanBodyFieldCalled int
	evalRulesCalled     int
	closeCalled         int
}

func (s *mockCustomRuleEngine) GeoDB() GeoDB {
	return nil
}

func (s *mockCustomRuleEvaluation) ScanHeaders() error {
	s.scanHeadersCalled++
	return nil
}

func (s *mockCustomRuleEvaluation) ScanBodyField(contentType ContentType, fieldName string, data string) error {
	s.scanBodyFieldCalled++
	return nil
}

func (s *mockCustomRuleEvaluation) EvalRules() Decision {
	s.evalRulesCalled++
	return Pass
}

func (s *mockCustomRuleEvaluation) Close() {
	s.closeCalled++
}

type mockGeoDB struct {
}

func (mgdb *mockGeoDB) PutGeoIPData(geoIPData []GeoIPDataRecord) (err error) { return }
func (mgdb *mockGeoDB) GeoLookup(ipAddr string) (countryCode string)         { return }
