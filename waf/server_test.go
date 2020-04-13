package waf

import (
	"azwaf/testutils"
	"bytes"
	"io"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestWafServerEvalRequest(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	mrl := &mockResultsLogger{}
	mrlf := &mockResultsLoggerFactory{mockResultsLogger: mrl}
	smrlf := &mockResultsLoggerFactory{mockResultsLogger: mrl}
	msrev := &mockSecRuleEvaluation{decision: Pass}
	msre := &mockSecRuleEngine{msrev: msrev}
	msref := &mockSecRuleEngineFactory{msre: msre}
	mcrev := &mockCustomRuleEvaluation{}
	mcre := &mockCustomRuleEngine{mcrev: mcrev}
	mcref := &mockCustomRuleEngineFactory{mcre: mcre}
	c := make(map[int]Config)
	c[0] = &mockConfig{mpc: mockPolicyConfig{requestBodyCheck: true}}
	mrbpf := &mockRequestBodyParserFactory{}
	mcm := &mockConfigMgr{}
	mire := &mockIPReputationEngine{}
	mgdb := &mockGeoDB{}
	s, err := NewServer(logger, mcm, c, mrlf, smrlf, msref, mrbpf, mcref, mire, mgdb)
	if err != nil {
		t.Fatalf("Error from NewServer: %s", err)
	}
	req := newDefaultMockWafHTTPRequest()

	// Act
	d, err := s.EvalRequest(req)

	// Assert
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if d != Pass {
		t.Fatalf("Unexpected decision: %v", d)
	}

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

	if msrev.evalRulesPhase1Called != 1 {
		t.Fatalf("Unexpected number of calls to mockSecRuleEvaluation.EvalRulesPhase1: %v", msrev.evalRulesPhase1Called)
	}

	if msrev.evalRulesPhase2to5Called != 1 {
		t.Fatalf("Unexpected number of calls to mockSecRuleEvaluation.evalRulesPhase2to5Called: %v", msrev.evalRulesPhase2to5Called)
	}

	if msrev.bodyParseErrorOccurredCalled != 0 {
		t.Fatalf("Unexpected number of calls to mockSecRuleEvaluation.bodyParseErrorOccurred: %v", msrev.bodyParseErrorOccurredCalled)
	}

	if msrev.closeCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockSecRuleEvaluation.Close: %v", msrev.closeCalled)
	}

	if mire.evalRequestCount != 1 {
		t.Fatalf("Unexpected number of calls to mockIPReputationEngine.EvalRequest: %v", mire.evalRequestCount)
	}
}

func TestRequestBodyCheckOff(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	mrl := &mockResultsLogger{}
	mrlf := &mockResultsLoggerFactory{mockResultsLogger: mrl}
	smrlf := &mockResultsLoggerFactory{mockResultsLogger: mrl}
	msrev := &mockSecRuleEvaluation{decision: Pass}
	msre := &mockSecRuleEngine{msrev: msrev}
	msref := &mockSecRuleEngineFactory{msre: msre}
	mcrev := &mockCustomRuleEvaluation{}
	mcre := &mockCustomRuleEngine{mcrev: mcrev}
	mcref := &mockCustomRuleEngineFactory{mcre: mcre}
	c := make(map[int]Config)
	c[0] = &mockConfig{mpc: mockPolicyConfig{requestBodyCheck: false}}
	mrbpf := &mockRequestBodyParserFactory{}
	mcm := &mockConfigMgr{}
	mire := &mockIPReputationEngine{}
	mgdb := &mockGeoDB{}
	s, err := NewServer(logger, mcm, c, mrlf, smrlf, msref, mrbpf, mcref, mire, mgdb)
	if err != nil {
		t.Fatalf("Error from NewServer: %s", err)
	}
	req := newDefaultMockWafHTTPRequest()

	// Act
	d, err := s.EvalRequest(req)

	// Assert
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if d != Pass {
		t.Fatalf("Unexpected decision: %v", d)
	}

	if mcref.newEngineCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockCustomRuleEngineFactory.NewEngine: %v", mcref.newEngineCalled)
	}

	if mcre.newEvaluationCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockCustomRuleEngine.NewEvaluation: %v", mcre.newEvaluationCalled)
	}

	if mcrev.scanHeadersCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockCustomRuleEvaluation.ScanHeaders: %v", mcrev.scanHeadersCalled)
	}

	if mcrev.scanBodyFieldCalled != 0 {
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

	if msrev.scanBodyFieldCalled != 0 {
		t.Fatalf("Unexpected number of calls to mockSecRuleEvaluation.ScanBodyField: %v", msrev.scanBodyFieldCalled)
	}

	if msrev.evalRulesPhase1Called != 1 {
		t.Fatalf("Unexpected number of calls to mockSecRuleEvaluation.EvalRulesPhase1: %v", msrev.evalRulesPhase1Called)
	}

	if msrev.evalRulesPhase2to5Called != 1 {
		t.Fatalf("Unexpected number of calls to mockSecRuleEvaluation.evalRulesPhase2to5Called: %v", msrev.evalRulesPhase2to5Called)
	}

	if msrev.bodyParseErrorOccurredCalled != 0 {
		t.Fatalf("Unexpected number of calls to mockSecRuleEvaluation.bodyParseErrorOccurred: %v", msrev.bodyParseErrorOccurredCalled)
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
	mrlf := &mockResultsLoggerFactory{mockResultsLogger: mrl}
	smrlf := &mockResultsLoggerFactory{mockResultsLogger: mrl}
	msrev := &mockSecRuleEvaluation{decision: Block} // SecRule engine decides to block request
	msre := &mockSecRuleEngine{msrev: msrev}
	msref := &mockSecRuleEngineFactory{msre: msre}
	mcrev := &mockCustomRuleEvaluation{}
	mcre := &mockCustomRuleEngine{mcrev: mcrev}
	mcref := &mockCustomRuleEngineFactory{mcre: mcre}
	c := make(map[int]Config)
	mc := &mockConfig{}
	c[0] = mc
	mrbpf := &mockRequestBodyParserFactory{}
	mcm := &mockConfigMgr{}
	mire := &mockIPReputationEngine{}
	mgdb := &mockGeoDB{}
	req := newDefaultMockWafHTTPRequest()

	// Act
	mc.mpc.isDetectionMode = false
	s, err := NewServer(logger, mcm, c, mrlf, smrlf, msref, mrbpf, mcref, mire, mgdb)
	if err != nil {
		t.Fatalf("Error from NewServer: %s", err)
	}
	d1, err := s.EvalRequest(req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	mc.mpc.isDetectionMode = true
	s, err = NewServer(logger, mcm, c, mrlf, smrlf, msref, mrbpf, mcref, mire, mgdb)
	if err != nil {
		t.Fatalf("Error from NewServer: %s", err)
	}
	d2, err := s.EvalRequest(req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Assert
	if d1 != Block {
		t.Fatalf("Unexpected decision: %v", d1)
	}

	if d2 != Pass {
		t.Fatalf("Unexpected decision: %v", d2)
	}
}

func TestWafShadowModeCustomRuleBlock(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	mrl := &mockResultsLogger{}
	mrlf := &mockResultsLoggerFactory{mockResultsLogger: mrl}
	smrlf := &mockResultsLoggerFactory{mockResultsLogger: mrl}
	msrev := &mockSecRuleEvaluation{decision: Allow} // SecRule engine decides to allow request
	msre := &mockSecRuleEngine{msrev: msrev}
	msref := &mockSecRuleEngineFactory{msre: msre}
	mcrev := &mockCustomRuleEvaluation{decision: Block} // Custom rules engine decides to block request
	mcre := &mockCustomRuleEngine{mcrev: mcrev}
	mcref := &mockCustomRuleEngineFactory{mcre: mcre}
	c := make(map[int]Config)
	mc := &mockConfig{mpc: mockPolicyConfig{isDetectionMode: false, isShadowMode: true}}
	c[0] = mc
	mrbpf := &mockRequestBodyParserFactory{}
	mcm := &mockConfigMgr{}
	mire := &mockIPReputationEngine{}
	mgdb := &mockGeoDB{}
	s, err := NewServer(logger, mcm, c, mrlf, smrlf, msref, mrbpf, mcref, mire, mgdb)
	if err != nil {
		t.Fatalf("Error from NewServer: %s", err)
	}
	req := newDefaultMockWafHTTPRequest()

	// Act
	d, err := s.EvalRequest(req)

	// Assert
	if d != Pass {
		t.Fatalf("Unexpected decision: %v", d)
	}
}

func TestWafShadowModeSecRuleBlock(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	mrl := &mockResultsLogger{}
	mrlf := &mockResultsLoggerFactory{mockResultsLogger: mrl}
	smrlf := &mockResultsLoggerFactory{mockResultsLogger: mrl}
	msrev := &mockSecRuleEvaluation{decision: Block} // SecRule engine decides to block request
	msre := &mockSecRuleEngine{msrev: msrev}
	msref := &mockSecRuleEngineFactory{msre: msre}
	mcrev := &mockCustomRuleEvaluation{decision: Allow} // Custom rules engine decides to allow request
	mcre := &mockCustomRuleEngine{mcrev: mcrev}
	mcref := &mockCustomRuleEngineFactory{mcre: mcre}
	c := make(map[int]Config)
	mc := &mockConfig{mpc: mockPolicyConfig{isDetectionMode: false, isShadowMode: true}}
	c[0] = mc
	mrbpf := &mockRequestBodyParserFactory{}
	mcm := &mockConfigMgr{}
	mire := &mockIPReputationEngine{}
	mgdb := &mockGeoDB{}
	s, err := NewServer(logger, mcm, c, mrlf, smrlf, msref, mrbpf, mcref, mire, mgdb)
	if err != nil {
		t.Fatalf("Error from NewServer: %s", err)
	}
	req := newDefaultMockWafHTTPRequest()

	// Act
	d, err := s.EvalRequest(req)

	// Assert
	if d != Pass {
		t.Fatalf("Unexpected decision: %v", d)
	}
}

func TestWafShadowDetectionMode(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	mrl := &mockResultsLogger{}
	mrlf := &mockResultsLoggerFactory{mockResultsLogger: mrl}
	smrlf := &mockResultsLoggerFactory{mockResultsLogger: mrl}
	msrev := &mockSecRuleEvaluation{decision: Block} // SecRule engine decides to block request
	msre := &mockSecRuleEngine{msrev: msrev}
	msref := &mockSecRuleEngineFactory{msre: msre}
	mcrev := &mockCustomRuleEvaluation{decision: Block} // Custom rules engine decides to block request
	mcre := &mockCustomRuleEngine{mcrev: mcrev}
	mcref := &mockCustomRuleEngineFactory{mcre: mcre}
	c := make(map[int]Config)
	mc := &mockConfig{mpc: mockPolicyConfig{isDetectionMode: true, isShadowMode: true}}
	c[0] = mc
	mrbpf := &mockRequestBodyParserFactory{}
	mcm := &mockConfigMgr{}
	mire := &mockIPReputationEngine{}
	mgdb := &mockGeoDB{}
	s, err := NewServer(logger, mcm, c, mrlf, smrlf, msref, mrbpf, mcref, mire, mgdb)
	if err != nil {
		t.Fatalf("Error from NewServer: %s", err)
	}
	req := newDefaultMockWafHTTPRequest()

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
	mrlf := &mockResultsLoggerFactory{mockResultsLogger: mrl}
	smrlf := &mockResultsLoggerFactory{mockResultsLogger: mrl}
	msrev := &mockSecRuleEvaluation{}
	msre := &mockSecRuleEngine{msrev: msrev}
	msref := &mockSecRuleEngineFactory{msre: msre}
	mcre := &mockCustomRuleEngine{}
	mcref := &mockCustomRuleEngineFactory{mcre: mcre}
	c := make(map[int]Config)
	c[0] = &mockConfig{}
	mrbpf := &mockRequestBodyParserFactory{}
	mcm := &mockConfigMgr{}
	mire := &mockIPReputationEngine{}
	mgdb := &mockGeoDB{}
	s, err := NewServer(logger, mcm, c, mrlf, smrlf, msref, mrbpf, mcref, mire, mgdb)
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
	mrlf := &mockResultsLoggerFactory{mockResultsLogger: mrl}
	smrlf := &mockResultsLoggerFactory{mockResultsLogger: mrl}
	msrev := &mockSecRuleEvaluation{decision: Pass}
	msre := &mockSecRuleEngine{msrev: msrev}
	msref := &mockSecRuleEngineFactory{msre: msre}
	mcrev := &mockCustomRuleEvaluation{}
	mcre := &mockCustomRuleEngine{mcrev: mcrev}
	mcref := &mockCustomRuleEngineFactory{mcre: mcre}
	c := make(map[int]Config)
	c[0] = &mockConfig{mpc: mockPolicyConfig{requestBodyCheck: true}}
	mrbp := &mockRequestBodyParser{
		parseCb: func(
			logger zerolog.Logger,
			bodyReader io.Reader,
			fieldCb ParsedBodyFieldCb,
			reqBodyType ReqBodyType,
			contentLengthOptional int,
			multipartBoundary string,
			alsoScanFullRawBody bool,
		) (err error) {
			err = errToSimulate
			return
		},
	}
	mrbpf := &mockRequestBodyParserFactory{mrbp: mrbp}
	mcm := &mockConfigMgr{}
	mire := &mockIPReputationEngine{}
	mgdb := &mockGeoDB{}
	s, err := NewServer(logger, mcm, c, mrlf, smrlf, msref, mrbpf, mcref, mire, mgdb)
	if err != nil {
		t.Fatalf("Unexpected error from NewServer: %s", err)
	}

	req := newDefaultMockWafHTTPRequest()

	// Act
	r, err := s.EvalRequest(req)

	// Assert
	if err != nil {
		t.Fatalf("Unexpected error from EvalRequest: %s", err)
	}

	if r != Block {
		t.Fatalf("EvalRequest did not return pass: %v", Pass)
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

func TestWafServerPutConfigLengthLimits(t *testing.T) {
	// Arrange
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)
	mrl := &mockResultsLogger{}
	mrlf := &mockResultsLoggerFactory{mockResultsLogger: mrl}
	smrlf := &mockResultsLoggerFactory{mockResultsLogger: mrl}
	msrev := &mockSecRuleEvaluation{decision: Pass}
	msre := &mockSecRuleEngine{msrev: msrev}
	msref := &mockSecRuleEngineFactory{msre: msre}
	mcrev := &mockCustomRuleEvaluation{}
	mcre := &mockCustomRuleEngine{mcrev: mcrev}
	mcref := &mockCustomRuleEngineFactory{mcre: mcre}
	c := make(map[int]Config)
	c[0] = &mockConfig{mpc: mockPolicyConfig{requestBodyCheck: false}}
	mrbp := &mockRequestBodyParser{}
	mrbpf := &mockRequestBodyParserFactory{mrbp: mrbp}
	mcm := &mockConfigMgr{}
	mire := &mockIPReputationEngine{}
	mgdb := &mockGeoDB{}
	s, err := NewServer(logger, mcm, c, mrlf, smrlf, msref, mrbpf, mcref, mire, mgdb)

	assert.Nil(err)

	s.PutConfig(&mockConfig{
		mpc: mockPolicyConfig{
			isDetectionMode:          true,
			fileUploadSizeLimitInMb:  10,
			isShadowMode:             true,
			requestBodyCheck:         true,
			requestBodySizeLimitInKb: 128,
		},
	})

	assert.Equal(1024*128, mrbp.LengthLimits().MaxLengthPausable)
	assert.Equal(2147483647, mrbp.LengthLimits().MaxLengthField)
	assert.Equal(2147483647, mrbp.LengthLimits().MaxLengthTotal)
	assert.Equal(2147483647, mrbp.LengthLimits().MaxLengthTotalFullRawRequestBody)
}

type mockRequestBodyParserFactory struct {
	mrbp *mockRequestBodyParser
}

func (m *mockRequestBodyParserFactory) NewRequestBodyParser(lengthLimits LengthLimits) RequestBodyParser {
	if m.mrbp == nil {
		return &mockRequestBodyParser{lengthLimits: lengthLimits}
	}
	m.mrbp.lengthLimits = lengthLimits
	return m.mrbp
}

type mockRequestBodyParser struct {
	parseCb func(
		logger zerolog.Logger,
		bodyReader io.Reader,
		fieldCb ParsedBodyFieldCb,
		reqBodyType ReqBodyType,
		contentLengthOptional int,
		multipartBoundary string,
		alsoScanFullRawBody bool,
	) error
	lengthLimits LengthLimits
}

func (r *mockRequestBodyParser) Parse(
	logger zerolog.Logger,
	bodyReader io.Reader,
	fieldCb ParsedBodyFieldCb,
	reqBodyType ReqBodyType,
	contentLengthOptional int,
	multipartBoundary string,
	alsoScanFullRawBody bool,
) (err error) {
	if r.parseCb != nil {
		err = r.parseCb(
			logger,
			bodyReader,
			fieldCb,
			reqBodyType,
			contentLengthOptional,
			multipartBoundary,
			alsoScanFullRawBody,
		)
	} else {
		fieldCb(MultipartFormDataContent, "somearg", "somevalue")
	}

	return
}

func (r *mockRequestBodyParser) LengthLimits() LengthLimits {
	return r.lengthLimits
}

type mockSecRuleEvaluation struct {
	scanHeadersCalled            int
	scanBodyFieldCalled          int
	evalRulesPhase1Called        int
	evalRulesPhase2to5Called     int
	bodyParseErrorOccurredCalled int
	closeCalled                  int
	decision                     Decision
}

func (m *mockSecRuleEvaluation) ScanHeaders() (err error) {
	m.scanHeadersCalled++
	return
}
func (m *mockSecRuleEvaluation) ScanBodyField(contentType FieldContentType, fieldName string, data string) (err error) {
	m.scanBodyFieldCalled++
	return
}
func (m *mockSecRuleEvaluation) EvalRulesPhase1() Decision {
	m.evalRulesPhase1Called++
	return m.decision
}
func (m *mockSecRuleEvaluation) EvalRulesPhase2to5() Decision {
	m.evalRulesPhase2to5Called++
	return m.decision
}
func (m *mockSecRuleEvaluation) BodyParseErrorOccurred() {
	m.bodyParseErrorOccurredCalled++
}
func (m *mockSecRuleEvaluation) Close() {
	m.closeCalled++
}
func (m *mockSecRuleEvaluation) AlsoScanFullRawRequestBody() bool {
	return false
}

type mockSecRuleEngine struct {
	newEvaluationCalled int
	msrev               *mockSecRuleEvaluation
}

func (m *mockSecRuleEngine) NewEvaluation(logger zerolog.Logger, resultsLogger SecRuleResultsLogger, req HTTPRequest, reqBodyType ReqBodyType) SecRuleEvaluation {
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

type mockIPReputationEngine struct {
	evalRequestCount         int
	putIPReputationListCount int
}

func (m *mockIPReputationEngine) PutIPReputationList([]string) {
	m.putIPReputationListCount++
}

func (m *mockIPReputationEngine) EvalRequest(req IPReputationEngineHTTPRequest, resultsLogger IPReputationResultsLogger) Decision {
	m.evalRequestCount++
	return Pass
}

type mockWafHTTPRequest struct {
	uri        string
	method     string
	protocol   string
	remoteAddr string
	headers    []HeaderPair
	configID   string
	body       string
}

func newDefaultMockWafHTTPRequest() HTTPRequest {
	return &mockWafHTTPRequest{
		method:     "GET",
		uri:        "/hello.php?arg1=aaaaaaabccc",
		protocol:   "HTTP/1.1",
		remoteAddr: "0.0.0.0",
		configID:   "waf policy 1",
	}
}

func (r *mockWafHTTPRequest) Method() string        { return r.method }
func (r *mockWafHTTPRequest) URI() string           { return r.uri }
func (r *mockWafHTTPRequest) Protocol() string      { return r.protocol }
func (r *mockWafHTTPRequest) RemoteAddr() string    { return r.remoteAddr }
func (r *mockWafHTTPRequest) Headers() []HeaderPair { return r.headers }
func (r *mockWafHTTPRequest) ConfigID() string      { return r.configID }
func (r *mockWafHTTPRequest) BodyReader() io.Reader {
	var b bytes.Buffer
	b.WriteString(r.body)
	return &b
}
func (r *mockWafHTTPRequest) LogMetaData() RequestLogMetaData { return &mockLogMetaData{} }
func (r *mockWafHTTPRequest) TransactionID() string           { return "abc" }

type mockLogMetaData struct {
}

func (h *mockLogMetaData) Scope() string     { return "Global" }
func (h *mockLogMetaData) ScopeName() string { return "Default Policy" }

type mockResultsLoggerFactory struct {
	mockResultsLogger *mockResultsLogger
}

func (f *mockResultsLoggerFactory) NewResultsLogger(request HTTPRequest, configLogMetaData ConfigLogMetaData, isDetectionMode bool) ResultsLogger {
	return f.mockResultsLogger
}

type mockResultsLogger struct {
	fieldBytesLimitExceededCalled              int
	pausableBytesLimitExceededCalled           int
	totalBytesLimitExceededCalled              int
	totalFullRawRequestBodyLimitExceededCalled int
	bodyParseErrorCalled                       int
}

func (r *mockResultsLogger) FieldBytesLimitExceeded(limit int) {
	r.fieldBytesLimitExceededCalled++
}
func (r *mockResultsLogger) PausableBytesLimitExceeded(limit int) {
	r.pausableBytesLimitExceededCalled++
}
func (r *mockResultsLogger) TotalBytesLimitExceeded(limit int) {
	r.totalBytesLimitExceededCalled++
}
func (r *mockResultsLogger) TotalFullRawRequestBodyLimitExceeded(limit int) {
	r.totalFullRawRequestBodyLimitExceededCalled++
}
func (r *mockResultsLogger) BodyParseError(err error) {
	r.bodyParseErrorCalled++
}

func (r *mockResultsLogger) HeaderParseError(err error) {}

func (r *mockResultsLogger) SecRuleTriggered(ruleID int, decision Decision, msg string, logData string, ruleSetID RuleSetID) {
}

func (r *mockResultsLogger) CustomRuleTriggered(customRuleID string, action string, matchedConditions []ResultsLoggerCustomRulesMatchedConditions) {
}

func (r *mockResultsLogger) IPReputationTriggered() {}

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

func (s *mockCustomRuleEngine) NewEvaluation(logger zerolog.Logger, resultsLogger CustomRuleResultsLogger, req HTTPRequest, reqBodyType ReqBodyType) CustomRuleEvaluation {
	s.newEvaluationCalled++
	return s.mcrev
}

type mockCustomRuleEvaluation struct {
	scanHeadersCalled   int
	scanBodyFieldCalled int
	evalRulesCalled     int
	closeCalled         int
	decision            Decision
}

func (s *mockCustomRuleEngine) GeoDB() GeoDB {
	return nil
}

func (s *mockCustomRuleEvaluation) ScanHeaders() error {
	s.scanHeadersCalled++
	return nil
}

func (s *mockCustomRuleEvaluation) ScanBodyField(contentType FieldContentType, fieldName string, data string) error {
	s.scanBodyFieldCalled++
	return nil
}

func (s *mockCustomRuleEvaluation) EvalRules() Decision {
	s.evalRulesCalled++
	return s.decision
}

func (s *mockCustomRuleEvaluation) Close() {
	s.closeCalled++
}

func (s *mockCustomRuleEvaluation) AlsoScanFullRawRequestBody() bool {
	return false
}

type mockGeoDB struct {
}

func (mgdb *mockGeoDB) PutGeoIPData(geoIPData []GeoIPDataRecord) (err error) { return }
func (mgdb *mockGeoDB) GeoLookup(ipAddr string) (countryCode string)         { return }
