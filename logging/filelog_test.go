package logging

import (
	"azwaf/waf"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestSecRuleTriggered(t *testing.T) {
	// Arrange
	logger, fileSystem, _ := arrangeTestResultsLogger(t, false)

	// Act
	logger.SecRuleTriggered(11, "Matched", "abc", "bce", waf.RuleSetID("OWASP CRS 3.0"))

	// Assert
	if fileSystem.openCalledMap[Path+FileName] != 1 {
		t.Fatalf("file open count wrong")
	}

	logLine := fileSystem.Get(Path + FileName)
	assertJSONLogLine(t, logLine, `
		{
			"timeStamp": "0000-00-00T00:00:00+00:00",
			"resourceId": "appgw",
			"operationName": "ApplicationGatewayFirewall",
			"category": "ApplicationGatewayFirewallLog",
			"properties": {
				"instanceId": "vm1",
				"clientIp": "1.2.3.4",
				"requestUri": "/hello.php?arg1=aaaaaaabccc",
				"ruleSetType": "OWASP",
				"ruleSetVersion": "CRS 3.0",
				"ruleId": "11",
				"ruleGroup": "",
				"message": "abc",
				"action": "Matched",
				"details": {
					"message": "bce",
					"data": "",
					"file": "",
					"line": ""
				},
				"hostname": "example.com",
				"transactionId": "abc",
				"policyId": "waf policy 1",
				"policyScope": "Global",
				"policyScopeName": "Default Policy",
				"engine": "Azwaf"
			}
		}
	`)
}

func TestSecRuleTriggeredBlocked(t *testing.T) {
	// Arrange
	logger, fileSystem, _ := arrangeTestResultsLogger(t, false)

	// Act
	logger.SecRuleTriggered(11, "Blocked", "abc", "bce", waf.RuleSetID("OWASP CRS 3.0"))

	// Assert
	logLine := fileSystem.Get(Path + FileName)
	assertJSONLogLine(t, logLine, `
		{
			"timeStamp": "0000-00-00T00:00:00+00:00",
			"resourceId": "appgw",
			"operationName": "ApplicationGatewayFirewall",
			"category": "ApplicationGatewayFirewallLog",
			"properties": {
				"instanceId": "vm1",
				"clientIp": "1.2.3.4",
				"requestUri": "/hello.php?arg1=aaaaaaabccc",
				"ruleSetType": "OWASP",
				"ruleSetVersion": "CRS 3.0",
				"ruleId": "11",
				"ruleGroup": "",
				"message": "abc",
				"action": "Blocked",
				"details": {
					"message": "bce",
					"data": "",
					"file": "",
					"line": ""
				},
				"hostname": "example.com",
				"transactionId": "abc",
				"policyId": "waf policy 1",
				"policyScope": "Global",
				"policyScopeName": "Default Policy",
				"engine": "Azwaf"
			}
		}
	`)
}

func TestLogFileReopen(t *testing.T) {
	// Arrange
	logger, fileSystem, reopenFileCh := arrangeTestResultsLogger(t, false)

	// Act
	reopenFileCh <- true
	logger.SecRuleTriggered(11, "Matched", "abc", "bce", waf.RuleSetID("OWASP CRS 3.0"))

	// Assert
	if fileSystem.openCalledMap[Path+FileName] != 2 {
		t.Fatalf("file reopen failed")
	}

	logLine := fileSystem.Get(Path + FileName)
	assertJSONLogLine(t, logLine, `
			{
				"timeStamp": "0000-00-00T00:00:00+00:00",
				"resourceId": "appgw",
				"operationName": "ApplicationGatewayFirewall",
				"category": "ApplicationGatewayFirewallLog",
				"properties": {
					"instanceId": "vm1",
					"clientIp": "1.2.3.4",
					"requestUri": "/hello.php?arg1=aaaaaaabccc",
					"ruleSetType": "OWASP",
					"ruleSetVersion": "CRS 3.0",
					"ruleId": "11",
					"ruleGroup": "",
					"message": "abc",
					"action": "Matched",
					"details": {
						"message": "bce",
						"data": "",
						"file": "",
						"line": ""
					},
					"hostname": "example.com",
					"transactionId": "abc",
					"policyId": "waf policy 1",
					"policyScope": "Global",
					"policyScopeName": "Default Policy",
					"engine": "Azwaf"
				}
			}
		`)
}

func TestSecRuleDetectionModeTriggered(t *testing.T) {
	// Arrange
	logger, fileSystem, _ := arrangeTestResultsLogger(t, true)

	// Act
	logger.SecRuleTriggered(11, "Matched", "abc", "bce", waf.RuleSetID("OWASP CRS 3.0"))

	// Assert
	logLine := fileSystem.Get(Path + FileName)
	assertJSONLogLine(t, logLine, `
		{
			"timeStamp": "0000-00-00T00:00:00+00:00",
			"resourceId": "appgw",
			"operationName": "ApplicationGatewayFirewall",
			"category": "ApplicationGatewayFirewallLog",
			"properties": {
				"instanceId": "vm1",
				"clientIp": "1.2.3.4",
				"requestUri": "/hello.php?arg1=aaaaaaabccc",
				"ruleSetType": "OWASP",
				"ruleSetVersion": "CRS 3.0",
				"ruleId": "11",
				"ruleGroup": "",
				"message": "abc",
				"action": "Matched",
				"details": {
					"message": "bce",
					"data": "",
					"file": "",
					"line": ""
				},
				"hostname": "example.com",
				"transactionId": "abc",
				"policyId": "waf policy 1",
				"policyScope": "Global",
				"policyScopeName": "Default Policy",
				"engine": "Azwaf"
			}
		}
	`)
}

func TestSecRuleDetectionModeBlocked(t *testing.T) {
	// Arrange
	logger, fileSystem, _ := arrangeTestResultsLogger(t, true)

	// Act
	logger.SecRuleTriggered(11, "Blocked", "abc", "bce", waf.RuleSetID("OWASP CRS 3.0"))

	// Assert
	logLine := fileSystem.Get(Path + FileName)
	assertJSONLogLine(t, logLine, `
		{
			"timeStamp": "0000-00-00T00:00:00+00:00",
			"resourceId": "appgw",
			"operationName": "ApplicationGatewayFirewall",
			"category": "ApplicationGatewayFirewallLog",
			"properties": {
				"instanceId": "vm1",
				"clientIp": "1.2.3.4",
				"requestUri": "/hello.php?arg1=aaaaaaabccc",
				"ruleSetType": "OWASP",
				"ruleSetVersion": "CRS 3.0",
				"ruleId": "11",
				"ruleGroup": "",
				"message": "abc",
				"action": "Detected",
				"details": {
					"message": "bce",
					"data": "",
					"file": "",
					"line": ""
				},
				"hostname": "example.com",
				"transactionId": "abc",
				"policyId": "waf policy 1",
				"policyScope": "Global",
				"policyScopeName": "Default Policy",
				"engine": "Azwaf"
			}
		}
	`)
}

func TestIPReputationTriggered(t *testing.T) {
	// Arrange
	logger, fileSystem, _ := arrangeTestResultsLogger(t, false)

	// Act
	logger.IPReputationTriggered()

	// Assert
	logLine := fileSystem.Get(Path + FileName)
	assertJSONLogLine(t, logLine, `
	{
		"timeStamp": "0000-00-00T00:00:00+00:00",
			"resourceId": "appgw",
			"operationName": "ApplicationGatewayFirewall",
			"category": "ApplicationGatewayFirewallLog",
			"properties": {
			"instanceId": "vm1",
				"clientIp": "1.2.3.4",
				"requestUri": "/hello.php?arg1=aaaaaaabccc",
				"ruleSetType": "MicrosoftBotProtection",
				"message": "IPReputationTriggered",
				"action": "Blocked",
				"hostname": "example.com",
				"transactionId": "abc",
				"policyId": "waf policy 1",
				"policyScope": "Global",
				"policyScopeName": "Default Policy",
				"engine": "Azwaf"
		}
	}
	`)
}

func TestIPReputationDetectionMode(t *testing.T) {
	// Arrange
	logger, fileSystem, _ := arrangeTestResultsLogger(t, true)

	// Act
	logger.IPReputationTriggered()

	// Assert
	logLine := fileSystem.Get(Path + FileName)
	assertJSONLogLine(t, logLine, `
	{
		"timeStamp": "0000-00-00T00:00:00+00:00",
			"resourceId": "appgw",
			"operationName": "ApplicationGatewayFirewall",
			"category": "ApplicationGatewayFirewallLog",
			"properties": {
			"instanceId": "vm1",
				"clientIp": "1.2.3.4",
				"requestUri": "/hello.php?arg1=aaaaaaabccc",
				"ruleSetType": "MicrosoftBotProtection",
				"message": "IPReputationTriggered",
				"action": "Detected",
				"hostname": "example.com",
				"transactionId": "abc",
				"policyId": "waf policy 1",
				"policyScope": "Global",
				"policyScopeName": "Default Policy",
				"engine": "Azwaf"
		}
	}
	`)
}

func TestCustomRuleTriggeredBlocked(t *testing.T) {
	// Arrange
	logger, fileSystem, _ := arrangeTestResultsLogger(t, false)
	rlmc := []waf.ResultsLoggerCustomRulesMatchedConditions{
		{
			ConditionIndex: 0,
			VariableName:   "PostArgs",
			FieldName:      "somefield",
			MatchedValue:   "hello'\"\x00world",
		},
		{
			ConditionIndex: 1,
			VariableName:   "RequestUri",
			FieldName:      "",
			MatchedValue:   "abc",
		},
	}

	// Act
	logger.CustomRuleTriggered("myCustomRule1", "Block", rlmc)

	// Assert
	logLine := fileSystem.Get(Path + FileName)
	assertJSONLogLine(t, logLine, `
		{
			"timeStamp": "0000-00-00T00:00:00+00:00",
			"resourceId": "appgw",
			"operationName": "ApplicationGatewayFirewall",
			"category": "ApplicationGatewayFirewallLog",
			"properties": {
				"instanceId": "vm1",
				"clientIp": "1.2.3.4",
				"requestUri": "/hello.php?arg1=aaaaaaabccc",
				"ruleSetType": "Custom",
				"ruleId": "myCustomRule1",
				"message": "Found condition 0 in PostArgs, field name somefield, with value hello'\"\u0000world. Found condition 1 in RequestUri, with value abc.",
				"action": "Blocked",
				"hostname": "example.com",
				"transactionId": "abc",
				"policyId": "waf policy 1",
				"policyScope": "Global",
				"policyScopeName": "Default Policy",
				"engine": "Azwaf"
			}
		}
	`)
}

func TestCustomRuleTriggeredAllowed(t *testing.T) {
	// Arrange
	logger, fileSystem, _ := arrangeTestResultsLogger(t, false)
	rlmc := []waf.ResultsLoggerCustomRulesMatchedConditions{
		{
			ConditionIndex: 0,
			VariableName:   "RequestUri",
			FieldName:      "",
			MatchedValue:   "abc",
		},
	}

	// Act
	logger.CustomRuleTriggered("myCustomRule1", "Allow", rlmc)

	// Assert
	logLine := fileSystem.Get(Path + FileName)
	assertJSONLogLine(t, logLine, `
		{
			"timeStamp": "0000-00-00T00:00:00+00:00",
			"resourceId": "appgw",
			"operationName": "ApplicationGatewayFirewall",
			"category": "ApplicationGatewayFirewallLog",
			"properties": {
				"instanceId": "vm1",
				"clientIp": "1.2.3.4",
				"requestUri": "/hello.php?arg1=aaaaaaabccc",
				"ruleSetType": "Custom",
				"ruleId": "myCustomRule1",
				"message": "Found condition 0 in RequestUri, with value abc.",
				"action": "Allowed",
				"hostname": "example.com",
				"transactionId": "abc",
				"policyId": "waf policy 1",
				"policyScope": "Global",
				"policyScopeName": "Default Policy",
				"engine": "Azwaf"
			}
		}
	`)
}

func TestCustomRuleDetectionModeBlocked(t *testing.T) {
	// Arrange
	logger, fileSystem, _ := arrangeTestResultsLogger(t, true)
	rlmc := []waf.ResultsLoggerCustomRulesMatchedConditions{
		{
			ConditionIndex: 0,
			VariableName:   "RequestUri",
			FieldName:      "",
			MatchedValue:   "abc",
		},
	}

	// Act
	logger.CustomRuleTriggered("myCustomRule1", "Block", rlmc)

	// Assert
	logLine := fileSystem.Get(Path + FileName)
	assertJSONLogLine(t, logLine, `
		{
			"timeStamp": "0000-00-00T00:00:00+00:00",
			"resourceId": "appgw",
			"operationName": "ApplicationGatewayFirewall",
			"category": "ApplicationGatewayFirewallLog",
			"properties": {
				"instanceId": "vm1",
				"clientIp": "1.2.3.4",
				"requestUri": "/hello.php?arg1=aaaaaaabccc",
				"ruleSetType": "Custom",
				"ruleId": "myCustomRule1",
				"message": "Found condition 0 in RequestUri, with value abc.",
				"action": "Detected",
				"hostname": "example.com",
				"transactionId": "abc",
				"policyId": "waf policy 1",
				"policyScope": "Global",
				"policyScopeName": "Default Policy",
				"engine": "Azwaf"
			}
		}
	`)
}

func TestCustomRuleDetectionModeAllowed(t *testing.T) {
	// Arrange
	logger, fileSystem, _ := arrangeTestResultsLogger(t, true)
	rlmc := []waf.ResultsLoggerCustomRulesMatchedConditions{
		{
			ConditionIndex: 0,
			VariableName:   "RequestUri",
			FieldName:      "",
			MatchedValue:   "abc",
		},
	}

	// Act
	logger.CustomRuleTriggered("myCustomRule1", "Allow", rlmc)

	// Assert
	logLine := fileSystem.Get(Path + FileName)
	assertJSONLogLine(t, logLine, `
		{
			"timeStamp": "0000-00-00T00:00:00+00:00",
			"resourceId": "appgw",
			"operationName": "ApplicationGatewayFirewall",
			"category": "ApplicationGatewayFirewallLog",
			"properties": {
				"instanceId": "vm1",
				"clientIp": "1.2.3.4",
				"requestUri": "/hello.php?arg1=aaaaaaabccc",
				"ruleSetType": "Custom",
				"ruleId": "myCustomRule1",
				"message": "Found condition 0 in RequestUri, with value abc.",
				"action": "Allowed",
				"hostname": "example.com",
				"transactionId": "abc",
				"policyId": "waf policy 1",
				"policyScope": "Global",
				"policyScopeName": "Default Policy",
				"engine": "Azwaf"
			}
		}
	`)
}

func arrangeTestResultsLogger(t *testing.T, isDetectionMode bool) (waf.ResultsLogger, *mockFileSystem, chan bool) {
	request := &mockWafHTTPRequest{}
	zeroLogger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).Level(1).With().Timestamp().Caller().Logger()
	fileSystem := newMockFileSystem()

	reopenFileCh := make(chan bool)

	f, err := NewFileLogResultsLoggerFactory(fileSystem, zeroLogger, reopenFileCh)
	if err != nil {
		t.Fatalf("Unexpected error %T: %v", err, err)
	}
	mclmd := &mockConfigLogMetaData{}
	logger := f.NewResultsLogger(request, mclmd, isDetectionMode)
	if err != nil {
		t.Fatalf("Unexpected error %T: %v", err, err)
	}
	return logger, fileSystem, reopenFileCh
}

func assertJSONLogLine(t *testing.T, actual string, expected string) {
	if !(strings.Count(actual, "\n") == 1 && actual[:len(actual)-2] != "\n") {
		t.Fatalf("Log line did not end with a line break")
	}

	actual = neutralizeDate(actual)

	var err error
	actual, err = reformatJSON(actual)
	if err != nil {
		t.Fatalf("Unexpected error %T: %v", err, err)
	}

	expected, err = reformatJSON(expected)
	if err != nil {
		t.Fatalf("Unexpected error %T: %v", err, err)
	}

	if actual != expected {
		t.Fatalf("Unexpected log entry. Actual:\n%v\nExpected:\n%v\n", actual, expected)
	}
}

func reformatJSON(s string) (string, error) {
	var buf bytes.Buffer
	err := json.Indent(&buf, []byte(s), "", "  ")
	return strings.TrimSpace(buf.String()), err
}

func neutralizeDate(s string) string {
	azureLogDateFormatRegex := regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00`)
	return azureLogDateFormatRegex.ReplaceAllString(s, "0000-00-00T00:00:00+00:00")
}

type mockFile struct {
	Content string
}

func (fs *mockFile) Append(content []byte) (err error) {
	fs.Content = fs.Content + string(content)
	return nil
}

func (fs *mockFile) Close() (err error) {
	return nil
}

type mockFileSystem struct {
	fmap          map[string]LogFile
	openCalledMap map[string]int
}

func newMockFileSystem() *mockFileSystem {
	fileSystem := &mockFileSystem{}
	fileSystem.fmap = make(map[string]LogFile)
	fileSystem.openCalledMap = make(map[string]int)
	return fileSystem
}

func (fs *mockFileSystem) MkDir(name string) error {
	return nil
}

func (fs *mockFileSystem) Open(name string) (f LogFile, err error) {
	f = &mockFile{}
	fs.fmap[name] = f

	if c, ok := fs.openCalledMap[name]; ok {
		fs.openCalledMap[name] = c + 1
		return f, nil
	}

	fs.openCalledMap[name] = 1
	return f, nil
}

func (fs *mockFileSystem) Get(name string) (content string) {
	return fs.fmap[name].(*mockFile).Content
}

type mockWafHTTPRequest struct{}

func (r *mockWafHTTPRequest) Method() string     { return "GET" }
func (r *mockWafHTTPRequest) URI() string        { return "/hello.php?arg1=aaaaaaabccc" }
func (r *mockWafHTTPRequest) Protocol() string   { return "HTTP/1.1" }
func (r *mockWafHTTPRequest) RemoteAddr() string { return "1.2.3.4" }
func (r *mockWafHTTPRequest) Headers() []waf.HeaderPair {
	return []waf.HeaderPair{&mockHeaderPair{k: "Host", v: "example.com"}}
}
func (r *mockWafHTTPRequest) ConfigID() string                    { return "waf policy 1" }
func (r *mockWafHTTPRequest) BodyReader() io.Reader               { return &bytes.Buffer{} }
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

type mockConfigLogMetaData struct {
}

func (h *mockConfigLogMetaData) ResourceID() string { return "appgw" }
func (h *mockConfigLogMetaData) InstanceID() string { return "vm1" }

type mockMatchCondition struct{}

func (*mockMatchCondition) MatchVariables() []waf.MatchVariable { return nil }
func (*mockMatchCondition) Operator() string                    { return "Contains" }
func (*mockMatchCondition) NegateCondition() bool               { return false }
func (*mockMatchCondition) MatchValues() []string               { return []string{"val1", "val2"} }
func (*mockMatchCondition) Transforms() []string                { return []string{"Lowercase", "Trim"} }
