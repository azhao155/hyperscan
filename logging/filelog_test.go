package logging

import (
	"azwaf/customrule"
	"azwaf/secrule"
	"azwaf/waf"
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestSecRuleTriggered(t *testing.T) {
	// Arrange
	request := &mockWafHTTPRequest{
		configID: "waf1",
		uri:      "/a",
	}

	stat := &secrule.Rule{
		ID: 11,
	}

	zeroLogger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).Level(1).With().Timestamp().Caller().Logger()
	fileSystem := newMockFileSystem()
	logger, err := NewFileResultsLogger(fileSystem, zeroLogger)
	if err != nil {
		t.Fatalf("Unexpected error %T: %v", err, err)
	}

	// Act
	logger.SetLogMetaData(&mockConfigLogMetaData{})
	logger.SecRuleTriggered(request, stat, "deny", "abc", "bce")
	log := fileSystem.Get(Path + FileName)

	// Assert
	if !(strings.Count(log, "\n") == 1 && log[:len(log)-2] != "\n") {
		t.Fatalf("Log line did not end with a line break")
	}

	// TODO remove this when ResultsLogger is per request and triggeredTime is just a field of ResultsLogger
	azureLogDateFormatRegex := regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00`)
	log = azureLogDateFormatRegex.ReplaceAllString(log, "0000-00-00T00:00:00+00:00")

	log, err = reformatJSON(log)
	if err != nil {
		t.Fatalf("Unexpected error %T: %v", err, err)
	}

	expected := `
		{
			"timeStamp": "0000-00-00T00:00:00+00:00",
			"resourceId": "appgw",
			"operationName": "ApplicationGatewayFirewall",
			"category": "ApplicationGatewayFirewallLog",
			"properties": {
				"instanceId": "vm1",
				"clientIp": "",
				"clientPort": "",
				"requestUri": "/a",
				"ruleSetType": "",
				"ruleSetVersion": "",
				"ruleId": "11",
				"ruleGroup": "",
				"message": "abc",
				"action": "deny",
				"details": {
					"message": "bce",
					"data": "",
					"file": "",
					"line": ""
				},
				"hostname": "",
				"transactionId": "abc",
				"policyId": "waf1",
				"policyScope": "Global",
				"policyScopeName": "Default Policy"
			}
		}
	`
	expected, err = reformatJSON(expected)
	if err != nil {
		t.Fatalf("Unexpected error %T: %v", err, err)
	}

	if log != expected {
		t.Fatalf("Unexpected log entry. Actual:\n%v\nExpected:\n%v\n", log, expected)
	}
}

func TestIPReputationTriggered(t *testing.T) {
	// Arrange
	request := &mockWafHTTPRequest{
		configID: "waf1",
		uri:      "/a",
	}

	zeroLogger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).Level(1).With().Timestamp().Caller().Logger()
	fileSystem := newMockFileSystem()
	logger, err := NewFileResultsLogger(fileSystem, zeroLogger)
	if err != nil {
		t.Fatalf("Unexpected error %T: %v", err, err)
	}

	// Act
	logger.SetLogMetaData(&mockConfigLogMetaData{})
	logger.IPReputationTriggered(request)
	log := fileSystem.Get(Path + FileName)

	// Assert
	if !(strings.Count(log, "\n") == 1 && log[:len(log)-2] != "\n") {
		t.Fatalf("Log line did not end with a line break")
	}

	// TODO remove this when ResultsLogger is per request and triggeredTime is just a field of ResultsLogger
	azureLogDateFormatRegex := regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00`)
	log = azureLogDateFormatRegex.ReplaceAllString(log, "0000-00-00T00:00:00+00:00")

	log, err = reformatJSON(log)
	if err != nil {
		t.Fatalf("Unexpected error %T: %v", err, err)
	}

	expected := `
		{
			"timeStamp": "0000-00-00T00:00:00+00:00",
			"resourceId": "appgw",
			"operationName": "ApplicationGatewayFirewall",
			"category": "ApplicationGatewayFirewallLog",
			"properties": {
				"instanceId": "vm1",
				"clientIp": "",
				"clientPort": "",
				"requestUri": "/a",
				"ruleSetType": "",
				"ruleSetVersion": "",
				"message": "IPReputationTriggered",
				"action": "Blocked",
				"hostname": "",
				"transactionId": "abc",
				"policyId": "waf1",
				"policyScope": "Global",
				"policyScopeName": "Default Policy"
			}
		}
	`
	expected, err = reformatJSON(expected)
	if err != nil {
		t.Fatalf("Unexpected error %T: %v", err, err)
	}

	if log != expected {
		t.Fatalf("Unexpected log entry. Actual:\n%v\nExpected:\n%v\n", log, expected)
	}
}

func TestCustomRuleTriggered(t *testing.T) {
	// Arrange
	request := &mockWafHTTPRequest{configID: "waf1", uri: "/a"}
	zeroLogger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).Level(1).With().Timestamp().Caller().Logger()
	fileSystem := newMockFileSystem()
	logger, err := NewFileResultsLogger(fileSystem, zeroLogger)
	if err != nil {
		t.Fatalf("Unexpected error %T: %v", err, err)
	}
	customRule := &mockCustomRule{}
	if err != nil {
		t.Fatalf("Unexpected error %T: %v", err, err)
	}
	rlmc := []customrule.ResultsLoggerMatchedConditions{
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
	logger.SetLogMetaData(&mockConfigLogMetaData{})
	logger.CustomRuleTriggered(request, customRule, rlmc)
	log := fileSystem.Get(Path + FileName)

	// Assert
	if !(strings.Count(log, "\n") == 1 && log[:len(log)-2] != "\n") {
		t.Fatalf("Log line did not end with a line break")
	}

	// TODO remove this when ResultsLogger is per request and triggeredTime is just a field of ResultsLogger
	azureLogDateFormatRegex := regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00`)
	log = azureLogDateFormatRegex.ReplaceAllString(log, "0000-00-00T00:00:00+00:00")

	log, err = reformatJSON(log)
	if err != nil {
		t.Fatalf("Unexpected error %T: %v", err, err)
	}

	expected := `
		{
			"timeStamp": "0000-00-00T00:00:00+00:00",
			"resourceId": "appgw",
			"operationName": "ApplicationGatewayFirewall",
			"category": "ApplicationGatewayFirewallLog",
			"properties": {
				"instanceId": "vm1",
				"clientIp": "1.2.3.4",
				"requestUri": "/a",
				"ruleSetType": "Custom",
				"ruleId": "myCustomRule1",
				"message": "Found condition 0 in PostArgs, field name somefield, with value hello'\"\u0000world. Found condition 1 in RequestUri, with value abc.",
				"action": "Blocked",
				"hostname": "example.com",
				"transactionId": "abc",
				"policyId": "waf1",
				"policyScope": "Global",
				"policyScopeName": "Default Policy",
				"engine": "Azwaf"
			}
		}
	`
	expected, err = reformatJSON(expected)
	if err != nil {
		t.Fatalf("Unexpected error %T: %v", err, err)
	}

	ioutil.WriteFile("actual.txt", []byte(log), 0777)
	ioutil.WriteFile("expected.txt", []byte(expected), 0777)

	if log != expected {
		t.Fatalf("Unexpected log entry. Actual:\n%v\nExpected:\n%v\n", log, expected)
	}
}

type mockFile struct {
	Content string
}

func (fs *mockFile) Append(content []byte) (err error) {
	fs.Content = fs.Content + string(content)
	return nil
}

type mockFileSystem struct {
	fmap map[string]LogFile
}

func newMockFileSystem() *mockFileSystem {
	fileSystem := &mockFileSystem{}
	fileSystem.fmap = make(map[string]LogFile)
	return fileSystem
}

func (fs *mockFileSystem) MkDir(name string) error {
	return nil
}

func (fs *mockFileSystem) Open(name string) (f LogFile, err error) {
	f = &mockFile{}
	fs.fmap[name] = f
	return f, nil
}

func (fs *mockFileSystem) Get(name string) (content string) {
	return fs.fmap[name].(*mockFile).Content
}

type mockWafHTTPRequest struct {
	uri      string
	method   string
	configID string
	body     string
}

func (r *mockWafHTTPRequest) ConfigID() string   { return r.configID }
func (r *mockWafHTTPRequest) URI() string        { return r.uri }
func (r *mockWafHTTPRequest) RemoteAddr() string { return "1.2.3.4" }
func (r *mockWafHTTPRequest) Headers() []waf.HeaderPair {
	return []waf.HeaderPair{&mockHeaderPair{k: "Host", v: "example.com"}}
}
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

type mockCustomRule struct{}

func (*mockCustomRule) Name() string     { return "myCustomRule1" }
func (*mockCustomRule) Priority() int    { return 100 }
func (*mockCustomRule) RuleType() string { return "MatchRule" }
func (*mockCustomRule) MatchConditions() []waf.MatchCondition {
	return []waf.MatchCondition{&mockMatchCondition{}}
}
func (*mockCustomRule) Action() string { return "Block" }

type mockMatchCondition struct{}

func (*mockMatchCondition) MatchVariables() []waf.MatchVariable { return nil }
func (*mockMatchCondition) Operator() string                    { return "Contains" }
func (*mockMatchCondition) NegateCondition() bool               { return false }
func (*mockMatchCondition) MatchValues() []string               { return []string{"val1", "val2"} }
func (*mockMatchCondition) Transforms() []string                { return []string{"Lowercase", "Trim"} }

func reformatJSON(s string) (string, error) {
	var buf bytes.Buffer
	err := json.Indent(&buf, []byte(s), "", "  ")
	return strings.TrimSpace(buf.String()), err
}
