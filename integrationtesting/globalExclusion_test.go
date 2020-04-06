package integrationtesting

import (
	"azwaf/waf"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestExclusionPutConfig(t *testing.T) {
	assert := assert.New(t)

	ex := &mockExclusion{
		matchVariable:         "RequestArgNames",
		selectorMatchOperator: "Contains",
		selector:              "test",
	}

	config := &mockWAFConfig{
		configVersion: 0,
		policyConfigs: []waf.PolicyConfig{
			&mockPolicyConfig{
				configID: "abc",
				secRuleConfig: &mockSecRuleConfig{
					enabled:    true,
					ruleSetID:  "OWASP CRS 3.0",
					exclusions: []waf.Exclusion{ex},
				},
				customRuleConfig:   &mockCustomRuleConfig{},
				ipReputationConfig: &mockIPReputationConfig{},
			},
		},
		logMetaData: &mockConfigLogMetaData{},
	}

	// Arrange
	wafServer := newTestAzwafServer(t)

	// Act
	err := wafServer.PutConfig(config)

	// Assert
	assert.Nil(err)
}

type reqRespStruct struct {
	request          mockWafHTTPRequest
	expectedDecision waf.Decision
}

func testRequest(t *testing.T, testCase string, secRuleConfig *mockSecRuleConfig, withExclReqResp []reqRespStruct, withoutExclReqResp []reqRespStruct) {
	testRequestWithSecRuleConfig(t, testCase, secRuleConfig, withExclReqResp)
	withouExclusionSecRuleConfig := secRuleConfig
	withouExclusionSecRuleConfig.exclusions = []waf.Exclusion{}
	if withoutExclReqResp == nil {
		withoutExclReqResp = changePassToBlock(withExclReqResp)
	}
	testRequestWithSecRuleConfig(t, testCase+" WithoutExclusion ", withouExclusionSecRuleConfig, withoutExclReqResp)
}

func testRequestWithSecRuleConfig(t *testing.T, testCase string, secRuleConfig *mockSecRuleConfig, reqResponces []reqRespStruct) {
	wafServer := newTestStandaloneSecruleServer(t, secRuleConfig)

	for _, reqres := range reqResponces {
		// Act
		decision, err := wafServer.EvalRequest(&reqres.request)
		if err != nil {
			t.Fatalf("%s: Got unexpected error: %v", testCase, err)
		}

		// Assert
		if decision != reqres.expectedDecision {
			t.Fatalf("%s: Expected decision: %v Actual decision: %v ", testCase, reqres.expectedDecision, decision)
		}
	}
}

func changePassToBlock(in []reqRespStruct) []reqRespStruct {
	result := []reqRespStruct{}
	for _, reqres := range in {
		if reqres.expectedDecision == waf.Pass {
			temp := reqRespStruct{request: reqres.request, expectedDecision: waf.Block}
			result = append(result, temp)
		} else {
			result = append(result, reqres)
		}
	}

	return result
}

func TestArgsGetExclusion(t *testing.T) {
	origLogLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	defer zerolog.SetGlobalLevel(origLogLevel)

	// Arrange
	ex := &mockExclusion{
		matchVariable:         "RequestArgNames",
		selectorMatchOperator: "Equals",
		selector:              "text",
	}

	msrc := &mockSecRuleConfig{
		enabled:    true,
		ruleSetID:  "OWASP CRS 3.0",
		exclusions: []waf.Exclusion{ex},
	}

	reqResp := []reqRespStruct{
		reqRespStruct{
			request:          mockWafHTTPRequest{uri: "http://localhost:8080/?text=/etc/passwd", method: "GET", headers: []waf.HeaderPair{&mockHeaderPair{k: "Host", v: "example.com"}}, protocol: "HTTP/1.1"},
			expectedDecision: waf.Pass,
		},
	}

	testRequest(t, "TestArgsGetExclusion", msrc, reqResp, nil)
}

func TestExclusionEvalRequest(t *testing.T) {
	origLogLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	defer zerolog.SetGlobalLevel(origLogLevel)

	// Arrange
	ex := &mockExclusion{
		matchVariable:         "RequestArgNames",
		selectorMatchOperator: "Contains",
		selector:              "arg1",
	}

	msrc := &mockSecRuleConfig{
		enabled:    true,
		ruleSetID:  "OWASP CRS 3.0",
		exclusions: []waf.Exclusion{ex},
	}

	headers := []waf.HeaderPair{&mockHeaderPair{k: "Host", v: "example.com"}}

	reqResponses := []reqRespStruct{
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/?arg1=/etc/passwd", method: "GET", headers: headers, protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/?b=/etc/passwd", method: "GET", headers: headers, protocol: "HTTP/1.1"}, expectedDecision: waf.Block},
	}

	testRequest(t, "TestExclusionEvalRequest", msrc, reqResponses, nil)
}

func TestNewStandaloneSecruleServerEvalRequestCrs30WithExclusionsOnArgNames(t *testing.T) {
	origLogLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	defer zerolog.SetGlobalLevel(origLogLevel)

	// Arrange
	msrc := &mockSecRuleConfig{
		ruleSetID: "OWASP CRS 3.0",
		exclusions: []waf.Exclusion{
			&mockExclusion{selectorMatchOperator: "Contains", selector: "arg1", matchVariable: "RequestArgNames"},
			&mockExclusion{selectorMatchOperator: "Equals", selector: "arg2", matchVariable: "RequestArgNames"},
			&mockExclusion{selectorMatchOperator: "StartsWith", selector: "arg3", matchVariable: "RequestArgNames"},
			&mockExclusion{selectorMatchOperator: "Contains", selector: "xyz", matchVariable: "RequestArgNames"},
			&mockExclusion{selectorMatchOperator: "EndsWith", selector: "arg4", matchVariable: "RequestArgNames"},
			&mockExclusion{selectorMatchOperator: "Equals", selector: "a[^$.|*()\\b", matchVariable: "RequestArgNames"}},
	}

	headers := []waf.HeaderPair{&mockHeaderPair{k: "Host", v: "example.com"}}
	reqResponses := []reqRespStruct{
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/?b=/etc/passwd", method: "GET", headers: headers, protocol: "HTTP/1.1"}, expectedDecision: waf.Block},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/?arg1Something=/etc/passwd", method: "GET", headers: headers, protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/?somethingarg1=/etc/passwd", method: "GET", headers: headers, protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/?start_arg1_end=/etc/passwd", method: "GET", headers: headers, protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/?arg2=/etc/passwd", method: "GET", headers: headers, protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/?something_arg2_someting=/etc/passwd", method: "GET", headers: headers, protocol: "HTTP/1.1"}, expectedDecision: waf.Block},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/?arg3Var=/etc/passwd", method: "GET", headers: headers, protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/?endsWitharg4=/etc/passwd", method: "GET", headers: headers, protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/?abdxyzgb=/etc/passwd", method: "GET", headers: headers, protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/?arg3endsWitharg4=/etc/passwd", method: "GET", headers: headers, protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/?a[^$.|*()\\b=/etc/passwd", method: "GET", headers: headers, protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
	}

	testRequest(t, "TestNewStandaloneSecruleServerEvalRequestCrs30WithExclusionsOnArgNames", msrc, reqResponses, nil)
}

func TestNewStandaloneSecruleServerEvalRequestCrs30WithExclusionsOnArgNamesEqualsAny(t *testing.T) {
	origLogLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	defer zerolog.SetGlobalLevel(origLogLevel)

	// Arrange
	ex := &mockExclusion{
		matchVariable:         "RequestArgNames",
		selectorMatchOperator: "EqualsAny",
		selector:              "",
	}

	msrc := &mockSecRuleConfig{
		enabled:    true,
		ruleSetID:  "OWASP CRS 3.0",
		exclusions: []waf.Exclusion{ex},
	}

	headers := []waf.HeaderPair{&mockHeaderPair{k: "Host", v: "example.com"}}

	reqResponses := []reqRespStruct{
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/?arg1=/etc/passwd", method: "GET", headers: headers, protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/?arg2=/etc/passwd", method: "GET", headers: headers, protocol: "HTTP/1.1"}, expectedDecision: waf.Pass}}

	testRequest(t, "TestNewStandaloneSecruleServerEvalRequestCrs30WithExclusionsOnArgNamesEqualsAny", msrc, reqResponses, nil)
}

func TestGlobalExclusionsOnCookieNames(t *testing.T) {
	origLogLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	defer zerolog.SetGlobalLevel(origLogLevel)

	exclusions := []waf.Exclusion{
		&mockExclusion{selectorMatchOperator: "Contains", selector: "arg1", matchVariable: "RequestCookieNames"},
		&mockExclusion{selectorMatchOperator: "Equals", selector: "arg2", matchVariable: "RequestCookieNames"},
		&mockExclusion{selectorMatchOperator: "StartsWith", selector: "arg3", matchVariable: "RequestCookieNames"},
		&mockExclusion{selectorMatchOperator: "Contains", selector: "xyz", matchVariable: "RequestCookieNames"},
		&mockExclusion{selectorMatchOperator: "EndsWith", selector: "arg4", matchVariable: "RequestCookieNames"},
		&mockExclusion{selectorMatchOperator: "Equals", selector: "a[^$.|*()\\b", matchVariable: "RequestCookieNames"},
	}

	// Arrange
	msrc := &mockSecRuleConfig{
		ruleSetID:  "OWASP CRS 3.0",
		exclusions: exclusions,
	}

	headers := []waf.HeaderPair{&mockHeaderPair{k: "Host", v: "example.com"}}
	reqResponses := []reqRespStruct{
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/", method: "GET", headers: append(headers, &mockHeaderPair{k: "Cookie", v: "test=/etc/passwd"}), protocol: "HTTP/1.1"}, expectedDecision: waf.Block},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/", method: "GET", headers: append(headers, &mockHeaderPair{k: "Cookie", v: "arg1=/etc/passwd"}), protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/", method: "GET", headers: append(headers, &mockHeaderPair{k: "Cookie", v: "arg2=/etc/passwd"}), protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/", method: "GET", headers: append(headers, &mockHeaderPair{k: "Cookie", v: "arg3=/etc/passwd"}), protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/", method: "GET", headers: append(headers, &mockHeaderPair{k: "Cookie", v: "arg4=/etc/passwd"}), protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/", method: "GET", headers: append(headers, &mockHeaderPair{k: "Cookie", v: "xyz=/etc/passwd"}), protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/", method: "GET", headers: append(headers, &mockHeaderPair{k: "Cookie", v: "a[^$.|*()\\b=/etc/passwd"}), protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
	}

	testRequest(t, "TestGlobalExclusionsOnCookieNames", msrc, reqResponses, nil)
}

func TestGlobalExclusionsOnCookieNamesWithEqualsAny(t *testing.T) {
	origLogLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	defer zerolog.SetGlobalLevel(origLogLevel)

	// Arrange
	exclusions := []waf.Exclusion{&mockExclusion{selectorMatchOperator: "EqualsAny", matchVariable: "RequestCookieNames"}}

	msrc := &mockSecRuleConfig{
		ruleSetID:  "OWASP CRS 3.0",
		exclusions: exclusions,
	}

	headers := []waf.HeaderPair{&mockHeaderPair{k: "Host", v: "example.com"}}
	reqResponses := []reqRespStruct{
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/", method: "GET", headers: append(headers, &mockHeaderPair{k: "Cookie", v: "test=/etc/passwd"}), protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/", method: "GET", headers: append(headers, &mockHeaderPair{k: "Cookie", v: "a[^$.|*()\\b=/etc/passwd"}), protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
	}

	testRequest(t, "TestGlobalExclusionsOnCookieNamesWithEqualsAny", msrc, reqResponses, nil)
}

func TestGlobalExclusionsOnRequestHeaderNames(t *testing.T) {
	origLogLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.FatalLevel)
	defer zerolog.SetGlobalLevel(origLogLevel)

	// Arrange
	exclusions := []waf.Exclusion{
		&mockExclusion{matchVariable: "RequestHeaderNames", selectorMatchOperator: "Equals", selector: "head1"},
		&mockExclusion{matchVariable: "RequestHeaderNames", selectorMatchOperator: "Contains", selector: "head2"},
		&mockExclusion{matchVariable: "RequestHeaderNames", selectorMatchOperator: "StartsWith", selector: "head3"},
		&mockExclusion{matchVariable: "RequestHeaderNames", selectorMatchOperator: "EndsWith", selector: "head4"},
		&mockExclusion{matchVariable: "RequestHeaderNames", selectorMatchOperator: "Equals", selector: "a[^$.|*()\\b"},
		&mockExclusion{matchVariable: "RequestHeaderNames", selectorMatchOperator: "Contains", selector: "xyz"},
	}

	msrc := &mockSecRuleConfig{
		ruleSetID:  "OWASP CRS 3.0",
		enabled:    true,
		exclusions: exclusions,
	}

	headers := []waf.HeaderPair{
		&mockHeaderPair{k: "Accept", v: "*/*"},
		&mockHeaderPair{k: "Host", v: "example.com"},
		&mockHeaderPair{k: "Max-Forwards", v: "10"},
		&mockHeaderPair{k: "User-Agent", v: "curl/7.50.3"},
		&mockHeaderPair{k: "head1", v: "X-Scanner"},
		&mockHeaderPair{k: "bla_head2_bla", v: "X-Scanner"},
		&mockHeaderPair{k: "head3SomethingElse", v: "X-Scanner"},
		&mockHeaderPair{k: "somethingElsehead4", v: "X-Scanner"},
		&mockHeaderPair{k: "a[^$.|*()\\b", v: "X-Scanner"},
		&mockHeaderPair{k: "xyz", v: "X-Scanner"},
		&mockHeaderPair{k: "fooxyzbar", v: "X-Scanner"},
	}

	reqResponses := []reqRespStruct{
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/", method: "GET", headers: append(headers, &mockHeaderPair{k: "NotExcluded", v: "X-Scanner"}), protocol: "HTTP/1.1"}, expectedDecision: waf.Block},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/", method: "GET", headers: headers, protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
	}

	testRequest(t, "TestGlobalExclusionsOnRequestHeaderNames", msrc, reqResponses, nil)

}

func TestGlobalExclusionsOnRequestHeaderNamesWithEqualsAny(t *testing.T) {
	origLogLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.FatalLevel)
	defer zerolog.SetGlobalLevel(origLogLevel)

	// Arrange
	exclusions := []waf.Exclusion{
		&mockExclusion{matchVariable: "RequestHeaderNames", selectorMatchOperator: "EqualsAny"},
	}

	msrc := &mockSecRuleConfig{
		ruleSetID:  "OWASP CRS 3.0",
		enabled:    true,
		exclusions: exclusions,
	}

	headers := []waf.HeaderPair{
		&mockHeaderPair{k: "Accept", v: "*/*"},
		&mockHeaderPair{k: "Host", v: "example.com"},
		&mockHeaderPair{k: "Max-Forwards", v: "10"},
		&mockHeaderPair{k: "User-Agent", v: "curl/7.50.3"},
		&mockHeaderPair{k: "head1", v: "X-Scanner"},
		&mockHeaderPair{k: "bla_head2_bla", v: "X-Scanner"},
		&mockHeaderPair{k: "head3SomethingElse", v: "X-Scanner"},
		&mockHeaderPair{k: "somethingElsehead4", v: "X-Scanner"},
		&mockHeaderPair{k: "a[^$.|*()\\b", v: "X-Scanner"},
		&mockHeaderPair{k: "xyz", v: "X-Scanner"},
		&mockHeaderPair{k: "fooxyzbar", v: "X-Scanner"},
		&mockHeaderPair{k: "NotExcluded", v: "X-Scanner"},
	}

	reqResponses := []reqRespStruct{
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/", method: "GET", headers: headers, protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
	}

	testRequest(t, "TestGlobalExclusionsOnRequestHeaderNames", msrc, reqResponses, nil)
}
