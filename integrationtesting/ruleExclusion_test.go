package integrationtesting

import (
	"azwaf/waf"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestRuleExclusionPutConfig(t *testing.T) {
	assert := assert.New(t)

	ex := &mockExclusion{
		matchVariable:         "RequestArgNames",
		selectorMatchOperator: "Contains",
		selector:              "test",
		rules:                 []int32{930120, 932160},
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

func TestArgsRuleExclusion(t *testing.T) {
	// Arrange
	ex := &mockExclusion{
		matchVariable:         "RequestArgNames",
		selectorMatchOperator: "Equals",
		selector:              "text",
		rules:                 []int32{930120, 932160},
	}

	msrc := &mockSecRuleConfig{
		enabled:    true,
		ruleSetID:  "OWASP CRS 3.0",
		exclusions: []waf.Exclusion{ex},
	}

	headers := []waf.HeaderPair{&mockHeaderPair{k: "Host", v: "example.com"}}
	reqResp := []reqRespStruct{
		reqRespStruct{
			request:          mockWafHTTPRequest{uri: "http://localhost:8080/?text=/etc/passwd", method: "GET", headers: headers, protocol: "HTTP/1.1"},
			expectedDecision: waf.Pass,
		},
	}

	testRequest(t, "TestArgsRuleExclusion", msrc, reqResp, nil)
}

func TestRuleExclusionEvalRequest(t *testing.T) {
	// Arrange
	ex := &mockExclusion{
		matchVariable:         "RequestArgNames",
		selectorMatchOperator: "Contains",
		selector:              "arg1",
		rules:                 []int32{930120, 932160},
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

	testRequest(t, "TestRuleExclusionEvalRequest", msrc, reqResponses, nil)
}

func TestRuleExclusionsOnArgNames(t *testing.T) {
	origLogLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	defer zerolog.SetGlobalLevel(origLogLevel)

	// Arrange
	ruleExclusions := []waf.Exclusion{
		&mockExclusion{selectorMatchOperator: "Contains", selector: "arg1", matchVariable: "RequestArgNames", rules: []int32{930120, 932160}},
		&mockExclusion{selectorMatchOperator: "Equals", selector: "arg2", matchVariable: "RequestArgNames", rules: []int32{930120, 932160}},
		&mockExclusion{selectorMatchOperator: "StartsWith", selector: "arg3", matchVariable: "RequestArgNames", rules: []int32{930120, 932160}},
		&mockExclusion{selectorMatchOperator: "Contains", selector: "xyz", matchVariable: "RequestArgNames", rules: []int32{930120, 932160}},
		&mockExclusion{selectorMatchOperator: "EndsWith", selector: "arg4", matchVariable: "RequestArgNames", rules: []int32{930120, 932160}},
		&mockExclusion{selectorMatchOperator: "Equals", selector: "a[^$.|*()\\b", matchVariable: "RequestArgNames", rules: []int32{930120, 932160}},
	}

	msrc := &mockSecRuleConfig{
		enabled:    true,
		ruleSetID:  "OWASP CRS 3.0",
		exclusions: ruleExclusions,
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

	testRequest(t, "TestRuleExclusionsOnArgNames", msrc, reqResponses, nil)
}

func TestRuleExclusionsOnArgNamesWithEqulsAny(t *testing.T) {
	origLogLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	defer zerolog.SetGlobalLevel(origLogLevel)

	// Arrange
	ex := &mockExclusion{
		matchVariable:         "RequestArgNames",
		selectorMatchOperator: "EqualsAny",
		selector:              "",
		rules:                 []int32{930120, 932160},
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

	testRequest(t, "TestRuleExclusionsOnArgNamesWithEqulsAny", msrc, reqResponses, nil)
}

func TestRuleExclusionsOnCookieNames(t *testing.T) {
	origLogLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	defer zerolog.SetGlobalLevel(origLogLevel)

	// Arrange
	ruleExclusions := []waf.Exclusion{
		&mockExclusion{selectorMatchOperator: "Contains", selector: "arg1", matchVariable: "RequestCookieNames", rules: []int32{930120, 932160}},
		&mockExclusion{selectorMatchOperator: "Equals", selector: "arg2", matchVariable: "RequestCookieNames", rules: []int32{930120, 932160}},
		&mockExclusion{selectorMatchOperator: "StartsWith", selector: "arg3", matchVariable: "RequestCookieNames", rules: []int32{930120, 932160}},
		&mockExclusion{selectorMatchOperator: "Contains", selector: "xyz", matchVariable: "RequestCookieNames", rules: []int32{930120, 932160}},
		&mockExclusion{selectorMatchOperator: "EndsWith", selector: "arg4", matchVariable: "RequestCookieNames", rules: []int32{930120, 932160}},
		&mockExclusion{selectorMatchOperator: "Equals", selector: "a[^$.|*()\\b", matchVariable: "RequestCookieNames", rules: []int32{930120, 932160}},
	}

	msrc := &mockSecRuleConfig{
		enabled:    true,
		ruleSetID:  "OWASP CRS 3.0",
		exclusions: ruleExclusions,
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

	testRequest(t, "TestRuleExclusionsOnCookieNames", msrc, reqResponses, nil)
}

func TestRuleExclusionsOnCookieNamesWithEqualsAny(t *testing.T) {
	origLogLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	defer zerolog.SetGlobalLevel(origLogLevel)

	// Arrange
	ex := &mockExclusion{selectorMatchOperator: "EqualsAny", matchVariable: "RequestCookieNames", rules: []int32{930120, 932160}}

	msrc := &mockSecRuleConfig{
		ruleSetID:  "OWASP CRS 3.0",
		exclusions: []waf.Exclusion{ex},
	}

	headers := []waf.HeaderPair{&mockHeaderPair{k: "Host", v: "example.com"}}
	reqResponses := []reqRespStruct{
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/", method: "GET", headers: append(headers, &mockHeaderPair{k: "Cookie", v: "test=/etc/passwd"}), protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
		{request: mockWafHTTPRequest{uri: "http://localhost:8080/", method: "GET", headers: append(headers, &mockHeaderPair{k: "Cookie", v: "a[^$.|*()\\b=/etc/passwd"}), protocol: "HTTP/1.1"}, expectedDecision: waf.Pass},
	}

	testRequest(t, "TestRuleExclusionsOnCookieNamesWithEqualsAny", msrc, reqResponses, nil)
}

func TestRuleExclusionsOnRequestHeaderNames(t *testing.T) {
	origLogLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.FatalLevel)
	defer zerolog.SetGlobalLevel(origLogLevel)

	// Arrange
	exclusions := []waf.Exclusion{
		&mockExclusion{matchVariable: "RequestHeaderNames", selectorMatchOperator: "Equals", selector: "head1", rules: []int32{913110}},
		&mockExclusion{matchVariable: "RequestHeaderNames", selectorMatchOperator: "Contains", selector: "head2", rules: []int32{913110}},
		&mockExclusion{matchVariable: "RequestHeaderNames", selectorMatchOperator: "StartsWith", selector: "head3", rules: []int32{913110}},
		&mockExclusion{matchVariable: "RequestHeaderNames", selectorMatchOperator: "EndsWith", selector: "head4", rules: []int32{913110}},
		&mockExclusion{matchVariable: "RequestHeaderNames", selectorMatchOperator: "Equals", selector: "a[^$.|*()\\b", rules: []int32{913110}},
		&mockExclusion{matchVariable: "RequestHeaderNames", selectorMatchOperator: "Contains", selector: "xyz", rules: []int32{913110}},
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

	testRequest(t, "TestRuleExclusionsOnRequestHeaderNames", msrc, reqResponses, nil)

}

func TestRuleExclusionsOnRequestHeaderNamesWithEqualsAny(t *testing.T) {
	origLogLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.FatalLevel)
	defer zerolog.SetGlobalLevel(origLogLevel)

	// Arrange
	exclusions := []waf.Exclusion{
		&mockExclusion{matchVariable: "RequestHeaderNames", selectorMatchOperator: "EqualsAny", rules: []int32{913110}},
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

	testRequest(t, "TestRuleExclusionsOnRequestHeaderNamesWithEqualsAny", msrc, reqResponses, nil)
}
