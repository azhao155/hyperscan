package integrationtesting

import (
	"azwaf/waf"
	"testing"

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

func TestExclusionEvalRequest(t *testing.T) {
	// Arrange
	ex := &mockExclusion{
		matchVariable:         "RequestArgNames",
		selectorMatchOperator: "Contains",
		selector:              "a",
	}

	msrc := &mockSecRuleConfig{
		enabled:    true,
		ruleSetID:  "OWASP CRS 3.0",
		exclusions: []waf.Exclusion{ex},
	}
	wafServer := newTestStandaloneSecruleServer(t, msrc)
	headers := []waf.HeaderPair{&mockHeaderPair{k: "Host", v: "example.com"}}
	req1 := &mockWafHTTPRequest{uri: "http://localhost:8080/?a=hello", method: "GET", headers: headers, protocol: "HTTP/1.1"}
	req2 := &mockWafHTTPRequest{uri: "http://localhost:8080/?a=/etc/passwd", method: "GET", headers: headers, protocol: "HTTP/1.1"}
	req3 := &mockWafHTTPRequest{uri: "http://localhost:8080/?b=/etc/passwd", method: "GET", headers: headers, protocol: "HTTP/1.1"}

	// Act
	decision1, err := wafServer.EvalRequest(req1)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	decision2, err := wafServer.EvalRequest(req2)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	decision3, err := wafServer.EvalRequest(req3)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Assert
	if decision1 != waf.Pass {
		t.Fatalf("EvalRequest did not return pass")
	}

	// Exclusion resulted in Pass instead of Block
	if decision2 != waf.Pass {
		t.Fatalf("EvalRequest did not return pass")
	}

	if decision3 != waf.Block {
		t.Fatalf("EvalRequest did not return block")
	}
}