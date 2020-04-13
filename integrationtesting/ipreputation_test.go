package integrationtesting

import (
	"azwaf/waf"
	"testing"

	"github.com/stretchr/testify/assert"
)

func newIPReputationConfig() waf.Config {
	config := &mockWAFConfig{
		configVersion: 0,
		policyConfigs: []waf.PolicyConfig{
			&mockPolicyConfig{
				configID: "abc",
				secRuleConfig: &mockSecRuleConfig{
					enabled:   false,
					ruleSetID: "OWASP CRS 3.0",
				},
				customRuleConfig:   &mockCustomRuleConfig{},
				ipReputationConfig: &mockIPReputationConfig{enabled: true},
			},
		},
		logMetaData: &mockConfigLogMetaData{},
	}
	return config
}

func TestPutIPReputationConfig(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	wafServer := newTestAzwafServer(t)

	// Act
	config := newIPReputationConfig()
	err := wafServer.PutConfig(config)

	// Assert
	assert.Nil(err)
}

func TestEvalRequestMatchedIP(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	req := &mockWafHTTPRequest{remoteAddr: "255.255.255.255", configID: "abc"}
	wafServer := newTestAzwafServer(t)
	config := newIPReputationConfig()
	wafServer.PutConfig(config)
	wafServer.PutIPReputationList([]string{"0.0.0.0", "255.255.255.255", "8.16.24.32/24"})

	// Act
	decision, err := wafServer.EvalRequest(req)

	// Assert
	assert.Equal(waf.Block, decision)
	assert.Nil(err)
}

func TestEvalRequestUnmatchedIP(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	req := &mockWafHTTPRequest{remoteAddr: "123.12.1.4", configID: "abc"}
	wafServer := newTestAzwafServer(t)
	config := newIPReputationConfig()
	wafServer.PutConfig(config)
	wafServer.PutIPReputationList([]string{"0.0.0.0", "255.255.255.255", "8.16.24.32/24"})

	// Act
	decision, err := wafServer.EvalRequest(req)

	// Assert
	assert.Equal(waf.Pass, decision)
	assert.Nil(err)
}
