package integrationtesting

import (
	"azwaf/waf"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func newRequestBodySizeConfig() waf.Config {
	config := &mockWAFConfig{
		configVersion: 0,
		policyConfigs: []waf.PolicyConfig{
			&mockPolicyConfig{
				configID:                 "abc",
				requestBodyCheck:         true,
				requestBodySizeLimitInKb: 128,
			},
		},
		logMetaData: &mockConfigLogMetaData{},
	}
	return config
}

func TestPutRequestBodySizeLimitConfig(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	wafServer := newTestAzwafServer(t)

	// Act
	config := newRequestBodySizeConfig()
	err := wafServer.PutConfig(config)

	// Assert
	assert.Nil(err)
}

func TestEvalRequestSizeLimit(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	bodyContentOverLimit := "[" + strings.Repeat(`"a",`, (128*1024)/4) + `"a"]`
	overLimitReq := &mockWafHTTPRequest{
		configID:   "abc",
		remoteAddr: "255.255.255.255",
		uri:        "/",
		headers: []waf.HeaderPair{
			&mockHeaderPair{
				k: "Content-Length",
				v: fmt.Sprint(len(bodyContentOverLimit)),
			},
			&mockHeaderPair{
				k: "Content-Type",
				v: "application/json",
			},
		},
		body: bodyContentOverLimit,
	}

	bodyContentUnderLimit := "[" + strings.Repeat(`"a",`, (127*1024)/4) + `"a"]`
	underLimitReq := &mockWafHTTPRequest{
		configID:   "abc",
		remoteAddr: "255.255.255.255",
		uri:        "/",
		headers: []waf.HeaderPair{
			&mockHeaderPair{
				k: "Content-Length",
				v: fmt.Sprint(len(bodyContentUnderLimit)),
			},
			&mockHeaderPair{
				k: "Content-Type",
				v: "application/json",
			},
		},
		body: bodyContentUnderLimit,
	}

	wafServer := newTestAzwafServer(t)
	config := newRequestBodySizeConfig()
	wafServer.PutConfig(config)

	// Act
	blockDecision, err := wafServer.EvalRequest(overLimitReq)
	assert.Nil(err)
	passDecision, err := wafServer.EvalRequest(underLimitReq)
	assert.Nil(err)

	// Assert
	assert.Equal(waf.Block, blockDecision)
	assert.Equal(waf.Pass, passDecision)
}
