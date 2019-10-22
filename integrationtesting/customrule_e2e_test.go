package integrationtesting

import (
	"azwaf/waf"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var stringMatchBypassRule = &mockCustomRule{
	name:     "stringMatchBypassRule",
	priority: 1,
	ruleType: "MatchRule",
	matchConditions: []waf.MatchCondition{
		&mockMatchCondition{
			matchVariables: []waf.MatchVariable{
				&mockMatchVariable{
					variableName: "RequestHeader",
					selector:     "X-Bypass-String",
				},
				&mockMatchVariable{
					variableName: "PostArgs",
					selector:     "bypassString",
				},
			},
			operator:        "Equals",
			negateCondition: false,
			matchValues:     []string{"always-allow", "bypass-all-rules"},
			transforms:      []string{"Lowercase"},
		},
		&mockMatchCondition{
			matchVariables: []waf.MatchVariable{
				&mockMatchVariable{
					variableName: "RequestHeader",
					selector:     "X-Bypass-Enabled",
				},
				&mockMatchVariable{
					variableName: "PostArgs",
					selector:     "bypassEnabled",
				},
			},
			operator:        "Equals",
			negateCondition: false,
			matchValues:     []string{"true"},
			transforms:      []string{"Lowercase"},
		},
	},
	action: "Allow",
}

var numericBypassRule = &mockCustomRule{
	name:     "numericBypassRule",
	priority: 2,
	ruleType: "MatchRule",
	matchConditions: []waf.MatchCondition{
		&mockMatchCondition{
			matchVariables: []waf.MatchVariable{
				&mockMatchVariable{
					variableName: "RequestHeader",
					selector:     "Content-Length",
				},
			},
			operator:        "GreaterThan",
			negateCondition: true,
			matchValues:     []string{"10"},
		},
	},
	action: "Allow",
}

var geoBlacklistRule = &mockCustomRule{
	name:     "geoBlacklistRule",
	priority: 3,
	ruleType: "MatchRule",
	matchConditions: []waf.MatchCondition{
		&mockMatchCondition{
			matchVariables: []waf.MatchVariable{
				&mockMatchVariable{
					variableName: "RemoteAddr",
				},
				&mockMatchVariable{
					variableName: "RequestHeaders",
					selector:     "X-Forwarded-For",
				},
			},
			operator:        "GeoMatch",
			negateCondition: false,
			matchValues:     []string{"AB", "CD", "EF"},
		},
	},
	action: "Block",
}

var wafConfigWithCustomRules = &mockWAFConfig{
	policyConfigs: []waf.PolicyConfig{
		&mockPolicyConfig{
			secRuleConfig: &mockSecRuleConfig{},
			customRuleConfig: &mockCustomRuleConfig{
				customRules: []waf.CustomRule{
					geoBlacklistRule,
					numericBypassRule,
					stringMatchBypassRule,
				},
			},
		},
	},
	logMetaData: &mockConfigLogMetaData{},
}

var geoIPDataRecords = []waf.GeoIPDataRecord{
	&mockGeoIPDataRecord{startIP: 0x00000000, endIP: 0x9fffffff, countryCode: "OK"},
	&mockGeoIPDataRecord{startIP: 0xa0000000, endIP: 0xbfffffff, countryCode: "AB"},
	&mockGeoIPDataRecord{startIP: 0xc0000000, endIP: 0xdfffffff, countryCode: "CD"},
	&mockGeoIPDataRecord{startIP: 0xe0000000, endIP: 0xffffffff, countryCode: "EF"},
}

func TestCustomRuleGeoBlackList(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	wafServer := newTestAzwafServer(t)

	err := wafServer.PutConfig(wafConfigWithCustomRules)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	err = wafServer.PutGeoIPData(geoIPDataRecords)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	remoteAddrBlockReq := &mockWafHTTPRequest{
		// 255.255.255.255 == 0xffffffff => "EF", blocked.
		remoteAddr: "255.255.255.255",
		uri:        "/",
	}
	remoteAddrBlockDecision, remoteAddrBlockErr := wafServer.EvalRequest(remoteAddrBlockReq)

	xForwardedForBlockReq := &mockWafHTTPRequest{
		remoteAddr: "0.0.0.0",
		uri:        "/",
		headers: []waf.HeaderPair{
			&mockHeaderPair{
				k: "X-Forwarded-For",
				v: "10.0.0.1,255.255.255.255:8080,127.0.0.1:1337",
			},
		},
	}
	xForwardedForBlockDecision, xForwardedForBlockErr := wafServer.EvalRequest(xForwardedForBlockReq)

	// Assert
	assert.Nil(remoteAddrBlockErr)
	assert.Equal(waf.Block, remoteAddrBlockDecision)
	assert.Nil(xForwardedForBlockErr)
	assert.Equal(waf.Block, xForwardedForBlockDecision)
}

func TestCustomRuleStringBypass(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	wafServer := newTestAzwafServer(t)

	err := wafServer.PutConfig(wafConfigWithCustomRules)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	err = wafServer.PutGeoIPData(geoIPDataRecords)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	incompleteStringBypassReq := &mockWafHTTPRequest{
		// 255.255.255.255 == 0xffffffff => "EF", blocked.
		remoteAddr: "255.255.255.255",
		uri:        "/",
		headers: []waf.HeaderPair{
			&mockHeaderPair{
				k: "X-Bypass-String",
				v: "Bypass-All-Rules",
			},
		},
	}
	blockDecision, blockErr := wafServer.EvalRequest(incompleteStringBypassReq)

	bodyContent := "bypassEnabled=True"
	completeStringBypassReq := &mockWafHTTPRequest{
		// 255.255.255.255 == 0xffffffff => "EF", blocked.
		remoteAddr: "255.255.255.255",
		uri:        "/",
		headers: []waf.HeaderPair{
			&mockHeaderPair{
				k: "X-Bypass-String",
				v: "Bypass-All-Rules",
			},
			&mockHeaderPair{
				k: "Content-Length",
				v: fmt.Sprint(len(bodyContent)),
			},
		},
		body: bodyContent,
	}
	allowDecision, allowErr := wafServer.EvalRequest(completeStringBypassReq)

	// Assert
	assert.Equal(waf.Block, blockDecision)
	assert.Nil(blockErr)
	assert.Equal(waf.Block, allowDecision)
	assert.Nil(allowErr)
}

func TestCustomRuleNumericBypass(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	wafServer := newTestAzwafServer(t)

	err := wafServer.PutConfig(wafConfigWithCustomRules)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	err = wafServer.PutGeoIPData(geoIPDataRecords)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	body16byte := "0123456789abcdef"
	incorrectNumericBypassReq := &mockWafHTTPRequest{
		// 255.255.255.255 == 0xffffffff => "EF", blocked.
		remoteAddr: "255.255.255.255",
		uri:        "/",
		headers: []waf.HeaderPair{
			&mockHeaderPair{
				k: "Content-Length",
				v: fmt.Sprint(len(body16byte)),
			},
		},
		body: body16byte,
	}
	blockDecision, blockErr := wafServer.EvalRequest(incorrectNumericBypassReq)

	body10byte := "0123456789"
	correctNumericBypassReq := &mockWafHTTPRequest{
		// 255.255.255.255 == 0xffffffff => "EF", blocked.
		remoteAddr: "255.255.255.255",
		uri:        "/",
		headers: []waf.HeaderPair{
			&mockHeaderPair{
				k: "Content-Length",
				v: fmt.Sprint(len(body10byte)),
			},
		},
		body: body10byte,
	}
	allowDecision, allowErr := wafServer.EvalRequest(correctNumericBypassReq)

	// Assert
	assert.Equal(waf.Block, blockDecision)
	assert.Nil(blockErr)
	assert.Equal(waf.Block, allowDecision)
	assert.Nil(allowErr)
}
