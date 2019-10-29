package customrule

import (
	"azwaf/testutils"
	"azwaf/waf"
	"testing"

	"github.com/stretchr/testify/assert"
)

var geoMatchRemoteAddrBlockRule = &mockCustomRule{
	name:     "geoMatchXForwardedForBlockRule",
	priority: 1,
	ruleType: "MatchRule",
	matchConditions: []waf.MatchCondition{
		&mockMatchCondition{
			matchVariables: []waf.MatchVariable{
				&mockMatchVariable{
					variableName: "RemoteAddr",
				},
			},
			operator:        "GeoMatch",
			negateCondition: false,
			matchValues:     []string{"CC"},
		},
	},
	action: "Block",
}

func TestGeoMatchRemoteAddrBlockRulePositive(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	req := &mockWafHTTPRequest{
		uri:        "/",
		method:     "GET",
		remoteAddr: "2.2.2.2",
	}

	engine, resLog, err := newEngineWithCustomRules(geoMatchRemoteAddrBlockRule)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	eval := engine.NewEvaluation(logger, resLog, req)
	defer eval.Close()
	err = eval.ScanHeaders()
	decision := eval.EvalRules()

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
}

func TestGeoMatchRemoteAddrBlockRuleNegative(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	req := &mockWafHTTPRequest{
		uri:    "/",
		method: "GET",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Forwarded-For", v: "2.2.2.2"},
		},
	}

	engine, resLog, err := newEngineWithCustomRules(geoMatchRemoteAddrBlockRule)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	eval := engine.NewEvaluation(logger, resLog, req)
	defer eval.Close()
	err = eval.ScanHeaders()
	decision := eval.EvalRules()

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
}

var geoMatchXForwardedForBlockRule = &mockCustomRule{
	name:     "geoMatchXForwardedForBlockRule",
	priority: 1,
	ruleType: "MatchRule",
	matchConditions: []waf.MatchCondition{
		&mockMatchCondition{
			matchVariables: []waf.MatchVariable{
				&mockMatchVariable{
					variableName: "RequestHeaders",
					selector:     "X-Forwarded-For",
				},
			},
			operator:        "GeoMatch",
			negateCondition: false,
			matchValues:     []string{"CC"},
		},
	},
	action: "Block",
}

func TestGeoMatchXForwardedForBlockRulePositive(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	req := &mockWafHTTPRequest{
		uri:    "/",
		method: "GET",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Forwarded-For", v: "0.0.0.0,1.1.1.1:24601,2.2.2.2"},
		},
	}

	engine, resLog, err := newEngineWithCustomRules(geoMatchXForwardedForBlockRule)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	eval := engine.NewEvaluation(logger, resLog, req)
	defer eval.Close()
	err = eval.ScanHeaders()
	decision := eval.EvalRules()

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
}

func TestGeoMatchXForwardedForBlockRuleNegative(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	req := &mockWafHTTPRequest{
		uri:        "/",
		method:     "GET",
		remoteAddr: "2.2.2.2",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Forwarded-For", v: "0.0.0.0,1.1.1.1"},
		},
	}

	engine, resLog, err := newEngineWithCustomRules(geoMatchXForwardedForBlockRule)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	eval := engine.NewEvaluation(logger, resLog, req)
	defer eval.Close()
	err = eval.ScanHeaders()
	decision := eval.EvalRules()

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
}
