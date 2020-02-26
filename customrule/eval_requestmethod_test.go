package customrule

import (
	"azwaf/testutils"
	"azwaf/waf"
	"testing"

	"github.com/stretchr/testify/assert"
)

var requestMethodEqualsBlockRule = &mockCustomRule{
	name:     "requestMethodEqualsBlockRule",
	priority: 1,
	ruleType: "MatchRule",
	matchConditions: []waf.MatchCondition{
		&mockMatchCondition{
			matchVariables: []waf.MatchVariable{
				&mockMatchVariable{
					variableName: "RequestMethod",
				},
			},
			operator:        "Equals",
			negateCondition: false,
			matchValues:     []string{"DELETE"},
			transforms:      []string{"Uppercase"},
		},
	},
	action: "Block",
}

func TestRequestMethodEqualsBlockPositive(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	req := &mockWafHTTPRequest{
		uri:    "/",
		method: "DELETE",
	}
	engine, resLog, err := newEngineWithCustomRules(requestMethodEqualsBlockRule)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	eval := engine.NewEvaluation(logger, resLog, req, waf.OtherBody)
	defer eval.Close()
	err = eval.ScanHeaders()
	decision := eval.EvalRules()

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
}

func TestRequestMethodEqualsBlockNegative(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	req := &mockWafHTTPRequest{
		uri:    "/",
		method: "GET",
	}
	engine, resLog, err := newEngineWithCustomRules(requestMethodEqualsBlockRule)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	eval := engine.NewEvaluation(logger, resLog, req, waf.OtherBody)
	defer eval.Close()
	err = eval.ScanHeaders()
	decision := eval.EvalRules()

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
}
