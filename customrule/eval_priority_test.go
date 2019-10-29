package customrule

import (
	"azwaf/testutils"
	"azwaf/waf"
	"testing"

	"github.com/stretchr/testify/assert"
)

var headerAllowHighPriorityRule = &mockCustomRule{
	name:     "headerAllowHighPriorityRule",
	priority: 1,
	ruleType: "MatchRule",
	matchConditions: []waf.MatchCondition{
		&mockMatchCondition{
			matchVariables: []waf.MatchVariable{
				&mockMatchVariable{
					variableName: "RequestHeaders",
					selector:     "X-Bypass",
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

var methodBlockLowPriorityRule = &mockCustomRule{
	name:     "methodBlockLowPriorityRule",
	priority: 100,
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
		},
	},
	action: "Block",
}

func TestCustomRulesWithPriorities(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	engine, resLog, err := newEngineWithCustomRules(headerAllowHighPriorityRule, methodBlockLowPriorityRule)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	blockReq := &mockWafHTTPRequest{
		uri:    "/",
		method: "DELETE",
	}

	allowReq := &mockWafHTTPRequest{
		uri:    "/",
		method: "DELETE",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Bypass", v: "true"},
		},
	}

	// Act
	blockEval := engine.NewEvaluation(logger, resLog, blockReq)
	defer blockEval.Close()
	blockErr := blockEval.ScanHeaders()
	blockDecision := blockEval.EvalRules()

	allowEval := engine.NewEvaluation(logger, resLog, allowReq)
	defer allowEval.Close()
	allowErr := allowEval.ScanHeaders()
	allowDecision := allowEval.EvalRules()

	// Assert
	assert.Nil(blockErr)
	assert.Equal(waf.Block, blockDecision)

	assert.Nil(allowErr)
	assert.Equal(waf.Allow, allowDecision)
}

func TestCustomRulesWithPrioritiesInvertedOrder(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	engine, resLog, err := newEngineWithCustomRules(methodBlockLowPriorityRule, headerAllowHighPriorityRule)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	blockReq := &mockWafHTTPRequest{
		uri:    "/",
		method: "DELETE",
	}

	allowReq := &mockWafHTTPRequest{
		uri:    "/",
		method: "DELETE",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Bypass", v: "true"},
		},
	}

	// Act
	blockEval := engine.NewEvaluation(logger, resLog, blockReq)
	defer blockEval.Close()
	blockErr := blockEval.ScanHeaders()
	blockDecision := blockEval.EvalRules()

	allowEval := engine.NewEvaluation(logger, resLog, allowReq)
	defer allowEval.Close()
	allowErr := allowEval.ScanHeaders()
	allowDecision := allowEval.EvalRules()

	// Assert
	assert.Nil(blockErr)
	assert.Equal(waf.Block, blockDecision)

	assert.Nil(allowErr)
	assert.Equal(waf.Allow, allowDecision)
}
