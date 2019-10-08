package customrule

import (
	"azwaf/testutils"
	"azwaf/waf"
	"testing"

	"github.com/stretchr/testify/assert"
)

var requestHeadersContainsBlockRule = &mockCustomRule{
	name:     "requestHeadersContainsBlockRule",
	priority: 1,
	ruleType: "MatchRule",
	matchConditions: []waf.MatchCondition{
		&mockMatchCondition{
			matchVariables: []waf.MatchVariable{
				&mockMatchVariable{
					variableName: "RequestHeaders",
					selector:     "X-First-Name",
				},
			},
			operator:        "Contains",
			negateCondition: false,
			matchValues:     []string{"john", "paul", "george", "ringo"},
			transforms:      []string{"Lowercase"},
		},
	},
	action: "Block",
}

func TestRequestHeadersContainsBlockPositive(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	req := &mockWafHTTPRequest{
		uri:    "/",
		method: "GET",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-First-Name", v: "John"},
			&mockHeaderPair{k: "X-Last-Name", v: "Travolta"},
		},
	}
	engine, err := newEngineWithCustomRules(logger, requestHeadersContainsBlockRule)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	eval := engine.NewEvaluation(logger, req)
	err = eval.ScanHeaders()
	decision := eval.EvalRules()

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
}

func TestRequestHeadersContainsBlockNegative(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	req := &mockWafHTTPRequest{
		uri:    "/",
		method: "GET",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-First-Name", v: "Bob"},
			&mockHeaderPair{k: "X-Last-Name", v: "Dylan"},
		},
	}
	engine, err := newEngineWithCustomRules(logger, requestHeadersContainsBlockRule)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	eval := engine.NewEvaluation(logger, req)
	err = eval.ScanHeaders()
	decision := eval.EvalRules()

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
}
