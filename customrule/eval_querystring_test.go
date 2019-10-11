package customrule

import (
	"azwaf/testutils"
	"azwaf/waf"
	"testing"

	"github.com/stretchr/testify/assert"
)

var queryStringContainsBlockRule = &mockCustomRule{
	name:     "queryStringContainsBlockRule",
	priority: 1,
	ruleType: "MatchRule",
	matchConditions: []waf.MatchCondition{
		&mockMatchCondition{
			matchVariables: []waf.MatchVariable{
				&mockMatchVariable{
					variableName: "QueryString",
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

func TestQueryStringContainsBlockPositive(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	req := &mockWafHTTPRequest{
		uri:    "/?firstName=john&lastName=lenon",
		method: "GET",
	}
	engine, _, err := newEngineWithCustomRules(queryStringContainsBlockRule)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	eval := engine.NewEvaluation(logger, req)
	defer eval.Close()
	err = eval.ScanHeaders()
	decision := eval.EvalRules()

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
}

func TestQueryStringContainsBlockNegative(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	req := &mockWafHTTPRequest{
		uri:    "/?firstName=bob&lastName=dylan",
		method: "GET",
	}
	engine, _, err := newEngineWithCustomRules(queryStringContainsBlockRule)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	eval := engine.NewEvaluation(logger, req)
	defer eval.Close()
	err = eval.ScanHeaders()
	decision := eval.EvalRules()

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
}
