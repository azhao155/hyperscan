package customrule

import (
	"azwaf/testutils"
	"azwaf/waf"
	"testing"

	"github.com/stretchr/testify/assert"
)

var requestCookiesContainsBlockRule = &mockCustomRule{
	name:     "requestCookiesContainsBlockRule",
	priority: 1,
	ruleType: "MatchRule",
	matchConditions: []waf.MatchCondition{
		&mockMatchCondition{
			matchVariables: []waf.MatchVariable{
				&mockMatchVariable{
					variableName: "RequestCookies",
					selector:     "the_oracles_special_recipe",
				},
			},
			operator:        "Contains",
			negateCondition: false,
			matchValues:     []string{"neo", "morpheus", "trinity"},
			transforms:      []string{"Lowercase"},
		},
	},
	action: "Block",
}

func TestRequestCookiesContainsBlockPositive(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	req := &mockWafHTTPRequest{
		uri:    "/",
		method: "GET",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "Cookie", v: "the_oracles_special_recipe=neo+is+the+one; the_matrix_cookie_house=agent+smith"},
		},
	}
	engine, err := newEngineWithCustomRules(logger, requestCookiesContainsBlockRule)
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

func TestRequestCookiesContainsBlockNegative(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	req := &mockWafHTTPRequest{
		uri:    "/",
		method: "GET",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "Cookie", v: "the_oracles_special_recipe=the+one; the_matrix_cookie_house=neo+is+the+anomaly"},
		},
	}
	engine, err := newEngineWithCustomRules(logger, queryStringContainsBlockRule)
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
