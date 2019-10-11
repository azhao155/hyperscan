package customrules2

import (
	"azwaf/testutils"
	"azwaf/waf"
	"testing"

	"github.com/stretchr/testify/assert"
)

var requestURIBeginsWithBlockRule = &mockCustomRule{
	name:     "requestURIBeginsWithBlockRule",
	priority: 1,
	ruleType: "MatchRule",
	matchConditions: []waf.MatchCondition{
		&mockMatchCondition{
			matchVariables: []waf.MatchVariable{
				&mockMatchVariable{
					variableName: "RequestUri",
				},
			},
			operator:        "BeginsWith",
			negateCondition: false,
			matchValues:     []string{"/sensitive.php", "/sensitive.html"},
		},
	},
	action: "Block",
}

func TestRequestURIBeginsWithBlockPositive(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	req := &mockWafHTTPRequest{
		uri:    "/sensitive.php?password=12345",
		method: "GET",
	}
	engine, _, err := newEngineWithCustomRules(requestURIBeginsWithBlockRule)
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

func TestRequestURIBeginsWithBlockNegative(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	req := &mockWafHTTPRequest{
		uri:    "/nonsensitive.php?password=12345",
		method: "GET",
	}
	engine, _, err := newEngineWithCustomRules(requestURIBeginsWithBlockRule)
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
