package customrule

import (
	"azwaf/testutils"
	"azwaf/waf"
	"fmt"
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
	engine, resLog, err := newEngineWithCustomRules(requestHeadersContainsBlockRule)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	eval := engine.NewEvaluation(logger, resLog, req, waf.OtherBody)
	err = eval.ScanHeaders()
	decision := eval.EvalRules()

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
}

func TestRequestHeadersWithDifferentCasingContainsBlockPositive(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	req := &mockWafHTTPRequest{
		uri:    "/",
		method: "GET",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "x-first-name", v: "John"},
			&mockHeaderPair{k: "x-last-name", v: "Travolta"},
		},
	}
	engine, resLog, err := newEngineWithCustomRules(requestHeadersContainsBlockRule)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	eval := engine.NewEvaluation(logger, resLog, req, waf.OtherBody)
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
	engine, resLog, err := newEngineWithCustomRules(requestHeadersContainsBlockRule)
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

// Content-Length - LessThan - Block
var contentLengthLessThanBlockRule = &mockCustomRule{
	name:     "contentLengthLessThanBlock",
	priority: 1,
	ruleType: "MatchRule",
	matchConditions: []waf.MatchCondition{
		&mockMatchCondition{
			matchVariables: []waf.MatchVariable{
				&mockMatchVariable{
					variableName: "RequestHeaders",
					selector:     "Content-Length",
				},
			},
			operator:        "LessThan",
			negateCondition: false,
			matchValues:     []string{"65536"},
		},
	},
	action: "Block",
}

func TestContentLengthLessThan(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	content := "john travolta"
	req := &mockWafHTTPRequest{
		uri:    "/",
		method: "GET",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "Content-Length", v: fmt.Sprint(len(content))},
			&mockHeaderPair{k: "Content-Type", v: "text/plain"},
		},
	}
	engine, resLog, err := newEngineWithCustomRules(contentLengthLessThanBlockRule)
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
