package customrule

import (
	"azwaf/testutils"
	"azwaf/waf"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var postArgsEqualsBlockRule = &mockCustomRule{
	name:     "postArgsEqualsBlockRule",
	priority: 1,
	ruleType: "MatchRule",
	matchConditions: []waf.MatchCondition{
		&mockMatchCondition{
			matchVariables: []waf.MatchVariable{
				&mockMatchVariable{
					variableName: "PostArgs",
					selector:     "firstName",
				},
			},
			operator:        "Equals",
			negateCondition: false,
			matchValues:     []string{"john", "paul", "george", "ringo"},
			transforms:      []string{"Lowercase"},
		},
	},
	action: "Block",
}

func TestPostArgsEqualsBlockPositive(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	content := "firstName=john&lastName=travolta"
	req := &mockWafHTTPRequest{
		uri:    "/",
		method: "POST",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "Content-Type", v: "application/x-www-form-urlencoded"},
			&mockHeaderPair{k: "Content-Length", v: fmt.Sprint(len(content))},
		},
		body: content,
	}
	engine, resLog, err := newEngineWithCustomRules(postArgsEqualsBlockRule)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	eval := engine.NewEvaluation(logger, resLog, req)
	defer eval.Close()
	err = eval.ScanHeaders()
	err = eval.ScanBodyField(waf.URLEncodedContent, "firstName", "john")
	err = eval.ScanBodyField(waf.URLEncodedContent, "lastName", "travolta")
	decision := eval.EvalRules()

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
}

func TestPostArgsEqualsBlockNegative(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	content := "firstName=bob&lastName=dylan"
	req := &mockWafHTTPRequest{
		uri:    "/",
		method: "POST",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "Content-Type", v: "application/x-www-form-urlencoded"},
			&mockHeaderPair{k: "Content-Length", v: fmt.Sprint(len(content))},
		},
		body: content,
	}
	engine, resLog, err := newEngineWithCustomRules(postArgsEqualsBlockRule)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	eval := engine.NewEvaluation(logger, resLog, req)
	defer eval.Close()
	err = eval.ScanHeaders()
	err = eval.ScanBodyField(waf.URLEncodedContent, "firstName", "bob")
	err = eval.ScanBodyField(waf.URLEncodedContent, "lastName", "dylan")
	decision := eval.EvalRules()

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
}
