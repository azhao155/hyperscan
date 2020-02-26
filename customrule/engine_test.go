package customrule

import (
	"azwaf/testutils"
	"azwaf/waf"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringOperators(t *testing.T) {
	logger := testutils.NewTestLogger(t)

	type testcase struct {
		inputURI string
		op       string
		matchVal string
		expected waf.Decision
	}
	tests := []testcase{
		{"/?a=abbbc", "Regex", "ab+c", waf.Block},
		{"/?a=xyyyz", "Regex", "ab+c", waf.Pass},
		{"/?a=abc", "BeginsWith", "a=", waf.Block},
		{"/?x=xyz", "BeginsWith", "a=", waf.Pass},
		{"/?a=abc", "EndsWith", "bc", waf.Block},
		{"/?x=xyz", "EndsWith", "bc", waf.Pass},
		{"/?a=abc", "Contains", "ab", waf.Block},
		{"/?x=xyz", "Contains", "ab", waf.Pass},
		{"/?a=abc", "Equals", "a=abc", waf.Block},
		{"/?aa=abcc", "Equals", "a=abc", waf.Pass},
	}

	var b strings.Builder
	for i, test := range tests {
		// Arrange
		rules := []waf.CustomRule{
			&mockCustomRule{
				name:     "rule1",
				priority: 1,
				ruleType: "MatchRule",
				matchConditions: []waf.MatchCondition{
					&mockMatchCondition{
						matchVariables: []waf.MatchVariable{
							&mockMatchVariable{variableName: "QueryString"},
						},
						operator:    test.op,
						matchValues: []string{test.matchVal},
					},
				},
				action: "Block",
			},
		}

		engine, resLog, err := newEngineWithCustomRules(rules...)
		if err != nil {
			fmt.Fprintf(&b, "Test case %v: Got unexpected error: %s\n", i, err)
			continue
		}

		req1 := &mockWafHTTPRequest{uri: test.inputURI, method: "GET"}

		// Act
		eval := engine.NewEvaluation(logger, resLog, req1, waf.OtherBody)
		defer eval.Close()
		err = eval.ScanHeaders()
		decision := eval.EvalRules()

		// Assert
		if err != nil {
			fmt.Fprintf(&b, "Test case %v: Got unexpected error: %s\n", i, err)
			continue
		}

		if decision != test.expected {
			fmt.Fprintf(&b, "Test case %v: Got unexpected decision: %v\n", i, decision)
			continue
		}
	}

	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}
}

func TestTransformations(t *testing.T) {
	logger := testutils.NewTestLogger(t)

	type testcase struct {
		input           string
		transformations []string
		matchVal        string
		expected        waf.Decision
	}
	tests := []testcase{
		{"ABC", []string{"Lowercase"}, "abc", waf.Block},
		{"ABC", []string{}, "ABC", waf.Block},
		{"ABC", []string{"Lowercase"}, "ABC", waf.Pass},

		{" abc ", []string{"Trim"}, "abc", waf.Block},
		{" abc ", []string{}, " abc ", waf.Block},
		{" abc ", []string{"Trim"}, " abc ", waf.Pass},

		{"%61%62%63", []string{"UrlDecode"}, "abc", waf.Block},
		{"%61%62%63", []string{}, "%61%62%63", waf.Block},
		{"%61%62%63", []string{"UrlDecode"}, "%61%62%63", waf.Pass},
		{`hello%20world`, []string{"UrlDecode"}, `hello world`, waf.Block},
		{`hello+world`, []string{"UrlDecode"}, `hello world`, waf.Block},
		{`hello%ggworld`, []string{"UrlDecode"}, `hello%ggworld`, waf.Block},
		{`hello%20`, []string{"UrlDecode"}, `hello `, waf.Block},
		{`hello%2`, []string{"UrlDecode"}, `hello%2`, waf.Block},
		{`hello%`, []string{"UrlDecode"}, `hello%`, waf.Block},
		{`%20`, []string{"UrlDecode"}, ` `, waf.Block},
		{`%2`, []string{"UrlDecode"}, `%2`, waf.Block},
		{`%`, []string{"UrlDecode"}, `%`, waf.Block},
		{``, []string{"UrlDecode"}, ``, waf.Block},
		{`%00`, []string{"UrlDecode"}, "\x00", waf.Block},
		{`x%6ax`, []string{"UrlDecode"}, `xjx`, waf.Block},
		{`x%6Ax`, []string{"UrlDecode"}, `xjx`, waf.Block},

		{"a b", []string{"UrlEncode"}, "a%20b", waf.Block},
		{"a b", []string{}, "a b", waf.Block},
		{"a b", []string{"UrlEncode"}, "a b", waf.Pass},

		{"a\x00bc", []string{"RemoveNulls"}, "abc", waf.Block},
		{"a\x00bc", []string{}, "a\x00bc", waf.Block},
		{"a\x00bc", []string{"RemoveNulls"}, "a\x00bc", waf.Pass},

		{"a&#98;c", []string{"HtmlEntityDecode"}, "abc", waf.Block},
		{"a&#98;c", []string{}, "a&#98;c", waf.Block},
		{"a&#98;c", []string{"HtmlEntityDecode"}, "a&#98;c", waf.Pass},
	}

	var b strings.Builder
	for i, test := range tests {
		// Arrange
		rules := []waf.CustomRule{
			&mockCustomRule{
				name:     "rule1",
				priority: 1,
				ruleType: "MatchRule",
				matchConditions: []waf.MatchCondition{
					&mockMatchCondition{
						matchVariables: []waf.MatchVariable{
							&mockMatchVariable{variableName: "RequestHeaders"},
						},
						operator:    "Equals",
						matchValues: []string{test.matchVal},
						transforms:  test.transformations,
					},
				},
				action: "Block",
			},
		}

		engine, resLog, err := newEngineWithCustomRules(rules...)
		if err != nil {
			fmt.Fprintf(&b, "Test case %v: Got unexpected error: %s\n", i, err)
			continue
		}

		req1 := &mockWafHTTPRequest{uri: "/", method: "GET", headers: []waf.HeaderPair{&mockHeaderPair{k: "X-Some-Header", v: test.input}}}

		// Act
		eval := engine.NewEvaluation(logger, resLog, req1, waf.OtherBody)
		defer eval.Close()
		err = eval.ScanHeaders()
		decision := eval.EvalRules()

		// Assert
		if err != nil {
			fmt.Fprintf(&b, "Test case %v: Got unexpected error: %s\n", i, err)
			continue
		}

		if decision != test.expected {
			fmt.Fprintf(&b, "Test case %v: Got unexpected decision: %v\n", i, decision)
			continue
		}
	}

	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}
}

func TestMultipleRulesSameMatchVar(t *testing.T) {
	// Arrange
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)
	rules := []waf.CustomRule{
		&mockCustomRule{
			name:     "rule1",
			priority: 1,
			ruleType: "MatchRule",
			matchConditions: []waf.MatchCondition{
				&mockMatchCondition{
					matchVariables: []waf.MatchVariable{
						&mockMatchVariable{variableName: "QueryString"},
					},
					operator:    "Contains",
					matchValues: []string{"abc"},
					transforms:  []string{"Lowercase", "Trim"},
				},
			},
			action: "Block",
		},
		&mockCustomRule{
			name:     "rule2",
			priority: 2,
			ruleType: "MatchRule",
			matchConditions: []waf.MatchCondition{
				&mockMatchCondition{
					matchVariables: []waf.MatchVariable{
						&mockMatchVariable{variableName: "QueryString"},
					},
					operator:    "Contains",
					matchValues: []string{"def"},
					transforms:  []string{"Lowercase", "Trim"},
				},
			},
			action: "Block",
		},
	}
	engine, resLog, err := newEngineWithCustomRules(rules...)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	req1 := &mockWafHTTPRequest{uri: "/?a=abc", method: "GET"}
	req2 := &mockWafHTTPRequest{uri: "/?a=def", method: "GET"}
	req3 := &mockWafHTTPRequest{uri: "/?a=ghi", method: "GET"}

	// Act
	eval1 := engine.NewEvaluation(logger, resLog, req1, waf.OtherBody)
	defer eval1.Close()
	err1 := eval1.ScanHeaders()
	decision1 := eval1.EvalRules()

	eval2 := engine.NewEvaluation(logger, resLog, req2, waf.OtherBody)
	defer eval2.Close()
	err2 := eval2.ScanHeaders()
	decision2 := eval2.EvalRules()

	eval3 := engine.NewEvaluation(logger, resLog, req3, waf.OtherBody)
	defer eval3.Close()
	err3 := eval3.ScanHeaders()
	decision3 := eval3.EvalRules()

	// Assert
	assert.Nil(err1)
	assert.Nil(err2)
	assert.Nil(err3)
	assert.Equal(waf.Block, decision1)
	assert.Equal(waf.Block, decision2)
	assert.Equal(waf.Pass, decision3)
}

func TestMultipleMatchValues(t *testing.T) {
	// Arrange
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)
	rules := []waf.CustomRule{
		&mockCustomRule{
			name:     "rule1",
			priority: 1,
			ruleType: "MatchRule",
			matchConditions: []waf.MatchCondition{
				&mockMatchCondition{
					matchVariables: []waf.MatchVariable{
						&mockMatchVariable{variableName: "QueryString"},
					},
					operator: "Contains",
					matchValues: []string{
						"abc",
						"def",
					},
				},
			},
			action: "Block",
		},
	}
	engine, resLog, err := newEngineWithCustomRules(rules...)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	req1 := &mockWafHTTPRequest{uri: "/?a=abc", method: "GET"}
	req2 := &mockWafHTTPRequest{uri: "/?a=def", method: "GET"}
	req3 := &mockWafHTTPRequest{uri: "/?a=ghi", method: "GET"}

	// Act
	eval1 := engine.NewEvaluation(logger, resLog, req1, waf.OtherBody)
	defer eval1.Close()
	err1 := eval1.ScanHeaders()
	decision1 := eval1.EvalRules()

	eval2 := engine.NewEvaluation(logger, resLog, req2, waf.OtherBody)
	defer eval2.Close()
	err2 := eval2.ScanHeaders()
	decision2 := eval2.EvalRules()

	eval3 := engine.NewEvaluation(logger, resLog, req3, waf.OtherBody)
	defer eval3.Close()
	err3 := eval3.ScanHeaders()
	decision3 := eval3.EvalRules()

	// Assert
	assert.Nil(err1)
	assert.Nil(err2)
	assert.Nil(err3)
	assert.Equal(waf.Block, decision1)
	assert.Equal(waf.Block, decision2)
	assert.Equal(waf.Pass, decision3)
}

func TestMultipleMatchVars(t *testing.T) {
	// Arrange
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)
	rules := []waf.CustomRule{
		&mockCustomRule{
			name:     "rule1",
			priority: 1,
			ruleType: "MatchRule",
			matchConditions: []waf.MatchCondition{
				&mockMatchCondition{
					matchVariables: []waf.MatchVariable{
						&mockMatchVariable{variableName: "QueryString"},
						&mockMatchVariable{variableName: "RequestHeaders"},
					},
					operator:    "Contains",
					matchValues: []string{"abc"},
				},
			},
			action: "Block",
		},
	}
	engine, resLog, err := newEngineWithCustomRules(rules...)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	req1 := &mockWafHTTPRequest{uri: "/?a=abc", method: "GET", headers: []waf.HeaderPair{&mockHeaderPair{k: "X-Some-Header", v: "xyz"}}}
	req2 := &mockWafHTTPRequest{uri: "/?a=xyz", method: "GET", headers: []waf.HeaderPair{&mockHeaderPair{k: "X-Some-Header", v: "abc"}}}
	req3 := &mockWafHTTPRequest{uri: "/?a=xyz", method: "GET", headers: []waf.HeaderPair{&mockHeaderPair{k: "X-Some-Header", v: "xyz"}}}

	// Act
	eval1 := engine.NewEvaluation(logger, resLog, req1, waf.OtherBody)
	defer eval1.Close()
	err1 := eval1.ScanHeaders()
	decision1 := eval1.EvalRules()

	eval2 := engine.NewEvaluation(logger, resLog, req2, waf.OtherBody)
	defer eval2.Close()
	err2 := eval2.ScanHeaders()
	decision2 := eval2.EvalRules()

	eval3 := engine.NewEvaluation(logger, resLog, req3, waf.OtherBody)
	defer eval3.Close()
	err3 := eval3.ScanHeaders()
	decision3 := eval3.EvalRules()

	// Assert
	assert.Nil(err1)
	assert.Nil(err2)
	assert.Nil(err3)
	assert.Equal(waf.Block, decision1)
	assert.Equal(waf.Block, decision2)
	assert.Equal(waf.Pass, decision3)
}

func TestMultipleMatchVarsAndVals(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	rules := []waf.CustomRule{
		&mockCustomRule{
			name:     "rule1",
			priority: 1,
			ruleType: "MatchRule",
			matchConditions: []waf.MatchCondition{
				&mockMatchCondition{
					matchVariables: []waf.MatchVariable{
						&mockMatchVariable{variableName: "QueryString"},
						&mockMatchVariable{variableName: "RequestHeaders"},
					},
					operator: "Contains",
					matchValues: []string{
						"abc",
						"def",
					},
				},
			},
			action: "Block",
		},
	}
	engine, resLog, err := newEngineWithCustomRules(rules...)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	type testcase struct {
		inputURI       string
		inputHeaderVal string
		expected       waf.Decision
	}
	tests := []testcase{
		{"/?a=abc", "xyz", waf.Block},
		{"/?a=xyz", "abc", waf.Block},
		{"/?a=xyz", "xyz", waf.Pass},
		{"/?a=def", "xyz", waf.Block},
		{"/?a=xyz", "def", waf.Block},
		{"/?a=xyz", "xyz", waf.Pass},
	}

	var b strings.Builder
	for i, test := range tests {
		req := &mockWafHTTPRequest{uri: test.inputURI, method: "GET", headers: []waf.HeaderPair{&mockHeaderPair{k: "X-Some-Header", v: test.inputHeaderVal}}}

		// Act
		eval := engine.NewEvaluation(logger, resLog, req, waf.OtherBody)
		defer eval.Close()
		err = eval.ScanHeaders()
		decision := eval.EvalRules()

		// Assert
		if err != nil {
			fmt.Fprintf(&b, "Test case %v: Got unexpected error: %s\n", i, err)
			continue
		}

		if decision != test.expected {
			fmt.Fprintf(&b, "Test case %v: Got unexpected decision: %v\n", i, decision)
			continue
		}
	}

	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}
}

func TestRuleAllow(t *testing.T) {
	// Arrange
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)
	rules := []waf.CustomRule{
		&mockCustomRule{
			name:     "rule1",
			priority: 1,
			ruleType: "MatchRule",
			matchConditions: []waf.MatchCondition{
				&mockMatchCondition{
					matchVariables: []waf.MatchVariable{
						&mockMatchVariable{variableName: "QueryString"},
					},
					operator:    "Contains",
					matchValues: []string{"abc"},
				},
			},
			action: "Allow",
		},
	}
	engine, resLog, err := newEngineWithCustomRules(rules...)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	req1 := &mockWafHTTPRequest{uri: "/?a=abc", method: "GET"}
	req2 := &mockWafHTTPRequest{uri: "/?a=def", method: "GET"}

	// Act
	eval1 := engine.NewEvaluation(logger, resLog, req1, waf.OtherBody)
	defer eval1.Close()
	err1 := eval1.ScanHeaders()
	decision1 := eval1.EvalRules()

	eval2 := engine.NewEvaluation(logger, resLog, req2, waf.OtherBody)
	defer eval2.Close()
	err2 := eval2.ScanHeaders()
	decision2 := eval2.EvalRules()

	// Assert
	assert.Nil(err1)
	assert.Nil(err2)
	assert.Equal(waf.Allow, decision1)
	assert.Equal(waf.Pass, decision2)
}

func TestLogging(t *testing.T) {
	// Arrange
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)
	rules := []waf.CustomRule{
		&mockCustomRule{
			name:     "rule1",
			priority: 1,
			ruleType: "MatchRule",
			matchConditions: []waf.MatchCondition{
				&mockMatchCondition{
					matchVariables: []waf.MatchVariable{
						&mockMatchVariable{variableName: "QueryString"},
					},
					operator:    "Contains",
					matchValues: []string{"abc"},
				},
			},
			action: "Allow",
		},
	}
	engine, resLog, err := newEngineWithCustomRules(rules...)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	req1 := &mockWafHTTPRequest{uri: "/?a=abc", method: "GET"}

	// Act
	eval1 := engine.NewEvaluation(logger, resLog, req1, waf.OtherBody)
	defer eval1.Close()
	err1 := eval1.ScanHeaders()
	decision1 := eval1.EvalRules()

	// Assert
	assert.Nil(err1)
	assert.Equal(waf.Allow, decision1)
	assert.Equal(resLog.ruleMatched["rule1"], true)
}

func TestIPMatch(t *testing.T) {
	// Arrange
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)
	rules := []waf.CustomRule{
		&mockCustomRule{
			name:     "rule1",
			priority: 1,
			ruleType: "MatchRule",
			matchConditions: []waf.MatchCondition{
				&mockMatchCondition{
					matchVariables: []waf.MatchVariable{
						&mockMatchVariable{variableName: "RequestHeaders", selector: "X-Some-Header"},
					},
					operator:    "IPMatch",
					matchValues: []string{"1.1.0.0/16"},
				},
			},
			action: "Block",
		},
	}
	engine, resLog, err := newEngineWithCustomRules(rules...)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	req1 := &mockWafHTTPRequest{uri: "/", method: "GET", headers: []waf.HeaderPair{&mockHeaderPair{k: "X-Some-Header", v: "1.1.123.123"}}}
	req2 := &mockWafHTTPRequest{uri: "/", method: "GET", headers: []waf.HeaderPair{&mockHeaderPair{k: "X-Some-Header", v: "1.2.0.0"}}}

	// Act
	eval1 := engine.NewEvaluation(logger, resLog, req1, waf.OtherBody)
	defer eval1.Close()
	err1 := eval1.ScanHeaders()
	decision1 := eval1.EvalRules()

	eval2 := engine.NewEvaluation(logger, resLog, req2, waf.OtherBody)
	defer eval2.Close()
	err2 := eval2.ScanHeaders()
	decision2 := eval2.EvalRules()

	// Assert
	assert.Nil(err1)
	assert.Nil(err2)
	assert.Equal(waf.Block, decision1)
	assert.Equal(waf.Pass, decision2)
}

func TestGeoMatch(t *testing.T) {
	// Arrange
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)
	rules := []waf.CustomRule{
		&mockCustomRule{
			name:     "rule1",
			priority: 1,
			ruleType: "MatchRule",
			matchConditions: []waf.MatchCondition{
				&mockMatchCondition{
					matchVariables: []waf.MatchVariable{
						&mockMatchVariable{variableName: "RequestHeaders", selector: "X-Some-Header"},
					},
					operator:    "GeoMatch",
					matchValues: []string{"CC"},
				},
			},
			action: "Block",
		},
	}
	engine, resLog, err := newEngineWithCustomRules(rules...)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	req1 := &mockWafHTTPRequest{uri: "/", method: "GET", headers: []waf.HeaderPair{&mockHeaderPair{k: "X-Some-Header", v: "1.1.1.1:443,2.2.2.2:443"}}}
	req2 := &mockWafHTTPRequest{uri: "/", method: "GET", headers: []waf.HeaderPair{&mockHeaderPair{k: "X-Some-Header", v: "3.3.3.3:443,4.4.4.4:443"}}}

	// Act
	eval1 := engine.NewEvaluation(logger, resLog, req1, waf.OtherBody)
	defer eval1.Close()
	err1 := eval1.ScanHeaders()
	decision1 := eval1.EvalRules()

	eval2 := engine.NewEvaluation(logger, resLog, req2, waf.OtherBody)
	defer eval2.Close()
	err2 := eval2.ScanHeaders()
	decision2 := eval2.EvalRules()

	// Assert
	assert.Nil(err1)
	assert.Nil(err2)
	assert.Equal(waf.Block, decision1)
	assert.Equal(waf.Pass, decision2)
}
